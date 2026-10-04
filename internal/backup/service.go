package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zentworks/zentcal/internal/security"
	"github.com/zentworks/zentcal/internal/webhook"
)

type RuntimeConfig struct {
	DBHost, DBPort, DBName, DBUser, DBPasswordFile string
	DataDir                                        string
}

type Config struct {
	Enabled            bool
	Provider           string
	Schedule           string
	Time               string
	Weekday            int // legacy single-day setting
	Weekdays           []int
	Retention          int
	EncryptionPassword string
	SFTPHost           string
	SFTPPort           int
	SFTPUser           string
	SFTPPassword       string
	SFTPPrivateKey     string
	SFTPAuthMethod     string
	SFTPPath           string
	SFTPVerifyHost     bool
	S3                 S3Config
}

type Item struct {
	ID, Filename, Provider, ObjectKey, Status, Stage, Checksum, Error string
	Size                                                              int64
	CreatedAt                                                         time.Time
	CompletedAt                                                       *time.Time
}

type restoreBackupMetadata struct {
	ID          string    `json:"id"`
	Filename    string    `json:"filename"`
	Provider    string    `json:"provider"`
	ObjectKey   string    `json:"object_key"`
	Checksum    string    `json:"checksum"`
	Size        int64     `json:"size_bytes"`
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	CompletedAt time.Time `json:"completed_at"`
}

type restoreBackupCatalogItem struct {
	ID          string     `json:"id"`
	Filename    string     `json:"filename"`
	Provider    string     `json:"provider"`
	ObjectKey   string     `json:"object_key"`
	Status      string     `json:"status"`
	Stage       string     `json:"stage"`
	Size        int64      `json:"size_bytes"`
	Checksum    string     `json:"checksum"`
	Error       string     `json:"error"`
	CreatedBy   string     `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type Service struct {
	DB          *pgxpool.Pool
	Secrets     *security.SecretBox
	Log         *slog.Logger
	Runtime     RuntimeConfig
	Version     string
	Webhooks    *webhook.Service
	running     atomic.Bool
	maintenance atomic.Bool
}

func New(db *pgxpool.Pool, secrets *security.SecretBox, log *slog.Logger, runtime RuntimeConfig, version string) *Service {
	return &Service{DB: db, Secrets: secrets, Log: log, Runtime: runtime, Version: version}
}
func (s *Service) Maintenance() bool { return s.maintenance.Load() }
func (s *Service) Running() bool     { return s.running.Load() }
func (s *Service) RecoverInterrupted(ctx context.Context) error {
	_, err := s.DB.Exec(ctx, `UPDATE backups SET status='failed',stage='failed',error=CASE WHEN error='' THEN 'Backup wurde durch einen Neustart unterbrochen.' ELSE error END,completed_at=coalesce(completed_at,now()) WHERE status='running'`)
	return err
}
func (s *Service) snapshotBackupCatalog(ctx context.Context) ([]restoreBackupCatalogItem, error) {
	rows, err := s.DB.Query(ctx, `SELECT id::text,filename,provider,object_key,status,stage,size_bytes,checksum,coalesce(error,''),coalesce(created_by::text,''),created_at,completed_at FROM backups ORDER BY created_at,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]restoreBackupCatalogItem, 0)
	for rows.Next() {
		var item restoreBackupCatalogItem
		if err := rows.Scan(&item.ID, &item.Filename, &item.Provider, &item.ObjectKey, &item.Status, &item.Stage, &item.Size, &item.Checksum, &item.Error, &item.CreatedBy, &item.CreatedAt, &item.CompletedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Service) restoreBackupCatalog(ctx context.Context, items []restoreBackupCatalogItem) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `DELETE FROM backups`); err != nil {
		return err
	}
	for _, item := range items {
		if item.ID == "" || item.Filename == "" || item.Provider == "" || item.ObjectKey == "" || item.Status == "" {
			return errors.New("Backup-Katalog enthält ungültige Metadaten.")
		}
		if _, err = tx.Exec(ctx, `INSERT INTO backups(id,filename,provider,object_key,status,stage,size_bytes,checksum,error,created_by,created_at,completed_at)
VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,(SELECT id FROM users WHERE id=NULLIF($10,'')::uuid),$11,$12)`,
			item.ID, item.Filename, item.Provider, item.ObjectKey, item.Status, item.Stage, item.Size, item.Checksum, item.Error, item.CreatedBy, item.CreatedAt, item.CompletedAt); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Service) backupDir() string {
	if s.Runtime.DataDir == "" {
		return "/data"
	}
	return s.Runtime.DataDir
}

func (s *Service) tempDir() (string, error) {
	dir := filepath.Join(s.backupDir(), "tmp")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func (s *Service) LoadConfig(ctx context.Context) (Config, error) {
	vals := map[string]string{}
	rows, err := s.DB.Query(ctx, `SELECT key,value,secret FROM settings WHERE key LIKE 'backup_%'`)
	if err != nil {
		return Config{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		var sec bool
		if err := rows.Scan(&k, &v, &sec); err != nil {
			return Config{}, err
		}
		if sec && v != "" {
			v, err = s.Secrets.Decrypt(v)
			if err != nil {
				return Config{}, fmt.Errorf("Backup-Secret %s konnte nicht entschlüsselt werden", k)
			}
		}
		vals[k] = v
	}
	atoi := func(k string, d int) int {
		v, e := strconv.Atoi(vals[k])
		if e != nil {
			return d
		}
		return v
	}
	b := func(k string, d bool) bool {
		v, ok := vals[k]
		if !ok {
			return d
		}
		return v == "true"
	}
	cfg := Config{Enabled: b("backup_enabled", false), Provider: def(vals["backup_provider"], "local"), Schedule: def(vals["backup_schedule"], "daily"), Time: def(vals["backup_time"], "03:00"), Weekday: atoi("backup_weekday", 0), Retention: atoi("backup_retention", 14), EncryptionPassword: vals["backup_encryption_password"], SFTPHost: vals["backup_sftp_host"], SFTPPort: atoi("backup_sftp_port", 22), SFTPUser: vals["backup_sftp_user"], SFTPPassword: vals["backup_sftp_password"], SFTPPrivateKey: vals["backup_sftp_private_key"], SFTPAuthMethod: def(vals["backup_sftp_auth_method"], ""), SFTPPath: def(vals["backup_sftp_path"], "zentcal"), SFTPVerifyHost: b("backup_sftp_verify_host", true)}
	if cfg.SFTPAuthMethod == "" {
		if cfg.SFTPPrivateKey != "" {
			cfg.SFTPAuthMethod = "key"
		} else {
			cfg.SFTPAuthMethod = "password"
		}
	}
	cfg.Weekdays = parseWeekdays(vals["backup_weekdays"], cfg.Weekday)
	cfg.S3 = S3Config{Endpoint: vals["backup_s3_endpoint"], Region: def(vals["backup_s3_region"], "us-east-1"), Bucket: vals["backup_s3_bucket"], AccessKey: vals["backup_s3_access_key"], SecretKey: vals["backup_s3_secret_key"], Prefix: def(vals["backup_s3_prefix"], "zentcal"), TLSVerify: b("backup_s3_tls_verify", true)}
	return cfg, nil
}
func parseWeekdays(raw string, legacy int) []int {
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(raw, ",") {
		v, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil && v >= 0 && v <= 6 && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	if len(out) == 0 && legacy >= 0 && legacy <= 6 {
		out = []int{legacy}
	}
	return out
}

func def(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return strings.TrimSpace(v)
}

func (s *Service) List(ctx context.Context, limit int) ([]Item, error) {
	rows, err := s.DB.Query(ctx, `SELECT id::text,filename,provider,object_key,status,stage,size_bytes,checksum,coalesce(error,''),created_at,completed_at FROM backups ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var i Item
		if err := rows.Scan(&i.ID, &i.Filename, &i.Provider, &i.ObjectKey, &i.Status, &i.Stage, &i.Size, &i.Checksum, &i.Error, &i.CreatedAt, &i.CompletedAt); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (s *Service) Create(ctx context.Context, actor string) (Item, error) {
	if !s.running.CompareAndSwap(false, true) {
		return Item{}, errors.New("Es läuft bereits ein Backup.")
	}
	defer s.running.Store(false)
	cfg, err := s.LoadConfig(ctx)
	if err != nil {
		return Item{}, err
	}
	if cfg.Provider != "local" && cfg.Provider != "sftp" && cfg.Provider != "s3" {
		return Item{}, errors.New("Unbekannter Backup-Provider.")
	}
	id := security.UUID()
	stamp := time.Now().UTC().Format("20060102-150405")
	filename := "zentcal-" + stamp + "-" + s.Version + ".zcbak"
	objectKey := filename
	_, err = s.DB.Exec(ctx, `INSERT INTO backups(id,filename,provider,object_key,status,stage,created_by) VALUES($1,$2,$3,$4,'running','preparing',NULLIF($5,'')::uuid)`, id, filename, cfg.Provider, objectKey, actor)
	if err != nil {
		return Item{}, err
	}
	setStage := func(stage string) {
		_, _ = s.DB.Exec(context.Background(), `UPDATE backups SET stage=$2 WHERE id=$1`, id, stage)
	}
	fail := func(e error) (Item, error) {
		_, _ = s.DB.Exec(context.Background(), `UPDATE backups SET status='failed',stage='failed',error=$2,completed_at=now() WHERE id=$1`, id, truncate(e.Error(), 1000))
		s.emitActor(context.Background(), "backup.failed", id, actor, map[string]any{"provider": cfg.Provider, "filename": filename, "error": truncate(e.Error(), 500)})
		return Item{}, e
	}
	if len(cfg.EncryptionPassword) < 10 {
		return fail(errors.New("Bitte zuerst ein Backup-Verschlüsselungspasswort festlegen."))
	}
	if err := s.validateProvider(cfg); err != nil {
		return fail(err)
	}
	tmpRoot, err := s.tempDir()
	if err != nil {
		return fail(err)
	}
	tmp, err := os.MkdirTemp(tmpRoot, "backup-")
	if err != nil {
		return fail(err)
	}
	defer os.RemoveAll(tmp)
	dump := filepath.Join(tmp, "database.dump")
	setStage("database")
	if err = s.pgDump(ctx, dump); err != nil {
		return fail(err)
	}
	secretsFile := filepath.Join(tmp, "secrets.json")
	setStage("data")
	if err = s.exportSecrets(ctx, secretsFile); err != nil {
		return fail(err)
	}
	manifest := map[string]any{"product": "ZentCal", "version": s.Version, "created_at": time.Now().UTC().Format(time.RFC3339Nano), "database_format": "pg_dump_custom"}
	mb, _ := json.MarshalIndent(manifest, "", "  ")
	if err = os.WriteFile(filepath.Join(tmp, "manifest.json"), mb, 0600); err != nil {
		return fail(err)
	}
	archive := filepath.Join(tmp, "archive.tar.gz")
	setStage("archive")
	if err = createTarGz(archive, map[string]string{"database.dump": dump, "secrets.json": secretsFile, "manifest.json": filepath.Join(tmp, "manifest.json")}); err != nil {
		return fail(err)
	}
	encrypted := filepath.Join(tmp, filename)
	setStage("encrypt")
	if err = encryptFile(archive, encrypted, cfg.EncryptionPassword); err != nil {
		return fail(err)
	}
	checksum, size, err := checksumFile(encrypted)
	if err != nil {
		return fail(err)
	}
	setStage("upload")
	if err = s.put(ctx, cfg, objectKey, encrypted); err != nil {
		return fail(err)
	}
	_, err = s.DB.Exec(ctx, `UPDATE backups SET status='success',stage='done',size_bytes=$2,checksum=$3,completed_at=now(),error='' WHERE id=$1`, id, size, checksum)
	if err != nil {
		return fail(err)
	}
	_ = s.enforceRetention(ctx, cfg)
	var item Item
	err = s.DB.QueryRow(ctx, `SELECT id::text,filename,provider,object_key,status,stage,size_bytes,checksum,coalesce(error,''),created_at,completed_at FROM backups WHERE id=$1`, id).Scan(&item.ID, &item.Filename, &item.Provider, &item.ObjectKey, &item.Status, &item.Stage, &item.Size, &item.Checksum, &item.Error, &item.CreatedAt, &item.CompletedAt)
	if err == nil {
		s.emitActor(ctx, "backup.succeeded", id, actor, map[string]any{"provider": item.Provider, "filename": item.Filename, "size_bytes": item.Size})
	}
	return item, err
}

func (s *Service) validateProvider(c Config) error {
	switch c.Provider {
	case "local":
		return os.MkdirAll(filepath.Join(s.backupDir(), "backups"), 0700)
	case "sftp":
		if c.SFTPHost == "" || c.SFTPUser == "" || c.SFTPPath == "" {
			return errors.New("SFTP Host, Benutzer und Pfad sind erforderlich.")
		}
		if c.SFTPAuthMethod != "password" && c.SFTPAuthMethod != "key" {
			return errors.New("Bitte eine SFTP-Authentifizierung auswählen.")
		}
		if c.SFTPAuthMethod == "password" && c.SFTPPassword == "" {
			return errors.New("Für SFTP mit Passwort ist ein Passwort erforderlich.")
		}
		if c.SFTPAuthMethod == "key" && c.SFTPPrivateKey == "" {
			return errors.New("Für SFTP mit SSH Private Key ist ein Private Key erforderlich.")
		}
		return nil
	case "s3":
		if c.S3.Endpoint == "" || c.S3.Bucket == "" || c.S3.AccessKey == "" || c.S3.SecretKey == "" {
			return errors.New("S3 Endpoint, Bucket, Access Key und Secret Key sind erforderlich.")
		}
		return nil
	default:
		return errors.New("Unbekannter Backup-Provider.")
	}
}
func (s *Service) put(ctx context.Context, c Config, key, file string) error {
	switch c.Provider {
	case "local":
		dst := filepath.Join(s.backupDir(), "backups", filepath.Base(key))
		return copyFile(file, dst)
	case "sftp":
		return s.sftp(ctx, c, "put", file, key)
	case "s3":
		return c.S3.Put(ctx, key, file)
	}
	return errors.New("provider")
}
func (s *Service) get(ctx context.Context, c Config, key, file string) error {
	switch c.Provider {
	case "local":
		return copyFile(filepath.Join(s.backupDir(), "backups", filepath.Base(key)), file)
	case "sftp":
		return s.sftp(ctx, c, "get", file, key)
	case "s3":
		return c.S3.Get(ctx, key, file)
	}
	return errors.New("provider")
}
func (s *Service) deleteObject(ctx context.Context, c Config, key string) error {
	switch c.Provider {
	case "local":
		err := os.Remove(filepath.Join(s.backupDir(), "backups", filepath.Base(key)))
		if os.IsNotExist(err) {
			return nil
		}
		return err
	case "sftp":
		return s.sftp(ctx, c, "delete", "", key)
	case "s3":
		return c.S3.Delete(ctx, key)
	}
	return errors.New("provider")
}

func (s *Service) TestProvider(ctx context.Context, c Config) error {
	if err := s.validateProvider(c); err != nil {
		return err
	}
	switch c.Provider {
	case "local":
		f, err := os.CreateTemp(filepath.Join(s.backupDir(), "backups"), ".test-")
		if err != nil {
			return err
		}
		name := f.Name()
		_ = f.Close()
		return os.Remove(name)
	case "sftp":
		return s.sftp(ctx, c, "test", "", "")
	case "s3":
		return c.S3.Test(ctx)
	}
	return nil
}

func (s *Service) Delete(ctx context.Context, id string) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("Es läuft bereits ein Backup oder Restore.")
	}
	defer s.running.Store(false)
	return s.deleteUnlocked(ctx, id)
}

func (s *Service) deleteUnlocked(ctx context.Context, id string) error {
	var provider, key, status string
	if err := s.DB.QueryRow(ctx, `SELECT provider,object_key,status FROM backups WHERE id=$1`, id).Scan(&provider, &key, &status); err != nil {
		return err
	}
	if status == "running" {
		return errors.New("Ein laufendes Backup kann nicht gelöscht werden.")
	}
	cfg, err := s.LoadConfig(ctx)
	if err != nil {
		return err
	}
	cfg.Provider = provider
	if err = s.deleteObject(ctx, cfg, key); err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `DELETE FROM backups WHERE id=$1`, id)
	return err
}

func (s *Service) restore(ctx context.Context, id, password string) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("Es läuft bereits ein Backup oder Restore.")
	}
	defer s.running.Store(false)
	s.maintenance.Store(true)
	ok := false
	defer func() {
		if !ok {
			s.maintenance.Store(false)
		}
	}()
	var meta restoreBackupMetadata
	if err := s.DB.QueryRow(ctx, `SELECT id::text,filename,provider,object_key,checksum,size_bytes,coalesce(created_by::text,''),created_at,coalesce(completed_at,created_at) FROM backups WHERE id=$1 AND status='success'`, id).Scan(&meta.ID, &meta.Filename, &meta.Provider, &meta.ObjectKey, &meta.Checksum, &meta.Size, &meta.CreatedBy, &meta.CreatedAt, &meta.CompletedAt); err != nil {
		return err
	}
	provider, key, expected := meta.Provider, meta.ObjectKey, meta.Checksum
	cfg, err := s.LoadConfig(ctx)
	if err != nil {
		return err
	}
	cfg.Provider = provider
	tmpRoot, err := s.tempDir()
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(tmpRoot, "restore-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	enc := filepath.Join(tmp, "backup.zcbak")
	if err = s.get(ctx, cfg, key, enc); err != nil {
		return err
	}
	sum, _, err := checksumFile(enc)
	if err != nil {
		return err
	}
	if expected != "" && sum != expected {
		return errors.New("Backup-Checksumme stimmt nicht überein.")
	}
	archive := filepath.Join(tmp, "archive.tar.gz")
	if err = decryptFile(enc, archive, password); err != nil {
		return err
	}
	if err = extractTarGz(archive, tmp); err != nil {
		return err
	}
	manifestRaw, err := os.ReadFile(filepath.Join(tmp, "manifest.json"))
	if err != nil {
		return errors.New("Backup-Manifest fehlt.")
	}
	var manifest map[string]any
	if json.Unmarshal(manifestRaw, &manifest) != nil || manifest["product"] != "ZentCal" {
		return errors.New("Backup ist kein gültiges ZentCal-Backup.")
	}
	if _, err = os.Stat(filepath.Join(tmp, "database.dump")); err != nil {
		return errors.New("Backup-Datenbank fehlt.")
	}
	if _, err = os.Stat(filepath.Join(tmp, "secrets.json")); err != nil {
		return errors.New("Backup-Secrets fehlen.")
	}
	catalog, err := s.snapshotBackupCatalog(ctx)
	if err != nil {
		return fmt.Errorf("Aktueller Backup-Katalog konnte nicht gesichert werden: %w", err)
	}
	pending := filepath.Join(s.backupDir(), "restore-pending")
	staged := pending + ".new"
	_ = os.RemoveAll(staged)
	if err = os.MkdirAll(staged, 0700); err != nil {
		return err
	}
	for _, name := range []string{"database.dump", "secrets.json", "manifest.json"} {
		if err = copyFile(filepath.Join(tmp, name), filepath.Join(staged, name)); err != nil {
			_ = os.RemoveAll(staged)
			return err
		}
	}
	metaRaw, err := json.Marshal(meta)
	if err != nil {
		_ = os.RemoveAll(staged)
		return err
	}
	if err = os.WriteFile(filepath.Join(staged, "restore-meta.json"), metaRaw, 0600); err != nil {
		_ = os.RemoveAll(staged)
		return err
	}
	catalogRaw, err := json.Marshal(catalog)
	if err != nil {
		_ = os.RemoveAll(staged)
		return err
	}
	if err = os.WriteFile(filepath.Join(staged, "backup-catalog.json"), catalogRaw, 0600); err != nil {
		_ = os.RemoveAll(staged)
		return err
	}
	if err = os.WriteFile(filepath.Join(staged, "pending"), []byte(time.Now().UTC().Format(time.RFC3339Nano)), 0600); err != nil {
		_ = os.RemoveAll(staged)
		return err
	}
	_ = os.RemoveAll(pending)
	if err = os.Rename(staged, pending); err != nil {
		return err
	}
	ok = true
	return nil
}

// ApplyPendingDatabaseRestore runs before ZentCal opens its PostgreSQL pool. This
// prevents web requests, webhook workers and scheduling jobs from writing into a
// database while pg_restore is replacing its contents.
func ApplyPendingDatabaseRestore(ctx context.Context, runtime RuntimeConfig) error {
	pending := filepath.Join(runtime.DataDir, "restore-pending")
	if _, err := os.Stat(filepath.Join(pending, "pending")); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(pending, "database.applied")); err == nil {
		return nil
	}
	env, err := pgEnvForRuntime(runtime)
	if err != nil {
		return err
	}
	src := filepath.Join(pending, "database.dump")
	args := []string{"--host", runtime.DBHost, "--port", runtime.DBPort, "--username", runtime.DBUser, "--dbname", runtime.DBName, "--clean", "--if-exists", "--no-owner", "--no-acl", "--single-transaction", "--exit-on-error", src}
	cmd := exec.CommandContext(ctx, "pg_restore", args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pending pg_restore fehlgeschlagen: %s", truncate(string(out), 1000))
	}
	return os.WriteFile(filepath.Join(pending, "database.applied"), []byte(time.Now().UTC().Format(time.RFC3339Nano)), 0600)
}

func (s *Service) CompletePendingRestore(ctx context.Context) error {
	pending := filepath.Join(s.backupDir(), "restore-pending")
	if _, err := os.Stat(filepath.Join(pending, "database.applied")); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := s.importSecrets(ctx, filepath.Join(pending, "secrets.json")); err != nil {
		return err
	}

	catalogRaw, catalogErr := os.ReadFile(filepath.Join(pending, "backup-catalog.json"))
	if catalogErr == nil {
		var catalog []restoreBackupCatalogItem
		if err := json.Unmarshal(catalogRaw, &catalog); err != nil {
			return fmt.Errorf("Backup-Katalog des Restores ist ungültig: %w", err)
		}
		if err := s.restoreBackupCatalog(ctx, catalog); err != nil {
			return fmt.Errorf("Backup-Katalog konnte nach dem Restore nicht wiederhergestellt werden: %w", err)
		}
		return os.RemoveAll(pending)
	}
	if !errors.Is(catalogErr, os.ErrNotExist) {
		return fmt.Errorf("Backup-Katalog des Restores konnte nicht gelesen werden: %w", catalogErr)
	}

	// Backward compatibility for a restore staged by 0.1.27/0.1.28. Those
	// versions preserved only the source backup metadata, not the full catalog.
	metaRaw, err := os.ReadFile(filepath.Join(pending, "restore-meta.json"))
	if errors.Is(err, os.ErrNotExist) {
		// Even older pending restores did not have metadata at all. The database
		// is already applied, so avoid turning a harmless upgrade into a loop.
		return os.RemoveAll(pending)
	}
	if err != nil {
		return fmt.Errorf("Restore-Metadaten konnten nicht gelesen werden: %w", err)
	}
	var meta restoreBackupMetadata
	if err = json.Unmarshal(metaRaw, &meta); err != nil || meta.ID == "" || meta.Filename == "" || meta.Provider == "" || meta.ObjectKey == "" {
		return errors.New("Restore-Metadaten sind ungültig.")
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO backups(id,filename,provider,object_key,status,stage,size_bytes,checksum,error,created_by,created_at,completed_at)
VALUES($1::uuid,$2,$3,$4,'success','done',$5,$6,'',(SELECT id FROM users WHERE id=NULLIF($7,'')::uuid),$8,$9)
ON CONFLICT(id) DO UPDATE SET filename=excluded.filename,provider=excluded.provider,object_key=excluded.object_key,status='success',stage='done',size_bytes=excluded.size_bytes,checksum=excluded.checksum,error='',created_by=excluded.created_by,created_at=excluded.created_at,completed_at=excluded.completed_at`,
		meta.ID, meta.Filename, meta.Provider, meta.ObjectKey, meta.Size, meta.Checksum, meta.CreatedBy, meta.CreatedAt, meta.CompletedAt)
	if err != nil {
		return fmt.Errorf("Restore-Backupstatus konnte nicht wiederhergestellt werden: %w", err)
	}
	return os.RemoveAll(pending)
}

func (s *Service) verify(ctx context.Context, id, password string) error {
	var provider, key, expected string
	if err := s.DB.QueryRow(ctx, `SELECT provider,object_key,checksum FROM backups WHERE id=$1 AND status='success'`, id).Scan(&provider, &key, &expected); err != nil {
		return err
	}
	cfg, err := s.LoadConfig(ctx)
	if err != nil {
		return err
	}
	cfg.Provider = provider
	tmpRoot, err := s.tempDir()
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(tmpRoot, "verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	enc := filepath.Join(tmp, "backup.zcbak")
	if err = s.get(ctx, cfg, key, enc); err != nil {
		return err
	}
	sum, _, err := checksumFile(enc)
	if err != nil {
		return err
	}
	if expected != "" && sum != expected {
		return errors.New("Backup-Checksumme stimmt nicht überein.")
	}
	archive := filepath.Join(tmp, "archive.tar.gz")
	if err = decryptFile(enc, archive, password); err != nil {
		return err
	}
	return extractTarGz(archive, tmp)
}

func (s *Service) Restore(ctx context.Context, id, password string) error {
	err := s.restore(ctx, id, password)
	if err != nil {
		s.emit(ctx, "backup.restore.failed", id, map[string]any{"error": truncate(err.Error(), 500)})
		return err
	}
	s.emit(ctx, "backup.restore.started", id, nil)
	return nil
}

func (s *Service) Verify(ctx context.Context, id, password string) error {
	err := s.verify(ctx, id, password)
	if err != nil {
		s.emit(ctx, "backup.verify.failed", id, map[string]any{"error": truncate(err.Error(), 500)})
	}
	return err
}

func (s *Service) emit(ctx context.Context, event, id string, data any) {
	s.emitActor(ctx, event, id, "", data)
}

func (s *Service) emitActor(ctx context.Context, event, id, actor string, data any) {
	if s.Webhooks != nil {
		s.Webhooks.Emit(ctx, event, actor, "backup", id, data)
	}
}

func pgEnvForRuntime(runtime RuntimeConfig) ([]string, error) {
	b, err := os.ReadFile(runtime.DBPasswordFile)
	if err != nil {
		return nil, err
	}
	return append(os.Environ(), "PGPASSWORD="+strings.TrimSpace(string(b))), nil
}

func (s *Service) pgEnv() ([]string, error) { return pgEnvForRuntime(s.Runtime) }
func pgDumpArgs(runtime RuntimeConfig, dst string) []string {
	return []string{"--host", runtime.DBHost, "--port", runtime.DBPort, "--username", runtime.DBUser, "--dbname", runtime.DBName, "--format=custom", "--no-owner", "--no-acl", "--exclude-table-data=public.backups", "--file", dst}
}

func (s *Service) pgDump(ctx context.Context, dst string) error {
	env, err := s.pgEnv()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "pg_dump", pgDumpArgs(s.Runtime, dst)...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pg_dump fehlgeschlagen: %s", truncate(string(out), 500))
	}
	return nil
}
func (s *Service) pgRestore(ctx context.Context, src string) error {
	env, err := s.pgEnv()
	if err != nil {
		return err
	}
	args := []string{"--host", s.Runtime.DBHost, "--port", s.Runtime.DBPort, "--username", s.Runtime.DBUser, "--dbname", s.Runtime.DBName, "--clean", "--if-exists", "--no-owner", "--no-acl", "--single-transaction", "--exit-on-error", src}
	cmd := exec.CommandContext(ctx, "pg_restore", args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pg_restore fehlgeschlagen: %s", truncate(string(out), 1000))
	}
	return nil
}

func (s *Service) exportSecrets(ctx context.Context, dst string) error {
	type secretBundle struct {
		Settings map[string]string `json:"settings"`
		Webhooks map[string]string `json:"webhooks"`
	}
	b := secretBundle{Settings: map[string]string{}, Webhooks: map[string]string{}}
	rows, err := s.DB.Query(ctx, `SELECT key,value FROM settings WHERE secret`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) == nil {
			plain, e := s.Secrets.Decrypt(v)
			if e != nil {
				rows.Close()
				return e
			}
			b.Settings[k] = plain
		}
	}
	rows.Close()
	wr, err := s.DB.Query(ctx, `SELECT id::text,secret FROM webhooks`)
	if err == nil {
		for wr.Next() {
			var id, v string
			if wr.Scan(&id, &v) == nil {
				plain, e := s.Secrets.Decrypt(v)
				if e != nil {
					wr.Close()
					return e
				}
				b.Webhooks[id] = plain
			}
		}
		wr.Close()
	}
	raw, _ := json.Marshal(b)
	return os.WriteFile(dst, raw, 0600)
}
func (s *Service) importSecrets(ctx context.Context, src string) error {
	type secretBundle struct {
		Settings map[string]string `json:"settings"`
		Webhooks map[string]string `json:"webhooks"`
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	var b secretBundle
	if err = json.Unmarshal(raw, &b); err != nil {
		return err
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for k, v := range b.Settings {
		enc, e := s.Secrets.Encrypt(v)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO settings(key,value,secret) VALUES($1,$2,true) ON CONFLICT(key) DO UPDATE SET value=excluded.value,secret=true,updated_at=now()`, k, enc); e != nil {
			return e
		}
	}
	for id, v := range b.Webhooks {
		enc, e := s.Secrets.Encrypt(v)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE webhooks SET secret=$1 WHERE id=$2`, enc, id); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}

func (s *Service) sftp(ctx context.Context, c Config, op, local, key string) error {
	if strings.ContainsAny(c.SFTPHost+c.SFTPUser+c.SFTPPath+key, "\r\n") {
		return errors.New("Ungültige SFTP-Konfiguration.")
	}
	known := filepath.Join(s.backupDir(), "ssh", "known_hosts")
	_ = os.MkdirAll(filepath.Dir(known), 0700)
	strict := "no"
	if c.SFTPVerifyHost {
		strict = "accept-new"
	}
	args := []string{"-o", "UserKnownHostsFile=" + known, "-o", "StrictHostKeyChecking=" + strict, "-P", strconv.Itoa(c.SFTPPort)}
	var keyFile string
	if c.SFTPAuthMethod == "key" {
		tmpRoot, err := s.tempDir()
		if err != nil {
			return err
		}
		f, err := os.CreateTemp(tmpRoot, "sftp-key-")
		if err != nil {
			return err
		}
		keyFile = f.Name()
		if err = os.WriteFile(keyFile, []byte(c.SFTPPrivateKey), 0600); err != nil {
			return err
		}
		defer os.Remove(keyFile)
		args = append(args, "-i", keyFile, "-o", "BatchMode=yes")
	} else {
		args = append(args, "-o", "BatchMode=no")
	}
	target := c.SFTPUser + "@" + c.SFTPHost
	args = append(args, target)
	remote := strings.TrimRight(c.SFTPPath, "/") + "/" + filepath.Base(key)
	batch := ""
	quote := func(v string) string {
		v = strings.ReplaceAll(v, `\`, `\\`)
		v = strings.ReplaceAll(v, `"`, `\"`)
		return `"` + v + `"`
	}
	switch op {
	case "put":
		// A pre-existing directory must not abort an SFTP batch.
		batch = "-mkdir " + quote(c.SFTPPath) + "\nput " + quote(local) + " " + quote(remote) + "\n"
	case "get":
		batch = "get " + quote(remote) + " " + quote(local) + "\n"
	case "delete":
		batch = "rm " + quote(remote) + "\n"
	case "test":
		batch = "ls .\n"
	}
	var cmd *exec.Cmd
	if c.SFTPAuthMethod == "password" {
		cmd = exec.CommandContext(ctx, "sshpass", append([]string{"-e", "sftp"}, args...)...)
		cmd.Env = append(os.Environ(), "SSHPASS="+c.SFTPPassword)
	} else {
		cmd = exec.CommandContext(ctx, "sftp", args...)
	}
	cmd.Stdin = strings.NewReader(batch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("SFTP fehlgeschlagen: %s", truncate(string(out), 800))
	}
	return nil
}

func (s *Service) enforceRetention(ctx context.Context, c Config) error {
	if c.Retention < 1 {
		return nil
	}
	rows, err := s.DB.Query(ctx, `SELECT id::text FROM backups WHERE status='success' ORDER BY created_at DESC OFFSET $1`, c.Retention)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	for _, id := range ids {
		_ = s.deleteUnlocked(ctx, id)
	}
	return nil
}

func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runDue(ctx)
		}
	}
}
func (s *Service) runDue(ctx context.Context) {
	cfg, err := s.LoadConfig(ctx)
	if err != nil || !cfg.Enabled || cfg.EncryptionPassword == "" {
		return
	}
	var last *time.Time
	_ = s.DB.QueryRow(ctx, `SELECT max(completed_at) FROM backups WHERE status='success'`).Scan(&last)
	next := s.nextRun(ctx, cfg, last)
	if !time.Now().Before(next) {
		if _, err = s.Create(context.Background(), ""); err != nil && s.Log != nil {
			s.Log.Error("scheduled backup failed", "error", err)
		}
	}
}
func (s *Service) NextRun(ctx context.Context) (*time.Time, error) {
	cfg, err := s.LoadConfig(ctx)
	if err != nil || !cfg.Enabled {
		return nil, err
	}
	var last *time.Time
	_ = s.DB.QueryRow(ctx, `SELECT max(completed_at) FROM backups WHERE status='success'`).Scan(&last)
	n := s.nextRun(ctx, cfg, last)
	return &n, nil
}
func (s *Service) nextRun(ctx context.Context, c Config, last *time.Time) time.Time {
	tz := "Europe/Berlin"
	_ = s.DB.QueryRow(ctx, `SELECT value FROM settings WHERE key='timezone'`).Scan(&tz)
	loc, _ := time.LoadLocation(tz)
	if loc == nil {
		loc = time.Local
	}
	parts := strings.Split(c.Time, ":")
	hh, mm := 3, 0
	if len(parts) == 2 {
		if v, e := strconv.Atoi(parts[0]); e == nil {
			hh = v
		}
		if v, e := strconv.Atoi(parts[1]); e == nil {
			mm = v
		}
	}
	now := time.Now().In(loc)
	anchor := now
	if last != nil {
		anchor = last.In(loc)
	}
	if c.Schedule != "weekly" {
		candidate := time.Date(anchor.Year(), anchor.Month(), anchor.Day(), hh, mm, 0, 0, loc)
		if !candidate.After(anchor) {
			candidate = candidate.AddDate(0, 0, 1)
		}
		if last == nil && candidate.Before(now.Add(-time.Minute)) {
			candidate = candidate.AddDate(0, 0, 1)
		}
		return candidate
	}
	days := c.Weekdays
	if len(days) == 0 {
		days = []int{c.Weekday}
	}
	selected := map[int]bool{}
	for _, d := range days {
		if d >= 0 && d <= 6 {
			selected[d] = true
		}
	}
	if len(selected) == 0 {
		selected[0] = true
	}
	startDay := time.Date(anchor.Year(), anchor.Month(), anchor.Day(), hh, mm, 0, 0, loc)
	for offset := 0; offset <= 14; offset++ {
		candidate := startDay.AddDate(0, 0, offset)
		if !selected[int(candidate.Weekday())] {
			continue
		}
		if candidate.After(anchor) && (last != nil || !candidate.Before(now.Add(-time.Minute))) {
			return candidate
		}
	}
	// Defensive fallback; normally the loop always returns within seven days.
	return startDay.AddDate(0, 0, 7)
}

func (s *Service) Materialize(ctx context.Context, id string) (string, func(), error) {
	var provider, key string
	if err := s.DB.QueryRow(ctx, `SELECT provider,object_key FROM backups WHERE id=$1 AND status='success'`, id).Scan(&provider, &key); err != nil {
		return "", func() {}, err
	}
	cfg, err := s.LoadConfig(ctx)
	if err != nil {
		return "", func() {}, err
	}
	cfg.Provider = provider
	tmpRoot, err := s.tempDir()
	if err != nil {
		return "", func() {}, err
	}
	tmp, err := os.MkdirTemp(tmpRoot, "download-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	dst := filepath.Join(tmp, filepath.Base(key))
	if err = s.get(ctx, cfg, key, dst); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return dst, cleanup, nil
}

func (s *Service) ImportUploaded(ctx context.Context, src, originalName, actor string) (Item, error) {
	if err := os.MkdirAll(filepath.Join(s.backupDir(), "backups"), 0700); err != nil {
		return Item{}, err
	}
	name := filepath.Base(originalName)
	if !strings.HasSuffix(strings.ToLower(name), ".zcbak") {
		name = "zentcal-upload-" + time.Now().UTC().Format("20060102-150405") + ".zcbak"
	}
	name = strings.ReplaceAll(name, " ", "-")
	dst := filepath.Join(s.backupDir(), "backups", name)
	if err := copyFile(src, dst); err != nil {
		return Item{}, err
	}
	sum, size, err := checksumFile(dst)
	if err != nil {
		return Item{}, err
	}
	id := security.UUID()
	_, err = s.DB.Exec(ctx, `INSERT INTO backups(id,filename,provider,object_key,status,size_bytes,checksum,created_by,completed_at) VALUES($1,$2,'local',$2,'success',$3,$4,NULLIF($5,'')::uuid,now())`, id, name, size, sum, actor)
	if err != nil {
		_ = os.Remove(dst)
		return Item{}, err
	}
	return Item{ID: id, Filename: name, Provider: "local", ObjectKey: name, Status: "success", Size: size, Checksum: sum, CreatedAt: time.Now()}, nil
}

func createTarGz(dst string, files map[string]string) error {
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	for name, src := range files {
		f, err := os.Open(src)
		if err != nil {
			return err
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		hdr := &tar.Header{Name: name, Mode: 0600, Size: st.Size(), ModTime: st.ModTime()}
		if err = tw.WriteHeader(hdr); err != nil {
			f.Close()
			return err
		}
		_, err = io.Copy(tw, f)
		f.Close()
		if err != nil {
			return err
		}
	}
	if err = tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

const (
	maxRestoreArchiveBytes = int64(32 << 30)
	maxRestoreDatabaseSize = int64(32 << 30)
	maxRestoreSecretsSize  = int64(16 << 20)
	maxRestoreManifestSize = int64(1 << 20)
)

func extractTarGz(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	allowed := map[string]int64{
		"database.dump": maxRestoreDatabaseSize,
		"secrets.json":  maxRestoreSecretsSize,
		"manifest.json": maxRestoreManifestSize,
	}
	seen := make(map[string]bool, len(allowed))
	var total int64
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(h.Name)
		if filepath.IsAbs(name) || name != filepath.Base(name) || strings.HasPrefix(name, "..") || strings.Contains(name, "/..") {
			return errors.New("Ungültiger Pfad im Backup.")
		}
		limit, ok := allowed[name]
		if !ok || seen[name] {
			return errors.New("Unerwarteter oder doppelter Eintrag im Backup.")
		}
		if h.Typeflag != tar.TypeReg || h.Size < 0 || h.Size > limit {
			return errors.New("Ungültige Größe oder Art eines Backup-Eintrags.")
		}
		if total > maxRestoreArchiveBytes-h.Size {
			return errors.New("Backup ist nach dem Entpacken zu groß.")
		}
		total += h.Size
		target := filepath.Join(dst, name)
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		n, copyErr := io.Copy(out, io.LimitReader(tr, limit+1))
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if n != h.Size || n > limit {
			return errors.New("Backup-Eintrag hat eine ungültige Größe.")
		}
		seen[name] = true
	}
	for name := range allowed {
		if !seen[name] {
			return fmt.Errorf("Backup ist unvollständig: %s fehlt", name)
		}
	}
	return nil
}
func checksumFile(name string) (string, int64, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err = os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
func truncate(v string, n int) string {
	v = strings.TrimSpace(v)
	if len(v) > n {
		return v[:n]
	}
	return v
}
