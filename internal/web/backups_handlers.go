package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/zentworks/zentcal/internal/backup"
	"github.com/zentworks/zentcal/internal/httpx"
	"github.com/zentworks/zentcal/internal/security"
)

func (h *Handler) backupsPage(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminPage(w, r, "backups")
	if !ok {
		return
	}
	if h.Backup == nil {
		http.Error(w, "Backup service unavailable", 500)
		return
	}
	cfg, _ := h.Backup.LoadConfig(r.Context())
	items, _ := h.Backup.List(r.Context(), 200)
	var dbsize int64
	_ = h.DB.QueryRow(r.Context(), `SELECT pg_database_size(current_database())`).Scan(&dbsize)
	var last *time.Time
	_ = h.DB.QueryRow(r.Context(), `SELECT max(completed_at) FROM backups WHERE status='success'`).Scan(&last)
	next, _ := h.Backup.NextRun(r.Context())
	data := map[string]any{
		"Config": cfg, "Items": items, "DBSize": formatBytes(dbsize), "Last": last, "Next": next,
		"EncryptionSet": len(cfg.EncryptionPassword) >= 10, "SFTPPasswordSet": cfg.SFTPPassword != "", "SFTPKeySet": cfg.SFTPPrivateKey != "", "SFTPAuthMethod": cfg.SFTPAuthMethod, "S3SecretSet": cfg.S3.SecretKey != "",
		"ReauthAction": strings.TrimSpace(r.URL.Query().Get("reauth_action")), "ReauthTarget": strings.TrimSpace(r.URL.Query().Get("backup_id")),
	}
	h.render(w, "backups", ss, pageData{Title: "Backups", Page: "backups", Data: data})
}

func (h *Handler) backupConfigFromRequest(ctx context.Context, r *http.Request) (backup.Config, error) {
	current, err := h.Backup.LoadConfig(ctx)
	if err != nil {
		return backup.Config{}, err
	}
	port, err := parseIntRange(r.FormValue("backup_sftp_port"), 1, 65535)
	if err != nil {
		port = current.SFTPPort
		if port == 0 {
			port = 22
		}
	}
	ret, err := parseIntRange(r.FormValue("backup_retention"), 1, 3650)
	if err != nil {
		return backup.Config{}, errors.New("Retention muss zwischen 1 und 3650 Backups liegen.")
	}
	weekdays := []int{}
	seenDays := map[int]bool{}
	for _, rawDay := range r.Form["backup_weekdays"] {
		d, convErr := strconv.Atoi(rawDay)
		if convErr == nil && d >= 0 && d <= 6 && !seenDays[d] {
			seenDays[d] = true
			weekdays = append(weekdays, d)
		}
	}
	provider := strings.TrimSpace(r.FormValue("backup_provider"))
	if provider != "local" && provider != "sftp" && provider != "s3" {
		return backup.Config{}, errors.New("Ungültiger Backup-Provider.")
	}
	schedule := strings.TrimSpace(r.FormValue("backup_schedule"))
	if schedule != "daily" && schedule != "weekly" {
		schedule = "daily"
	}
	if schedule == "weekly" && len(weekdays) == 0 {
		return backup.Config{}, errors.New("Bitte mindestens einen Wochentag auswählen.")
	}
	tm := strings.TrimSpace(r.FormValue("backup_time"))
	if _, err := time.Parse("15:04", tm); err != nil {
		return backup.Config{}, errors.New("Ungültige Backup-Uhrzeit.")
	}
	cfg := current
	cfg.Enabled = r.FormValue("backup_enabled") == "true"
	cfg.Provider = provider
	cfg.Schedule = schedule
	cfg.Time = tm
	cfg.Weekdays = weekdays
	if len(weekdays) > 0 {
		cfg.Weekday = weekdays[0]
	}
	cfg.Retention = ret
	cfg.SFTPHost = strings.TrimSpace(r.FormValue("backup_sftp_host"))
	cfg.SFTPPort = port
	cfg.SFTPUser = strings.TrimSpace(r.FormValue("backup_sftp_user"))
	cfg.SFTPPath = strings.TrimSpace(r.FormValue("backup_sftp_path"))
	cfg.SFTPVerifyHost = r.FormValue("backup_sftp_verify_host") == "true"
	cfg.SFTPAuthMethod = strings.TrimSpace(r.FormValue("backup_sftp_auth_method"))
	if cfg.SFTPAuthMethod != "password" && cfg.SFTPAuthMethod != "key" {
		if current.SFTPPrivateKey != "" {
			cfg.SFTPAuthMethod = "key"
		} else {
			cfg.SFTPAuthMethod = "password"
		}
	}
	if v := r.FormValue("backup_sftp_password"); v != "" {
		cfg.SFTPPassword = v
	}
	if v := r.FormValue("backup_sftp_private_key"); v != "" {
		cfg.SFTPPrivateKey = v
	}
	cfg.S3.Endpoint = strings.TrimSpace(r.FormValue("backup_s3_endpoint"))
	cfg.S3.Region = strings.TrimSpace(r.FormValue("backup_s3_region"))
	cfg.S3.Bucket = strings.TrimSpace(r.FormValue("backup_s3_bucket"))
	cfg.S3.AccessKey = strings.TrimSpace(r.FormValue("backup_s3_access_key"))
	cfg.S3.Prefix = strings.TrimSpace(r.FormValue("backup_s3_prefix"))
	cfg.S3.TLSVerify = r.FormValue("backup_s3_tls_verify") == "true"
	if v := r.FormValue("backup_s3_secret_key"); v != "" {
		cfg.S3.SecretKey = v
	}
	if v := r.FormValue("backup_encryption_password"); v != "" {
		if current.EncryptionPassword != "" && v != current.EncryptionPassword {
			return backup.Config{}, errors.New("Das Backup-Verschlüsselungspasswort ist bereits festgelegt und kann nicht geändert werden. Alte Backups müssen dauerhaft mit demselben Passwort lesbar bleiben.")
		}
		cfg.EncryptionPassword = v
	}
	if cfg.EncryptionPassword != "" && len(cfg.EncryptionPassword) < 10 {
		return backup.Config{}, errors.New("Backup-Verschlüsselungspasswort muss mindestens 10 Zeichen lang sein.")
	}
	if cfg.Provider == "sftp" {
		if cfg.SFTPAuthMethod == "password" && cfg.SFTPPassword == "" {
			return backup.Config{}, errors.New("Bitte ein SFTP-Passwort hinterlegen.")
		}
		if cfg.SFTPAuthMethod == "key" && cfg.SFTPPrivateKey == "" {
			return backup.Config{}, errors.New("Bitte einen SSH Private Key hinterlegen.")
		}
	}
	return cfg, nil
}

func joinWeekdays(days []int) string {
	parts := make([]string, 0, len(days))
	for _, d := range days {
		if d >= 0 && d <= 6 {
			parts = append(parts, strconv.Itoa(d))
		}
	}
	return strings.Join(parts, ",")
}

func (h *Handler) saveBackupSettings(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	cfg, err := h.backupConfigFromRequest(r.Context(), r)
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	if cfg.Enabled && len(cfg.EncryptionPassword) < 10 {
		httpx.Error(w, 400, "Für automatische Backups muss zuerst ein Backup-Verschlüsselungspasswort mit mindestens 10 Zeichen festgelegt werden.")
		return
	}
	plain := map[string]string{"backup_enabled": strconv.FormatBool(cfg.Enabled), "backup_provider": cfg.Provider, "backup_schedule": cfg.Schedule, "backup_time": cfg.Time, "backup_weekday": strconv.Itoa(cfg.Weekday), "backup_weekdays": joinWeekdays(cfg.Weekdays), "backup_retention": strconv.Itoa(cfg.Retention), "backup_sftp_host": cfg.SFTPHost, "backup_sftp_port": strconv.Itoa(cfg.SFTPPort), "backup_sftp_user": cfg.SFTPUser, "backup_sftp_path": cfg.SFTPPath, "backup_sftp_auth_method": cfg.SFTPAuthMethod, "backup_sftp_verify_host": strconv.FormatBool(cfg.SFTPVerifyHost), "backup_s3_endpoint": cfg.S3.Endpoint, "backup_s3_region": cfg.S3.Region, "backup_s3_bucket": cfg.S3.Bucket, "backup_s3_access_key": cfg.S3.AccessKey, "backup_s3_prefix": cfg.S3.Prefix, "backup_s3_tls_verify": strconv.FormatBool(cfg.S3.TLSVerify)}
	if err = h.storeSettings(r.Context(), plain, false); err != nil {
		httpx.Error(w, 500, "Backup-Einstellungen konnten nicht gespeichert werden.")
		return
	}
	if cfg.SFTPAuthMethod == "password" {
		cfg.SFTPPrivateKey = ""
		_, _ = h.DB.Exec(r.Context(), `DELETE FROM settings WHERE key='backup_sftp_private_key'`)
	} else if cfg.SFTPAuthMethod == "key" {
		cfg.SFTPPassword = ""
		_, _ = h.DB.Exec(r.Context(), `DELETE FROM settings WHERE key='backup_sftp_password'`)
	}
	secrets := map[string]string{"backup_encryption_password": cfg.EncryptionPassword, "backup_sftp_password": cfg.SFTPPassword, "backup_sftp_private_key": cfg.SFTPPrivateKey, "backup_s3_secret_key": cfg.S3.SecretKey}
	for k, v := range secrets {
		if v == "" {
			continue
		}
		enc, e := h.Secrets.Encrypt(v)
		if e != nil {
			httpx.Error(w, 500, "Backup-Secret konnte nicht gespeichert werden.")
			return
		}
		if e = h.storeSettings(r.Context(), map[string]string{k: enc}, true); e != nil {
			httpx.Error(w, 500, "Backup-Secret konnte nicht gespeichert werden.")
			return
		}
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "backup.settings_updated", "backup", "settings", map[string]any{"provider": cfg.Provider, "enabled": cfg.Enabled, "schedule": cfg.Schedule})
	httpx.JSON(w, 200, map[string]any{"ok": true, "message": "Backup-Einstellungen gespeichert.", "reload": true})
}

func (h *Handler) testBackupProvider(w http.ResponseWriter, r *http.Request) {
	_, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	cfg, err := h.backupConfigFromRequest(r.Context(), r)
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	if err = h.Backup.TestProvider(r.Context(), cfg); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "message": "Backup-Ziel erfolgreich geprüft."})
}

func (h *Handler) runBackupNow(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	if h.Backup.Running() {
		httpx.Error(w, 409, "Es läuft bereits ein Backup oder Restore.")
		return
	}
	cfg, err := h.Backup.LoadConfig(r.Context())
	if err != nil {
		httpx.Error(w, 500, "Backup-Einstellungen konnten nicht geladen werden.")
		return
	}
	if len(cfg.EncryptionPassword) < 10 {
		httpx.Error(w, 400, "Bitte zuerst ein Backup-Verschlüsselungspasswort mit mindestens 10 Zeichen festlegen und speichern.")
		return
	}
	go func(actor string) {
		item, err := h.Backup.Create(context.Background(), actor)
		if err != nil {
			return
		}
		h.Audit.Write(context.Background(), nil, actor, "backup.completed", "backup", item.ID, map[string]any{"provider": item.Provider, "size": item.Size})
	}(ss.User.ID)
	httpx.JSON(w, 202, map[string]any{"ok": true, "message": "Backup wurde gestartet."})
}

func backupStageLabel(stage, lang string) string {
	en := strings.HasPrefix(strings.ToLower(lang), "en")
	labelsDE := map[string]string{"preparing": "Vorbereitung", "database": "Datenbank exportieren", "data": "ZentCal-Daten vorbereiten", "archive": "Archiv erstellen", "encrypt": "Backup verschlüsseln", "upload": "Zum Speicherziel übertragen", "done": "Abgeschlossen", "failed": "Fehlgeschlagen"}
	labelsEN := map[string]string{"preparing": "Preparing", "database": "Exporting database", "data": "Preparing ZentCal data", "archive": "Creating archive", "encrypt": "Encrypting backup", "upload": "Uploading to storage", "done": "Completed", "failed": "Failed"}
	if en {
		if v := labelsEN[stage]; v != "" {
			return v
		}
	} else if v := labelsDE[stage]; v != "" {
		return v
	}
	return stage
}

func (h *Handler) backupStatus(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	var id, status, stage, errText string
	var created time.Time
	err := h.DB.QueryRow(r.Context(), `SELECT id::text,status,stage,coalesce(error,''),created_at FROM backups ORDER BY created_at DESC LIMIT 1`).Scan(&id, &status, &stage, &errText, &created)
	if err != nil {
		httpx.JSON(w, 200, map[string]any{"ok": true, "running": h.Backup.Running()})
		return
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "running": h.Backup.Running(), "current": map[string]any{"id": id, "status": status, "stage": stage, "stage_label": backupStageLabel(stage, ss.User.Language), "error": errText, "created_at": created}})
}

func (h *Handler) verifyBackup(w http.ResponseWriter, r *http.Request) {
	_, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	_ = parseRequestForm(r)
	if err := h.Backup.Verify(r.Context(), r.PathValue("id"), r.FormValue("encryption_password")); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "message": "Backup ist lesbar, Checksumme und Verschlüsselung sind gültig."})
}

func (h *Handler) verifyLocalAdminPassword(ctx context.Context, userID, credential string) bool {
	if strings.TrimSpace(credential) == "" {
		return false
	}
	var hash string
	if err := h.DB.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=$1 AND auth_type='local' AND status='active'`, userID).Scan(&hash); err != nil {
		return false
	}
	return security.PasswordCheck(hash, credential)
}

func (h *Handler) backupReauthAuthorized(ctx context.Context, sessionID, userID, purpose, target string, consume bool) bool {
	var at time.Time
	var storedPurpose, storedTarget string
	if err := h.DB.QueryRow(ctx, `SELECT coalesce(reauthenticated_at,to_timestamp(0)),coalesce(reauth_purpose,''),coalesce(reauth_target,'') FROM sessions WHERE id=$1 AND user_id=$2 AND expires_at>now()`, sessionID, userID).Scan(&at, &storedPurpose, &storedTarget); err != nil {
		return false
	}
	if at.Before(time.Now().Add(-5*time.Minute)) || storedPurpose != purpose || storedTarget != target {
		return false
	}
	if consume {
		cmd, err := h.DB.Exec(ctx, `UPDATE sessions SET reauthenticated_at=NULL,reauth_purpose='',reauth_target='' WHERE id=$1 AND user_id=$2 AND reauthenticated_at=$3 AND reauth_purpose=$4 AND reauth_target=$5`, sessionID, userID, at, purpose, target)
		return err == nil && cmd.RowsAffected() == 1
	}
	return true
}

func (h *Handler) backupReauthStart(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	if ss.User.AuthType != "oidc" {
		httpx.Error(w, 400, "SSO-Bestätigung ist für dieses Konto nicht erforderlich.")
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	action := strings.TrimSpace(r.FormValue("action"))
	target := strings.TrimSpace(r.FormValue("target"))
	switch action {
	case "restore", "delete":
		if target == "" {
			httpx.Error(w, 400, "Backup fehlt.")
			return
		}
		var exists bool
		if err := h.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM backups WHERE id=$1)`, target).Scan(&exists); err != nil || !exists {
			httpx.Error(w, 404, "Backup wurde nicht gefunden.")
			return
		}
	case "upload_restore":
		target = "upload"
	default:
		httpx.Error(w, 400, "Ungültige Backup-Aktion.")
		return
	}
	cfg, err := h.OIDC.Load(r.Context())
	if err != nil || !cfg.Enabled {
		httpx.Error(w, 400, "Single Sign-On ist nicht aktiviert.")
		return
	}
	returnTo := "/backups?reauth_action=" + url.QueryEscape(action) + "&backup_id=" + url.QueryEscape(target)
	location, err := h.OIDC.BeginFlow(r.Context(), cfg, h.externalBaseURL()+"/auth/oidc/callback", returnTo, "reauth", ss.User.ID)
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "redirect": location})
}

func (h *Handler) restoreBackup(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	_ = parseRequestForm(r)
	if r.FormValue("confirm_text") != "RESTORE" || r.FormValue("final_confirm") != "yes" {
		httpx.Error(w, 400, "Restore wurde nicht vollständig bestätigt.")
		return
	}
	backupID := r.PathValue("id")
	if ss.User.AuthType == "oidc" {
		if !h.backupReauthAuthorized(r.Context(), ss.ID, ss.User.ID, "backup_restore", backupID, false) {
			httpx.Error(w, 403, "Bitte bestätige die Wiederherstellung zuerst erneut über Single Sign-On.")
			return
		}
	} else if !h.verifyLocalAdminPassword(r.Context(), ss.User.ID, r.FormValue("admin_password")) {
		httpx.Error(w, 403, "Aktuelles Passwort ist ungültig.")
		return
	}
	if err := h.Backup.Verify(r.Context(), backupID, r.FormValue("encryption_password")); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	if ss.User.AuthType == "oidc" && !h.backupReauthAuthorized(r.Context(), ss.ID, ss.User.ID, "backup_restore", backupID, true) {
		httpx.Error(w, 403, "Die SSO-Bestätigung ist abgelaufen. Bitte starte die Wiederherstellung erneut.")
		return
	}
	if err := h.Backup.Restore(r.Context(), backupID, r.FormValue("encryption_password")); err != nil {
		httpx.Error(w, 500, err.Error())
		return
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "backup.restored", "backup", backupID, nil)
	httpx.JSON(w, 200, map[string]any{"ok": true, "message": "Backup erfolgreich wiederhergestellt. ZentCal wird neu gestartet.", "reload_after_ms": 3000})
	go requestGracefulRestart()
}

func (h *Handler) deleteBackup(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	_ = parseRequestForm(r)
	if ss.User.AuthType == "oidc" {
		if !h.backupReauthAuthorized(r.Context(), ss.ID, ss.User.ID, "backup_delete", id, true) {
			httpx.Error(w, 403, "Bitte bestätige das Löschen zuerst erneut über Single Sign-On.")
			return
		}
	} else if !h.verifyLocalAdminPassword(r.Context(), ss.User.ID, r.FormValue("admin_password")) {
		httpx.Error(w, 403, "Aktuelles Passwort ist ungültig.")
		return
	}
	if err := h.Backup.Delete(r.Context(), id); err != nil {
		httpx.Error(w, 500, err.Error())
		return
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "backup.deleted", "backup", id, nil)
	httpx.JSON(w, 200, map[string]any{"ok": true, "reload": true})
}

func (h *Handler) downloadBackup(w http.ResponseWriter, r *http.Request) {
	_, ok := h.adminPage(w, r, "backups")
	if !ok {
		return
	}
	path, cleanup, err := h.Backup.Materialize(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, "Backup konnte nicht geladen werden.", 500)
		return
	}
	defer cleanup()
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filepath.Base(path)))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, path)
}

func (h *Handler) uploadRestoreBackup(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		httpx.Error(w, 400, "Backup-Upload ist ungültig oder zu groß.")
		return
	}
	if r.FormValue("confirm_text") != "RESTORE" || r.FormValue("final_confirm") != "yes" {
		httpx.Error(w, 400, "Restore wurde nicht vollständig bestätigt.")
		return
	}
	if ss.User.AuthType == "oidc" {
		if !h.backupReauthAuthorized(r.Context(), ss.ID, ss.User.ID, "backup_upload_restore", "upload", false) {
			httpx.Error(w, 403, "Bitte bestätige die Wiederherstellung zuerst erneut über Single Sign-On.")
			return
		}
	} else if !h.verifyLocalAdminPassword(r.Context(), ss.User.ID, r.FormValue("admin_password")) {
		httpx.Error(w, 403, "Aktuelles Passwort ist ungültig.")
		return
	}
	f, hdr, err := r.FormFile("backup_file")
	if err != nil {
		httpx.Error(w, 400, "Backup-Datei fehlt.")
		return
	}
	defer f.Close()
	uploadTmp := filepath.Join(h.Backup.Runtime.DataDir, "tmp")
	if err := os.MkdirAll(uploadTmp, 0700); err != nil {
		httpx.Error(w, 500, "Upload-Verzeichnis konnte nicht vorbereitet werden.")
		return
	}
	tmp, err := os.CreateTemp(uploadTmp, "zentcal-upload-*.zcbak")
	if err != nil {
		httpx.Error(w, 500, "Upload konnte nicht gespeichert werden.")
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = io.Copy(tmp, f); err != nil {
		tmp.Close()
		httpx.Error(w, 500, "Upload konnte nicht gespeichert werden.")
		return
	}
	_ = tmp.Close()
	item, err := h.Backup.ImportUploaded(r.Context(), tmpName, hdr.Filename, ss.User.ID)
	if err != nil {
		httpx.Error(w, 500, err.Error())
		return
	}
	if err = h.Backup.Verify(r.Context(), item.ID, r.FormValue("encryption_password")); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	if ss.User.AuthType == "oidc" && !h.backupReauthAuthorized(r.Context(), ss.ID, ss.User.ID, "backup_upload_restore", "upload", true) {
		httpx.Error(w, 403, "Die SSO-Bestätigung ist abgelaufen. Bitte starte die Wiederherstellung erneut.")
		return
	}
	if err = h.Backup.Restore(r.Context(), item.ID, r.FormValue("encryption_password")); err != nil {
		httpx.Error(w, 500, err.Error())
		return
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "backup.upload_restored", "backup", item.ID, nil)
	httpx.JSON(w, 200, map[string]any{"ok": true, "message": "Backup erfolgreich hochgeladen und wiederhergestellt. ZentCal wird neu gestartet.", "reload_after_ms": 3000})
	go requestGracefulRestart()
}

func requestGracefulRestart() {
	time.Sleep(1500 * time.Millisecond)
	if p, err := os.FindProcess(os.Getpid()); err == nil {
		_ = p.Signal(syscall.SIGTERM)
	}
}
