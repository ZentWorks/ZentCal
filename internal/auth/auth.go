package auth

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zentworks/zentcal/internal/db"
	"github.com/zentworks/zentcal/internal/security"
)

type User struct {
	ID                 string
	Name               string
	FirstName          string
	LastName           string
	Email              string
	Role               string
	Status             string
	AuthType           string
	Language           string
	Timezone           string
	MustChangePassword bool
	CreatedAt          time.Time
	LastLogin          *time.Time
	LastSync           *time.Time
}

type Session struct {
	ID        string
	User      User
	CSRFToken string
	ExpiresAt time.Time
}

const DAVRealm = "ZentCal"

type Service struct {
	DB       *pgxpool.Pool
	Lifetime time.Duration
}

func (s *Service) SetupComplete(ctx context.Context) (bool, error) {
	var n int
	err := s.DB.QueryRow(ctx, `SELECT count(*) FROM users WHERE role='owner' AND status='active'`).Scan(&n)
	return n > 0, err
}

func (s *Service) CreateOwner(ctx context.Context, firstName, lastName, email, password string) (User, error) {
	firstName, lastName, email = strings.TrimSpace(firstName), strings.TrimSpace(lastName), strings.ToLower(strings.TrimSpace(email))
	name := strings.TrimSpace(firstName + " " + lastName)
	if firstName == "" || !strings.Contains(email, "@") {
		return User{}, errors.New("Vorname und gültige E-Mail sind erforderlich.")
	}
	hash, err := security.PasswordHash(password)
	if err != nil {
		return User{}, err
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(99270101)`); err != nil {
		return User{}, err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return User{}, err
	}
	if n != 0 {
		return User{}, errors.New("Setup wurde bereits abgeschlossen.")
	}
	u := User{ID: security.UUID(), Name: name, FirstName: firstName, LastName: lastName, Email: email, Role: "owner", Status: "active", CreatedAt: time.Now()}
	_, err = tx.Exec(ctx, `INSERT INTO users(id,name,first_name,last_name,email,password_hash,role,status) VALUES($1,$2,$3,$4,$5,$6,'owner','active')`, u.ID, u.Name, u.FirstName, u.LastName, u.Email, hash)
	if err != nil {
		return User{}, err
	}
	if _, err = db.EnsurePersonalCalendar(ctx, tx, u.ID, u.Name); err != nil {
		return User{}, err
	}
	defaults := map[string]string{"timezone": "Europe/Berlin", "language": "de", "week_start": "monday", "session_lifetime_hours": "720", "login_max_failures": "5", "lockout_minutes": "5", "smtp_enabled": "false", "smtp_port": "587", "smtp_security": "starttls"}
	for k, v := range defaults {
		if _, err = tx.Exec(ctx, `INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO NOTHING`, k, v); err != nil {
			return User{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return User{}, err
	}
	return u, nil
}

func (s *Service) blocked(ctx context.Context, identity string) bool {
	var blockedUntil *time.Time
	_ = s.DB.QueryRow(ctx, `SELECT blocked_until FROM login_attempts WHERE identity=$1`, identity).Scan(&blockedUntil)
	return blockedUntil != nil && blockedUntil.After(time.Now())
}

func (s *Service) recordFailure(ctx context.Context, identity string) {
	maxFailures := s.intSetting(ctx, "login_max_failures", 5, 3, 20)
	lockoutMinutes := s.intSetting(ctx, "lockout_minutes", 5, 1, 1440)
	_, _ = s.DB.Exec(ctx, `INSERT INTO login_attempts(identity,failures,last_failed_at) VALUES($1,1,now()) ON CONFLICT(identity) DO UPDATE SET failures=login_attempts.failures+1,last_failed_at=now(),blocked_until=CASE WHEN login_attempts.failures+1 >= $2 THEN now()+($3 * interval '1 minute') ELSE login_attempts.blocked_until END`, identity, maxFailures, lockoutMinutes)
}

func (s *Service) clearFailures(ctx context.Context, identity string) {
	_, _ = s.DB.Exec(ctx, `DELETE FROM login_attempts WHERE identity=$1`, identity)
}

func rateKeys(channel, identity, source string) []string {
	identity = strings.ToLower(strings.TrimSpace(identity))
	source = strings.TrimSpace(source)
	if source == "" {
		return []string{channel + ":account:" + identity}
	}
	// Rate-limit an identity from a source, not the source globally. A reverse
	// proxy can legitimately be the source for every user; globally blocking its
	// address after a few failures would become an easy denial-of-service.
	return []string{channel + ":account:" + identity + ":source:" + source}
}

func (s *Service) rateBlocked(ctx context.Context, keys []string) bool {
	for _, key := range keys {
		if s.blocked(ctx, key) {
			return true
		}
	}
	return false
}

func (s *Service) rateFailure(ctx context.Context, keys []string) {
	for _, key := range keys {
		s.recordFailure(ctx, key)
	}
}

func (s *Service) rateSuccess(ctx context.Context, keys []string) {
	for _, key := range keys {
		s.clearFailures(ctx, key)
	}
}

const (
	identifySourceMaxAttempts = 300
	identifySourceWindow      = 5 * time.Minute
	identifySourceBlock       = 1 * time.Minute
)

func identifySourceKey(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return ""
	}
	return "login-identify:source:" + source
}

func (s *Service) identifySourceBlocked(ctx context.Context, source string) bool {
	key := identifySourceKey(source)
	return key != "" && s.blocked(ctx, key)
}

func (s *Service) recordIdentifySourceFailure(ctx context.Context, source string) {
	key := identifySourceKey(source)
	if key == "" {
		return
	}
	_, _ = s.DB.Exec(ctx, `INSERT INTO login_attempts(identity,failures,last_failed_at,blocked_until) VALUES($1,1,now(),NULL)
ON CONFLICT(identity) DO UPDATE SET
  failures=CASE WHEN login_attempts.last_failed_at < now()-($2::bigint * interval '1 second') THEN 1 ELSE login_attempts.failures+1 END,
  last_failed_at=now(),
  blocked_until=CASE
    WHEN login_attempts.blocked_until IS NOT NULL AND login_attempts.blocked_until>now() THEN login_attempts.blocked_until
    WHEN login_attempts.last_failed_at < now()-($2::bigint * interval '1 second') THEN NULL
    WHEN login_attempts.failures+1 >= $3 THEN now()+($4::bigint * interval '1 second')
    ELSE NULL
  END`, key, int64(identifySourceWindow/time.Second), identifySourceMaxAttempts, int64(identifySourceBlock/time.Second))
}

func (s *Service) loadUserWithHash(ctx context.Context, identity string) (User, string, error) {
	var u User
	var hash string
	err := s.DB.QueryRow(ctx, `SELECT id::text,name,first_name,last_name,email,password_hash,role,status,auth_type,language,timezone,must_change_password,created_at,last_login,last_sync FROM users WHERE lower(email)=lower($1)`, identity).Scan(&u.ID, &u.Name, &u.FirstName, &u.LastName, &u.Email, &hash, &u.Role, &u.Status, &u.AuthType, &u.Language, &u.Timezone, &u.MustChangePassword, &u.CreatedAt, &u.LastLogin, &u.LastSync)
	return u, hash, err
}

// ResolveLoginUser resolves the first step of the interactive login without
// checking a password. It deliberately uses its own rate-limit namespace so
// repeated account probing cannot bypass the normal login throttling while a
// successful identification does not clear password failures.
func (s *Service) ResolveLoginUser(ctx context.Context, email, source string) (User, error) {
	identity := strings.ToLower(strings.TrimSpace(email))
	keys := rateKeys("login-identify", identity, source)
	if identity == "" || s.identifySourceBlocked(ctx, source) || s.rateBlocked(ctx, keys) {
		return User{}, errors.New("Anmeldung vorübergehend nicht möglich.")
	}
	u, _, err := s.loadUserWithHash(ctx, identity)
	if err != nil || u.Status != "active" {
		s.rateFailure(ctx, keys)
		s.recordIdentifySourceFailure(ctx, source)
		return User{}, errors.New("Anmeldung nicht möglich.")
	}
	s.rateSuccess(ctx, keys)
	return u, nil
}

func (s *Service) Authenticate(ctx context.Context, email, password, source string) (User, error) {
	identity := strings.ToLower(strings.TrimSpace(email))
	keys := rateKeys("login", identity, source)
	if s.rateBlocked(ctx, keys) {
		return User{}, errors.New("Anmeldung vorübergehend gesperrt.")
	}
	u, hash, err := s.loadUserWithHash(ctx, identity)
	if err != nil || u.Status != "active" || !AllowsLocalPassword(u) || !security.PasswordCheck(hash, password) {
		s.rateFailure(ctx, keys)
		return User{}, errors.New("Ungültige Zugangsdaten.")
	}
	s.rateSuccess(ctx, keys)
	_, _ = s.DB.Exec(ctx, `UPDATE users SET last_login=now() WHERE id=$1`, u.ID)
	return u, nil
}

func (s *Service) AuthenticateDAV(ctx context.Context, username, password, source string) (User, error) {
	identity := strings.ToLower(strings.TrimSpace(username))
	keys := rateKeys("dav", identity, source)
	if identity == "" || s.rateBlocked(ctx, keys) {
		return User{}, errors.New("temporarily blocked")
	}
	var user User
	tokenHash := security.TokenHash(password)
	err := s.DB.QueryRow(ctx, `SELECT u.id::text,u.name,u.first_name,u.last_name,u.email,u.role,u.status,u.auth_type,u.language,u.timezone,u.must_change_password,u.created_at,u.last_login,u.last_sync
 FROM app_passwords ap JOIN users u ON u.id=ap.user_id
 WHERE lower(u.email)=lower($1) AND ap.token_hash=$2 AND ap.revoked_at IS NULL AND u.status='active'`, identity, tokenHash).Scan(&user.ID, &user.Name, &user.FirstName, &user.LastName, &user.Email, &user.Role, &user.Status, &user.AuthType, &user.Language, &user.Timezone, &user.MustChangePassword, &user.CreatedAt, &user.LastLogin, &user.LastSync)
	if err == nil {
		s.rateSuccess(ctx, keys)
		_, _ = s.DB.Exec(ctx, `UPDATE app_passwords SET last_used_at=now() WHERE token_hash=$1`, tokenHash)
		_, _ = s.DB.Exec(ctx, `UPDATE users SET last_sync=now() WHERE id=$1`, user.ID)
		return user, nil
	}
	s.rateFailure(ctx, keys)
	return User{}, errors.New("invalid credentials")
}

// AuthenticateDAVDigest validates an HTTP Digest response against the non-reversible
// DAV verifier derived when the high-entropy app password was originally created.
// Normal ZentCal account passwords are deliberately never candidates for DAV.
// The callback receives each app-password HA1 and returns true for a valid response.
func (s *Service) AuthenticateDAVDigest(ctx context.Context, username, source string, verify func(string) bool) (User, error) {
	identity := strings.ToLower(strings.TrimSpace(username))
	keys := rateKeys("dav", identity, source)
	if identity == "" || s.rateBlocked(ctx, keys) {
		return User{}, errors.New("temporarily blocked")
	}
	rows, err := s.DB.Query(ctx, `SELECT ap.id::text,ap.dav_digest_ha1,u.id::text,u.name,u.first_name,u.last_name,u.email,u.role,u.status,u.auth_type,u.language,u.timezone,u.must_change_password,u.created_at,u.last_login,u.last_sync
 FROM app_passwords ap JOIN users u ON u.id=ap.user_id
 WHERE lower(u.email)=lower($1) AND ap.revoked_at IS NULL AND ap.dav_digest_ha1 IS NOT NULL AND u.status='active'`, identity)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var appID, appHA1 string
			var candidate User
			if scanErr := rows.Scan(&appID, &appHA1, &candidate.ID, &candidate.Name, &candidate.FirstName, &candidate.LastName, &candidate.Email, &candidate.Role, &candidate.Status, &candidate.AuthType, &candidate.Language, &candidate.Timezone, &candidate.MustChangePassword, &candidate.CreatedAt, &candidate.LastLogin, &candidate.LastSync); scanErr != nil {
				continue
			}
			if appHA1 != "" && verify(appHA1) {
				s.rateSuccess(ctx, keys)
				_, _ = s.DB.Exec(ctx, `UPDATE app_passwords SET last_used_at=now() WHERE id=$1`, appID)
				_, _ = s.DB.Exec(ctx, `UPDATE users SET last_sync=now() WHERE id=$1`, candidate.ID)
				return candidate, nil
			}
		}
	}
	s.rateFailure(ctx, keys)
	return User{}, errors.New("invalid credentials")
}

func (s *Service) CreateSession(ctx context.Context, u User, r *http.Request) (string, Session, error) {
	if strings.TrimSpace(u.Language) == "" || u.Language == "auto" {
		u.Language = preferredLanguage(r)
		_, _ = s.DB.Exec(ctx, `UPDATE users SET language=$1,updated_at=now() WHERE id=$2`, u.Language, u.ID)
	}
	token, err := security.RandomToken(32)
	if err != nil {
		return "", Session{}, err
	}
	csrf, err := security.RandomToken(24)
	if err != nil {
		return "", Session{}, err
	}
	lifetimeHours := s.intSetting(ctx, "session_lifetime_hours", int(s.Lifetime/time.Hour), 1, 8760)
	ss := Session{ID: security.UUID(), User: u, CSRFToken: csrf, ExpiresAt: time.Now().Add(time.Duration(lifetimeHours) * time.Hour)}
	ip := ClientIP(r)
	_, err = s.DB.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,csrf_token,ip,user_agent,expires_at) VALUES($1,$2,$3,$4,NULLIF($5,'')::inet,$6,$7)`, ss.ID, u.ID, security.TokenHash(token), csrf, ip, r.UserAgent(), ss.ExpiresAt)
	return token, ss, err
}

func (s *Service) SessionFromRequest(r *http.Request) (*Session, error) {
	c, err := r.Cookie("zentcal_session")
	if err != nil {
		return nil, err
	}
	var ss Session
	var lastSeen time.Time
	err = s.DB.QueryRow(r.Context(), `SELECT s.id::text,s.csrf_token,s.expires_at,s.last_seen_at,u.id::text,u.name,u.first_name,u.last_name,u.email,u.role,u.status,u.auth_type,u.language,u.timezone,u.must_change_password,u.created_at,u.last_login,u.last_sync
 FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() AND u.status='active'`, security.TokenHash(c.Value)).Scan(&ss.ID, &ss.CSRFToken, &ss.ExpiresAt, &lastSeen, &ss.User.ID, &ss.User.Name, &ss.User.FirstName, &ss.User.LastName, &ss.User.Email, &ss.User.Role, &ss.User.Status, &ss.User.AuthType, &ss.User.Language, &ss.User.Timezone, &ss.User.MustChangePassword, &ss.User.CreatedAt, &ss.User.LastLogin, &ss.User.LastSync)
	if err != nil {
		return nil, err
	}
	// Avoid a database write/WAL record on every page and static-adjacent request.
	// Five-minute precision is sufficient for the UI's "last seen" semantics.
	if time.Since(lastSeen) >= 5*time.Minute {
		_, _ = s.DB.Exec(r.Context(), `UPDATE sessions SET last_seen_at=now() WHERE id=$1 AND last_seen_at<$2`, ss.ID, time.Now().Add(-5*time.Minute))
	}
	return &ss, nil
}

func (s *Service) Logout(ctx context.Context, r *http.Request) {
	if c, err := r.Cookie("zentcal_session"); err == nil {
		_, _ = s.DB.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1`, security.TokenHash(c.Value))
	}
}

func (s *Service) Cleanup(ctx context.Context) {
	_, _ = s.DB.Exec(ctx, `DELETE FROM sessions WHERE expires_at<now()`)
	_, _ = s.DB.Exec(ctx, `DELETE FROM login_attempts WHERE last_failed_at < now()-interval '2 days'`)
	_, _ = s.DB.Exec(ctx, `DELETE FROM password_reset_requests WHERE last_requested_at < now()-interval '1 day'`)
	_, _ = s.DB.Exec(ctx, `DELETE FROM invitations WHERE COALESCE(accepted_at,revoked_at,expires_at) < now()-interval '30 days'`)
}

func (s *Service) intSetting(ctx context.Context, key string, fallback, min, max int) int {
	var raw string
	if err := s.DB.QueryRow(ctx, `SELECT value FROM settings WHERE key=$1 AND NOT secret`, key).Scan(&raw); err != nil {
		return fallback
	}
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v < min || v > max {
		return fallback
	}
	return v
}

func (s *Service) CalendarRole(ctx context.Context, userID, calendarID string) (string, error) {
	var role string
	err := s.DB.QueryRow(ctx, `SELECT role FROM memberships WHERE user_id=$1 AND calendar_id=$2`, userID, calendarID).Scan(&role)
	return role, err
}

func CanRead(role string) bool {
	return role == "owner" || role == "contributor" || role == "viewer"
}
func CanCreate(role string) bool                     { return role == "owner" || role == "contributor" }
func CanEditAll(role string) bool                    { return role == "owner" || role == "contributor" }
func CanManage(role string) bool                     { return role == "owner" }
func IsAdmin(u User) bool                            { return u.Role == "owner" || u.Role == "administrator" }
func AllowsLocalPassword(u User) bool                { return u.AuthType != "oidc" }
func CanAdministerCalendar(u User, role string) bool { _ = u; return CanManage(role) }

func preferredLanguage(r *http.Request) string {
	raw := strings.TrimSpace(r.Header.Get("Accept-Language"))
	if raw == "" {
		return "en"
	}
	first := strings.ToLower(strings.TrimSpace(strings.Split(raw, ",")[0]))
	if i := strings.Index(first, ";"); i >= 0 {
		first = first[:i]
	}
	if first == "de" || strings.HasPrefix(first, "de-") || strings.HasSuffix(first, "-at") || strings.HasSuffix(first, "-ch") {
		return "de"
	}
	return "en"
}

func ClientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}

func IsNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
