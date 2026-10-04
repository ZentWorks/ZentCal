package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zentworks/zentcal/internal/app"
	"github.com/zentworks/zentcal/internal/audit"
	"github.com/zentworks/zentcal/internal/auth"
	"github.com/zentworks/zentcal/internal/backup"
	"github.com/zentworks/zentcal/internal/db"
	"github.com/zentworks/zentcal/internal/httpx"
	mailpkg "github.com/zentworks/zentcal/internal/mail"
	"github.com/zentworks/zentcal/internal/security"
	"github.com/zentworks/zentcal/internal/webhook"
)

type Handler struct {
	DB           *pgxpool.Pool
	App          *app.Service
	Audit        *audit.Logger
	Webhooks     *webhook.Service
	Backup       *backup.Service
	MailDelivery *mailpkg.DeliveryService
	Restart      func()
}

type principal struct {
	User   auth.User
	Scopes map[string]bool
}

type userResponse struct {
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	FirstName          string     `json:"first_name"`
	LastName           string     `json:"last_name"`
	Email              string     `json:"email"`
	Role               string     `json:"role"`
	Status             string     `json:"status"`
	AuthType           string     `json:"auth_type"`
	Language           string     `json:"language"`
	Timezone           string     `json:"timezone"`
	MustChangePassword bool       `json:"must_change_password"`
	CanCreateCalendars bool       `json:"can_create_calendars"`
	CreatedAt          time.Time  `json:"created_at"`
	LastLogin          *time.Time `json:"last_login,omitempty"`
	LastSync           *time.Time `json:"last_sync,omitempty"`
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/admin/v1", h.root)
	mux.HandleFunc("GET /api/admin/v1/users", h.users)
	mux.HandleFunc("POST /api/admin/v1/users", h.users)
	mux.HandleFunc("GET /api/admin/v1/users/{id}", h.user)
	mux.HandleFunc("PATCH /api/admin/v1/users/{id}", h.user)
	mux.HandleFunc("DELETE /api/admin/v1/users/{id}", h.user)

	mux.HandleFunc("GET /api/admin/v1/calendars", h.calendars)
	mux.HandleFunc("POST /api/admin/v1/calendars", h.calendars)
	mux.HandleFunc("GET /api/admin/v1/calendars/{id}", h.calendar)
	mux.HandleFunc("PATCH /api/admin/v1/calendars/{id}", h.calendar)
	mux.HandleFunc("DELETE /api/admin/v1/calendars/{id}", h.calendar)
	mux.HandleFunc("GET /api/admin/v1/calendars/{id}/members", h.calendarMembers)
	mux.HandleFunc("PUT /api/admin/v1/calendars/{id}/members/{user_id}", h.calendarMember)
	mux.HandleFunc("DELETE /api/admin/v1/calendars/{id}/members/{user_id}", h.calendarMember)

	mux.HandleFunc("GET /api/admin/v1/backup-settings", h.backupSettings)
	mux.HandleFunc("PATCH /api/admin/v1/backup-settings", h.backupSettings)
	mux.HandleFunc("POST /api/admin/v1/backup-settings/test", h.testBackupSettings)
	mux.HandleFunc("GET /api/admin/v1/backups", h.backups)
	mux.HandleFunc("POST /api/admin/v1/backups", h.backups)
	mux.HandleFunc("POST /api/admin/v1/backups/{id}/verify", h.verifyBackup)
	mux.HandleFunc("POST /api/admin/v1/backups/{id}/restore", h.restoreBackup)
	mux.HandleFunc("DELETE /api/admin/v1/backups/{id}", h.deleteBackup)

	mux.HandleFunc("GET /api/admin/v1/webhooks", h.webhooksList)
	mux.HandleFunc("POST /api/admin/v1/webhooks", h.webhooksList)
	mux.HandleFunc("GET /api/admin/v1/webhooks/{id}", h.webhookItem)
	mux.HandleFunc("PATCH /api/admin/v1/webhooks/{id}", h.webhookItem)
	mux.HandleFunc("DELETE /api/admin/v1/webhooks/{id}", h.webhookItem)
	mux.HandleFunc("POST /api/admin/v1/webhooks/{id}/rotate-secret", h.rotateWebhookSecret)
	mux.HandleFunc("POST /api/admin/v1/webhooks/{id}/test", h.testWebhook)
	mux.HandleFunc("GET /api/admin/v1/webhook-deliveries", h.webhookDeliveries)
	mux.HandleFunc("GET /api/admin/v1/email-deliveries", h.emailDeliveries)
}

func (h *Handler) emailDeliveries(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, "admin:mail:read"); !ok {
		return
	}
	if h.MailDelivery == nil {
		httpx.Error(w, 503, "E-Mail-Zustellungen nicht verfügbar.")
		return
	}
	rows, err := h.MailDelivery.List(r.Context(), strings.TrimSpace(r.URL.Query().Get("status")), strings.TrimSpace(r.URL.Query().Get("type")), strings.TrimSpace(r.URL.Query().Get("q")), 200)
	if err != nil {
		httpx.Error(w, 500, "E-Mail-Zustellungen konnten nicht geladen werden.")
		return
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "data": rows})
}

func (h *Handler) root(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, "admin:meta:read"); !ok {
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "name": "ZentCal Admin API", "version": "v1"})
}

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request, scope string) (principal, bool) {
	raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if raw == "" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		httpx.Error(w, http.StatusUnauthorized, "Admin API Token erforderlich.")
		return principal{}, false
	}
	var p principal
	var scopes []string
	err := h.DB.QueryRow(r.Context(), `SELECT u.id::text,u.name,u.first_name,u.last_name,u.email,u.role,u.status,u.auth_type,u.language,u.timezone,u.must_change_password,u.created_at,u.last_login,u.last_sync,t.scopes
FROM admin_api_tokens t JOIN users u ON u.id=t.created_by
WHERE t.token_hash=$1 AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at>now())
AND u.status='active' AND u.role IN ('owner','administrator')`, security.TokenHash(raw)).Scan(
		&p.User.ID, &p.User.Name, &p.User.FirstName, &p.User.LastName, &p.User.Email, &p.User.Role, &p.User.Status, &p.User.AuthType, &p.User.Language, &p.User.Timezone, &p.User.MustChangePassword, &p.User.CreatedAt, &p.User.LastLogin, &p.User.LastSync, &scopes)
	if err != nil {
		httpx.Error(w, http.StatusUnauthorized, "Ungültiger Admin API Token.")
		return principal{}, false
	}
	p.Scopes = map[string]bool{}
	for _, s := range scopes {
		p.Scopes[s] = true
	}
	if scope != "" && !hasScope(p.Scopes, scope) {
		httpx.Error(w, http.StatusForbidden, "Admin API Token hat nicht den benötigten Scope.")
		return principal{}, false
	}
	_, _ = h.DB.Exec(r.Context(), `UPDATE admin_api_tokens SET last_used_at=now() WHERE token_hash=$1`, security.TokenHash(raw))
	return p, true
}

func hasScope(scopes map[string]bool, required string) bool {
	if scopes["admin:*"] || scopes[required] {
		return true
	}
	parts := strings.Split(required, ":")
	if len(parts) == 3 && scopes[parts[0]+":"+parts[1]+":*"] {
		return true
	}
	return false
}

func (h *Handler) users(w http.ResponseWriter, r *http.Request) {
	scope := "admin:users:read"
	if r.Method == http.MethodPost {
		scope = "admin:users:write"
	}
	p, ok := h.authorize(w, r, scope)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		rows, err := h.DB.Query(r.Context(), `SELECT id::text,name,first_name,last_name,email,role,status,auth_type,language,timezone,must_change_password,can_create_calendars,created_at,last_login,last_sync FROM users ORDER BY lower(name),lower(email)`)
		if err != nil {
			httpx.Error(w, 500, "Benutzer konnten nicht geladen werden.")
			return
		}
		defer rows.Close()
		out := []userResponse{}
		for rows.Next() {
			var u userResponse
			if err := rows.Scan(&u.ID, &u.Name, &u.FirstName, &u.LastName, &u.Email, &u.Role, &u.Status, &u.AuthType, &u.Language, &u.Timezone, &u.MustChangePassword, &u.CanCreateCalendars, &u.CreatedAt, &u.LastLogin, &u.LastSync); err != nil {
				httpx.Error(w, 500, "Benutzer konnten nicht geladen werden.")
				return
			}
			out = append(out, u)
		}
		httpx.JSON(w, 200, map[string]any{"ok": true, "data": out})
		return
	}
	var in struct {
		FirstName          string `json:"first_name"`
		LastName           string `json:"last_name"`
		Email              string `json:"email"`
		Role               string `json:"role"`
		Status             string `json:"status"`
		Password           string `json:"password"`
		MustChangePassword *bool  `json:"must_change_password"`
		CanCreateCalendars *bool  `json:"can_create_calendars"`
		Language           string `json:"language"`
		Timezone           string `json:"timezone"`
	}
	if err := decodeJSON(r, &in); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	in.FirstName = strings.TrimSpace(in.FirstName)
	in.LastName = strings.TrimSpace(in.LastName)
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if in.FirstName == "" || !strings.Contains(in.Email, "@") {
		httpx.Error(w, 400, "Vorname und gültige E-Mail sind erforderlich.")
		return
	}
	if in.Role == "" {
		in.Role = "user"
	}
	if in.Role != "user" && in.Role != "administrator" {
		httpx.Error(w, 400, "Ungültige Rolle.")
		return
	}
	if in.Status == "" {
		in.Status = "active"
	}
	if in.Status != "active" && in.Status != "disabled" && in.Status != "locked" {
		httpx.Error(w, 400, "Ungültiger Status.")
		return
	}
	if in.Language == "" {
		in.Language = "auto"
	}
	if in.Language != "auto" && in.Language != "de" && in.Language != "en" {
		httpx.Error(w, 400, "Ungültige Sprache.")
		return
	}
	if in.Timezone == "" {
		in.Timezone = "Europe/Berlin"
	}
	if _, err := time.LoadLocation(in.Timezone); err != nil {
		httpx.Error(w, 400, "Ungültige Zeitzone.")
		return
	}
	generated := ""
	if in.Password == "" {
		tok, err := security.RandomToken(18)
		if err != nil {
			httpx.Error(w, 500, "Temporäres Passwort konnte nicht erzeugt werden.")
			return
		}
		generated = tok
		in.Password = generated
	}
	if len(in.Password) < 10 {
		httpx.Error(w, 400, "Passwort muss mindestens 10 Zeichen lang sein.")
		return
	}
	mustChange := true
	if in.MustChangePassword != nil {
		mustChange = *in.MustChangePassword
	}
	canCreateCalendars := true
	if in.CanCreateCalendars != nil {
		canCreateCalendars = *in.CanCreateCalendars
	}
	hash, err := security.PasswordHash(in.Password)
	if err != nil {
		httpx.Error(w, 500, "Benutzer konnte nicht erstellt werden.")
		return
	}
	id := security.UUID()
	name := strings.TrimSpace(in.FirstName + " " + in.LastName)
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		httpx.Error(w, 500, "Benutzer konnte nicht erstellt werden.")
		return
	}
	defer tx.Rollback(r.Context())
	_, err = tx.Exec(r.Context(), `INSERT INTO users(id,name,first_name,last_name,email,password_hash,role,status,auth_type,must_change_password,language,timezone,can_create_calendars) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'local',$9,$10,$11,$12)`, id, name, in.FirstName, in.LastName, in.Email, hash, in.Role, in.Status, mustChange, in.Language, in.Timezone, canCreateCalendars)
	if err != nil {
		httpx.Error(w, 400, "Benutzer konnte nicht erstellt werden. E-Mail eventuell bereits vorhanden.")
		return
	}
	if _, err = db.EnsurePersonalCalendar(r.Context(), tx, id, name); err != nil {
		httpx.Error(w, 500, "Persönlicher Kalender konnte nicht erstellt werden.")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		httpx.Error(w, 500, "Benutzer konnte nicht erstellt werden.")
		return
	}
	h.audit(r, p, "admin_api.user.created", "user", id, map[string]any{"email": in.Email, "role": in.Role, "status": in.Status})
	if h.Webhooks != nil {
		h.Webhooks.Emit(r.Context(), "user.created", p.User.ID, "user", id, map[string]any{"email": in.Email, "role": in.Role, "source": "admin_api"})
	}
	resp := map[string]any{"ok": true, "data": map[string]any{"id": id, "name": name, "email": in.Email, "role": in.Role, "status": in.Status, "auth_type": "local", "can_create_calendars": canCreateCalendars}}
	if generated != "" {
		resp["temporary_password"] = generated
		w.Header().Set("Cache-Control", "no-store")
	}
	httpx.JSON(w, 201, resp)
}

func (h *Handler) user(w http.ResponseWriter, r *http.Request) {
	scope := "admin:users:read"
	if r.Method != http.MethodGet {
		scope = "admin:users:write"
	}
	p, ok := h.authorize(w, r, scope)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if r.Method == http.MethodGet {
		u, err := h.loadUser(r, id)
		if err != nil {
			httpx.Error(w, 404, "Benutzer nicht gefunden.")
			return
		}
		httpx.JSON(w, 200, map[string]any{"ok": true, "data": u})
		return
	}
	if r.Method == http.MethodDelete {
		if err := h.deleteUser(r, p, id); err != nil {
			status := 400
			if errors.Is(err, pgx.ErrNoRows) {
				status = 404
			}
			httpx.Error(w, status, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	current, err := h.loadUser(r, id)
	if err != nil {
		httpx.Error(w, 404, "Benutzer nicht gefunden.")
		return
	}
	var in struct {
		FirstName          *string `json:"first_name"`
		LastName           *string `json:"last_name"`
		Email              *string `json:"email"`
		Role               *string `json:"role"`
		Status             *string `json:"status"`
		Language           *string `json:"language"`
		Timezone           *string `json:"timezone"`
		CanCreateCalendars *bool   `json:"can_create_calendars"`
	}
	if err := decodeJSON(r, &in); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	first, last, email, role, status, lang, tz := current.FirstName, current.LastName, current.Email, current.Role, current.Status, current.Language, current.Timezone
	canCreateCalendars := current.CanCreateCalendars
	if in.FirstName != nil {
		first = strings.TrimSpace(*in.FirstName)
	}
	if in.LastName != nil {
		last = strings.TrimSpace(*in.LastName)
	}
	if in.Email != nil {
		email = strings.ToLower(strings.TrimSpace(*in.Email))
	}
	if in.Role != nil {
		role = strings.TrimSpace(*in.Role)
	}
	if in.Status != nil {
		status = strings.TrimSpace(*in.Status)
	}
	if in.Language != nil {
		lang = strings.TrimSpace(*in.Language)
	}
	if in.Timezone != nil {
		tz = strings.TrimSpace(*in.Timezone)
	}
	if in.CanCreateCalendars != nil {
		canCreateCalendars = *in.CanCreateCalendars
	}
	if first == "" || !strings.Contains(email, "@") {
		httpx.Error(w, 400, "Vorname und gültige E-Mail sind erforderlich.")
		return
	}
	if role != "owner" && role != "administrator" && role != "user" {
		httpx.Error(w, 400, "Ungültige Rolle.")
		return
	}
	if status != "active" && status != "disabled" && status != "locked" {
		httpx.Error(w, 400, "Ungültiger Status.")
		return
	}
	if lang != "auto" && lang != "de" && lang != "en" {
		httpx.Error(w, 400, "Ungültige Sprache.")
		return
	}
	if _, err := time.LoadLocation(tz); err != nil {
		httpx.Error(w, 400, "Ungültige Zeitzone.")
		return
	}
	if current.Role == "owner" {
		role = "owner"
		status = "active"
	}
	if current.Role != "owner" && role == "owner" {
		httpx.Error(w, 400, "Owner-Rolle kann nicht über die Admin API vergeben werden.")
		return
	}
	if id == p.User.ID && status != "active" {
		httpx.Error(w, 400, "Das Konto des Token-Erstellers kann nicht deaktiviert oder gesperrt werden.")
		return
	}
	if id == p.User.ID && role != "owner" && role != "administrator" {
		httpx.Error(w, 400, "Das Konto des Token-Erstellers kann sich nicht selbst die Admin-Rolle entziehen.")
		return
	}
	name := strings.TrimSpace(first + " " + last)
	_, err = h.DB.Exec(r.Context(), `UPDATE users SET name=$1,first_name=$2,last_name=$3,email=$4,role=$5,status=$6,language=$7,timezone=$8,can_create_calendars=$9,updated_at=now() WHERE id=$10`, name, first, last, email, role, status, lang, tz, canCreateCalendars, id)
	if err != nil {
		httpx.Error(w, 400, "Benutzer konnte nicht gespeichert werden. E-Mail eventuell bereits vorhanden.")
		return
	}
	if !strings.EqualFold(current.Email, email) {
		_, _ = h.DB.Exec(r.Context(), `UPDATE app_passwords SET revoked_at=coalesce(revoked_at,now()) WHERE user_id=$1`, id)
	}
	if _, err = db.EnsurePersonalCalendar(r.Context(), h.DB, id, name); err != nil {
		httpx.Error(w, 500, "Persönlicher Kalender konnte nicht aktualisiert werden.")
		return
	}
	h.audit(r, p, "admin_api.user.updated", "user", id, map[string]any{"email": email, "role": role, "status": status, "can_create_calendars": canCreateCalendars})
	if h.Webhooks != nil && status == "disabled" && current.Status != "disabled" {
		h.Webhooks.Emit(r.Context(), "user.disabled", p.User.ID, "user", id, map[string]any{"status": status, "source": "admin_api"})
	}
	u, _ := h.loadUser(r, id)
	httpx.JSON(w, 200, map[string]any{"ok": true, "data": u})
}

func (h *Handler) loadUser(r *http.Request, id string) (userResponse, error) {
	var u userResponse
	err := h.DB.QueryRow(r.Context(), `SELECT id::text,name,first_name,last_name,email,role,status,auth_type,language,timezone,must_change_password,can_create_calendars,created_at,last_login,last_sync FROM users WHERE id=$1`, id).Scan(&u.ID, &u.Name, &u.FirstName, &u.LastName, &u.Email, &u.Role, &u.Status, &u.AuthType, &u.Language, &u.Timezone, &u.MustChangePassword, &u.CanCreateCalendars, &u.CreatedAt, &u.LastLogin, &u.LastSync)
	return u, err
}

func (h *Handler) deleteUser(r *http.Request, p principal, id string) error {
	if id == p.User.ID {
		return errors.New("Das Konto des Token-Erstellers kann nicht gelöscht werden.")
	}
	var role string
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	// Serialize destructive user operations so two concurrent owner deletions
	// cannot both observe another active owner and remove the last two accounts.
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtext('zentcal:user-delete'))`); err != nil {
		return err
	}
	if err = tx.QueryRow(r.Context(), `SELECT role FROM users WHERE id=$1 FOR UPDATE`, id).Scan(&role); err != nil {
		return pgx.ErrNoRows
	}
	if role == "owner" {
		var otherOwners int
		if err = tx.QueryRow(r.Context(), `SELECT count(*) FROM users WHERE role='owner' AND status='active' AND id<>$1`, id).Scan(&otherOwners); err != nil {
			return err
		}
		if otherOwners == 0 {
			return errors.New("Der letzte aktive ZentCal-Owner kann nicht gelöscht werden.")
		}
	}
	// Membership mutations use the same per-calendar advisory lock. Lock every
	// shared calendar owned by this account before deciding whether it needs a
	// replacement owner, so a concurrent downgrade/removal cannot orphan it.
	rows, err := tx.Query(r.Context(), `SELECT c.id::text FROM calendars c JOIN memberships m ON m.calendar_id=c.id WHERE m.user_id=$1 AND m.role='owner' AND c.deleted_at IS NULL AND coalesce(c.system_kind,'')='' AND NOT c.admin_managed ORDER BY c.id::text`, id)
	if err != nil {
		return err
	}
	ownedCalendarIDs := make([]string, 0)
	for rows.Next() {
		var calendarID string
		if err = rows.Scan(&calendarID); err != nil {
			rows.Close()
			return err
		}
		ownedCalendarIDs = append(ownedCalendarIDs, calendarID)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, calendarID := range ownedCalendarIDs {
		if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtext($1))`, calendarID); err != nil {
			return err
		}
	}
	// If the account is the sole owner of a shared calendar, transfer ownership
	// to the acting admin API principal before removing the user. Shared data is
	// never orphaned or silently deleted through the API.
	if _, err = tx.Exec(r.Context(), `INSERT INTO memberships(calendar_id,user_id,role,dav_name)
SELECT c.id,$1,'owner',coalesce(c.dav_name,c.id::text)
FROM calendars c
JOIN memberships m ON m.calendar_id=c.id AND m.user_id=$2 AND m.role='owner'
WHERE c.deleted_at IS NULL AND coalesce(c.system_kind,'')='' AND NOT c.admin_managed
  AND NOT EXISTS (SELECT 1 FROM memberships other WHERE other.calendar_id=c.id AND other.user_id<>$2 AND other.role='owner')
ON CONFLICT(calendar_id,user_id) DO UPDATE SET role='owner'`, p.User.ID, id); err != nil {
		return err
	}
	// Personal event history/delivery copies are not calendar-cascaded, so
	// remove them before deleting the personal calendar.
	if _, err = tx.Exec(r.Context(), `DELETE FROM event_versions WHERE event_id IN (SELECT e.id FROM events e JOIN calendars c ON c.id=e.calendar_id WHERE c.system_owner_user_id=$1 AND c.system_kind='personal')`, id); err != nil {
		return err
	}
	if _, err = tx.Exec(r.Context(), `DELETE FROM scheduling_deliveries WHERE event_id IN (SELECT e.id FROM events e JOIN calendars c ON c.id=e.calendar_id WHERE c.system_owner_user_id=$1 AND c.system_kind='personal')`, id); err != nil {
		return err
	}
	if _, err = tx.Exec(r.Context(), `DELETE FROM scheduling_messages WHERE event_id IN (SELECT e.id FROM events e JOIN calendars c ON c.id=e.calendar_id WHERE c.system_owner_user_id=$1 AND c.system_kind='personal')`, id); err != nil {
		return err
	}
	// Personal data owned exclusively by the user is removed. Shared calendars are retained and reassigned to the acting admin.
	if _, err = tx.Exec(r.Context(), `DELETE FROM calendars WHERE system_owner_user_id=$1 AND system_kind='personal'`, id); err != nil {
		return err
	}
	if _, err = tx.Exec(r.Context(), `UPDATE calendars
SET admin_manager_user_id=$1,admin_manager_visible=false,created_by=CASE WHEN created_by=$2 THEN $1 ELSE created_by END,updated_at=now()
WHERE admin_managed AND admin_manager_user_id=$2 AND deleted_at IS NULL`, p.User.ID, id); err != nil {
		return err
	}
	if _, err = tx.Exec(r.Context(), `UPDATE calendars SET created_by=$1 WHERE created_by=$2 AND coalesce(system_kind,'')=''`, p.User.ID, id); err != nil {
		return err
	}
	if _, err = tx.Exec(r.Context(), `UPDATE events SET created_by=NULL WHERE created_by=$1`, id); err != nil {
		return err
	}
	if _, err = tx.Exec(r.Context(), `UPDATE events SET updated_by=NULL WHERE updated_by=$1`, id); err != nil {
		return err
	}
	if _, err = tx.Exec(r.Context(), `UPDATE event_versions SET actor_user_id=NULL WHERE actor_user_id=$1`, id); err != nil {
		return err
	}
	if _, err = tx.Exec(r.Context(), `UPDATE invitations SET invited_by=NULL WHERE invited_by=$1`, id); err != nil {
		return err
	}
	if _, err = tx.Exec(r.Context(), `DELETE FROM users WHERE id=$1`, id); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	h.audit(r, p, "admin_api.user.deleted", "user", id, map[string]any{})
	if h.Webhooks != nil {
		h.Webhooks.Emit(r.Context(), "user.deleted", p.User.ID, "user", id, map[string]any{"source": "admin_api"})
	}
	return nil
}

func (h *Handler) calendars(w http.ResponseWriter, r *http.Request) {
	scope := "admin:calendars:read"
	if r.Method == http.MethodPost {
		scope = "admin:calendars:write"
	}
	p, ok := h.authorize(w, r, scope)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		cs, err := h.App.ListAdminCalendars(r.Context(), p.User)
		if err != nil {
			httpx.Error(w, 500, "Kalender konnten nicht geladen werden.")
			return
		}
		httpx.JSON(w, 200, map[string]any{"ok": true, "data": cs})
		return
	}
	var in struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Color       string `json:"color"`
		Type        string `json:"type"`
		Mode        string `json:"mode"`
	}
	if err := decodeJSON(r, &in); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	c, err := h.App.CreateAdminCalendar(r.Context(), r, p.User, in.Name, in.Description, in.Color, in.Type, in.Mode)
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	httpx.JSON(w, 201, map[string]any{"ok": true, "data": c})
}
func (h *Handler) calendar(w http.ResponseWriter, r *http.Request) {
	scope := "admin:calendars:read"
	if r.Method != http.MethodGet {
		scope = "admin:calendars:write"
	}
	p, ok := h.authorize(w, r, scope)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if r.Method == http.MethodGet {
		c, err := h.App.GetAdminCalendar(r.Context(), p.User, id)
		if err != nil || c.SystemKind != "" || !c.AdminManaged || c.AdminManagerUserID != p.User.ID {
			httpx.Error(w, 404, "Kalender nicht gefunden.")
			return
		}
		httpx.JSON(w, 200, map[string]any{"ok": true, "data": c})
		return
	}
	if r.Method == http.MethodDelete {
		c, err := h.App.GetAdminCalendar(r.Context(), p.User, id)
		if err != nil || !c.AdminManaged || c.AdminManagerUserID != p.User.ID {
			httpx.Error(w, 404, "Kalender nicht gefunden.")
			return
		}
		if err := h.App.DeleteAdminCalendar(r.Context(), r, p.User, id); err != nil {
			httpx.Error(w, 400, err.Error())
			return
		}
		w.WriteHeader(204)
		return
	}
	var in struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		Color       *string `json:"color"`
		Mode        *string `json:"mode"`
	}
	if err := decodeJSON(r, &in); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	c, err := h.App.GetAdminCalendar(r.Context(), p.User, id)
	if err != nil || c.SystemKind != "" || !c.AdminManaged || c.AdminManagerUserID != p.User.ID {
		httpx.Error(w, 404, "Kalender nicht gefunden.")
		return
	}
	name, desc, color, mode := c.Name, c.Description, c.Color, c.Mode
	if in.Name != nil {
		name = *in.Name
	}
	if in.Description != nil {
		desc = *in.Description
	}
	if in.Color != nil {
		color = *in.Color
	}
	if in.Mode != nil {
		mode = *in.Mode
	}
	c, err = h.App.UpdateAdminCalendar(r.Context(), r, p.User, id, name, desc, color, mode)
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "data": c})
}
func (h *Handler) calendarMembers(w http.ResponseWriter, r *http.Request) {
	p, ok := h.authorize(w, r, "admin:calendars:read")
	if !ok {
		return
	}
	_ = p
	id := r.PathValue("id")
	var systemKind string
	if err := h.DB.QueryRow(r.Context(), `SELECT coalesce(system_kind,'') FROM calendars WHERE id=$1 AND deleted_at IS NULL AND admin_managed AND admin_manager_user_id=$2`, id, p.User.ID).Scan(&systemKind); err != nil || systemKind != "" {
		httpx.Error(w, 404, "Kalender nicht gefunden.")
		return
	}
	rows, err := h.DB.Query(r.Context(), `SELECT u.id::text,u.name,u.email,m.role,m.created_at FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.calendar_id=$1 ORDER BY lower(u.name)`, id)
	if err != nil {
		httpx.Error(w, 500, "Mitglieder konnten nicht geladen werden.")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var uid, name, email, role string
		var created time.Time
		if err := rows.Scan(&uid, &name, &email, &role, &created); err != nil {
			httpx.Error(w, 500, "Mitglieder konnten nicht geladen werden.")
			return
		}
		out = append(out, map[string]any{"user_id": uid, "name": name, "email": email, "role": role, "created_at": created})
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "data": out})
}
func (h *Handler) calendarMember(w http.ResponseWriter, r *http.Request) {
	p, ok := h.authorize(w, r, "admin:calendars:write")
	if !ok {
		return
	}
	calID, uid := r.PathValue("id"), r.PathValue("user_id")
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		httpx.Error(w, 500, "Mitglied konnte nicht verarbeitet werden.")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtext($1))`, calID); err != nil {
		httpx.Error(w, 500, "Kalender konnte nicht gesperrt werden.")
		return
	}
	var systemKind string
	if err := tx.QueryRow(r.Context(), `SELECT coalesce(system_kind,'') FROM calendars WHERE id=$1 AND deleted_at IS NULL AND admin_managed AND admin_manager_user_id=$2`, calID, p.User.ID).Scan(&systemKind); err != nil || systemKind != "" {
		httpx.Error(w, 404, "Kalender nicht gefunden.")
		return
	}
	if uid == p.User.ID {
		httpx.Error(w, 400, "Die eigene schreibgeschützte Ansicht wird über die Kalenderverwaltung gesteuert.")
		return
	}
	var oldRole string
	oldErr := tx.QueryRow(r.Context(), `SELECT role FROM memberships WHERE calendar_id=$1 AND user_id=$2`, calID, uid).Scan(&oldRole)
	if oldErr != nil && !errors.Is(oldErr, pgx.ErrNoRows) {
		httpx.Error(w, 500, "Mitglied konnte nicht geprüft werden.")
		return
	}
	ensureOwnerRemains := func() bool { return true }
	if r.Method == http.MethodDelete {
		if errors.Is(oldErr, pgx.ErrNoRows) {
			httpx.Error(w, 404, "Mitglied nicht gefunden.")
			return
		}
		if !ensureOwnerRemains() {
			return
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM memberships WHERE calendar_id=$1 AND user_id=$2`, calID, uid); err != nil {
			httpx.Error(w, 500, "Mitglied konnte nicht entfernt werden.")
			return
		}
		if err = tx.Commit(r.Context()); err != nil {
			httpx.Error(w, 500, "Mitglied konnte nicht entfernt werden.")
			return
		}
		details := map[string]any{"user_id": uid, "source": "admin_api"}
		h.audit(r, p, "admin_api.member.removed", "calendar", calID, details)
		if h.Webhooks != nil {
			h.Webhooks.Emit(r.Context(), "member.removed", p.User.ID, "calendar", calID, details)
		}
		w.WriteHeader(204)
		return
	}
	var in struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(r, &in); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	if in.Role != "owner" && in.Role != "contributor" && in.Role != "viewer" {
		httpx.Error(w, 400, "Ungültige Rolle.")
		return
	}
	var userExists bool
	_ = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND status<>'disabled')`, uid).Scan(&userExists)
	if !userExists {
		httpx.Error(w, 404, "Benutzer nicht gefunden.")
		return
	}
	if oldRole == "owner" && in.Role != "owner" && !ensureOwnerRemains() {
		return
	}
	if _, err := tx.Exec(r.Context(), `INSERT INTO memberships(calendar_id,user_id,role,dav_name) VALUES($1,$2,$3,$4) ON CONFLICT(calendar_id,user_id) DO UPDATE SET role=excluded.role`, calID, uid, in.Role, calID); err != nil {
		httpx.Error(w, 400, "Mitglied konnte nicht gespeichert werden.")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		httpx.Error(w, 500, "Mitglied konnte nicht gespeichert werden.")
		return
	}
	details := map[string]any{"user_id": uid, "role": in.Role, "source": "admin_api"}
	h.audit(r, p, "admin_api.member.updated", "calendar", calID, details)
	if h.Webhooks != nil {
		h.Webhooks.Emit(r.Context(), "member.updated", p.User.ID, "calendar", calID, details)
	}
	httpx.JSON(w, 200, map[string]any{"ok": true})
}

type backupSettingsPayload struct {
	Enabled            *bool   `json:"enabled,omitempty"`
	Provider           *string `json:"provider,omitempty"`
	Schedule           *string `json:"schedule,omitempty"`
	Time               *string `json:"time,omitempty"`
	Weekdays           *[]int  `json:"weekdays,omitempty"`
	Retention          *int    `json:"retention,omitempty"`
	EncryptionPassword *string `json:"encryption_password,omitempty"`
	SFTPHost           *string `json:"sftp_host,omitempty"`
	SFTPPort           *int    `json:"sftp_port,omitempty"`
	SFTPUser           *string `json:"sftp_user,omitempty"`
	SFTPPassword       *string `json:"sftp_password,omitempty"`
	SFTPPrivateKey     *string `json:"sftp_private_key,omitempty"`
	SFTPAuthMethod     *string `json:"sftp_auth_method,omitempty"`
	SFTPPath           *string `json:"sftp_path,omitempty"`
	SFTPVerifyHost     *bool   `json:"sftp_verify_host,omitempty"`
	S3Endpoint         *string `json:"s3_endpoint,omitempty"`
	S3Region           *string `json:"s3_region,omitempty"`
	S3Bucket           *string `json:"s3_bucket,omitempty"`
	S3AccessKey        *string `json:"s3_access_key,omitempty"`
	S3SecretKey        *string `json:"s3_secret_key,omitempty"`
	S3Prefix           *string `json:"s3_prefix,omitempty"`
	S3TLSVerify        *bool   `json:"s3_tls_verify,omitempty"`
}

func backupSettingsResponse(cfg backup.Config) map[string]any {
	return map[string]any{
		"enabled": cfg.Enabled, "provider": cfg.Provider, "schedule": cfg.Schedule, "time": cfg.Time,
		"weekdays": cfg.Weekdays, "retention": cfg.Retention,
		"encryption_password_set": cfg.EncryptionPassword != "",
		"sftp_host":               cfg.SFTPHost, "sftp_port": cfg.SFTPPort, "sftp_user": cfg.SFTPUser, "sftp_path": cfg.SFTPPath, "sftp_auth_method": cfg.SFTPAuthMethod,
		"sftp_verify_host": cfg.SFTPVerifyHost, "sftp_password_set": cfg.SFTPPassword != "", "sftp_private_key_set": cfg.SFTPPrivateKey != "",
		"s3_endpoint": cfg.S3.Endpoint, "s3_region": cfg.S3.Region, "s3_bucket": cfg.S3.Bucket, "s3_access_key": cfg.S3.AccessKey,
		"s3_prefix": cfg.S3.Prefix, "s3_tls_verify": cfg.S3.TLSVerify, "s3_secret_key_set": cfg.S3.SecretKey != "",
	}
}

func applyBackupSettingsPatch(cfg backup.Config, in backupSettingsPayload) (backup.Config, error) {
	if in.Enabled != nil {
		cfg.Enabled = *in.Enabled
	}
	if in.Provider != nil {
		cfg.Provider = strings.TrimSpace(*in.Provider)
	}
	if in.Schedule != nil {
		cfg.Schedule = strings.TrimSpace(*in.Schedule)
	}
	if in.Time != nil {
		cfg.Time = strings.TrimSpace(*in.Time)
	}
	if in.Weekdays != nil {
		cfg.Weekdays = append([]int(nil), (*in.Weekdays)...)
		if len(cfg.Weekdays) > 0 {
			cfg.Weekday = cfg.Weekdays[0]
		}
	}
	if in.Retention != nil {
		cfg.Retention = *in.Retention
	}
	if in.SFTPHost != nil {
		cfg.SFTPHost = strings.TrimSpace(*in.SFTPHost)
	}
	if in.SFTPPort != nil {
		cfg.SFTPPort = *in.SFTPPort
	}
	if in.SFTPUser != nil {
		cfg.SFTPUser = strings.TrimSpace(*in.SFTPUser)
	}
	if in.SFTPAuthMethod != nil {
		cfg.SFTPAuthMethod = strings.TrimSpace(*in.SFTPAuthMethod)
	}
	if in.SFTPPassword != nil && *in.SFTPPassword != "" {
		cfg.SFTPPassword = *in.SFTPPassword
	}
	if in.SFTPPrivateKey != nil && *in.SFTPPrivateKey != "" {
		cfg.SFTPPrivateKey = *in.SFTPPrivateKey
	}
	if in.SFTPPath != nil {
		cfg.SFTPPath = strings.TrimSpace(*in.SFTPPath)
	}
	if in.SFTPVerifyHost != nil {
		cfg.SFTPVerifyHost = *in.SFTPVerifyHost
	}
	if in.S3Endpoint != nil {
		cfg.S3.Endpoint = strings.TrimSpace(*in.S3Endpoint)
	}
	if in.S3Region != nil {
		cfg.S3.Region = strings.TrimSpace(*in.S3Region)
	}
	if in.S3Bucket != nil {
		cfg.S3.Bucket = strings.TrimSpace(*in.S3Bucket)
	}
	if in.S3AccessKey != nil {
		cfg.S3.AccessKey = strings.TrimSpace(*in.S3AccessKey)
	}
	if in.S3SecretKey != nil && *in.S3SecretKey != "" {
		cfg.S3.SecretKey = *in.S3SecretKey
	}
	if in.S3Prefix != nil {
		cfg.S3.Prefix = strings.TrimSpace(*in.S3Prefix)
	}
	if in.S3TLSVerify != nil {
		cfg.S3.TLSVerify = *in.S3TLSVerify
	}
	if in.EncryptionPassword != nil && *in.EncryptionPassword != "" {
		if cfg.EncryptionPassword != "" && cfg.EncryptionPassword != *in.EncryptionPassword {
			return cfg, errors.New("Backup-Verschlüsselungspasswort kann nach dem erstmaligen Setzen nicht geändert werden.")
		}
		cfg.EncryptionPassword = *in.EncryptionPassword
	}
	if cfg.Provider != "local" && cfg.Provider != "sftp" && cfg.Provider != "s3" {
		return cfg, errors.New("Ungültiger Backup-Provider.")
	}
	if cfg.Schedule != "daily" && cfg.Schedule != "weekly" {
		return cfg, errors.New("Ungültiger Backup-Zeitplan.")
	}
	if _, err := time.Parse("15:04", cfg.Time); err != nil {
		return cfg, errors.New("Ungültige Backup-Uhrzeit.")
	}
	if cfg.Retention < 1 || cfg.Retention > 3650 {
		return cfg, errors.New("Retention muss zwischen 1 und 3650 Backups liegen.")
	}
	if cfg.SFTPPort < 1 || cfg.SFTPPort > 65535 {
		return cfg, errors.New("SFTP-Port muss zwischen 1 und 65535 liegen.")
	}
	if cfg.SFTPAuthMethod != "password" && cfg.SFTPAuthMethod != "key" {
		return cfg, errors.New("SFTP-Authentifizierung muss password oder key sein.")
	}
	if cfg.Schedule == "weekly" && len(cfg.Weekdays) == 0 {
		return cfg, errors.New("Für wöchentliche Backups ist mindestens ein Wochentag erforderlich.")
	}
	seen := map[int]bool{}
	clean := make([]int, 0, len(cfg.Weekdays))
	for _, d := range cfg.Weekdays {
		if d < 0 || d > 6 {
			return cfg, errors.New("Wochentage müssen zwischen 0 und 6 liegen.")
		}
		if !seen[d] {
			seen[d] = true
			clean = append(clean, d)
		}
	}
	cfg.Weekdays = clean
	if cfg.EncryptionPassword != "" && len(cfg.EncryptionPassword) < 10 {
		return cfg, errors.New("Backup-Verschlüsselungspasswort muss mindestens 10 Zeichen lang sein.")
	}
	if cfg.Provider == "sftp" {
		if cfg.SFTPAuthMethod == "password" && cfg.SFTPPassword == "" {
			return cfg, errors.New("Für SFTP mit Passwort ist sftp_password erforderlich.")
		}
		if cfg.SFTPAuthMethod == "key" && cfg.SFTPPrivateKey == "" {
			return cfg, errors.New("Für SFTP mit SSH-Key ist sftp_private_key erforderlich.")
		}
	}
	return cfg, nil
}

func joinBackupWeekdays(days []int) string {
	parts := make([]string, 0, len(days))
	for _, d := range days {
		parts = append(parts, strconv.Itoa(d))
	}
	return strings.Join(parts, ",")
}

func (h *Handler) persistBackupSettings(ctx context.Context, cfg backup.Config) error {
	plain := map[string]string{
		"backup_enabled": strconv.FormatBool(cfg.Enabled), "backup_provider": cfg.Provider, "backup_schedule": cfg.Schedule,
		"backup_time": cfg.Time, "backup_weekday": strconv.Itoa(cfg.Weekday), "backup_weekdays": joinBackupWeekdays(cfg.Weekdays), "backup_retention": strconv.Itoa(cfg.Retention),
		"backup_sftp_host": cfg.SFTPHost, "backup_sftp_port": strconv.Itoa(cfg.SFTPPort), "backup_sftp_user": cfg.SFTPUser, "backup_sftp_path": cfg.SFTPPath, "backup_sftp_auth_method": cfg.SFTPAuthMethod,
		"backup_sftp_verify_host": strconv.FormatBool(cfg.SFTPVerifyHost), "backup_s3_endpoint": cfg.S3.Endpoint, "backup_s3_region": cfg.S3.Region,
		"backup_s3_bucket": cfg.S3.Bucket, "backup_s3_access_key": cfg.S3.AccessKey, "backup_s3_prefix": cfg.S3.Prefix, "backup_s3_tls_verify": strconv.FormatBool(cfg.S3.TLSVerify),
	}
	for k, v := range plain {
		if _, err := h.DB.Exec(ctx, `INSERT INTO settings(key,value,secret,updated_at) VALUES($1,$2,false,now()) ON CONFLICT(key) DO UPDATE SET value=excluded.value,secret=false,updated_at=now()`, k, v); err != nil {
			return err
		}
	}
	if cfg.SFTPAuthMethod == "password" {
		cfg.SFTPPrivateKey = ""
		_, _ = h.DB.Exec(ctx, `DELETE FROM settings WHERE key='backup_sftp_private_key'`)
	} else if cfg.SFTPAuthMethod == "key" {
		cfg.SFTPPassword = ""
		_, _ = h.DB.Exec(ctx, `DELETE FROM settings WHERE key='backup_sftp_password'`)
	}
	secrets := map[string]string{"backup_encryption_password": cfg.EncryptionPassword, "backup_sftp_password": cfg.SFTPPassword, "backup_sftp_private_key": cfg.SFTPPrivateKey, "backup_s3_secret_key": cfg.S3.SecretKey}
	for k, v := range secrets {
		if v == "" {
			continue
		}
		enc, err := h.Backup.Secrets.Encrypt(v)
		if err != nil {
			return err
		}
		if _, err = h.DB.Exec(ctx, `INSERT INTO settings(key,value,secret,updated_at) VALUES($1,$2,true,now()) ON CONFLICT(key) DO UPDATE SET value=excluded.value,secret=true,updated_at=now()`, k, enc); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) backupSettings(w http.ResponseWriter, r *http.Request) {
	scope := "admin:backups:read"
	if r.Method == http.MethodPatch {
		scope = "admin:backups:write"
	}
	p, ok := h.authorize(w, r, scope)
	if !ok {
		return
	}
	if h.Backup == nil {
		httpx.Error(w, 503, "Backup-Service nicht verfügbar.")
		return
	}
	cfg, err := h.Backup.LoadConfig(r.Context())
	if err != nil {
		httpx.Error(w, 500, "Backup-Einstellungen konnten nicht geladen werden.")
		return
	}
	if r.Method == http.MethodGet {
		httpx.JSON(w, 200, map[string]any{"ok": true, "data": backupSettingsResponse(cfg)})
		return
	}
	var in backupSettingsPayload
	if err := decodeJSON(r, &in); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	cfg, err = applyBackupSettingsPatch(cfg, in)
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	if err = h.persistBackupSettings(r.Context(), cfg); err != nil {
		httpx.Error(w, 500, "Backup-Einstellungen konnten nicht gespeichert werden.")
		return
	}
	h.audit(r, p, "admin_api.backup.settings_updated", "backup", "settings", map[string]any{"provider": cfg.Provider, "enabled": cfg.Enabled, "schedule": cfg.Schedule})
	httpx.JSON(w, 200, map[string]any{"ok": true, "data": backupSettingsResponse(cfg)})
}

func (h *Handler) testBackupSettings(w http.ResponseWriter, r *http.Request) {
	_, ok := h.authorize(w, r, "admin:backups:write")
	if !ok {
		return
	}
	cfg, err := h.Backup.LoadConfig(r.Context())
	if err != nil {
		httpx.Error(w, 500, "Backup-Einstellungen konnten nicht geladen werden.")
		return
	}
	var in backupSettingsPayload
	if err := decodeJSON(r, &in); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	cfg, err = applyBackupSettingsPatch(cfg, in)
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

func (h *Handler) backups(w http.ResponseWriter, r *http.Request) {
	scope := "admin:backups:read"
	if r.Method == http.MethodPost {
		scope = "admin:backups:write"
	}
	p, ok := h.authorize(w, r, scope)
	if !ok {
		return
	}
	if h.Backup == nil {
		httpx.Error(w, 503, "Backup-Service nicht verfügbar.")
		return
	}
	if r.Method == http.MethodGet {
		items, err := h.Backup.List(r.Context(), 200)
		if err != nil {
			httpx.Error(w, 500, "Backups konnten nicht geladen werden.")
			return
		}
		httpx.JSON(w, 200, map[string]any{"ok": true, "data": items})
		return
	}
	if h.Backup.Running() {
		httpx.Error(w, http.StatusConflict, "Es läuft bereits ein Backup oder Restore.")
		return
	}
	go func(actor string) {
		ctx := context.Background()
		item, err := h.Backup.Create(ctx, actor)
		if err == nil && h.Audit != nil {
			h.Audit.Write(ctx, nil, actor, "backup.completed", "backup", item.ID, map[string]any{"provider": item.Provider, "size": item.Size, "source": "admin_api"})
		}
	}(p.User.ID)
	httpx.JSON(w, 202, map[string]any{"ok": true, "message": "Backup wurde gestartet."})
}
func (h *Handler) verifyBackup(w http.ResponseWriter, r *http.Request) {
	_, ok := h.authorize(w, r, "admin:backups:read")
	if !ok {
		return
	}
	var in struct {
		EncryptionPassword string `json:"encryption_password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	if err := h.Backup.Verify(r.Context(), r.PathValue("id"), in.EncryptionPassword); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	httpx.JSON(w, 200, map[string]any{"ok": true})
}
func (h *Handler) restoreBackup(w http.ResponseWriter, r *http.Request) {
	p, ok := h.authorize(w, r, "admin:backups:restore")
	if !ok {
		return
	}
	var in struct {
		EncryptionPassword string `json:"encryption_password"`
		Confirm            string `json:"confirm"`
	}
	if err := decodeJSON(r, &in); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	if in.Confirm != "RESTORE" {
		httpx.Error(w, 400, "Restore erfordert confirm=RESTORE.")
		return
	}
	if err := h.Backup.Restore(r.Context(), r.PathValue("id"), in.EncryptionPassword); err != nil {
		httpx.Error(w, 500, err.Error())
		return
	}
	h.audit(r, p, "admin_api.backup.restored", "backup", r.PathValue("id"), nil)
	httpx.JSON(w, 200, map[string]any{"ok": true, "message": "Backup wurde für die Wiederherstellung vorbereitet. ZentCal wird neu gestartet."})
	if h.Restart != nil {
		go h.Restart()
	}
}
func (h *Handler) deleteBackup(w http.ResponseWriter, r *http.Request) {
	p, ok := h.authorize(w, r, "admin:backups:write")
	if !ok {
		return
	}
	if err := h.Backup.Delete(r.Context(), r.PathValue("id")); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	h.audit(r, p, "admin_api.backup.deleted", "backup", r.PathValue("id"), nil)
	w.WriteHeader(204)
}

func (h *Handler) webhooksList(w http.ResponseWriter, r *http.Request) {
	scope := "admin:webhooks:read"
	if r.Method == http.MethodPost {
		scope = "admin:webhooks:write"
	}
	p, ok := h.authorize(w, r, scope)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		hooks, err := h.Webhooks.List(r.Context())
		if err != nil {
			httpx.Error(w, 500, "Webhooks konnten nicht geladen werden.")
			return
		}
		httpx.JSON(w, 200, map[string]any{"ok": true, "data": hooks})
		return
	}
	var in struct {
		Name         string   `json:"name"`
		TargetURL    string   `json:"target_url"`
		AuthType     string   `json:"auth_type"`
		Events       []string `json:"events"`
		Active       *bool    `json:"active"`
		AllowPrivate bool     `json:"allow_private"`
	}
	if err := decodeJSON(r, &in); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	active := true
	if in.Active != nil {
		active = *in.Active
	}
	hook, secret, err := h.Webhooks.Create(r.Context(), in.Name, in.TargetURL, in.AuthType, in.Events, active, in.AllowPrivate, p.User.ID)
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	h.audit(r, p, "admin_api.webhook.created", "webhook", hook.ID, map[string]any{"name": hook.Name})
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, 201, map[string]any{"ok": true, "data": hook, "secret": secret})
}
func (h *Handler) webhookItem(w http.ResponseWriter, r *http.Request) {
	scope := "admin:webhooks:read"
	if r.Method != http.MethodGet {
		scope = "admin:webhooks:write"
	}
	p, ok := h.authorize(w, r, scope)
	if !ok {
		return
	}
	id := r.PathValue("id")
	hooks, err := h.Webhooks.List(r.Context())
	if err != nil {
		httpx.Error(w, 500, "Webhooks konnten nicht geladen werden.")
		return
	}
	var current *webhook.Hook
	for i := range hooks {
		if hooks[i].ID == id {
			current = &hooks[i]
			break
		}
	}
	if current == nil {
		httpx.Error(w, 404, "Webhook nicht gefunden.")
		return
	}
	if r.Method == http.MethodGet {
		httpx.JSON(w, 200, map[string]any{"ok": true, "data": current})
		return
	}
	if r.Method == http.MethodDelete {
		if err := h.Webhooks.Delete(r.Context(), id); err != nil {
			httpx.Error(w, 400, err.Error())
			return
		}
		h.audit(r, p, "admin_api.webhook.deleted", "webhook", id, nil)
		w.WriteHeader(204)
		return
	}
	var in struct {
		Name         *string   `json:"name"`
		TargetURL    *string   `json:"target_url"`
		AuthType     *string   `json:"auth_type"`
		Events       *[]string `json:"events"`
		Active       *bool     `json:"active"`
		AllowPrivate *bool     `json:"allow_private"`
	}
	if err := decodeJSON(r, &in); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	name, target, authType, events, active, allowPrivate := current.Name, current.TargetURL, current.AuthType, current.Events, current.Active, current.AllowPrivate
	if in.Name != nil {
		name = *in.Name
	}
	if in.TargetURL != nil {
		target = *in.TargetURL
	}
	if in.AuthType != nil {
		authType = *in.AuthType
	}
	if in.Events != nil {
		events = *in.Events
	}
	if in.Active != nil {
		active = *in.Active
	}
	if in.AllowPrivate != nil {
		allowPrivate = *in.AllowPrivate
	}
	if err := h.Webhooks.Update(r.Context(), id, name, target, authType, events, active, allowPrivate); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	h.audit(r, p, "admin_api.webhook.updated", "webhook", id, nil)
	hooks, _ = h.Webhooks.List(r.Context())
	for i := range hooks {
		if hooks[i].ID == id {
			httpx.JSON(w, 200, map[string]any{"ok": true, "data": hooks[i]})
			return
		}
	}
	httpx.Error(w, 500, "Webhook konnte nicht neu geladen werden.")
}
func (h *Handler) rotateWebhookSecret(w http.ResponseWriter, r *http.Request) {
	p, ok := h.authorize(w, r, "admin:webhooks:write")
	if !ok {
		return
	}
	secret, err := h.Webhooks.RotateSecret(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.Error(w, 404, "Webhook nicht gefunden.")
		return
	}
	h.audit(r, p, "admin_api.webhook.secret_rotated", "webhook", r.PathValue("id"), nil)
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, 200, map[string]any{"ok": true, "secret": secret})
}
func (h *Handler) testWebhook(w http.ResponseWriter, r *http.Request) {
	p, ok := h.authorize(w, r, "admin:webhooks:write")
	if !ok {
		return
	}
	msg, err := h.Webhooks.Test(r.Context(), r.PathValue("id"), p.User.ID)
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "message": msg})
}
func (h *Handler) webhookDeliveries(w http.ResponseWriter, r *http.Request) {
	_, ok := h.authorize(w, r, "admin:webhooks:read")
	if !ok {
		return
	}
	items, err := h.Webhooks.Deliveries(r.Context(), 200)
	if err != nil {
		httpx.Error(w, 500, "Webhook-Auslieferungen konnten nicht geladen werden.")
		return
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "data": items})
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("Ungültiges JSON: " + err.Error())
	}
	return nil
}
func (h *Handler) audit(r *http.Request, p principal, action, resourceType, resourceID string, details any) {
	if h.Audit != nil {
		h.Audit.Write(r.Context(), r, p.User.ID, action, resourceType, resourceID, details)
	}
}
