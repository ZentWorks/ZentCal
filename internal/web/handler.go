package web

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zentworks/zentcal/internal/app"
	"github.com/zentworks/zentcal/internal/audit"
	"github.com/zentworks/zentcal/internal/auth"
	"github.com/zentworks/zentcal/internal/backup"
	"github.com/zentworks/zentcal/internal/db"
	"github.com/zentworks/zentcal/internal/httpx"
	"github.com/zentworks/zentcal/internal/ical"
	mailpkg "github.com/zentworks/zentcal/internal/mail"
	"github.com/zentworks/zentcal/internal/oidc"
	"github.com/zentworks/zentcal/internal/security"
	"github.com/zentworks/zentcal/internal/webhook"
)

type Handler struct {
	App          *app.Service
	Auth         *auth.Service
	Audit        *audit.Logger
	DB           *pgxpool.Pool
	WebDir       string
	templates    map[string]*template.Template
	Version      string
	Secrets      *security.SecretBox
	StartedAt    time.Time
	Location     atomic.Pointer[time.Location]
	OIDC         *oidc.Client
	Webhooks     *webhook.Service
	Backup       *backup.Service
	MailDelivery *mailpkg.DeliveryService
	BaseURL      string
}
type pageData struct {
	Title, Page, InstanceName, CSRF, Error, Flash, Version, Lang string
	User                                                         *auth.User
	AccountAppPasswords                                          []AppPasswordRow
	OIDCEnabled, OIDCLocalLogin, SMTPEnabled                     bool
	Data                                                         any
}

type Member struct{ ID, Name, Email, Role string }
type UserRow struct {
	ID, Name, FirstName, LastName, Email, Role, Status, AuthType string
	CanCreateCalendars                                           bool
	AdditionalCalendars                                          int
	CreatedAt                                                    time.Time
	LastLogin, LastSync                                          *time.Time
}
type AuditRow struct {
	ID                                                                         int64
	Actor, Action, ResourceType, ResourceID, Details, IP, UserAgent, RequestID string
	CreatedAt                                                                  time.Time
}
type AppPasswordRow struct {
	ID, Name, Prefix string
	CreatedAt        time.Time
	LastUsed         *time.Time
}

type InviteSummary struct {
	Accepted, Tentative, Declined, Pending int
}

type DashboardEventRow struct {
	ID, CalendarID, Summary, CalendarName, Color string
	Start, End                                   *time.Time
}

type TokenRow struct {
	ID, Name, Prefix  string
	Scopes            []string
	CreatedAt         time.Time
	LastUsed, Expires *time.Time
}

func New(a *app.Service, au *auth.Service, al *audit.Logger, db *pgxpool.Pool, webDir, version string, secrets *security.SecretBox, oidcClient *oidc.Client, webhooks *webhook.Service, baseURL string) (*Handler, error) {
	h := &Handler{App: a, Auth: au, Audit: al, DB: db, WebDir: webDir, Version: version, Secrets: secrets, OIDC: oidcClient, Webhooks: webhooks, BaseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"), StartedAt: time.Now(), templates: map[string]*template.Template{}}
	h.Location.Store(time.Local)
	userLocation := func(name string) *time.Location {
		if strings.TrimSpace(name) != "" {
			if loc, err := time.LoadLocation(name); err == nil {
				return loc
			}
		}
		return h.location()
	}
	funcs := template.FuncMap{"fmtTime": func(t *time.Time) string {
		if t == nil {
			return "–"
		}
		return t.In(h.location()).Format("02.01.2006 15:04")
	}, "fmtTimeV": func(t time.Time) string { return t.In(h.location()).Format("02.01.2006 15:04") },
		"fmtTimeTZ": func(t *time.Time, tz string) string {
			if t == nil {
				return "–"
			}
			return t.In(userLocation(tz)).Format("02.01.2006 15:04")
		},
		"fmtTimeVTZ": func(t time.Time, tz string) string { return t.In(userLocation(tz)).Format("02.01.2006 15:04") }, "fmtBytes": formatBytes, "upper": strings.ToUpper, "lower": strings.ToLower, "timezones": availableTimezones, "containsString": func(items []string, want string) bool {
			for _, v := range items {
				if v == want {
					return true
				}
			}
			return false
		}, "containsInt": func(items []int, want int) bool {
			for _, v := range items {
				if v == want {
					return true
				}
			}
			return false
		}, "tr": tr, "pageIcon": pageIcon, "initial": func(v string) string {
			r := []rune(strings.TrimSpace(v))
			if len(r) == 0 {
				return "?"
			}
			return strings.ToUpper(string(r[0]))
		}}
	pages := []string{"dashboard", "calendars", "admin_calendars", "calendar", "users", "activity", "api", "admin_api", "account", "settings", "system", "webhooks", "backups", "email_deliveries", "documentation"}
	baseRaw, err := os.ReadFile(filepath.Join(webDir, "templates", "base.html"))
	if err != nil {
		return nil, err
	}
	for _, p := range pages {
		pageRaw, readErr := os.ReadFile(filepath.Join(webDir, "templates", p+".html"))
		if readErr != nil {
			return nil, readErr
		}
		for _, lang := range []string{"de", "en"} {
			baseSource, pageSource := string(baseRaw), string(pageRaw)
			if lang == "en" {
				baseSource = translateTemplateSource(baseSource)
				pageSource = translateTemplateSource(pageSource)
			}
			t, parseErr := template.New("base.html").Funcs(funcs).Parse(baseSource)
			if parseErr == nil {
				_, parseErr = t.New(p + ".html").Parse(pageSource)
			}
			if parseErr != nil {
				return nil, fmt.Errorf("template %s (%s): %w", p, lang, parseErr)
			}
			key := p
			if lang == "en" {
				key += "|en"
			}
			h.templates[key] = t
		}
	}
	for _, p := range []string{"setup", "login", "invite", "forgot"} {
		raw, readErr := os.ReadFile(filepath.Join(webDir, "templates", p+".html"))
		if readErr != nil {
			return nil, readErr
		}
		for _, lang := range []string{"de", "en"} {
			source := string(raw)
			if lang == "en" {
				source = translateTemplateSource(source)
			}
			t, parseErr := template.New(p + ".html").Funcs(funcs).Parse(source)
			if parseErr != nil {
				return nil, fmt.Errorf("template %s (%s): %w", p, lang, parseErr)
			}
			key := p
			if lang == "en" {
				key += "|en"
			}
			h.templates[key] = t
		}
	}
	return h, nil
}

func (h *Handler) Register(mux *http.ServeMux) {
	fs := http.FileServer(http.Dir(filepath.Join(h.WebDir, "static")))
	mux.Handle("GET /static/", http.StripPrefix("/static/", fs))
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeFile(w, r, filepath.Join(h.WebDir, "static", "icons", "favicon.ico"))
	})
	mux.HandleFunc("GET /{$}", h.dashboard)
	mux.HandleFunc("GET /setup", h.setup)
	mux.HandleFunc("POST /setup", h.setup)
	mux.HandleFunc("GET /login", h.login)
	mux.HandleFunc("POST /login", h.login)
	mux.HandleFunc("GET /forgot-password", h.forgotPassword)
	mux.HandleFunc("POST /forgot-password", h.forgotPassword)
	mux.HandleFunc("POST /logout", h.logout)
	mux.HandleFunc("GET /calendars", h.calendars)
	mux.HandleFunc("GET /admin/calendars", h.adminCalendars)
	mux.HandleFunc("GET /ui/admin-calendars/search", h.adminCalendarsSearch)
	mux.HandleFunc("POST /ui/admin-calendars/{id}/visibility", h.adminCalendarVisibility)
	mux.HandleFunc("POST /ui/calendars", h.createCalendar)
	mux.HandleFunc("GET /calendars/{id}", h.calendar)
	mux.HandleFunc("POST /ui/calendars/{id}", h.updateCalendar)
	mux.HandleFunc("DELETE /ui/calendars/{id}", h.deleteCalendar)
	mux.HandleFunc("POST /ui/calendars/{id}/members", h.memberUpsert)
	mux.HandleFunc("DELETE /ui/calendars/{id}/members/{uid}", h.memberDelete)
	mux.HandleFunc("GET /users", h.users)
	mux.HandleFunc("GET /ui/users/search", h.usersSearch)
	mux.HandleFunc("GET /ui/users/{id}/delete-info", h.userDeleteInfo)
	mux.HandleFunc("POST /ui/users/{id}/delete", h.deleteUserUI)
	mux.HandleFunc("POST /ui/users", h.createUser)
	mux.HandleFunc("POST /ui/invitations", h.createInvitation)
	mux.HandleFunc("POST /ui/users/{id}", h.updateUser)
	mux.HandleFunc("POST /ui/users/{id}/reset-password", h.resetUserPassword)
	mux.HandleFunc("GET /activity", h.activity)
	mux.HandleFunc("GET /ui/activity", h.activityMore)
	mux.HandleFunc("GET /ui/activity/search", h.activitySearch)
	mux.HandleFunc("GET /account", h.accountPage)
	mux.HandleFunc("POST /ui/account/profile", h.updateOwnProfile)
	mux.HandleFunc("POST /ui/account/password", h.changeOwnPassword)
	mux.HandleFunc("GET /api-tokens", h.apiPage)
	mux.HandleFunc("POST /ui/api-tokens", h.createToken)
	mux.HandleFunc("GET /admin-api", h.adminAPIPage)
	mux.HandleFunc("GET /documentation", h.documentationPage)
	mux.HandleFunc("POST /ui/admin-api-tokens", h.createAdminAPIToken)
	mux.HandleFunc("DELETE /ui/admin-api-tokens/{id}", h.deleteAdminAPIToken)
	mux.HandleFunc("DELETE /ui/api-tokens/{id}", h.deleteToken)
	mux.HandleFunc("POST /ui/app-passwords", h.createAppPassword)
	mux.HandleFunc("DELETE /ui/app-passwords/{id}", h.deleteAppPassword)
	mux.HandleFunc("GET /ui/events/{id}/history", h.eventHistory)
	mux.HandleFunc("GET /settings", h.settings)
	mux.HandleFunc("POST /ui/settings", h.saveSettings)
	mux.HandleFunc("POST /ui/settings/smtp/test", h.testSMTP)
	mux.HandleFunc("POST /ui/settings/oidc/test", h.testOIDC)
	mux.HandleFunc("GET /auth/oidc/start", h.oidcStart)
	mux.HandleFunc("GET /auth/oidc/callback", h.oidcCallback)
	mux.HandleFunc("POST /ui/account/sso/link", h.oidcLinkStart)
	mux.HandleFunc("POST /ui/account/sso/unlink", h.oidcUnlinkStart)
	mux.HandleFunc("GET /webhooks", h.webhooksPage)
	mux.HandleFunc("POST /ui/webhooks", h.createWebhook)
	mux.HandleFunc("POST /ui/webhooks/{id}", h.updateWebhook)
	mux.HandleFunc("DELETE /ui/webhooks/{id}", h.deleteWebhook)
	mux.HandleFunc("POST /ui/webhooks/{id}/rotate-secret", h.rotateWebhookSecret)
	mux.HandleFunc("POST /ui/webhooks/{id}/test", h.testWebhook)
	mux.HandleFunc("POST /ui/webhook-deliveries/{id}/retry", h.retryWebhookDelivery)
	mux.HandleFunc("GET /backups", h.backupsPage)
	mux.HandleFunc("GET /email-deliveries", h.emailDeliveriesPage)
	mux.HandleFunc("GET /ui/email-deliveries", h.emailDeliveriesData)
	mux.HandleFunc("POST /ui/backups/settings", h.saveBackupSettings)
	mux.HandleFunc("POST /ui/backups/test", h.testBackupProvider)
	mux.HandleFunc("POST /ui/backups/run", h.runBackupNow)
	mux.HandleFunc("GET /ui/backups/status", h.backupStatus)
	mux.HandleFunc("POST /ui/backups/reauth", h.backupReauthStart)
	mux.HandleFunc("POST /ui/backups/{id}/verify", h.verifyBackup)
	mux.HandleFunc("POST /ui/backups/{id}/restore", h.restoreBackup)
	mux.HandleFunc("DELETE /ui/backups/{id}", h.deleteBackup)
	mux.HandleFunc("POST /ui/backups/{id}/delete", h.deleteBackup)
	mux.HandleFunc("GET /ui/backups/{id}/download", h.downloadBackup)
	mux.HandleFunc("POST /ui/backups/upload-restore", h.uploadRestoreBackup)
	mux.HandleFunc("GET /system", h.system)
	mux.HandleFunc("GET /invite/{token}", h.invite)
	mux.HandleFunc("POST /invite/{token}", h.invite)
}

func (h *Handler) setup(w http.ResponseWriter, r *http.Request) {
	done, err := h.Auth.SetupComplete(r.Context())
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}
	if done {
		http.Redirect(w, r, "/login", 303)
		return
	}
	if r.Method == http.MethodGet {
		h.renderPublic(w, r, "setup", pageData{Title: "ZentCal einrichten", Version: h.Version})
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderPublic(w, r, "setup", pageData{Title: "ZentCal einrichten", Error: "Ungültige Eingabe.", Version: h.Version})
		return
	}
	u, err := h.Auth.CreateOwner(r.Context(), r.FormValue("first_name"), r.FormValue("last_name"), r.FormValue("email"), r.FormValue("password"))
	if err != nil {
		h.renderPublic(w, r, "setup", pageData{Title: "ZentCal einrichten", Error: err.Error(), Version: h.Version})
		return
	}
	lang := browserLanguage(r)
	_, _ = h.DB.Exec(r.Context(), `UPDATE users SET language=$1 WHERE id=$2`, lang, u.ID)
	u.Language = lang
	token, _, err := h.Auth.CreateSession(r.Context(), u, r)
	if err != nil {
		http.Error(w, "Session error", 500)
		return
	}
	h.setSession(w, r, token)
	h.Audit.Write(r.Context(), r, u.ID, "setup.completed", "system", "", map[string]any{"email": u.Email})
	http.Redirect(w, r, "/", 303)
}
func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	done, _ := h.Auth.SetupComplete(r.Context())
	if !done {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		if _, err := h.Auth.SessionFromRequest(r); err == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		h.renderPublic(w, r, "login", pageData{Title: "Anmelden", Version: h.Version, Data: map[string]any{"Step": "email"}})
		return
	}
	if err := parseRequestForm(r); err != nil {
		h.renderPublic(w, r, "login", pageData{Title: "Anmelden", Version: h.Version, Error: "Ungültige Eingabe.", Data: map[string]any{"Step": "email"}})
		return
	}

	cfg, cfgErr := h.OIDC.Load(r.Context())
	if cfgErr != nil {
		// A broken OIDC configuration must not unexpectedly disable working local
		// accounts. OIDC-linked accounts are rejected below until the provider
		// configuration can be loaded again.
		cfg = oidc.Config{LocalLogin: true}
	}
	_, smtpEnabled, _ := h.loadSMTPConfig(r.Context())
	step := strings.TrimSpace(r.FormValue("step"))
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))

	renderEmail := func(message string) {
		h.renderPublic(w, r, "login", pageData{Title: "Anmelden", Version: h.Version, Error: message, Data: map[string]any{"Step": "email", "Email": email}})
	}
	renderPassword := func(message string) {
		h.renderPublic(w, r, "login", pageData{Title: "Anmelden", Version: h.Version, Error: message, Data: map[string]any{"Step": "password", "Email": email, "ForgotPassword": smtpEnabled}})
	}

	switch step {
	case "identify", "":
		u, err := h.Auth.ResolveLoginUser(r.Context(), email, auth.ClientIP(r))
		if err != nil {
			h.Audit.Write(r.Context(), r, "", "auth.login_identify_failed", "auth", "", nil)
			renderEmail("Mit diesen Angaben ist keine Anmeldung möglich.")
			return
		}
		switch u.AuthType {
		case "oidc":
			if cfgErr != nil || !cfg.Enabled {
				renderEmail("Mit diesen Angaben ist keine Anmeldung möglich.")
				return
			}
			location, err := h.OIDC.BeginFlow(r.Context(), cfg, h.externalBaseURL()+"/auth/oidc/callback", "/", "existing", u.ID)
			if err != nil {
				renderEmail("Single Sign-On konnte nicht gestartet werden.")
				return
			}
			http.Redirect(w, r, location, http.StatusFound)
			return
		case "local":
			if !cfg.LocalLogin && cfg.Enabled {
				renderEmail("Mit diesen Angaben ist keine Anmeldung möglich.")
				return
			}
			renderPassword("")
			return
		default:
			renderEmail("Mit diesen Angaben ist keine Anmeldung möglich.")
			return
		}

	case "password":
		if cfg.Enabled && !cfg.LocalLogin {
			renderEmail("Mit diesen Angaben ist keine Anmeldung möglich.")
			return
		}
		u, err := h.Auth.Authenticate(r.Context(), email, r.FormValue("password"), auth.ClientIP(r))
		if err != nil {
			h.Audit.Write(r.Context(), r, "", "auth.login_failed", "auth", "", nil)
			renderPassword("E-Mail oder Passwort ist falsch.")
			return
		}
		token, _, err := h.Auth.CreateSession(r.Context(), u, r)
		if err != nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}
		h.setSession(w, r, token)
		h.Audit.Write(r.Context(), r, u.ID, "auth.login", "auth", u.ID, nil)
		if u.MustChangePassword {
			http.Redirect(w, r, "/account?password_change=required", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	default:
		renderEmail("Ungültiger Anmeldevorgang.")
	}
}
func (h *Handler) forgotPassword(w http.ResponseWriter, r *http.Request) {
	_, smtpEnabled, smtpErr := h.loadSMTPConfig(r.Context())
	if smtpErr != nil || !smtpEnabled {
		http.NotFound(w, r)
		return
	}
	oidcCfg, _ := h.OIDC.Load(r.Context())
	localLoginAllowed := !oidcCfg.Enabled || oidcCfg.LocalLogin
	data := map[string]any{}
	if r.Method == http.MethodGet {
		h.renderPublic(w, r, "forgot", pageData{Title: "Passwort vergessen", Version: h.Version, Data: data})
		return
	}
	if err := parseRequestForm(r); err != nil {
		h.renderPublic(w, r, "forgot", pageData{Title: "Passwort vergessen", Version: h.Version, Error: "Ungültige Eingabe.", Data: data})
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	// Always return the same public response to avoid account enumeration.
	data["Sent"] = true
	if strings.Contains(email, "@") {
		var id, authType, status string
		err := h.DB.QueryRow(r.Context(), `SELECT id::text,auth_type,status FROM users WHERE lower(email)=lower($1)`, email).Scan(&id, &authType, &status)
		if err == nil && authType == "local" && status == "active" && localLoginAllowed {
			var allowed bool
			limitErr := h.DB.QueryRow(r.Context(), `INSERT INTO password_reset_requests(identity,last_requested_at) VALUES(lower($1),now())
ON CONFLICT(identity) DO UPDATE SET last_requested_at=excluded.last_requested_at
WHERE password_reset_requests.last_requested_at < now()-interval '15 minutes'
RETURNING true`, email).Scan(&allowed)
			if limitErr == nil && allowed {
				queued, queueErr := h.enqueuePasswordReset(r.Context(), id, h.externalBaseURL())
				if queueErr != nil {
					slog.Warn("password reset enqueue failed", "error", queueErr)
				} else if queued {
					h.Audit.Write(r.Context(), r, "", "auth.password_reset_requested", "user", id, map[string]any{"delivery": "smtp_queue"})
				}
			}
		}
	}
	h.renderPublic(w, r, "forgot", pageData{Title: "Passwort vergessen", Version: h.Version, Data: data})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.session(w, r)
	if !ok {
		return
	}
	if !h.csrfOK(r, ss) {
		httpx.Error(w, 403, "Ungültiges CSRF-Token.")
		return
	}
	h.Auth.Logout(r.Context(), r)
	clearSession(w)
	http.Redirect(w, r, "/login", 303)
}

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.page(w, r, "dashboard")
	if !ok {
		return
	}
	calendars, _ := h.App.ListCalendars(r.Context(), ss.User)
	c := len(calendars)
	var e, pending, users int
	_ = h.DB.QueryRow(r.Context(), `SELECT count(*) FROM events e
JOIN calendars c ON c.id=e.calendar_id
JOIN memberships m ON m.calendar_id=c.id AND m.user_id=$1
WHERE c.deleted_at IS NULL AND (coalesce(c.system_kind,'')='' OR (c.system_kind='personal' AND c.system_owner_user_id=$1))`, ss.User.ID).Scan(&e)
	_ = h.DB.QueryRow(r.Context(), `SELECT count(*) FROM event_attendees WHERE user_id=$1 AND partstat='NEEDS-ACTION'`, ss.User.ID).Scan(&pending)
	if auth.IsAdmin(ss.User) {
		_ = h.DB.QueryRow(r.Context(), `SELECT count(*) FROM users WHERE status='active'`).Scan(&users)
	}

	upcoming := make([]DashboardEventRow, 0, 5)
	rows, err := h.DB.Query(r.Context(), `SELECT e.id::text,e.calendar_id::text,e.summary,e.dtstart,e.dtend,c.name,c.color
FROM events e
JOIN calendars c ON c.id=e.calendar_id
JOIN memberships m ON m.calendar_id=c.id AND m.user_id=$1
WHERE c.deleted_at IS NULL
  AND (coalesce(c.system_kind,'')='' OR (c.system_kind='personal' AND c.system_owner_user_id=$1))
  AND coalesce(e.dtend,e.dtstart,e.created_at) >= now()
ORDER BY coalesce(e.dtstart,e.created_at), e.created_at
LIMIT 5`, ss.User.ID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var item DashboardEventRow
			if rows.Scan(&item.ID, &item.CalendarID, &item.Summary, &item.Start, &item.End, &item.CalendarName, &item.Color) == nil {
				upcoming = append(upcoming, item)
			}
		}
	}
	activity, _ := h.auditRowsVisible(r.Context(), 8, ss.User)
	canCreate, _ := h.App.CanCreateCalendars(r.Context(), ss.User.ID)
	h.render(w, "dashboard", ss, pageData{Title: "Dashboard", Page: "dashboard", Data: map[string]any{
		"Calendars": c, "Users": users, "Events": e, "PendingInvites": pending, "Upcoming": upcoming, "CalendarList": calendars, "Activity": activity, "CanCreateCalendars": canCreate,
	}})
}
func (h *Handler) calendars(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.page(w, r, "calendars")
	if !ok {
		return
	}
	cs, err := h.App.ListCalendars(r.Context(), ss.User)
	if err != nil {
		http.Error(w, "Kalender konnten nicht geladen werden", 500)
		return
	}
	canCreate, _ := h.App.CanCreateCalendars(r.Context(), ss.User.ID)
	h.render(w, "calendars", ss, pageData{Title: "Kalender", Page: "calendars", Data: map[string]any{"Calendars": cs, "CanCreateCalendars": canCreate}})
}

func (h *Handler) adminCalendars(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminPage(w, r, "admin-calendars")
	if !ok {
		return
	}
	cs, err := h.App.ListAdminCalendars(r.Context(), ss.User)
	if err != nil {
		http.Error(w, "Kalenderverwaltung konnte nicht geladen werden", 500)
		return
	}
	h.render(w, "admin_calendars", ss, pageData{Title: "Kalenderverwaltung", Page: "admin-calendars", Data: cs})
}
func (h *Handler) adminCalendarVisibility(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	visible := r.FormValue("visible") == "yes"
	c, err := h.App.SetAdminCalendarVisibility(r.Context(), r, ss.User, r.PathValue("id"), visible)
	if err != nil {
		httpx.Error(w, 403, err.Error())
		return
	}
	message := "Kalender wird nicht in deinen Kalendern angezeigt."
	if visible {
		message = "Kalender wird jetzt schreibgeschützt in deinen Kalendern angezeigt."
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "message": message, "reload": true, "data": c})
}

func (h *Handler) createCalendar(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.action(w, r, true)
	if !ok {
		return
	}
	_ = parseRequestForm(r)
	create := h.App.CreateCalendar
	if auth.IsAdmin(ss.User) && r.URL.Query().Get("admin") == "1" {
		create = h.App.CreateAdminCalendar
	}
	c, err := create(r.Context(), r, ss.User, r.FormValue("name"), r.FormValue("description"), r.FormValue("color"), r.FormValue("type"), r.FormValue("mode"))
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	redirect := "/calendars/" + c.ID
	if auth.IsAdmin(ss.User) && r.URL.Query().Get("admin") == "1" {
		redirect += "?admin=1"
	}
	httpx.JSON(w, 201, map[string]any{"ok": true, "redirect": redirect})
}
func (h *Handler) calendar(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.page(w, r, "calendars")
	if !ok {
		return
	}
	page := "calendars"
	if auth.IsAdmin(ss.User) && r.URL.Query().Get("admin") == "1" {
		page = "admin-calendars"
	}
	var c app.Calendar
	var err error
	adminView := auth.IsAdmin(ss.User) && r.URL.Query().Get("admin") == "1"
	if adminView {
		c, err = h.App.GetAdminCalendar(r.Context(), ss.User, r.PathValue("id"))
	} else {
		c, err = h.App.GetCalendar(r.Context(), ss.User, r.PathValue("id"))
	}
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var es []app.Event
	inviteSummary := map[string]InviteSummary{}
	if c.CanReadEvents {
		es, _ = h.App.ListEvents(r.Context(), ss.User, c.ID)
		rows, qerr := h.DB.Query(r.Context(), `SELECT ea.event_id::text,ea.partstat,count(*) FROM event_attendees ea JOIN events e ON e.id=ea.event_id WHERE e.calendar_id=$1 GROUP BY ea.event_id,ea.partstat`, c.ID)
		if qerr == nil {
			defer rows.Close()
			for rows.Next() {
				var eventID, state string
				var count int
				if rows.Scan(&eventID, &state, &count) == nil {
					v := inviteSummary[eventID]
					switch state {
					case "ACCEPTED":
						v.Accepted += count
					case "TENTATIVE":
						v.Tentative += count
					case "DECLINED":
						v.Declined += count
					default:
						v.Pending += count
					}
					inviteSummary[eventID] = v
				}
			}
		}
	}
	members, _ := h.members(r.Context(), c.ID)
	var users []UserRow
	if c.CanManage {
		users, _ = h.availableCalendarUsers(r.Context(), c.ID)
	}
	base := h.externalBaseURL()
	davRoot := base + "/dav/"
	principalURL := base + "/dav/principals/" + ss.User.ID + "/"
	calendarURL := base + "/dav/calendars/" + ss.User.ID + "/" + c.ID + "/"
	serverHost, serverPort, useSSL := r.Host, "", false
	if u, parseErr := url.Parse(base); parseErr == nil {
		serverHost = u.Hostname()
		serverPort = u.Port()
		useSSL = strings.EqualFold(u.Scheme, "https")
		if serverPort == "" {
			if useSSL {
				serverPort = "443"
			} else {
				serverPort = "80"
			}
		}
	}
	h.render(w, "calendar", ss, pageData{Title: c.Name, Page: page, Data: map[string]any{"Calendar": c, "Events": es, "InviteSummary": inviteSummary, "Members": members, "Users": users, "DAVURL": calendarURL, "DAVRoot": davRoot, "DAVPrincipal": principalURL, "DAVHost": serverHost, "DAVPort": serverPort, "DAVSSL": useSSL, "SSO": ss.User.AuthType == "oidc", "AdminView": adminView}})
}
func (h *Handler) updateCalendar(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.action(w, r, true)
	if !ok {
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	var c app.Calendar
	var err error
	if auth.IsAdmin(ss.User) && r.URL.Query().Get("admin") == "1" {
		c, err = h.App.UpdateAdminCalendar(r.Context(), r, ss.User, r.PathValue("id"), r.FormValue("name"), r.FormValue("description"), r.FormValue("color"), r.FormValue("mode"))
	} else {
		c, err = h.App.UpdateCalendar(r.Context(), r, ss.User, r.PathValue("id"), r.FormValue("name"), r.FormValue("description"), r.FormValue("color"), r.FormValue("mode"))
	}
	if err != nil {
		httpx.Error(w, 403, err.Error())
		return
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "message": "Kalender gespeichert.", "reload": true, "data": c})
}

func (h *Handler) deleteCalendar(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.action(w, r, true)
	if !ok {
		return
	}
	var err error
	if auth.IsAdmin(ss.User) && r.URL.Query().Get("admin") == "1" {
		err = h.App.DeleteAdminCalendar(r.Context(), r, ss.User, r.PathValue("id"))
	} else {
		err = h.App.DeleteCalendar(r.Context(), r, ss.User, r.PathValue("id"))
	}
	if err != nil {
		httpx.Error(w, 403, err.Error())
		return
	}
	redirect := "/calendars"
	if auth.IsAdmin(ss.User) && r.URL.Query().Get("admin") == "1" {
		redirect = "/admin/calendars"
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "message": "Kalender gelöscht.", "redirect": redirect})
}

func (h *Handler) memberUpsert(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.action(w, r, true)
	if !ok {
		return
	}
	calID := r.PathValue("id")
	var c app.Calendar
	var err error
	if auth.IsAdmin(ss.User) && r.URL.Query().Get("admin") == "1" {
		c, err = h.App.GetAdminCalendar(r.Context(), ss.User, calID)
	} else {
		c, err = h.App.GetCalendar(r.Context(), ss.User, calID)
	}
	if err != nil || !c.CanManage {
		httpx.Error(w, 403, "Keine Berechtigung.")
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	uid := strings.TrimSpace(r.FormValue("user_id"))
	if c.AdminManaged && uid == c.AdminManagerUserID {
		httpx.Error(w, 400, "Die eigene schreibgeschützte Ansicht wird über „In meinen Kalendern anzeigen“ verwaltet.")
		return
	}
	mr := strings.TrimSpace(r.FormValue("role"))
	if mr != "contributor" && mr != "viewer" && mr != "owner" {
		httpx.Error(w, 400, "Ungültige Rolle.")
		return
	}
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		httpx.Error(w, 500, "Mitglied konnte nicht gespeichert werden.")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtext($1))`, calID); err != nil {
		httpx.Error(w, 500, "Mitglied konnte nicht gesperrt werden.")
		return
	}
	var targetName, targetEmail, targetLanguage string
	if err := tx.QueryRow(r.Context(), `SELECT name,email,language FROM users WHERE id=$1 AND status<>'disabled'`, uid).Scan(&targetName, &targetEmail, &targetLanguage); err != nil {
		httpx.Error(w, 400, "Benutzer wurde nicht gefunden.")
		return
	}
	var oldRole string
	oldErr := tx.QueryRow(r.Context(), `SELECT role FROM memberships WHERE calendar_id=$1 AND user_id=$2`, calID, uid).Scan(&oldRole)
	if oldErr != nil && !errors.Is(oldErr, pgx.ErrNoRows) {
		httpx.Error(w, 500, "Mitglied konnte nicht geprüft werden.")
		return
	}
	if oldRole == "owner" && mr != "owner" {
		var otherOwners int
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM memberships WHERE calendar_id=$1 AND role='owner' AND user_id<>$2`, calID, uid).Scan(&otherOwners); err != nil {
			httpx.Error(w, 500, "Owner konnten nicht geprüft werden.")
			return
		}
		if otherOwners == 0 && !c.AdminManaged {
			httpx.Error(w, 400, "Ein Kalender muss mindestens einen Eigentümer haben.")
			return
		}
	}
	if oldRole == mr {
		httpx.JSON(w, 200, map[string]any{"ok": true, "message": "Keine Änderung erforderlich."})
		return
	}
	if _, err = tx.Exec(r.Context(), `INSERT INTO memberships(calendar_id,user_id,role,dav_name) VALUES($1,$2,$3,$4) ON CONFLICT(calendar_id,user_id) DO UPDATE SET role=excluded.role`, calID, uid, mr, calID); err != nil {
		httpx.Error(w, 400, "Mitglied konnte nicht gespeichert werden.")
		return
	}
	action := "member.updated"
	if errors.Is(oldErr, pgx.ErrNoRows) {
		action = "member.added"
		if cfg, enabled, mailErr := h.loadSMTPConfig(r.Context()); mailErr != nil {
			httpx.Error(w, 500, "Kalender wurde nicht freigegeben, weil SMTP nicht korrekt konfiguriert ist: "+mailErr.Error())
			return
		} else if enabled {
			roleLabel := map[string]string{"owner": "Eigentümer", "contributor": "Bearbeiten", "viewer": "Betrachter"}[mr]
			if normalizeLanguage(targetLanguage) == "en" {
				roleLabel = map[string]string{"owner": "Owner", "contributor": "Edit", "viewer": "Viewer"}[mr]
			}
			vars := map[string]string{"user_name": targetName, "inviter_name": ss.User.Name, "calendar_name": c.Name, "role": roleLabel}
			if mailErr := h.sendTemplatedMail(r.Context(), r, cfg, targetEmail, targetLanguage, "calendar_shared", vars, "", ""); mailErr != nil {
				httpx.Error(w, 502, "Kalender wurde nicht freigegeben, weil die Benachrichtigungsmail nicht gesendet werden konnte: "+mailErr.Error())
				return
			}
		}
	}
	if err = tx.Commit(r.Context()); err != nil {
		httpx.Error(w, 500, "Mitglied konnte nicht gespeichert werden.")
		return
	}
	details := map[string]any{"user_id": uid, "name": targetName, "email": targetEmail, "old_role": oldRole, "new_role": mr}
	h.Audit.Write(r.Context(), r, ss.User.ID, action, "calendar", calID, details)
	h.Webhooks.Emit(r.Context(), action, ss.User.ID, "calendar", calID, details)
	httpx.JSON(w, 200, map[string]any{"ok": true, "reload": true})
}
func (h *Handler) memberDelete(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.action(w, r, true)
	if !ok {
		return
	}
	calID := r.PathValue("id")
	var c app.Calendar
	var err error
	if auth.IsAdmin(ss.User) && r.URL.Query().Get("admin") == "1" {
		c, err = h.App.GetAdminCalendar(r.Context(), ss.User, calID)
	} else {
		c, err = h.App.GetCalendar(r.Context(), ss.User, calID)
	}
	if err != nil || !c.CanManage {
		httpx.Error(w, 403, "Keine Berechtigung.")
		return
	}
	uid := r.PathValue("uid")
	if c.AdminManaged && uid == c.AdminManagerUserID {
		httpx.Error(w, 400, "Die eigene schreibgeschützte Ansicht wird über „In meinen Kalendern anzeigen“ verwaltet.")
		return
	}
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		httpx.Error(w, 500, "Mitglied konnte nicht entfernt werden.")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtext($1))`, calID); err != nil {
		httpx.Error(w, 500, "Mitglied konnte nicht gesperrt werden.")
		return
	}
	var mr, targetName, targetEmail string
	if err := tx.QueryRow(r.Context(), `SELECT m.role,u.name,u.email FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.calendar_id=$1 AND m.user_id=$2`, calID, uid).Scan(&mr, &targetName, &targetEmail); err != nil {
		httpx.Error(w, 404, "Mitglied wurde nicht gefunden.")
		return
	}
	if mr == "owner" {
		var otherOwners int
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM memberships WHERE calendar_id=$1 AND role='owner' AND user_id<>$2`, calID, uid).Scan(&otherOwners); err != nil {
			httpx.Error(w, 500, "Owner konnten nicht geprüft werden.")
			return
		}
		if otherOwners == 0 && !c.AdminManaged {
			httpx.Error(w, 400, "Ein Kalender muss mindestens einen Eigentümer haben.")
			return
		}
	}
	ct, err := tx.Exec(r.Context(), `DELETE FROM memberships WHERE calendar_id=$1 AND user_id=$2`, calID, uid)
	if err != nil || ct.RowsAffected() == 0 {
		httpx.Error(w, 500, "Mitglied konnte nicht entfernt werden.")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		httpx.Error(w, 500, "Mitglied konnte nicht entfernt werden.")
		return
	}
	details := map[string]any{"user_id": uid, "name": targetName, "email": targetEmail, "old_role": mr}
	h.Audit.Write(r.Context(), r, ss.User.ID, "member.removed", "calendar", calID, details)
	h.Webhooks.Emit(r.Context(), "member.removed", ss.User.ID, "calendar", calID, details)
	httpx.JSON(w, 200, map[string]any{"ok": true, "reload": true})
}
func (h *Handler) users(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminPage(w, r, "users")
	if !ok {
		return
	}
	us, _ := h.allUsers(r.Context())
	oidcCfg, _ := h.OIDC.Load(r.Context())
	_, smtpEnabled, _ := h.loadSMTPConfig(r.Context())
	provisioning := "Nach dem Anlegen wird ein temporäres Passwort einmalig angezeigt."
	if oidcCfg.Enabled {
		provisioning = "Der Benutzer meldet sich über Single Sign-On an."
	} else if smtpEnabled {
		provisioning = "Der Benutzer erhält ein temporäres Passwort per E-Mail."
	}
	provisioning = tr(normalizeLanguage(ss.User.Language), provisioning)
	h.render(w, "users", ss, pageData{Title: "Benutzer", Page: "users", Data: map[string]any{"Users": us, "ProvisioningNote": provisioning, "ResetUserID": strings.TrimSpace(r.URL.Query().Get("reset_user")), "AdminSSO": ss.User.AuthType == "oidc", "OIDCEnabled": oidcCfg.Enabled}})
}
func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	firstName := strings.TrimSpace(r.FormValue("first_name"))
	lastName := strings.TrimSpace(r.FormValue("last_name"))
	name := fullName(firstName, lastName)
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	role := strings.TrimSpace(r.FormValue("role"))
	canCreateCalendars := r.FormValue("can_create_calendars") == "true"
	if firstName == "" || !strings.Contains(email, "@") {
		httpx.Error(w, 400, "Vorname und gültige E-Mail sind erforderlich.")
		return
	}
	if role != "administrator" {
		role = "user"
	}
	var exists int
	_ = h.DB.QueryRow(r.Context(), `SELECT count(*) FROM users WHERE lower(email)=lower($1)`, email).Scan(&exists)
	if exists > 0 {
		httpx.Error(w, 400, "Für diese E-Mail existiert bereits ein Benutzer.")
		return
	}
	oidcCfg, _ := h.OIDC.Load(r.Context())
	authType := "local"
	mustChange := true
	temporary, err := security.RandomToken(12)
	if err != nil {
		httpx.Error(w, 500, "Temporäres Passwort konnte nicht erzeugt werden.")
		return
	}
	if oidcCfg.Enabled {
		authType = "oidc"
		mustChange = false
		temporary, _ = security.RandomToken(48)
	}
	hash, err := security.PasswordHash(temporary)
	if err != nil {
		httpx.Error(w, 500, "Benutzer konnte nicht erstellt werden.")
		return
	}
	id := security.UUID()
	_, err = h.DB.Exec(r.Context(), `INSERT INTO users(id,name,first_name,last_name,email,password_hash,role,status,auth_type,must_change_password,can_create_calendars) VALUES($1,$2,$3,$4,$5,$6,$7,'active',$8,$9,$10)`, id, name, firstName, lastName, email, hash, role, authType, mustChange, canCreateCalendars)
	if err != nil {
		httpx.Error(w, 400, "Benutzer konnte nicht erstellt werden. E-Mail eventuell bereits vorhanden.")
		return
	}
	if _, err = db.EnsurePersonalCalendar(r.Context(), h.DB, id, name); err != nil {
		_, _ = h.DB.Exec(r.Context(), `DELETE FROM calendars WHERE system_owner_user_id=$1 AND system_kind='personal'`, id)
		_, _ = h.DB.Exec(r.Context(), `DELETE FROM users WHERE id=$1`, id)
		httpx.Error(w, 500, "Persönlicher Kalender konnte nicht erstellt werden.")
		return
	}
	mode := "sso"
	response := map[string]any{"ok": true, "reload": true, "message": "Benutzer wurde erstellt."}
	if authType == "local" {
		smtpCfg, enabled, smtpErr := h.loadSMTPConfig(r.Context())
		if smtpErr != nil {
			_, _ = h.DB.Exec(r.Context(), `DELETE FROM calendars WHERE system_owner_user_id=$1 AND system_kind='personal'`, id)
			_, _ = h.DB.Exec(r.Context(), `DELETE FROM users WHERE id=$1`, id)
			httpx.Error(w, 500, "SMTP ist aktiviert, aber die Konfiguration ist ungültig: "+smtpErr.Error())
			return
		}
		if enabled {
			vars := map[string]string{"user_name": name, "email": email, "temporary_password": temporary}
			if err := h.sendTemplatedMail(r.Context(), r, smtpCfg, email, "de", "account_created", vars, "", ""); err != nil {
				_, _ = h.DB.Exec(r.Context(), `DELETE FROM calendars WHERE system_owner_user_id=$1 AND system_kind='personal'`, id)
				_, _ = h.DB.Exec(r.Context(), `DELETE FROM users WHERE id=$1`, id)
				httpx.Error(w, 502, "Benutzer wurde nicht erstellt, weil die Zugangsmail nicht gesendet werden konnte: "+err.Error())
				return
			}
			mode = "smtp"
			response["message"] = "Benutzer wurde erstellt. Das temporäre Passwort wurde per E-Mail gesendet."
		} else {
			mode = "temporary"
			response["secret"] = temporary
			response["message"] = "Temporäres Passwort. Es wird nur einmal angezeigt und muss beim ersten Login geändert werden."
			response["reload_after_secret"] = true
			delete(response, "reload")
		}
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "user.created", "user", id, map[string]any{"email": email, "role": role, "auth_type": authType, "provisioning": mode})
	h.Webhooks.Emit(r.Context(), "user.created", ss.User.ID, "user", id, map[string]any{"email": email, "role": role, "auth_type": authType})
	httpx.JSON(w, 201, response)
}
func (h *Handler) createInvitation(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	_ = parseRequestForm(r)
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	firstName := strings.TrimSpace(r.FormValue("first_name"))
	lastName := strings.TrimSpace(r.FormValue("last_name"))
	name := fullName(firstName, lastName)
	role := r.FormValue("role")
	canCreateCalendars := r.FormValue("can_create_calendars") == "true"
	if !strings.Contains(email, "@") {
		httpx.Error(w, 400, "Gültige E-Mail ist erforderlich.")
		return
	}
	if role != "administrator" {
		role = "user"
	}
	var exists int
	_ = h.DB.QueryRow(r.Context(), `SELECT count(*) FROM users WHERE lower(email)=lower($1)`, email).Scan(&exists)
	if exists > 0 {
		httpx.Error(w, 400, "Für diese E-Mail existiert bereits ein Benutzer.")
		return
	}
	token, _ := security.RandomToken(32)
	id := security.UUID()
	_, err := h.DB.Exec(r.Context(), `INSERT INTO invitations(id,email,name,token_hash,role,invited_by,expires_at,can_create_calendars) VALUES($1,$2,$3,$4,$5,$6,now()+interval '7 days',$7)`, id, email, name, security.TokenHash(token), role, ss.User.ID, canCreateCalendars)
	if err != nil {
		httpx.Error(w, 500, "Einladung konnte nicht erstellt werden.")
		return
	}
	link := h.externalBaseURL() + "/invite/" + token
	h.Audit.Write(r.Context(), r, ss.User.ID, "user.invited", "invitation", id, map[string]any{"email": email, "role": role})
	httpx.JSON(w, 201, map[string]any{"ok": true, "secret": link, "message": "Einladungslink erstellt. Er ist 7 Tage gültig und wird nur einmal angezeigt."})
}

func (h *Handler) updateUser(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	id := r.PathValue("id")
	firstName := strings.TrimSpace(r.FormValue("first_name"))
	lastName := strings.TrimSpace(r.FormValue("last_name"))
	name := fullName(firstName, lastName)
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	role := strings.TrimSpace(r.FormValue("role"))
	status := strings.TrimSpace(r.FormValue("status"))
	canCreateCalendars := r.FormValue("can_create_calendars") == "true"
	if firstName == "" || !strings.Contains(email, "@") {
		httpx.Error(w, 400, "Vorname und gültige E-Mail sind erforderlich.")
		return
	}
	if role != "administrator" && role != "user" && role != "owner" {
		httpx.Error(w, 400, "Ungültige Rolle.")
		return
	}
	if status != "active" && status != "disabled" && status != "locked" {
		httpx.Error(w, 400, "Ungültiger Status.")
		return
	}
	var currentRole, currentEmail string
	if err := h.DB.QueryRow(r.Context(), `SELECT role,email FROM users WHERE id=$1`, id).Scan(&currentRole, &currentEmail); err != nil {
		httpx.Error(w, 404, "Benutzer nicht gefunden.")
		return
	}
	if currentRole == "owner" {
		role = "owner"
		status = "active"
	}
	if id == ss.User.ID && status != "active" {
		httpx.Error(w, 400, "Eigenes Konto kann hier nicht deaktiviert oder gesperrt werden.")
		return
	}
	if currentRole != "owner" && role == "owner" {
		httpx.Error(w, 400, "Die Owner-Rolle kann hier nicht vergeben werden.")
		return
	}
	ct, err := h.DB.Exec(r.Context(), `UPDATE users SET name=$1,first_name=$2,last_name=$3,email=$4,role=$5,status=$6,can_create_calendars=$7,updated_at=now() WHERE id=$8`, name, firstName, lastName, email, role, status, canCreateCalendars, id)
	if err == nil && !strings.EqualFold(currentEmail, email) {
		// HTTP Digest HA1 includes the username. Existing app passwords cannot be
		// re-derived after an email change because their plaintext is never stored.
		// Revoke them rather than leaving confusing credentials that can only partly work.
		_, _ = h.DB.Exec(r.Context(), `UPDATE app_passwords SET revoked_at=coalesce(revoked_at,now()) WHERE user_id=$1`, id)
	}
	if err != nil {
		httpx.Error(w, 400, "Benutzer konnte nicht gespeichert werden. E-Mail eventuell bereits vorhanden.")
		return
	}
	if ct.RowsAffected() == 0 {
		httpx.Error(w, 404, "Benutzer nicht gefunden.")
		return
	}
	if _, err := db.EnsurePersonalCalendar(r.Context(), h.DB, id, name); err != nil {
		httpx.Error(w, 500, "Persönlicher Kalender konnte nicht aktualisiert werden.")
		return
	}
	details := map[string]any{"name": name, "email": email, "role": role, "status": status, "can_create_calendars": canCreateCalendars}
	h.Audit.Write(r.Context(), r, ss.User.ID, "user.updated", "user", id, details)
	if status == "disabled" {
		h.Webhooks.Emit(r.Context(), "user.disabled", ss.User.ID, "user", id, map[string]any{"status": status})
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "reload": true})
}
func (h *Handler) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	targetID := r.PathValue("id")
	var name, email, authType, status string
	if err := h.DB.QueryRow(r.Context(), `SELECT name,email,auth_type,status FROM users WHERE id=$1`, targetID).Scan(&name, &email, &authType, &status); err != nil {
		httpx.Error(w, 404, "Benutzer nicht gefunden.")
		return
	}
	if authType == "oidc" {
		httpx.Error(w, 400, "Für SSO-Benutzer kann kein lokales Passwort zurückgesetzt werden.")
		return
	}
	if status != "active" {
		httpx.Error(w, 400, "Das Passwort kann nur für aktive Benutzer zurückgesetzt werden.")
		return
	}

	if ss.User.AuthType == "oidc" {
		var reauthenticatedAt *time.Time
		var reauthPurpose string
		if err := h.DB.QueryRow(r.Context(), `SELECT reauthenticated_at,coalesce(reauth_purpose,'') FROM sessions WHERE id=$1`, ss.ID).Scan(&reauthenticatedAt, &reauthPurpose); err != nil || reauthenticatedAt == nil || reauthPurpose != "" || time.Since(*reauthenticatedAt) > 5*time.Minute {
			next := "/users?reset_user=" + url.QueryEscape(targetID) + "&reauth_password_reset=1"
			httpx.JSON(w, 200, map[string]any{"ok": true, "message": "Administrator-Anmeldung wird erneut bestätigt.", "redirect": "/auth/oidc/start?next=" + url.QueryEscape(next)})
			return
		}
	} else {
		adminPassword := r.FormValue("admin_password")
		var hash string
		if err := h.DB.QueryRow(r.Context(), `SELECT password_hash FROM users WHERE id=$1`, ss.User.ID).Scan(&hash); err != nil || !security.PasswordCheck(hash, adminPassword) {
			httpx.Error(w, 403, "Administrator-Passwort ist falsch.")
			return
		}
	}
	if r.FormValue("confirm") != "yes" {
		httpx.Error(w, 400, "Bestätigung fehlt.")
		return
	}

	_, smtpEnabled, smtpErr := h.loadSMTPConfig(r.Context())
	if smtpErr != nil {
		httpx.Error(w, 500, "SMTP-Konfiguration ist ungültig: "+smtpErr.Error())
		return
	}
	temporary, err := h.issueTemporaryPassword(r.Context(), r, targetID, name, email, smtpEnabled)
	if err != nil {
		httpx.Error(w, 500, err.Error())
		return
	}
	if ss.User.AuthType == "oidc" {
		_, _ = h.DB.Exec(r.Context(), `UPDATE sessions SET reauthenticated_at=NULL,reauth_purpose='',reauth_target='' WHERE id=$1`, ss.ID)
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "auth.password_reset_admin", "user", targetID, map[string]any{"delivery": map[bool]string{true: "smtp", false: "admin"}[smtpEnabled]})
	if smtpEnabled {
		httpx.JSON(w, 200, map[string]any{"ok": true, "reload": true, "message": "Passwort wurde zurückgesetzt und das temporäre Passwort per E-Mail gesendet."})
		return
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "secret": temporary, "message": "Temporäres Passwort. Es wird nur einmal angezeigt.", "reload_after_secret": true})
}

func (h *Handler) issueTemporaryPassword(ctx context.Context, r *http.Request, userID, name, email string, sendMail bool) (string, error) {
	temporary, err := security.RandomToken(12)
	if err != nil {
		return "", errors.New("Temporäres Passwort konnte nicht erzeugt werden.")
	}
	newHash, err := security.PasswordHash(temporary)
	if err != nil {
		return "", errors.New("Temporäres Passwort konnte nicht gespeichert werden.")
	}
	var oldHash, language string
	var oldMustChange bool
	if err := h.DB.QueryRow(ctx, `SELECT password_hash,must_change_password,language FROM users WHERE id=$1 AND auth_type='local'`, userID).Scan(&oldHash, &oldMustChange, &language); err != nil {
		return "", errors.New("Lokales Benutzerkonto wurde nicht gefunden.")
	}
	if _, err := h.DB.Exec(ctx, `UPDATE users SET password_hash=$1,must_change_password=true,updated_at=now() WHERE id=$2 AND auth_type='local'`, newHash, userID); err != nil {
		return "", errors.New("Passwort konnte nicht zurückgesetzt werden.")
	}
	if sendMail {
		cfg, enabled, cfgErr := h.loadSMTPConfig(ctx)
		if cfgErr != nil || !enabled {
			_, _ = h.DB.Exec(ctx, `UPDATE users SET password_hash=$1,must_change_password=$2,updated_at=now() WHERE id=$3`, oldHash, oldMustChange, userID)
			if cfgErr != nil {
				return "", cfgErr
			}
			return "", errors.New("SMTP ist nicht aktiviert.")
		}
		vars := map[string]string{"user_name": name, "email": email, "temporary_password": temporary}
		if err := h.sendTemplatedMail(ctx, r, cfg, email, language, "password_reset", vars, "", ""); err != nil {
			_, _ = h.DB.Exec(ctx, `UPDATE users SET password_hash=$1,must_change_password=$2,updated_at=now() WHERE id=$3`, oldHash, oldMustChange, userID)
			return "", errors.New("Temporäres Passwort konnte nicht per E-Mail gesendet werden: " + err.Error())
		}
	}
	_, _ = h.DB.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, userID)
	return temporary, nil
}

func (h *Handler) activity(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminPage(w, r, "activity")
	if !ok {
		return
	}
	rows, _ := h.auditRowsBefore(r.Context(), 16, 0)
	hasMore := len(rows) > 15
	if hasMore {
		rows = rows[:15]
	}
	var cursor int64
	if len(rows) > 0 {
		cursor = rows[len(rows)-1].ID
	}
	h.render(w, "activity", ss, pageData{Title: "Aktivität", Page: "activity", Data: map[string]any{"Rows": rows, "HasMore": hasMore, "Cursor": cursor}})
}

func (h *Handler) activityMore(w http.ResponseWriter, r *http.Request) {
	_, ok := h.adminPage(w, r, "activity")
	if !ok {
		return
	}
	cursor, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("before")), 10, 64)
	if err != nil || cursor <= 0 {
		httpx.Error(w, 400, "Ungültiger Cursor.")
		return
	}
	rows, err := h.auditRowsBefore(r.Context(), 21, cursor)
	if err != nil {
		httpx.Error(w, 500, "Aktivität konnte nicht geladen werden.")
		return
	}
	hasMore := len(rows) > 20
	if hasMore {
		rows = rows[:20]
	}
	next := int64(0)
	if len(rows) > 0 {
		next = rows[len(rows)-1].ID
	}
	items := make([]map[string]any, 0, len(rows))
	ss, _ := h.Auth.SessionFromRequest(r)
	tz := "Europe/Berlin"
	if ss != nil && ss.User.Timezone != "" {
		tz = ss.User.Timezone
	}
	loc, _ := time.LoadLocation(tz)
	if loc == nil {
		loc = h.location()
	}
	for _, a := range rows {
		items = append(items, map[string]any{"id": a.ID, "time": a.CreatedAt.In(loc).Format("02.01.2006 15:04"), "actor": a.Actor, "action": a.Action, "resource_type": a.ResourceType, "resource_id": a.ResourceID, "ip": a.IP, "request_id": a.RequestID})
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "data": items, "has_more": hasMore, "next_cursor": next})
}

func (h *Handler) documentationPage(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.page(w, r, "documentation")
	if !ok {
		return
	}
	_, smtpEnabled, _ := h.loadSMTPConfig(r.Context())
	topics := documentationTopics(ss.User.Language, auth.IsAdmin(ss.User), smtpEnabled)
	h.render(w, "documentation", ss, pageData{Title: tr(ss.User.Language, "Dokumentation"), Page: "documentation", Data: map[string]any{"Topics": topics, "Sections": documentationSections(topics)}})
}

func (h *Handler) adminAPIPage(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminPage(w, r, "admin-api")
	if !ok {
		return
	}
	rows, err := h.DB.Query(r.Context(), `SELECT id::text,name,prefix,scopes,created_at,last_used_at,expires_at FROM admin_api_tokens WHERE revoked_at IS NULL ORDER BY created_at DESC`)
	if err != nil {
		http.Error(w, "DB error", 500)
		return
	}
	defer rows.Close()
	var tokens []TokenRow
	for rows.Next() {
		var t TokenRow
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &t.Scopes, &t.CreatedAt, &t.LastUsed, &t.Expires); err != nil {
			http.Error(w, "DB error", 500)
			return
		}
		tokens = append(tokens, t)
	}
	h.render(w, "admin_api", ss, pageData{Title: "Admin API", Page: "admin-api", Data: map[string]any{"Tokens": tokens, "Docs": adminAPIDocs()}})
}

func (h *Handler) createAdminAPIToken(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		httpx.Error(w, 400, "Name ist erforderlich.")
		return
	}
	scopes := []string{"admin:meta:read"}
	allowed := map[string]bool{"admin:users:*": true, "admin:calendars:*": true, "admin:webhooks:*": true, "admin:backups:read": true, "admin:backups:write": true, "admin:backups:restore": true, "admin:mail:read": true}
	seen := map[string]bool{"admin:meta:read": true}
	for _, scope := range r.Form["scopes"] {
		if allowed[scope] && !seen[scope] {
			seen[scope] = true
			scopes = append(scopes, scope)
		}
	}
	if len(scopes) == 1 {
		httpx.Error(w, 400, "Bitte mindestens einen Admin-API-Bereich auswählen.")
		return
	}
	var expires any
	expiresDays := strings.TrimSpace(r.FormValue("expires_days"))
	if expiresDays != "" && expiresDays != "0" {
		days, err := strconv.Atoi(expiresDays)
		if err != nil || days < 1 || days > 3650 {
			httpx.Error(w, 400, "Ablauf muss zwischen 1 und 3650 Tagen liegen.")
			return
		}
		expires = time.Now().Add(time.Duration(days) * 24 * time.Hour)
	}
	tok, err := security.RandomToken(32)
	if err != nil {
		httpx.Error(w, 500, "Token konnte nicht erzeugt werden.")
		return
	}
	full := "zca_admin_" + tok
	prefix := full
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	id := security.UUID()
	_, err = h.DB.Exec(r.Context(), `INSERT INTO admin_api_tokens(id,created_by,name,prefix,token_hash,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, ss.User.ID, name, prefix, security.TokenHash(full), scopes, expires)
	if err != nil {
		httpx.Error(w, 500, "Admin API Token konnte nicht erstellt werden.")
		return
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "admin_api_token.created", "admin_api_token", id, map[string]any{"name": name, "scopes": scopes})
	warning := "Dieser Admin API Token wird nach dem Schließen nicht erneut angezeigt."
	if normalizeLanguage(ss.User.Language) == "en" {
		warning = "This Admin API token will not be shown again after closing."
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, 201, map[string]any{"ok": true, "secret": full, "message": "Admin API Token wurde erstellt.", "secret_warning": warning, "reload_after_secret": true})
}

func (h *Handler) deleteAdminAPIToken(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	ct, err := h.DB.Exec(r.Context(), `UPDATE admin_api_tokens SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, id)
	if err != nil || ct.RowsAffected() == 0 {
		httpx.Error(w, 404, "Admin API Token nicht gefunden.")
		return
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "admin_api_token.revoked", "admin_api_token", id, nil)
	httpx.JSON(w, 200, map[string]any{"ok": true, "reload": true})
}

func (h *Handler) apiPage(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.page(w, r, "api")
	if !ok {
		return
	}
	rows, err := h.DB.Query(r.Context(), `SELECT id::text,name,prefix,scopes,created_at,last_used_at,expires_at FROM api_tokens WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at DESC`, ss.User.ID)
	if err != nil {
		http.Error(w, "DB error", 500)
		return
	}
	defer rows.Close()
	var tokens []TokenRow
	for rows.Next() {
		var t TokenRow
		_ = rows.Scan(&t.ID, &t.Name, &t.Prefix, &t.Scopes, &t.CreatedAt, &t.LastUsed, &t.Expires)
		tokens = append(tokens, t)
	}
	base := h.externalBaseURL()
	serverHost, serverPort, useSSL := r.Host, "", false
	if u, parseErr := url.Parse(base); parseErr == nil {
		serverHost = u.Hostname()
		serverPort = u.Port()
		useSSL = strings.EqualFold(u.Scheme, "https")
		if serverPort == "" {
			if useSSL {
				serverPort = "443"
			} else {
				serverPort = "80"
			}
		}
	}
	h.render(w, "api", ss, pageData{Title: "API & Geräte", Page: "api", Data: map[string]any{"Tokens": tokens, "DAVRoot": base, "DAVHost": serverHost, "DAVPort": serverPort, "DAVSSL": useSSL, "SSO": ss.User.AuthType == "oidc", "Docs": userAPIDocs()}})
}
func (h *Handler) accountPage(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.page(w, r, "account")
	if !ok {
		return
	}
	var apps []AppPasswordRow
	rows, err := h.DB.Query(r.Context(), `SELECT id::text,name,prefix,created_at,last_used_at FROM app_passwords WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at DESC`, ss.User.ID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var a AppPasswordRow
			_ = rows.Scan(&a.ID, &a.Name, &a.Prefix, &a.CreatedAt, &a.LastUsed)
			apps = append(apps, a)
		}
	}
	h.render(w, "account", ss, pageData{Title: "Mein Konto", Page: "account", Data: map[string]any{"AppPasswords": apps, "PasswordChangeRequired": r.URL.Query().Get("password_change") == "required", "SSOLinked": r.URL.Query().Get("sso_linked") == "1", "SSOError": strings.TrimSpace(r.URL.Query().Get("sso_error"))}})
}

func (h *Handler) updateOwnProfile(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.action(w, r, true)
	if !ok {
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	lang := strings.TrimSpace(r.FormValue("language"))
	tz := strings.TrimSpace(r.FormValue("timezone"))
	if lang != "de" && lang != "en" {
		httpx.Error(w, 400, "Ungültige Sprache.")
		return
	}
	if _, err := time.LoadLocation(tz); err != nil {
		httpx.Error(w, 400, "Ungültige Zeitzone.")
		return
	}
	_, err := h.DB.Exec(r.Context(), `UPDATE users SET language=$1,timezone=$2,updated_at=now() WHERE id=$3`, lang, tz, ss.User.ID)
	if err != nil {
		httpx.Error(w, 500, "Profil konnte nicht gespeichert werden.")
		return
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "user.profile_updated", "user", ss.User.ID, map[string]any{"language": lang, "timezone": tz})
	httpx.JSON(w, 200, map[string]any{"ok": true, "message": tr(lang, "Profil gespeichert."), "reload": true})
}

func (h *Handler) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.action(w, r, true)
	if !ok {
		return
	}
	if ss.User.AuthType == "oidc" {
		httpx.Error(w, 403, "Das Passwort wird über Single Sign-On verwaltet.")
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	current, newPass, confirm := r.FormValue("current_password"), r.FormValue("new_password"), r.FormValue("confirm_password")
	if newPass != confirm {
		httpx.Error(w, 400, "Die neuen Passwörter stimmen nicht überein.")
		return
	}
	if len(newPass) < 10 {
		httpx.Error(w, 400, "Das neue Passwort muss mindestens 10 Zeichen lang sein.")
		return
	}
	var hash string
	if err := h.DB.QueryRow(r.Context(), `SELECT password_hash FROM users WHERE id=$1`, ss.User.ID).Scan(&hash); err != nil || !security.PasswordCheck(hash, current) {
		httpx.Error(w, 400, "Aktuelles Passwort ist falsch.")
		return
	}
	newHash, err := security.PasswordHash(newPass)
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		httpx.Error(w, 500, "Passwort konnte nicht geändert werden.")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), `UPDATE users SET password_hash=$1,must_change_password=false,updated_at=now() WHERE id=$2`, newHash, ss.User.ID); err != nil {
		httpx.Error(w, 500, "Passwort konnte nicht geändert werden.")
		return
	}
	_, _ = tx.Exec(r.Context(), `DELETE FROM sessions WHERE user_id=$1 AND id<>$2`, ss.User.ID, ss.ID)
	if err = tx.Commit(r.Context()); err != nil {
		httpx.Error(w, 500, "Passwort konnte nicht geändert werden.")
		return
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "auth.password_changed", "user", ss.User.ID, nil)
	httpx.JSON(w, 200, map[string]any{"ok": true, "message": "Passwort geändert.", "reload": true})
}

func (h *Handler) createToken(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.action(w, r, true)
	if !ok {
		return
	}
	_ = parseRequestForm(r)
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		httpx.Error(w, 400, "Name ist erforderlich.")
		return
	}
	tok, _ := security.RandomToken(32)
	full := "zc_" + tok
	prefix := full[:10]
	scopes := []string{"calendar:read", "calendar:write", "event:read", "event:write"}
	id := security.UUID()
	_, err := h.DB.Exec(r.Context(), `INSERT INTO api_tokens(id,user_id,name,prefix,token_hash,scopes) VALUES($1,$2,$3,$4,$5,$6)`, id, ss.User.ID, name, prefix, security.TokenHash(full), scopes)
	if err != nil {
		httpx.Error(w, 500, "Token konnte nicht erstellt werden.")
		return
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "api_token.created", "api_token", id, map[string]any{"name": name})
	warning := "Dieser API Token wird nach dem Schließen nicht erneut angezeigt."
	if normalizeLanguage(ss.User.Language) == "en" {
		warning = "This API token will not be shown again after closing."
	}
	httpx.JSON(w, 201, map[string]any{"ok": true, "secret": full, "message": "API-Token wurde erstellt. Er wird nur einmal angezeigt.", "secret_warning": warning, "reload_after_secret": true})
}
func (h *Handler) deleteToken(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.action(w, r, true)
	if !ok {
		return
	}
	id := r.PathValue("id")
	_, _ = h.DB.Exec(r.Context(), `UPDATE api_tokens SET revoked_at=now() WHERE id=$1 AND user_id=$2`, id, ss.User.ID)
	h.Audit.Write(r.Context(), r, ss.User.ID, "api_token.revoked", "api_token", id, nil)
	httpx.JSON(w, 200, map[string]any{"ok": true, "reload": true})
}
func (h *Handler) createAppPassword(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.action(w, r, true)
	if !ok {
		return
	}
	_ = parseRequestForm(r)
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		httpx.Error(w, 400, "Name ist erforderlich.")
		return
	}
	tok, _ := security.RandomToken(24)
	full := "zca_" + tok
	id := security.UUID()
	_, err := h.DB.Exec(r.Context(), `INSERT INTO app_passwords(id,user_id,name,prefix,token_hash,dav_digest_ha1) VALUES($1,$2,$3,$4,$5,$6)`, id, ss.User.ID, name, full[:10], security.TokenHash(full), security.DigestHA1(ss.User.Email, auth.DAVRealm, full))
	if err != nil {
		httpx.Error(w, 500, "App-Passwort konnte nicht erstellt werden.")
		return
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "app_password.created", "app_password", id, map[string]any{"name": name})
	httpx.JSON(w, 201, map[string]any{"ok": true, "secret": full, "message": "App-Passwort wurde erstellt. Es wird nur einmal angezeigt.", "reload_after_secret": true})
}

func (h *Handler) deleteAppPassword(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.action(w, r, true)
	if !ok {
		return
	}
	id := r.PathValue("id")
	_, _ = h.DB.Exec(r.Context(), `UPDATE app_passwords SET revoked_at=now() WHERE id=$1 AND user_id=$2`, id, ss.User.ID)
	h.Audit.Write(r.Context(), r, ss.User.ID, "app_password.revoked", "app_password", id, nil)
	httpx.JSON(w, 200, map[string]any{"ok": true, "reload": true})
}

func (h *Handler) eventHistory(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.action(w, r, false)
	if !ok {
		return
	}
	eventID := r.PathValue("id")
	var calID string
	if err := h.DB.QueryRow(r.Context(), `SELECT calendar_id::text FROM events WHERE id=$1`, eventID).Scan(&calID); err != nil {
		httpx.Error(w, 404, "Termin nicht gefunden.")
		return
	}
	role, err := h.Auth.CalendarRole(r.Context(), ss.User.ID, calID)
	if err != nil || !auth.CanRead(role) {
		httpx.Error(w, 403, "Keine Berechtigung.")
		return
	}
	rows, err := h.DB.Query(r.Context(), `SELECT v.version,v.action,v.ics,v.created_at,coalesce(u.name,'System') FROM event_versions v LEFT JOIN users u ON u.id=v.actor_user_id WHERE v.event_id=$1 ORDER BY v.version`, eventID)
	if err != nil {
		httpx.Error(w, 500, "Historie konnte nicht geladen werden.")
		return
	}
	defer rows.Close()
	type item struct {
		Version   int       `json:"version"`
		Action    string    `json:"action"`
		Actor     string    `json:"actor"`
		CreatedAt time.Time `json:"created_at"`
		Changes   []string  `json:"changes"`
	}
	var out []item
	var prev ical.Meta
	havePrev := false
	for rows.Next() {
		var ver int
		var action, raw, actor string
		var at time.Time
		_ = rows.Scan(&ver, &action, &raw, &at, &actor)
		m, _ := ical.Parse(raw)
		changes := []string{}
		if !havePrev {
			if m.Summary != "" {
				changes = append(changes, "Titel: "+m.Summary)
			}
			for _, attendee := range m.Attendees {
				changes = append(changes, "Teilnehmer: "+attendee)
			}
		} else {
			if m.Summary != prev.Summary {
				changes = append(changes, "Titel geändert")
			}
			if m.Description != prev.Description {
				changes = append(changes, "Beschreibung geändert")
			}
			if m.Location != prev.Location {
				changes = append(changes, "Ort geändert")
			}
			if !sameTime(m.Start, prev.Start) {
				changes = append(changes, "Beginn geändert")
			}
			if !sameTime(m.End, prev.End) {
				changes = append(changes, "Ende geändert")
			}
			added, removed := attendeeDiff(prev.Attendees, m.Attendees)
			for _, attendee := range added {
				changes = append(changes, "Teilnehmer hinzugefügt: "+attendee)
			}
			for _, attendee := range removed {
				changes = append(changes, "Teilnehmer entfernt: "+attendee)
			}
			beforeStatus := map[string]string{}
			for _, a := range prev.AttendeeDetails {
				beforeStatus[strings.ToLower(a.Email)] = a.PartStat
			}
			for _, a := range m.AttendeeDetails {
				if old, ok := beforeStatus[strings.ToLower(a.Email)]; ok && old != a.PartStat {
					label := a.Email + ": " + a.PartStat
					switch a.PartStat {
					case "ACCEPTED":
						label = a.Email + ": angenommen"
					case "DECLINED":
						label = a.Email + ": abgelehnt"
					case "TENTATIVE":
						label = a.Email + ": vielleicht"
					}
					changes = append(changes, "Teilnehmerstatus geändert: "+label)
				}
			}
		}
		out = append(out, item{Version: ver, Action: action, Actor: actor, CreatedAt: at, Changes: changes})
		prev = m
		havePrev = true
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "data": out})
}
func attendeeDiff(before, after []string) (added, removed []string) {
	b := make(map[string]string, len(before))
	a := make(map[string]string, len(after))
	for _, v := range before {
		b[strings.ToLower(strings.TrimSpace(v))] = v
	}
	for _, v := range after {
		a[strings.ToLower(strings.TrimSpace(v))] = v
	}
	for key, v := range a {
		if _, ok := b[key]; !ok {
			added = append(added, v)
		}
	}
	for key, v := range b {
		if _, ok := a[key]; !ok {
			removed = append(removed, v)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func (h *Handler) settings(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminPage(w, r, "settings")
	if !ok {
		return
	}
	vals := map[string]string{
		"timezone":               "Europe/Berlin",
		"session_lifetime_hours": "720",
		"login_max_failures":     "5",
		"lockout_minutes":        "5",
		"smtp_enabled":           "false",
		"smtp_port":              "587",
		"smtp_security":          "starttls",
		"oidc_enabled":           "false",
		"oidc_scopes":            "openid profile email",
		"oidc_groups_claim":      "groups",
		"oidc_auth_method":       "client_secret_post",
		"oidc_auto_provision":    "true",
		"oidc_sync_name":         "true",
		"oidc_sync_email":        "true",
		"oidc_sync_groups":       "false",
		"oidc_local_login":       "true",
	}
	for k, v := range mailTemplateDefaultsForSettings() {
		vals[k] = v
	}
	rows, _ := h.DB.Query(r.Context(), `SELECT key,value FROM settings WHERE NOT secret`)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var k, v string
			_ = rows.Scan(&k, &v)
			vals[k] = v
		}
	}
	var hasSMTPPassword bool
	_ = h.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM settings WHERE key='smtp_password' AND secret AND value<>'')`).Scan(&hasSMTPPassword)
	if hasSMTPPassword {
		vals["smtp_password_set"] = "true"
	}
	var hasOIDCSecret bool
	_ = h.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM settings WHERE key='oidc_client_secret' AND secret AND value<>'')`).Scan(&hasOIDCSecret)
	if hasOIDCSecret {
		vals["oidc_client_secret_set"] = "true"
	}
	vals["oidc_redirect_uri"] = h.externalBaseURL() + "/auth/oidc/callback"
	if vals["oidc_enabled"] == "true" && strings.TrimSpace(vals["oidc_issuer"]) != "" && strings.TrimSpace(vals["oidc_client_id"]) != "" && hasOIDCSecret {
		vals["oidc_login_url"] = h.externalBaseURL() + "/auth/oidc/start"
	}
	h.render(w, "settings", ss, pageData{Title: "Einstellungen", Page: "settings", Data: vals})
}

func (h *Handler) saveSettings(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	section := strings.TrimSpace(r.FormValue("section"))
	switch section {
	case "general":
		if err := h.saveGeneralSettings(r.Context(), r); err != nil {
			httpx.Error(w, 400, err.Error())
			return
		}
	case "security":
		if err := h.saveSecuritySettings(r.Context(), r); err != nil {
			httpx.Error(w, 400, err.Error())
			return
		}
	case "smtp":
		if err := h.saveSMTPSettings(r.Context(), r); err != nil {
			httpx.Error(w, 400, err.Error())
			return
		}
	case "mail_templates":
		if err := h.saveMailTemplateSettings(r.Context(), r); err != nil {
			httpx.Error(w, 400, err.Error())
			return
		}
	case "oidc":
		if err := h.saveOIDCSettings(r.Context(), r); err != nil {
			httpx.Error(w, 400, err.Error())
			return
		}
	default:
		httpx.Error(w, 400, "Unbekannter Einstellungsbereich.")
		return
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "settings.updated", "settings", section, map[string]any{"section": section})
	h.Webhooks.Emit(r.Context(), "settings.updated", ss.User.ID, "settings", section, map[string]any{"section": section})
	httpx.JSON(w, 200, map[string]any{"ok": true, "message": "Einstellungen gespeichert.", "reload": true})
}

func (h *Handler) saveGeneralSettings(ctx context.Context, r *http.Request) error {
	tz := strings.TrimSpace(r.FormValue("timezone"))
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return errors.New("Ungültige Zeitzone.")
	}
	values := map[string]string{
		"timezone": tz,
	}
	if err := h.storeSettings(ctx, values, false); err != nil {
		return err
	}
	h.Location.Store(loc)
	return nil
}

func (h *Handler) saveSecuritySettings(ctx context.Context, r *http.Request) error {
	lifetime, err := parseIntRange(r.FormValue("session_lifetime_hours"), 1, 8760)
	if err != nil {
		return errors.New("Session-Laufzeit muss zwischen 1 und 8760 Stunden liegen.")
	}
	maxFailures, err := parseIntRange(r.FormValue("login_max_failures"), 3, 20)
	if err != nil {
		return errors.New("Fehlversuche müssen zwischen 3 und 20 liegen.")
	}
	lockout, err := parseIntRange(r.FormValue("lockout_minutes"), 1, 1440)
	if err != nil {
		return errors.New("Sperrdauer muss zwischen 1 und 1440 Minuten liegen.")
	}
	return h.storeSettings(ctx, map[string]string{
		"session_lifetime_hours": strconv.Itoa(lifetime),
		"login_max_failures":     strconv.Itoa(maxFailures),
		"lockout_minutes":        strconv.Itoa(lockout),
	}, false)
}

func (h *Handler) saveMailTemplateSettings(ctx context.Context, r *http.Request) error {
	values := map[string]string{}
	for kind := range defaultMailTemplates {
		for _, lang := range []string{"de", "en"} {
			subjectKey, bodyKey := mailTemplateSettingKeys(kind, lang)
			subject := trimMailTemplateValue(r.FormValue(subjectKey), 240)
			body := trimMailTemplateValue(r.FormValue(bodyKey), 8000)
			if subject == "" || body == "" {
				return errors.New("Betreff und Inhalt dürfen bei E-Mail-Vorlagen nicht leer sein.")
			}
			values[subjectKey] = subject
			values[bodyKey] = body
		}
	}
	htmlEnabled := r.FormValue("mail_html_enabled") == "true"
	htmlTemplate := trimMailTemplateValue(r.FormValue("mail_html_template"), 50000)
	if htmlTemplate == "" {
		htmlTemplate = mailpkg.DefaultHTMLLayout
	}
	if htmlEnabled && !strings.Contains(htmlTemplate, "{{email_template}}") {
		return errors.New("Das HTML-Layout muss den Platzhalter {{email_template}} enthalten.")
	}
	values["mail_html_enabled"] = strconv.FormatBool(htmlEnabled)
	values["mail_html_template"] = htmlTemplate
	return h.storeSettings(ctx, values, false)
}

func (h *Handler) saveSMTPSettings(ctx context.Context, r *http.Request) error {
	cfg, err := h.smtpConfigFromRequest(ctx, r)
	if err != nil {
		return err
	}
	enabled := r.FormValue("smtp_enabled") == "true"
	if enabled {
		if err := cfg.Validate(); err != nil {
			return err
		}
	}
	values := map[string]string{
		"smtp_enabled":    strconv.FormatBool(enabled),
		"smtp_host":       strings.TrimSpace(r.FormValue("smtp_host")),
		"smtp_port":       strconv.Itoa(cfg.Port),
		"smtp_security":   cfg.Security,
		"smtp_username":   strings.TrimSpace(r.FormValue("smtp_username")),
		"smtp_from_name":  strings.TrimSpace(r.FormValue("smtp_from_name")),
		"smtp_from_email": strings.TrimSpace(r.FormValue("smtp_from_email")),
	}
	if err := h.storeSettings(ctx, values, false); err != nil {
		return err
	}
	if r.FormValue("smtp_password_clear") == "true" {
		_, err = h.DB.Exec(ctx, `DELETE FROM settings WHERE key='smtp_password'`)
		return err
	}
	password := r.FormValue("smtp_password")
	if password != "" {
		enc, err := h.Secrets.Encrypt(password)
		if err != nil {
			return fmt.Errorf("SMTP-Passwort konnte nicht sicher gespeichert werden: %w", err)
		}
		return h.storeSettings(ctx, map[string]string{"smtp_password": enc}, true)
	}
	return nil
}

func (h *Handler) testSMTP(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	cfg, err := h.smtpConfigFromRequest(r.Context(), r)
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	recipient := strings.TrimSpace(r.FormValue("smtp_test_recipient"))
	if recipient == "" {
		recipient = ss.User.Email
	}
	instanceName := "ZentCal"
	htmlEnabled := h.setting(r.Context(), "mail_html_enabled", "false") == "true"
	htmlTemplate := h.setting(r.Context(), "mail_html_template", mailpkg.DefaultHTMLLayout)
	subject, textBody, htmlBody := mailpkg.RenderTemplate(mailpkg.TemplateData{InstanceName: instanceName, BaseURL: h.externalBaseURL(), Language: normalizeLanguage(ss.User.Language), Subject: "{{instance_name}} SMTP-Test", Body: "Diese Testmail wurde von {{instance_name}} gesendet. Die SMTP-Konfiguration funktioniert.", HTMLEnabled: htmlEnabled, HTMLTemplate: htmlTemplate})
	send := mailpkg.SendMessage
	if h.MailDelivery != nil {
		send = func(c mailpkg.SMTPConfig, rcp, sub, txt, html string) error {
			return h.MailDelivery.SendMessage(r.Context(), "smtp_test", c, rcp, sub, txt, html)
		}
	}
	if err := send(cfg, recipient, subject, textBody, htmlBody); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "smtp.test_sent", "settings", "smtp", map[string]any{"recipient": recipient})
	httpx.JSON(w, 200, map[string]any{"ok": true, "message": "Testmail wurde gesendet."})
}

func (h *Handler) loadSMTPConfig(ctx context.Context) (mailpkg.SMTPConfig, bool, error) {
	vals := map[string]string{}
	rows, err := h.DB.Query(ctx, `SELECT key,value,secret FROM settings WHERE key LIKE 'smtp_%'`)
	if err != nil {
		return mailpkg.SMTPConfig{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		var sec bool
		if err := rows.Scan(&k, &v, &sec); err != nil {
			return mailpkg.SMTPConfig{}, false, err
		}
		if sec && v != "" {
			v, err = h.Secrets.Decrypt(v)
			if err != nil {
				return mailpkg.SMTPConfig{}, false, err
			}
		}
		vals[k] = v
	}
	if vals["smtp_enabled"] != "true" {
		return mailpkg.SMTPConfig{}, false, nil
	}
	port, err := strconv.Atoi(vals["smtp_port"])
	if err != nil {
		return mailpkg.SMTPConfig{}, true, err
	}
	cfg := mailpkg.SMTPConfig{Host: vals["smtp_host"], Port: port, Security: vals["smtp_security"], Username: vals["smtp_username"], Password: vals["smtp_password"], FromName: vals["smtp_from_name"], FromEmail: vals["smtp_from_email"]}
	if err := cfg.Validate(); err != nil {
		return mailpkg.SMTPConfig{}, true, err
	}
	return cfg, true, nil
}

func (h *Handler) smtpConfigFromRequest(ctx context.Context, r *http.Request) (mailpkg.SMTPConfig, error) {
	port, err := parseIntRange(r.FormValue("smtp_port"), 1, 65535)
	if err != nil {
		return mailpkg.SMTPConfig{}, errors.New("Ungültiger SMTP-Port.")
	}
	password := r.FormValue("smtp_password")
	if password == "" && r.FormValue("smtp_password_clear") != "true" {
		var encrypted string
		err := h.DB.QueryRow(ctx, `SELECT value FROM settings WHERE key='smtp_password' AND secret`).Scan(&encrypted)
		if err == nil && encrypted != "" {
			password, err = h.Secrets.Decrypt(encrypted)
			if err != nil {
				return mailpkg.SMTPConfig{}, errors.New("Gespeichertes SMTP-Passwort konnte nicht entschlüsselt werden.")
			}
		} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return mailpkg.SMTPConfig{}, err
		}
	}
	return mailpkg.SMTPConfig{
		Host:      strings.TrimSpace(r.FormValue("smtp_host")),
		Port:      port,
		Security:  strings.TrimSpace(r.FormValue("smtp_security")),
		Username:  strings.TrimSpace(r.FormValue("smtp_username")),
		Password:  password,
		FromName:  strings.TrimSpace(r.FormValue("smtp_from_name")),
		FromEmail: strings.TrimSpace(r.FormValue("smtp_from_email")),
	}, nil
}

func (h *Handler) storeSettings(ctx context.Context, values map[string]string, secret bool) error {
	tx, err := h.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for k, v := range values {
		if _, err := tx.Exec(ctx, `INSERT INTO settings(key,value,secret) VALUES($1,$2,$3) ON CONFLICT(key) DO UPDATE SET value=excluded.value,secret=excluded.secret,updated_at=now()`, k, v, secret); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func parseIntRange(raw string, min, max int) (int, error) {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v < min || v > max {
		return 0, errors.New("out of range")
	}
	return v, nil
}

func (h *Handler) system(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminPage(w, r, "system")
	if !ok {
		return
	}
	var dbsize int64
	_ = h.DB.QueryRow(r.Context(), `SELECT pg_database_size(current_database())`).Scan(&dbsize)
	var users, calendars, events, sessions int
	_ = h.DB.QueryRow(r.Context(), `SELECT count(*) FROM users WHERE status='active'`).Scan(&users)
	_ = h.DB.QueryRow(r.Context(), `SELECT count(*) FROM calendars WHERE deleted_at IS NULL`).Scan(&calendars)
	_ = h.DB.QueryRow(r.Context(), `SELECT count(*) FROM events`).Scan(&events)
	_ = h.DB.QueryRow(r.Context(), `SELECT count(*) FROM sessions WHERE expires_at>now()`).Scan(&sessions)
	loc := h.location()
	h.render(w, "system", ss, pageData{Title: "System", Page: "system", Data: map[string]any{
		"DBSize": formatBytes(dbsize), "Version": h.Version,
		"Uptime": formatDuration(time.Since(h.StartedAt)),
		"Users":  users, "Calendars": calendars, "Events": events, "Sessions": sessions,
		"Timezone": loc.String(), "ServerTime": time.Now().In(loc).Format("02.01.2006 15:04:05 MST"),
	}})
}

func formatBytes(v int64) string {
	const unit = 1024
	if v < unit {
		return fmt.Sprintf("%d B", v)
	}
	div, exp := int64(unit), 0
	for n := v / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(v)/float64(div), "KMGTPE"[exp])
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return "< 1 Minute"
	}
	days := int(d / (24 * time.Hour))
	hours := int((d % (24 * time.Hour)) / time.Hour)
	minutes := int((d % time.Hour) / time.Minute)
	if days > 0 {
		return fmt.Sprintf("%d T %d Std", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%d Std %d Min", hours, minutes)
	}
	return fmt.Sprintf("%d Min", minutes)
}

func (h *Handler) invite(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	var id, email, name, role, invitedBy string
	var canCreateCalendars bool
	var expires time.Time
	err := h.DB.QueryRow(r.Context(), `SELECT id::text,email,name,role,expires_at,coalesce(invited_by::text,''),can_create_calendars FROM invitations WHERE token_hash=$1 AND accepted_at IS NULL AND revoked_at IS NULL`, security.TokenHash(token)).Scan(&id, &email, &name, &role, &expires, &invitedBy, &canCreateCalendars)
	if err != nil || time.Now().After(expires) {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		firstName, lastName := splitDisplayName(name)
		h.renderPublic(w, r, "invite", pageData{Title: "Einladung", Data: map[string]any{"Email": email, "Name": name, "FirstName": firstName, "LastName": lastName, "Token": token}, Version: h.Version})
		return
	}
	_ = parseRequestForm(r)
	firstName := strings.TrimSpace(r.FormValue("first_name"))
	lastName := strings.TrimSpace(r.FormValue("last_name"))
	if firstName == "" {
		firstName, lastName = splitDisplayName(name)
	}
	acceptedName := fullName(firstName, lastName)
	hash, err := security.PasswordHash(r.FormValue("password"))
	if err != nil {
		h.renderPublic(w, r, "invite", pageData{Title: "Einladung", Error: err.Error(), Data: map[string]any{"Email": email, "Name": name, "Token": token}, Version: h.Version})
		return
	}
	uid := security.UUID()
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		http.Error(w, "DB error", 500)
		return
	}
	defer tx.Rollback(r.Context())
	_, err = tx.Exec(r.Context(), `INSERT INTO users(id,name,first_name,last_name,email,password_hash,role,status,can_create_calendars) VALUES($1,$2,$3,$4,$5,$6,$7,'active',$8)`, uid, acceptedName, firstName, lastName, email, hash, role, canCreateCalendars)
	if err == nil {
		_, err = db.EnsurePersonalCalendar(r.Context(), tx, uid, acceptedName)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE invitations SET accepted_at=now() WHERE id=$1`, id)
	}
	if err != nil {
		http.Error(w, "Einladung konnte nicht angenommen werden.", 400)
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		http.Error(w, "Einladung konnte nicht angenommen werden.", 500)
		return
	}
	h.Audit.Write(r.Context(), r, invitedBy, "user.created", "user", uid, map[string]any{"email": email, "role": role, "invitation_id": id})
	h.Webhooks.Emit(r.Context(), "user.created", invitedBy, "user", uid, map[string]any{"email": email, "role": role})
	http.Redirect(w, r, "/login", 303)
}

func fullName(firstName, lastName string) string {
	return strings.TrimSpace(strings.TrimSpace(firstName) + " " + strings.TrimSpace(lastName))
}
func splitDisplayName(name string) (string, string) {
	parts := strings.Fields(strings.TrimSpace(name))
	if len(parts) == 0 {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], strings.Join(parts[1:], " ")
}

func parseRequestForm(r *http.Request) error {
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data") {
		return r.ParseMultipartForm(10 << 20)
	}
	return r.ParseForm()
}

func (h *Handler) page(w http.ResponseWriter, r *http.Request, page string) (*auth.Session, bool) {
	done, _ := h.Auth.SetupComplete(r.Context())
	if !done {
		http.Redirect(w, r, "/setup", 303)
		return nil, false
	}
	ss, err := h.Auth.SessionFromRequest(r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return nil, false
	}
	if ss.User.MustChangePassword && r.URL.Path != "/account" {
		http.Redirect(w, r, "/account?password_change=required", http.StatusSeeOther)
		return nil, false
	}
	return ss, true
}
func (h *Handler) adminPage(w http.ResponseWriter, r *http.Request, page string) (*auth.Session, bool) {
	ss, ok := h.page(w, r, page)
	if !ok {
		return nil, false
	}
	if !auth.IsAdmin(ss.User) {
		http.Error(w, "Forbidden", 403)
		return nil, false
	}
	return ss, true
}
func (h *Handler) action(w http.ResponseWriter, r *http.Request, csrf bool) (*auth.Session, bool) {
	ss, err := h.Auth.SessionFromRequest(r)
	if err != nil {
		httpx.Error(w, 401, "Anmeldung erforderlich.")
		return nil, false
	}
	if csrf && !h.csrfOK(r, ss) {
		httpx.Error(w, 403, "Ungültiges CSRF-Token.")
		return nil, false
	}
	if ss.User.MustChangePassword && r.URL.Path != "/ui/account/password" && r.URL.Path != "/ui/account/profile" {
		httpx.Error(w, 428, "Bitte zuerst das temporäre Passwort ändern.")
		return nil, false
	}
	return ss, true
}
func (h *Handler) adminAction(w http.ResponseWriter, r *http.Request) (*auth.Session, bool) {
	ss, ok := h.action(w, r, true)
	if !ok {
		return nil, false
	}
	if !auth.IsAdmin(ss.User) {
		httpx.Error(w, 403, "Keine Berechtigung.")
		return nil, false
	}
	return ss, true
}
func (h *Handler) csrfOK(r *http.Request, ss *auth.Session) bool {
	v := r.Header.Get("X-CSRF-Token")
	if v == "" {
		_ = parseRequestForm(r)
		v = r.FormValue("csrf")
	}
	return v != "" && v == ss.CSRFToken
}
func (h *Handler) render(w http.ResponseWriter, name string, ss *auth.Session, d pageData) {
	d.User = &ss.User
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rows, err := h.DB.Query(ctx, `SELECT id::text,name,prefix,created_at,last_used_at FROM app_passwords WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at DESC`, ss.User.ID)
	if err == nil {
		for rows.Next() {
			var a AppPasswordRow
			if rows.Scan(&a.ID, &a.Name, &a.Prefix, &a.CreatedAt, &a.LastUsed) == nil {
				d.AccountAppPasswords = append(d.AccountAppPasswords, a)
			}
		}
		rows.Close()
	}
	flags := map[string]string{"oidc_enabled": "false", "oidc_local_login": "true", "smtp_enabled": "false"}
	settingRows, err := h.DB.Query(ctx, `SELECT key,value FROM settings WHERE key = ANY($1) AND NOT secret`, []string{"oidc_enabled", "oidc_local_login", "smtp_enabled"})
	if err == nil {
		for settingRows.Next() {
			var key, value string
			if settingRows.Scan(&key, &value) == nil {
				flags[key] = value
			}
		}
		settingRows.Close()
	}
	d.Lang = normalizeLanguage(ss.User.Language)
	d.Title = tr(d.Lang, d.Title)
	d.CSRF = ss.CSRFToken
	d.Version = h.Version
	d.InstanceName = "ZentCal"
	d.OIDCEnabled = flags["oidc_enabled"] == "true"
	d.OIDCLocalLogin = flags["oidc_local_login"] == "true"
	d.SMTPEnabled = flags["smtp_enabled"] == "true"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templateKey := name
	if d.Lang == "en" {
		templateKey += "|en"
	}
	if err := h.templates[templateKey].ExecuteTemplate(w, "base", d); err != nil {
		http.Error(w, "Template error", 500)
	}
}

func httpsOrigin(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.User != nil {
		return ""
	}
	return "https://" + u.Host
}

func (h *Handler) loginContentSecurityPolicy(ctx context.Context) string {
	if h == nil || h.DB == nil {
		return httpx.ContentSecurityPolicy()
	}
	vals := map[string]string{}
	rows, err := h.DB.Query(ctx, `SELECT key,value FROM settings WHERE key = ANY($1) AND NOT secret`, []string{"oidc_enabled", "oidc_authorization_origin", "oidc_issuer"})
	if err != nil {
		return httpx.ContentSecurityPolicy()
	}
	defer rows.Close()
	for rows.Next() {
		var key, value string
		if rows.Scan(&key, &value) == nil {
			vals[key] = value
		}
	}
	if vals["oidc_enabled"] != "true" {
		return httpx.ContentSecurityPolicy()
	}
	origin := httpsOrigin(vals["oidc_authorization_origin"])
	if origin == "" {
		// Pre-0.1.34 installations do not yet have the discovered authorization
		// origin persisted. The validated HTTPS issuer origin is a safe fallback
		// until the OIDC settings are saved again.
		origin = httpsOrigin(vals["oidc_issuer"])
	}
	return httpx.ContentSecurityPolicy(origin)
}

func (h *Handler) renderPublic(w http.ResponseWriter, r *http.Request, name string, d pageData) {
	d.Lang = browserLanguage(r)
	d.Title = tr(d.Lang, d.Title)
	if name == "login" {
		w.Header().Set("Content-Security-Policy", h.loginContentSecurityPolicy(r.Context()))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templateKey := name
	if d.Lang == "en" {
		templateKey += "|en"
	}
	_ = h.templates[templateKey].ExecuteTemplate(w, name+".html", d)
}
func (h *Handler) session(w http.ResponseWriter, r *http.Request) (*auth.Session, bool) {
	ss, err := h.Auth.SessionFromRequest(r)
	if err != nil {
		http.Redirect(w, r, "/login", 303)
		return nil, false
	}
	return ss, true
}
func (h *Handler) setting(ctx context.Context, key, def string) string {
	var v string
	if err := h.DB.QueryRow(ctx, `SELECT value FROM settings WHERE key=$1`, key).Scan(&v); err != nil || v == "" {
		return def
	}
	return v
}
func (h *Handler) members(ctx context.Context, calID string) ([]Member, error) {
	rows, err := h.DB.Query(ctx, `SELECT u.id::text,u.name,u.email,m.role FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.calendar_id=$1 ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'editor' THEN 1 WHEN 'contributor' THEN 2 ELSE 3 END,lower(u.name)`, calID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		_ = rows.Scan(&m.ID, &m.Name, &m.Email, &m.Role)
		out = append(out, m)
	}
	return out, rows.Err()
}

func (h *Handler) availableCalendarUsers(ctx context.Context, calID string) ([]UserRow, error) {
	rows, err := h.DB.Query(ctx, `
		SELECT u.id::text,u.name,u.first_name,u.last_name,u.email,u.role,u.status,u.auth_type,u.can_create_calendars,u.created_at,u.last_login,u.last_sync
		FROM users u
		WHERE u.status <> 'disabled'
		  AND NOT EXISTS (
			SELECT 1 FROM memberships m WHERE m.calendar_id=$1 AND m.user_id=u.id
		  )
		  AND NOT EXISTS (
			SELECT 1 FROM calendars c WHERE c.id=$1 AND c.admin_managed AND c.admin_manager_user_id=u.id
		  )
		ORDER BY lower(u.name), lower(u.email)
	`, calID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserRow
	for rows.Next() {
		var u UserRow
		if err := rows.Scan(&u.ID, &u.Name, &u.FirstName, &u.LastName, &u.Email, &u.Role, &u.Status, &u.AuthType, &u.CanCreateCalendars, &u.CreatedAt, &u.LastLogin, &u.LastSync); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (h *Handler) allUsers(ctx context.Context) ([]UserRow, error) {
	rows, err := h.DB.Query(ctx, `SELECT u.id::text,u.name,u.first_name,u.last_name,u.email,u.role,u.status,u.auth_type,u.can_create_calendars,coalesce(ac.additional_calendars,0),u.created_at,u.last_login,u.last_sync
FROM users u
LEFT JOIN (
  SELECT m.user_id,count(*)::int AS additional_calendars
  FROM memberships m JOIN calendars c ON c.id=m.calendar_id
  WHERE c.deleted_at IS NULL AND coalesce(c.system_kind,'')=''
  GROUP BY m.user_id
) ac ON ac.user_id=u.id
ORDER BY lower(u.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserRow
	for rows.Next() {
		var u UserRow
		_ = rows.Scan(&u.ID, &u.Name, &u.FirstName, &u.LastName, &u.Email, &u.Role, &u.Status, &u.AuthType, &u.CanCreateCalendars, &u.AdditionalCalendars, &u.CreatedAt, &u.LastLogin, &u.LastSync)
		out = append(out, u)
	}
	return out, rows.Err()
}
func (h *Handler) auditRowsVisible(ctx context.Context, limit int, u auth.User) ([]AuditRow, error) {
	if auth.IsAdmin(u) {
		return h.auditRows(ctx, limit)
	}
	rows, err := h.DB.Query(ctx, `SELECT a.id,coalesce(x.name,'System'),a.action,a.resource_type,a.resource_id,a.details::text,coalesce(a.ip::text,''),a.user_agent,a.request_id,a.created_at FROM audit_logs a LEFT JOIN users x ON x.id=a.actor_user_id WHERE a.actor_user_id=$1 ORDER BY a.created_at DESC LIMIT $2`, u.ID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var a AuditRow
		_ = rows.Scan(&a.ID, &a.Actor, &a.Action, &a.ResourceType, &a.ResourceID, &a.Details, &a.IP, &a.UserAgent, &a.RequestID, &a.CreatedAt)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (h *Handler) auditRowsBefore(ctx context.Context, limit int, beforeID int64) ([]AuditRow, error) {
	query := `SELECT a.id,coalesce(u.name,'System'),a.action,a.resource_type,a.resource_id,a.details::text,coalesce(a.ip::text,''),a.user_agent,a.request_id,a.created_at FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_user_id`
	args := []any{}
	if beforeID > 0 {
		query += ` WHERE a.id < $1`
		args = append(args, beforeID)
	}
	query += ` ORDER BY a.id DESC LIMIT $` + strconv.Itoa(len(args)+1)
	args = append(args, limit)
	rows, err := h.DB.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var a AuditRow
		if err := rows.Scan(&a.ID, &a.Actor, &a.Action, &a.ResourceType, &a.ResourceID, &a.Details, &a.IP, &a.UserAgent, &a.RequestID, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (h *Handler) auditRows(ctx context.Context, limit int) ([]AuditRow, error) {
	rows, err := h.DB.Query(ctx, `SELECT a.id,coalesce(u.name,'System'),a.action,a.resource_type,a.resource_id,a.details::text,coalesce(a.ip::text,''),a.user_agent,a.request_id,a.created_at FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY a.created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var a AuditRow
		_ = rows.Scan(&a.ID, &a.Actor, &a.Action, &a.ResourceType, &a.ResourceID, &a.Details, &a.IP, &a.UserAgent, &a.RequestID, &a.CreatedAt)
		out = append(out, a)
	}
	return out, rows.Err()
}
func (h *Handler) setSession(w http.ResponseWriter, r *http.Request, token string) {
	secure := r.TLS != nil || strings.HasPrefix(strings.ToLower(h.BaseURL), "https://")
	http.SetCookie(w, &http.Cookie{Name: "zentcal_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 30 * 24 * 3600, Secure: secure})
}
func clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "zentcal_session", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}
func (h *Handler) location() *time.Location {
	if h != nil {
		if loc := h.Location.Load(); loc != nil {
			return loc
		}
	}
	return time.UTC
}

func (h *Handler) externalBaseURL() string {
	return h.BaseURL
}
