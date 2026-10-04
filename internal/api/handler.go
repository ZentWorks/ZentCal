package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zentworks/zentcal/internal/app"
	"github.com/zentworks/zentcal/internal/auth"
	"github.com/zentworks/zentcal/internal/httpx"
	"github.com/zentworks/zentcal/internal/security"
)

type Handler struct {
	App  *app.Service
	Auth *auth.Service
	DB   *pgxpool.Pool
}
type principal struct {
	User    auth.User
	Scopes  map[string]bool
	Session bool
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1", h.root)
	mux.HandleFunc("GET /api/v1/calendars", h.calendars)
	mux.HandleFunc("POST /api/v1/calendars", h.calendars)
	mux.HandleFunc("GET /api/v1/calendars/{id}", h.calendar)
	mux.HandleFunc("PATCH /api/v1/calendars/{id}", h.calendar)
	mux.HandleFunc("DELETE /api/v1/calendars/{id}", h.calendar)
	mux.HandleFunc("GET /api/v1/calendars/{id}/events", h.calendarEvents)
	mux.HandleFunc("POST /api/v1/calendars/{id}/events", h.calendarEvents)
	mux.HandleFunc("GET /api/v1/events/{id}", h.event)
	mux.HandleFunc("DELETE /api/v1/events/{id}", h.event)
	mux.HandleFunc("GET /api/v1/me", h.me)
}

func (h *Handler) root(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, 200, map[string]any{"name": "ZentCal API", "version": "v1", "ok": true})
}
func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	p, ok := h.authorize(w, r, "")
	if !ok {
		return
	}
	canCreate, _ := h.App.CanCreateCalendars(r.Context(), p.User.ID)
	data := struct {
		auth.User
		CanCreateCalendars bool `json:"CanCreateCalendars"`
	}{User: p.User, CanCreateCalendars: canCreate}
	httpx.JSON(w, 200, map[string]any{"ok": true, "data": data})
}

func (h *Handler) calendars(w http.ResponseWriter, r *http.Request) {
	p, ok := h.authorize(w, r, scopeFor(r.Method, "calendars"))
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		cs, err := h.App.ListCalendars(r.Context(), p.User)
		if err != nil {
			httpx.Error(w, 500, "Kalender konnten nicht geladen werden.")
			return
		}
		httpx.JSON(w, 200, map[string]any{"ok": true, "data": cs})
		return
	}
	var in struct{ Name, Description, Color, Type, Mode string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		httpx.Error(w, 400, "Ungültiges JSON.")
		return
	}
	c, err := h.App.CreateCalendar(r.Context(), r, p.User, in.Name, in.Description, in.Color, in.Type, in.Mode)
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	httpx.JSON(w, 201, map[string]any{"ok": true, "data": c})
}
func (h *Handler) calendar(w http.ResponseWriter, r *http.Request) {
	scope := "calendar:read"
	if r.Method != http.MethodGet {
		scope = "calendar:write"
	}
	p, ok := h.authorize(w, r, scope)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if r.Method == http.MethodGet {
		c, err := h.App.GetCalendar(r.Context(), p.User, id)
		if err != nil {
			httpx.Error(w, 404, "Kalender nicht gefunden.")
			return
		}
		httpx.JSON(w, 200, map[string]any{"ok": true, "data": c})
		return
	}
	if r.Method == http.MethodDelete {
		if err := h.App.DeleteCalendar(r.Context(), r, p.User, id); err != nil {
			httpx.Error(w, 403, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var in struct{ Name, Description, Color, Mode string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		httpx.Error(w, 400, "Ungültiges JSON.")
		return
	}
	c, err := h.App.UpdateCalendar(r.Context(), r, p.User, id, in.Name, in.Description, in.Color, in.Mode)
	if err != nil {
		httpx.Error(w, 403, err.Error())
		return
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "data": c})
}
func (h *Handler) calendarEvents(w http.ResponseWriter, r *http.Request) {
	p, ok := h.authorize(w, r, scopeFor(r.Method, "events"))
	if !ok {
		return
	}
	id := r.PathValue("id")
	if r.Method == http.MethodGet {
		es, err := h.App.ListEvents(r.Context(), p.User, id)
		if err != nil {
			httpx.Error(w, 404, "Kalender nicht gefunden.")
			return
		}
		httpx.JSON(w, 200, map[string]any{"ok": true, "data": es})
		return
	}
	var in struct{ ICS, Href string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		httpx.Error(w, 400, "Ungültiges JSON.")
		return
	}
	e, created, err := h.App.PutEvent(r.Context(), r, p.User, id, in.Href, in.ICS, "")
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	status := 200
	if created {
		status = 201
	}
	httpx.JSON(w, status, map[string]any{"ok": true, "data": e})
}
func (h *Handler) event(w http.ResponseWriter, r *http.Request) {
	p, ok := h.authorize(w, r, scopeFor(r.Method, "events"))
	if !ok {
		return
	}
	e, err := h.App.GetEvent(r.Context(), p.User, r.PathValue("id"))
	if err != nil {
		httpx.Error(w, 404, "Termin nicht gefunden.")
		return
	}
	if r.Method == http.MethodGet {
		httpx.JSON(w, 200, map[string]any{"ok": true, "data": e})
		return
	}
	if err := h.App.DeleteEvent(r.Context(), r, p.User, e.CalendarID, e.Href); err != nil {
		httpx.Error(w, 403, err.Error())
		return
	}
	w.WriteHeader(204)
}

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request, scope string) (principal, bool) {
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(a, "Bearer "))
		var p principal
		var scopes []string
		err := h.DB.QueryRow(r.Context(), `SELECT u.id::text,u.name,u.email,u.role,u.status,u.created_at,u.last_login,u.last_sync,t.scopes FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=$1 AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at>now()) AND u.status='active'`, security.TokenHash(token)).Scan(&p.User.ID, &p.User.Name, &p.User.Email, &p.User.Role, &p.User.Status, &p.User.CreatedAt, &p.User.LastLogin, &p.User.LastSync, &scopes)
		if err != nil {
			httpx.Error(w, 401, "Ungültiger API-Token.")
			return principal{}, false
		}
		p.Scopes = map[string]bool{}
		for _, s := range scopes {
			p.Scopes[s] = true
		}
		if scope != "" && !p.Scopes[scope] && !p.Scopes["*"] {
			httpx.Error(w, 403, "API-Token hat nicht den benötigten Scope.")
			return principal{}, false
		}
		_, _ = h.DB.Exec(r.Context(), `UPDATE api_tokens SET last_used_at=now() WHERE token_hash=$1`, security.TokenHash(token))
		return p, true
	}
	ss, err := h.Auth.SessionFromRequest(r)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
		}
		httpx.Error(w, 401, "Anmeldung erforderlich.")
		return principal{}, false
	}
	// Cookie sessions are convenient for read-only calls from the browser, but
	// mutating API requests deliberately require an API token. This prevents a
	// browser session from becoming a CSRF-capable write credential for /api/v1.
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
		httpx.Error(w, 403, "Schreibzugriffe auf die API erfordern einen API-Token.")
		return principal{}, false
	}
	return principal{User: ss.User, Session: true}, true
}
func scopeFor(method, resource string) string {
	if method == http.MethodGet {
		return strings.TrimSuffix(resource, "s") + ":read"
	}
	return strings.TrimSuffix(resource, "s") + ":write"
}
