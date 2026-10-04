package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zentworks/zentcal/internal/auth"
	"github.com/zentworks/zentcal/internal/httpx"
)

func (h *Handler) adminJSON(w http.ResponseWriter, r *http.Request) (*auth.Session, bool) {
	ss, ok := h.action(w, r, false)
	if !ok {
		return nil, false
	}
	if !auth.IsAdmin(ss.User) {
		httpx.Error(w, http.StatusForbidden, "Keine Berechtigung.")
		return nil, false
	}
	return ss, true
}

func formatUserTime(t *time.Time, timezone string) string {
	if t == nil {
		return "–"
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.Local
	}
	return t.In(loc).Format("02.01.2006 15:04")
}

func formatUserTimeValue(t time.Time, timezone string) string {
	return formatUserTime(&t, timezone)
}

func (h *Handler) usersSearch(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminJSON(w, r)
	if !ok {
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	rows, err := h.DB.Query(r.Context(), `SELECT u.id::text,u.name,u.first_name,u.last_name,u.email,u.role,u.status,u.auth_type,u.can_create_calendars,coalesce(ac.additional_calendars,0),u.created_at,u.last_login,u.last_sync
FROM users u
LEFT JOIN (
  SELECT m.user_id,count(*)::int AS additional_calendars
  FROM memberships m JOIN calendars c ON c.id=m.calendar_id
  WHERE c.deleted_at IS NULL AND coalesce(c.system_kind,'')=''
  GROUP BY m.user_id
) ac ON ac.user_id=u.id
WHERE $1='' OR u.name ILIKE '%'||$1||'%' OR u.email ILIKE '%'||$1||'%' OR u.first_name ILIKE '%'||$1||'%' OR u.last_name ILIKE '%'||$1||'%'
ORDER BY lower(u.name),lower(u.email)
LIMIT 100`, q)
	if err != nil {
		httpx.Error(w, 500, "Benutzer konnten nicht gesucht werden.")
		return
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var u UserRow
		if err := rows.Scan(&u.ID, &u.Name, &u.FirstName, &u.LastName, &u.Email, &u.Role, &u.Status, &u.AuthType, &u.CanCreateCalendars, &u.AdditionalCalendars, &u.CreatedAt, &u.LastLogin, &u.LastSync); err != nil {
			httpx.Error(w, 500, "Benutzer konnten nicht gelesen werden.")
			return
		}
		out = append(out, map[string]any{
			"id": u.ID, "name": u.Name, "first_name": u.FirstName, "last_name": u.LastName, "email": u.Email,
			"role": u.Role, "status": u.Status, "auth_type": u.AuthType, "can_create_calendars": u.CanCreateCalendars, "additional_calendars": u.AdditionalCalendars, "self": u.ID == ss.User.ID,
			"created": formatUserTimeValue(u.CreatedAt, ss.User.Timezone), "last_login": formatUserTime(u.LastLogin, ss.User.Timezone), "last_sync": formatUserTime(u.LastSync, ss.User.Timezone),
		})
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "data": out})
}

func (h *Handler) adminCalendarsSearch(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminJSON(w, r)
	if !ok {
		return
	}
	items, err := h.App.ListAdminCalendarsFiltered(r.Context(), ss.User, r.URL.Query().Get("q"))
	if err != nil {
		httpx.Error(w, 500, "Kalender konnten nicht gesucht werden.")
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, c := range items {
		out = append(out, map[string]any{
			"id": c.ID, "name": c.Name, "description": c.Description, "color": c.Color, "type": c.Type,
			"access": c.Access, "owner_names": c.OwnerNames, "mode": c.Mode, "members": c.Members, "events": c.Events, "can_read_events": c.CanReadEvents, "needs_owner": c.NeedsOwner, "admin_manager_visible": c.AdminManagerVisible,
		})
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "data": out})
}

func (h *Handler) activitySearch(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminJSON(w, r)
	if !ok {
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	resourceType := strings.TrimSpace(r.URL.Query().Get("type"))
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 || days > 60 {
		days = 60
	}
	rows, err := h.DB.Query(r.Context(), `SELECT a.id,coalesce(u.name,'System'),a.action,a.resource_type,a.resource_id,a.details::text,coalesce(a.ip::text,''),a.user_agent,a.request_id,a.created_at
FROM audit_logs a
LEFT JOIN users u ON u.id=a.actor_user_id
WHERE a.created_at >= now()-($1::int*interval '1 day')
  AND ($2='' OR a.resource_type=$2 OR a.action LIKE $2||'.%')
  AND ($3='' OR coalesce(u.name,'System') ILIKE '%'||$3||'%' OR a.action ILIKE '%'||$3||'%' OR a.resource_type ILIKE '%'||$3||'%' OR a.resource_id ILIKE '%'||$3||'%' OR a.details::text ILIKE '%'||$3||'%' OR coalesce(a.ip::text,'') ILIKE '%'||$3||'%' OR a.request_id ILIKE '%'||$3||'%')
ORDER BY a.id DESC
LIMIT 100`, days, resourceType, q)
	if err != nil {
		httpx.Error(w, 500, "Aktivitäten konnten nicht gesucht werden.")
		return
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var a AuditRow
		if err := rows.Scan(&a.ID, &a.Actor, &a.Action, &a.ResourceType, &a.ResourceID, &a.Details, &a.IP, &a.UserAgent, &a.RequestID, &a.CreatedAt); err != nil {
			httpx.Error(w, 500, "Aktivitäten konnten nicht gelesen werden.")
			return
		}
		out = append(out, map[string]any{
			"id": a.ID, "time": formatUserTimeValue(a.CreatedAt, ss.User.Timezone), "actor": a.Actor, "action": a.Action,
			"resource_type": a.ResourceType, "resource_id": a.ResourceID, "ip": a.IP, "request_id": a.RequestID,
		})
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "data": out})
}

func (h *Handler) allUsersSearch(ctx context.Context, q string) ([]UserRow, error) {
	q = strings.TrimSpace(q)
	rows, err := h.DB.Query(ctx, `SELECT u.id::text,u.name,u.first_name,u.last_name,u.email,u.role,u.status,u.auth_type,u.can_create_calendars,coalesce(ac.additional_calendars,0),u.created_at,u.last_login,u.last_sync
FROM users u
LEFT JOIN (
  SELECT m.user_id,count(*)::int AS additional_calendars
  FROM memberships m JOIN calendars c ON c.id=m.calendar_id
  WHERE c.deleted_at IS NULL AND coalesce(c.system_kind,'')=''
  GROUP BY m.user_id
) ac ON ac.user_id=u.id
WHERE $1='' OR u.name ILIKE '%'||$1||'%' OR u.email ILIKE '%'||$1||'%' OR u.first_name ILIKE '%'||$1||'%' OR u.last_name ILIKE '%'||$1||'%'
ORDER BY lower(u.name),lower(u.email) LIMIT 100`, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserRow
	for rows.Next() {
		var u UserRow
		if err := rows.Scan(&u.ID, &u.Name, &u.FirstName, &u.LastName, &u.Email, &u.Role, &u.Status, &u.AuthType, &u.CanCreateCalendars, &u.AdditionalCalendars, &u.CreatedAt, &u.LastLogin, &u.LastSync); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
