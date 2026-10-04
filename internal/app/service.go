package app

import (
	"context"
	"errors"
	"net/http"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zentworks/zentcal/internal/audit"
	"github.com/zentworks/zentcal/internal/auth"
	"github.com/zentworks/zentcal/internal/ical"
	"github.com/zentworks/zentcal/internal/scheduling"
	"github.com/zentworks/zentcal/internal/security"
	"github.com/zentworks/zentcal/internal/webhook"
)

const adminCalendarViewerMembershipUpsertSQL = `INSERT INTO memberships(calendar_id,user_id,role,dav_name) VALUES($1,$2,'viewer',$3)
ON CONFLICT(calendar_id,user_id) DO UPDATE SET role='viewer'`

type Service struct {
	DB         *pgxpool.Pool
	Auth       *auth.Service
	Audit      *audit.Logger
	Webhooks   *webhook.Service
	Scheduling *scheduling.Service
}

type Calendar struct {
	ID, Name, Description, Color, Type, Mode, Role, Access string
	OwnerNames                                             string
	DAVName, CalendarTimezone                              string
	SystemKind                                             string `json:"-"`
	SystemOwnerUserID                                      string `json:"-"`
	AdminManagerUserID                                     string `json:"-"`
	Members, Events                                        int
	CanManage, CanReadEvents                               bool
	AdminManaged, AdminManagerVisible, NeedsOwner          bool
	CreatedAt, UpdatedAt                                   time.Time
}
type Event struct {
	ID, CalendarID, UID, Href, Summary, ICS, ETag, ScheduleTag string
	Start, End                                                 *time.Time
	Version                                                    int
	CreatedBy, UpdatedBy                                       string
	CreatedAt, UpdatedAt                                       time.Time
}

func (s *Service) ListCalendars(ctx context.Context, u auth.User) ([]Calendar, error) {
	rows, err := s.DB.Query(ctx, `SELECT c.id::text,c.name,c.description,c.color,c.type,c.mode,m.dav_name,c.calendar_timezone,m.role,coalesce(c.system_kind,''),coalesce(c.system_owner_user_id::text,''),
 coalesce(mc.members,0),coalesce(ec.events,0),c.created_at,c.updated_at
 FROM memberships m
 JOIN calendars c ON c.id=m.calendar_id
 LEFT JOIN (SELECT calendar_id,count(*)::int AS members FROM memberships GROUP BY calendar_id) mc ON mc.calendar_id=c.id
 LEFT JOIN (SELECT calendar_id,count(*)::int AS events FROM events GROUP BY calendar_id) ec ON ec.calendar_id=c.id
 WHERE m.user_id=$1 AND c.deleted_at IS NULL
   AND (coalesce(c.system_kind,'')='' OR (c.system_kind='personal' AND c.system_owner_user_id=$1))
 ORDER BY CASE WHEN c.system_kind='personal' THEN 0 ELSE 1 END, lower(c.name)`, u.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanCalendars(rows, u)
}

// ListAdminCalendars returns only administratively managed, non-system calendars.
// Personal calendars deliberately stay out of this view so large installations do
// not turn the administration list into a per-user calendar directory.
func (s *Service) ListAdminCalendars(ctx context.Context, u auth.User) ([]Calendar, error) {
	return s.ListAdminCalendarsFiltered(ctx, u, "")
}

func (s *Service) ListAdminCalendarsFiltered(ctx context.Context, u auth.User, search string) ([]Calendar, error) {
	if !auth.IsAdmin(u) {
		return nil, errors.New("Keine Berechtigung.")
	}
	search = strings.TrimSpace(search)
	rows, err := s.DB.Query(ctx, `SELECT c.id::text,c.name,c.description,c.color,c.type,c.mode,coalesce(m.dav_name,c.dav_name),c.calendar_timezone,coalesce(m.role,''),coalesce(c.system_kind,''),coalesce(c.system_owner_user_id::text,''),
 coalesce(mc.members,0),coalesce(ec.events,0),c.created_at,c.updated_at,c.admin_managed,coalesce(c.admin_manager_user_id::text,''),c.admin_manager_visible,
 NOT EXISTS(SELECT 1 FROM memberships own WHERE own.calendar_id=c.id AND own.role='owner') AS needs_owner,
 coalesce(oc.owners,'')
 FROM calendars c
 LEFT JOIN memberships m ON m.calendar_id=c.id AND m.user_id=$1
 LEFT JOIN (SELECT calendar_id,count(*)::int AS members FROM memberships GROUP BY calendar_id) mc ON mc.calendar_id=c.id
 LEFT JOIN (SELECT calendar_id,count(*)::int AS events FROM events GROUP BY calendar_id) ec ON ec.calendar_id=c.id
 LEFT JOIN (
   SELECT om.calendar_id,string_agg(coalesce(nullif(trim(concat_ws(' ',ou.first_name,ou.last_name)),''),ou.name,ou.email), ', ' ORDER BY lower(coalesce(nullif(trim(concat_ws(' ',ou.first_name,ou.last_name)),''),ou.name,ou.email))) AS owners
   FROM memberships om JOIN users ou ON ou.id=om.user_id
   WHERE om.role='owner'
   GROUP BY om.calendar_id
 ) oc ON oc.calendar_id=c.id
 WHERE c.deleted_at IS NULL AND coalesce(c.system_kind,'')='' AND c.admin_managed AND c.admin_manager_user_id=$1
   AND ($2='' OR c.name ILIKE '%'||$2||'%' OR c.description ILIKE '%'||$2||'%' OR EXISTS (
     SELECT 1 FROM memberships om JOIN users ou ON ou.id=om.user_id
     WHERE om.calendar_id=c.id AND om.role='owner' AND (ou.name ILIKE '%'||$2||'%' OR ou.email ILIKE '%'||$2||'%')
   ))
 ORDER BY lower(c.name)
 LIMIT 200`, u.ID, search)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Calendar
	for rows.Next() {
		var c Calendar
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.Color, &c.Type, &c.Mode, &c.DAVName, &c.CalendarTimezone, &c.Role, &c.SystemKind, &c.SystemOwnerUserID, &c.Members, &c.Events, &c.CreatedAt, &c.UpdatedAt, &c.AdminManaged, &c.AdminManagerUserID, &c.AdminManagerVisible, &c.NeedsOwner, &c.OwnerNames); err != nil {
			return nil, err
		}
		c.CanReadEvents = auth.CanRead(c.Role)
		c.CanManage = c.AdminManaged && c.AdminManagerUserID == u.ID
		if !c.CanReadEvents {
			c.Events = 0
		}
		if c.Role != "" {
			c.Access = c.Role
		} else {
			c.Access = "administration"
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Service) scanCalendars(rows pgx.Rows, u auth.User) ([]Calendar, error) {
	var out []Calendar
	for rows.Next() {
		var c Calendar
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.Color, &c.Type, &c.Mode, &c.DAVName, &c.CalendarTimezone, &c.Role, &c.SystemKind, &c.SystemOwnerUserID, &c.Members, &c.Events, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		c.CanReadEvents = auth.CanRead(c.Role)
		c.CanManage = auth.CanManage(c.Role) && c.SystemKind == ""
		if !c.CanReadEvents {
			c.Events = 0
		}
		switch {
		case c.Role != "":
			c.Access = c.Role
		case auth.IsAdmin(u):
			c.Access = "administration"
		default:
			c.Access = "overview"
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Service) GetCalendar(ctx context.Context, u auth.User, id string) (Calendar, error) {
	return s.getCalendar(ctx, u, id, false)
}

func (s *Service) GetAdminCalendar(ctx context.Context, u auth.User, id string) (Calendar, error) {
	if !auth.IsAdmin(u) {
		return Calendar{}, errors.New("Keine Berechtigung.")
	}
	return s.getCalendar(ctx, u, id, true)
}

func (s *Service) getCalendar(ctx context.Context, u auth.User, id string, administrative bool) (Calendar, error) {
	var c Calendar
	err := s.DB.QueryRow(ctx, `SELECT c.id::text,c.name,c.description,c.color,c.type,c.mode,coalesce(m.dav_name,c.dav_name),c.calendar_timezone,coalesce(m.role,''),coalesce(c.system_kind,''),coalesce(c.system_owner_user_id::text,''),
 (SELECT count(*) FROM memberships WHERE calendar_id=c.id),(SELECT count(*) FROM events WHERE calendar_id=c.id),c.created_at,c.updated_at,
 c.admin_managed,coalesce(c.admin_manager_user_id::text,''),c.admin_manager_visible,
 NOT EXISTS(SELECT 1 FROM memberships own WHERE own.calendar_id=c.id AND own.role='owner') AS needs_owner
 FROM calendars c
 LEFT JOIN memberships m ON m.calendar_id=c.id AND m.user_id=$2
 WHERE c.id=$1 AND c.deleted_at IS NULL
   AND (
     (NOT $3 AND m.user_id IS NOT NULL AND (coalesce(c.system_kind,'')='' OR (c.system_kind='personal' AND c.system_owner_user_id=$2)))
     OR ($3 AND c.admin_managed AND c.admin_manager_user_id=$2 AND coalesce(c.system_kind,'')='')
   )`, id, u.ID, administrative && auth.IsAdmin(u)).Scan(
		&c.ID, &c.Name, &c.Description, &c.Color, &c.Type, &c.Mode, &c.DAVName, &c.CalendarTimezone, &c.Role, &c.SystemKind, &c.SystemOwnerUserID,
		&c.Members, &c.Events, &c.CreatedAt, &c.UpdatedAt, &c.AdminManaged, &c.AdminManagerUserID, &c.AdminManagerVisible, &c.NeedsOwner,
	)
	if err != nil {
		return c, err
	}
	c.CanReadEvents = auth.CanRead(c.Role)
	c.CanManage = auth.CanManage(c.Role) || (administrative && auth.IsAdmin(u) && c.AdminManaged && c.AdminManagerUserID == u.ID)
	if !c.CanReadEvents {
		c.Events = 0
	}
	switch {
	case c.Role != "":
		c.Access = c.Role
	case administrative && c.AdminManaged && c.AdminManagerUserID == u.ID:
		c.Access = "administration"
	default:
		c.Access = "overview"
	}
	return c, nil
}

func (s *Service) CanCreateCalendars(ctx context.Context, userID string) (bool, error) {
	var allowed bool
	err := s.DB.QueryRow(ctx, `SELECT can_create_calendars FROM users WHERE id=$1 AND status='active'`, userID).Scan(&allowed)
	return allowed, err
}

func (s *Service) CreateCalendar(ctx context.Context, r *http.Request, u auth.User, name, desc, color, typ, mode string) (Calendar, error) {
	return s.createCalendar(ctx, r, u, name, desc, color, typ, mode, false)
}

func (s *Service) CreateAdminCalendar(ctx context.Context, r *http.Request, u auth.User, name, desc, color, typ, mode string) (Calendar, error) {
	if !auth.IsAdmin(u) {
		return Calendar{}, errors.New("Keine Berechtigung.")
	}
	return s.createCalendar(ctx, r, u, name, desc, color, typ, mode, true)
}

func (s *Service) SetAdminCalendarVisibility(ctx context.Context, r *http.Request, u auth.User, id string, visible bool) (Calendar, error) {
	if !auth.IsAdmin(u) {
		return Calendar{}, errors.New("Keine Berechtigung.")
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return Calendar{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, id); err != nil {
		return Calendar{}, err
	}
	var managerID string
	var managed, currentVisible bool
	if err = tx.QueryRow(ctx, `SELECT admin_managed,coalesce(admin_manager_user_id::text,''),admin_manager_visible FROM calendars WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, id).Scan(&managed, &managerID, &currentVisible); err != nil {
		return Calendar{}, err
	}
	if !managed || managerID != u.ID {
		return Calendar{}, errors.New("Keine Berechtigung.")
	}
	if currentVisible == visible {
		if err = tx.Commit(ctx); err != nil {
			return Calendar{}, err
		}
		return s.GetAdminCalendar(ctx, u, id)
	}
	if visible {
		if _, err = tx.Exec(ctx, adminCalendarViewerMembershipUpsertSQL, id, u.ID, id); err != nil {
			return Calendar{}, err
		}
	} else {
		if _, err = tx.Exec(ctx, `DELETE FROM memberships WHERE calendar_id=$1 AND user_id=$2`, id, u.ID); err != nil {
			return Calendar{}, err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE calendars SET admin_manager_visible=$1,updated_at=now() WHERE id=$2`, visible, id); err != nil {
		return Calendar{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Calendar{}, err
	}
	details := map[string]any{"visible": visible}
	s.Audit.Write(ctx, r, u.ID, "calendar.admin_visibility_changed", "calendar", id, details)
	s.Webhooks.Emit(ctx, "calendar.updated", u.ID, "calendar", id, details)
	return s.GetAdminCalendar(ctx, u, id)
}

func (s *Service) createCalendar(ctx context.Context, r *http.Request, u auth.User, name, desc, color, typ, mode string, administrative bool) (Calendar, error) {
	if !administrative {
		allowed, err := s.CanCreateCalendars(ctx, u.ID)
		if err != nil {
			return Calendar{}, err
		}
		if !allowed {
			return Calendar{}, errors.New("Für dieses Benutzerkonto ist das Erstellen eigener Kalender deaktiviert.")
		}
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Calendar{}, errors.New("Kalendername ist erforderlich.")
	}
	desc = strings.TrimSpace(desc)
	if utf8.RuneCountInString(desc) > 50 {
		return Calendar{}, errors.New("Die Beschreibung darf maximal 50 Zeichen enthalten.")
	}
	if typ != "resource" {
		typ = "calendar"
	}
	if mode != "personal" {
		mode = "normal"
	}
	id := security.UUID()
	if strings.TrimSpace(color) == "" {
		color = calendarColorForID(id)
	} else {
		color = normalizeColor(color)
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return Calendar{}, err
	}
	defer tx.Rollback(ctx)
	if administrative {
		_, err = tx.Exec(ctx, `INSERT INTO calendars(id,name,description,color,type,mode,created_by,dav_name,admin_managed,admin_manager_user_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,true,$7)`, id, name, desc, color, typ, mode, u.ID, id)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO calendars(id,name,description,color,type,mode,created_by,dav_name) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, name, desc, color, typ, mode, u.ID, id)
	}
	if err != nil {
		return Calendar{}, err
	}
	// User-created calendars are owned by their creator. Centrally managed
	// calendars deliberately keep administrative control separate from content
	// access; the manager may opt in as a read-only viewer later.
	if !administrative {
		if _, err = tx.Exec(ctx, `INSERT INTO memberships(calendar_id,user_id,role,dav_name) VALUES($1,$2,'owner',$3)`, id, u.ID, id); err != nil {
			return Calendar{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return Calendar{}, err
	}
	s.Audit.Write(ctx, r, u.ID, "calendar.created", "calendar", id, map[string]any{"name": name, "description": desc, "color": color, "type": typ, "mode": mode})
	s.Webhooks.Emit(ctx, "calendar.created", u.ID, "calendar", id, map[string]any{"name": name, "description": desc, "color": color, "type": typ, "mode": mode})
	if administrative {
		return s.GetAdminCalendar(ctx, u, id)
	}
	return s.GetCalendar(ctx, u, id)
}

func (s *Service) GetCalendarByDAVName(ctx context.Context, u auth.User, davName string) (Calendar, error) {
	var c Calendar
	err := s.DB.QueryRow(ctx, `SELECT c.id::text,c.name,c.description,c.color,c.type,c.mode,coalesce(m.dav_name,c.dav_name),c.calendar_timezone,coalesce(m.role,''),coalesce(c.system_kind,''),coalesce(c.system_owner_user_id::text,''),
 (SELECT count(*) FROM memberships WHERE calendar_id=c.id),(SELECT count(*) FROM events WHERE calendar_id=c.id),c.created_at,c.updated_at
 FROM calendars c JOIN memberships m ON m.calendar_id=c.id AND m.user_id=$2
 WHERE m.dav_name=$1 AND c.deleted_at IS NULL AND (coalesce(c.system_kind,'')='' OR c.system_owner_user_id=$2)
 ORDER BY c.created_at LIMIT 1`, davName, u.ID).Scan(&c.ID, &c.Name, &c.Description, &c.Color, &c.Type, &c.Mode, &c.DAVName, &c.CalendarTimezone, &c.Role, &c.SystemKind, &c.SystemOwnerUserID, &c.Members, &c.Events, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return c, err
	}
	c.CanReadEvents = auth.CanRead(c.Role)
	c.CanManage = auth.CanManage(c.Role) && c.SystemKind == ""
	if !c.CanReadEvents {
		c.Events = 0
	}
	c.Access = c.Role
	return c, nil
}

func (s *Service) CreateDAVCalendar(ctx context.Context, r *http.Request, u auth.User, davName, name, desc, color, timezone string) (Calendar, error) {
	allowed, err := s.CanCreateCalendars(ctx, u.ID)
	if err != nil {
		return Calendar{}, err
	}
	if !allowed {
		return Calendar{}, errors.New("Für dieses Benutzerkonto ist das Erstellen eigener Kalender deaktiviert.")
	}
	davName = strings.TrimSpace(davName)
	if davName == "" || davName == "." || davName == ".." || strings.ContainsAny(davName, "/\\") || utf8.RuneCountInString(davName) > 180 {
		return Calendar{}, errors.New("Ungültiger CalDAV-Pfad.")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = davName
	}
	desc = strings.TrimSpace(desc)
	if utf8.RuneCountInString(desc) > 50 {
		return Calendar{}, errors.New("Die Beschreibung darf maximal 50 Zeichen enthalten.")
	}
	color = normalizeColor(color)
	timezone = strings.TrimSpace(timezone)
	if utf8.RuneCountInString(timezone) > 128*1024 {
		return Calendar{}, errors.New("Kalender-Zeitzone ist zu groß.")
	}
	var exists bool
	if err := s.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM calendars c JOIN memberships m ON m.calendar_id=c.id AND m.user_id=$1 WHERE m.dav_name=$2 AND c.deleted_at IS NULL)`, u.ID, davName).Scan(&exists); err != nil {
		return Calendar{}, err
	}
	if exists {
		return Calendar{}, errors.New("CalDAV-Ressource existiert bereits.")
	}
	id := security.UUID()
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return Calendar{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO calendars(id,name,description,color,type,mode,created_by,dav_name,calendar_timezone) VALUES($1,$2,$3,$4,'calendar','normal',$5,$6,$7)`, id, name, desc, color, u.ID, davName, timezone); err != nil {
		return Calendar{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO memberships(calendar_id,user_id,role,dav_name) VALUES($1,$2,'owner',$3)`, id, u.ID, davName); err != nil {
		return Calendar{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Calendar{}, err
	}
	details := map[string]any{"name": name, "description": desc, "color": color, "type": "calendar", "mode": "normal", "source": "caldav"}
	s.Audit.Write(ctx, r, u.ID, "calendar.created", "calendar", id, details)
	s.Webhooks.Emit(ctx, "calendar.created", u.ID, "calendar", id, details)
	return s.GetCalendar(ctx, u, id)
}

func (s *Service) UpdateCalendar(ctx context.Context, r *http.Request, u auth.User, id, name, desc, color, mode string) (Calendar, error) {
	return s.updateCalendar(ctx, r, u, id, name, desc, color, mode, false)
}

func (s *Service) UpdateAdminCalendar(ctx context.Context, r *http.Request, u auth.User, id, name, desc, color, mode string) (Calendar, error) {
	if !auth.IsAdmin(u) {
		return Calendar{}, errors.New("Keine Berechtigung.")
	}
	return s.updateCalendar(ctx, r, u, id, name, desc, color, mode, true)
}

func (s *Service) updateCalendar(ctx context.Context, r *http.Request, u auth.User, id, name, desc, color, mode string, administrative bool) (Calendar, error) {
	var c Calendar
	var err error
	if administrative {
		c, err = s.GetAdminCalendar(ctx, u, id)
	} else {
		c, err = s.GetCalendar(ctx, u, id)
	}
	if err != nil {
		return Calendar{}, err
	}
	if !c.CanManage {
		return Calendar{}, errors.New("Keine Berechtigung.")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Calendar{}, errors.New("Kalendername ist erforderlich.")
	}
	desc = strings.TrimSpace(desc)
	if utf8.RuneCountInString(desc) > 50 {
		return Calendar{}, errors.New("Die Beschreibung darf maximal 50 Zeichen enthalten.")
	}
	color = normalizeColor(color)
	if mode == "" {
		mode = c.Mode
	}
	if mode != "personal" {
		mode = "normal"
	}
	if name == c.Name && desc == c.Description && strings.EqualFold(color, c.Color) && mode == c.Mode {
		return c, nil
	}
	_, err = s.DB.Exec(ctx, `UPDATE calendars SET name=$1,description=$2,color=$3,mode=$4,updated_at=now() WHERE id=$5 AND deleted_at IS NULL`, name, desc, color, mode, id)
	if err != nil {
		return Calendar{}, err
	}
	details := map[string]any{
		"before": map[string]any{"name": c.Name, "description": c.Description, "color": c.Color, "mode": c.Mode},
		"after":  map[string]any{"name": name, "description": desc, "color": color, "mode": mode},
	}
	s.Audit.Write(ctx, r, u.ID, "calendar.updated", "calendar", id, details)
	s.Webhooks.Emit(ctx, "calendar.updated", u.ID, "calendar", id, details)
	if administrative {
		return s.GetAdminCalendar(ctx, u, id)
	}
	return s.GetCalendar(ctx, u, id)
}

func (s *Service) DeleteCalendar(ctx context.Context, r *http.Request, u auth.User, id string) error {
	return s.deleteCalendar(ctx, r, u, id, false)
}

func (s *Service) DeleteAdminCalendar(ctx context.Context, r *http.Request, u auth.User, id string) error {
	if !auth.IsAdmin(u) {
		return errors.New("Keine Berechtigung.")
	}
	return s.deleteCalendar(ctx, r, u, id, true)
}

func (s *Service) deleteCalendar(ctx context.Context, r *http.Request, u auth.User, id string, administrative bool) error {
	var c Calendar
	var err error
	if administrative {
		c, err = s.GetAdminCalendar(ctx, u, id)
	} else {
		c, err = s.GetCalendar(ctx, u, id)
	}
	if err != nil {
		return errors.New("Kalender wurde nicht gefunden.")
	}
	if c.SystemKind != "" {
		return errors.New("Persönliche und interne Kalender können nicht gelöscht werden.")
	}
	if !c.CanManage {
		return errors.New("Keine Berechtigung.")
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, id); err != nil {
		return err
	}
	// Re-check authorization under the same lock. A global administrator alone
	// is not enough: deletion requires calendar ownership or administrative
	// management of this centrally managed calendar.
	var stillAllowed bool
	if err = tx.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM memberships WHERE calendar_id=$1 AND user_id=$2 AND role='owner')
		OR EXISTS(SELECT 1 FROM calendars WHERE id=$1 AND admin_managed AND admin_manager_user_id=$2 AND deleted_at IS NULL)`, id, u.ID).Scan(&stillAllowed); err != nil || !stillAllowed {
		return errors.New("Keine Berechtigung.")
	}
	// event_versions has no FK by design; delete it explicitly before the events.
	if _, err = tx.Exec(ctx, `DELETE FROM event_versions WHERE event_id IN (SELECT id FROM events WHERE calendar_id=$1) OR event_id IN (SELECT ea.attendee_event_id FROM event_attendees ea JOIN events e ON e.id=ea.event_id WHERE e.calendar_id=$1 AND ea.attendee_event_id IS NOT NULL)`, id); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM scheduling_deliveries WHERE event_id IN (SELECT id FROM events WHERE calendar_id=$1)`, id); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM scheduling_messages WHERE event_id IN (SELECT id FROM events WHERE calendar_id=$1)`, id); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM events WHERE id IN (SELECT ea.attendee_event_id FROM event_attendees ea JOIN events e ON e.id=ea.event_id WHERE e.calendar_id=$1 AND ea.attendee_event_id IS NOT NULL)`, id); err != nil {
		return err
	}
	ct, err := tx.Exec(ctx, `DELETE FROM calendars WHERE id=$1 AND deleted_at IS NULL AND coalesce(system_kind,'')=''`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errors.New("Kalender wurde nicht gefunden.")
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	s.Audit.Write(ctx, r, u.ID, "calendar.deleted", "calendar", id, map[string]any{"name": c.Name})
	s.Webhooks.Emit(ctx, "calendar.deleted", u.ID, "calendar", id, map[string]any{"name": c.Name})
	return nil
}

var calendarPalette = []string{
	"#4f8cff", "#7c5cff", "#3fb8af", "#46a66f", "#d28b36",
	"#d65c70", "#5b9bd5", "#9b6fd6", "#2fa7c4", "#7aa84b",
}

func calendarColorForID(id string) string {
	// UUIDs are random. Reusing one nibble keeps color selection dependency-free
	// while still giving new calendars a varied, curated initial palette.
	for i := len(id) - 1; i >= 0; i-- {
		c := id[i]
		var n int
		switch {
		case c >= '0' && c <= '9':
			n = int(c - '0')
		case c >= 'a' && c <= 'f':
			n = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			n = int(c-'A') + 10
		default:
			continue
		}
		return calendarPalette[n%len(calendarPalette)]
	}
	return calendarPalette[0]
}

func normalizeColor(color string) string {
	color = strings.TrimSpace(color)
	if len(color) != 7 || color[0] != '#' {
		return "#4f8cff"
	}
	for _, r := range color[1:] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return "#4f8cff"
		}
	}
	return strings.ToLower(color)
}

func canEditEvent(role, mode, createdBy, userID string) bool {
	if mode == "personal" {
		return auth.CanCreate(role) && createdBy != "" && createdBy == userID
	}
	return auth.CanEditAll(role)
}

func (s *Service) ListEvents(ctx context.Context, u auth.User, calendarID string) ([]Event, error) {
	return s.listEvents(ctx, u, calendarID, 500)
}

// ListEventsDAV is used by CalDAV reports and collection discovery. DAV correctness
// must not depend on UI pagination limits; clients expect the complete requested set.
func (s *Service) ListEventsDAV(ctx context.Context, u auth.User, calendarID string) ([]Event, error) {
	return s.listEvents(ctx, u, calendarID, 0)
}

func (s *Service) listEvents(ctx context.Context, u auth.User, calendarID string, limit int) ([]Event, error) {
	role, err := s.Auth.CalendarRole(ctx, u.ID, calendarID)
	if err != nil || !auth.CanRead(role) {
		return nil, pgx.ErrNoRows
	}
	q := `SELECT id::text,calendar_id::text,uid,href,summary,dtstart,dtend,ics,etag,coalesce(schedule_tag,''),version,coalesce(created_by::text,''),coalesce(updated_by::text,''),created_at,updated_at FROM events WHERE calendar_id=$1 ORDER BY dtstart NULLS LAST,created_at DESC`
	var rows pgx.Rows
	if limit > 0 {
		rows, err = s.DB.Query(ctx, q+` LIMIT $2`, calendarID, limit)
	} else {
		rows, err = s.DB.Query(ctx, q, calendarID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err = rows.Scan(&e.ID, &e.CalendarID, &e.UID, &e.Href, &e.Summary, &e.Start, &e.End, &e.ICS, &e.ETag, &e.ScheduleTag, &e.Version, &e.CreatedBy, &e.UpdatedBy, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Service) GetEventByHref(ctx context.Context, u auth.User, calendarID, href string) (Event, error) {
	role, err := s.Auth.CalendarRole(ctx, u.ID, calendarID)
	if err != nil || !auth.CanRead(role) {
		return Event{}, pgx.ErrNoRows
	}
	var e Event
	err = s.DB.QueryRow(ctx, `SELECT id::text,calendar_id::text,uid,href,summary,dtstart,dtend,ics,etag,coalesce(schedule_tag,''),version,coalesce(created_by::text,''),coalesce(updated_by::text,''),created_at,updated_at FROM events WHERE calendar_id=$1 AND href=$2`, calendarID, href).Scan(&e.ID, &e.CalendarID, &e.UID, &e.Href, &e.Summary, &e.Start, &e.End, &e.ICS, &e.ETag, &e.ScheduleTag, &e.Version, &e.CreatedBy, &e.UpdatedBy, &e.CreatedAt, &e.UpdatedAt)
	return e, err
}
func (s *Service) GetEvent(ctx context.Context, u auth.User, id string) (Event, error) {
	var cal string
	if err := s.DB.QueryRow(ctx, `SELECT calendar_id::text FROM events WHERE id=$1`, id).Scan(&cal); err != nil {
		return Event{}, err
	}
	role, err := s.Auth.CalendarRole(ctx, u.ID, cal)
	if err != nil || !auth.CanRead(role) {
		return Event{}, pgx.ErrNoRows
	}
	var e Event
	err = s.DB.QueryRow(ctx, `SELECT id::text,calendar_id::text,uid,href,summary,dtstart,dtend,ics,etag,coalesce(schedule_tag,''),version,coalesce(created_by::text,''),coalesce(updated_by::text,''),created_at,updated_at FROM events WHERE id=$1`, id).Scan(&e.ID, &e.CalendarID, &e.UID, &e.Href, &e.Summary, &e.Start, &e.End, &e.ICS, &e.ETag, &e.ScheduleTag, &e.Version, &e.CreatedBy, &e.UpdatedBy, &e.CreatedAt, &e.UpdatedAt)
	return e, err
}

func (s *Service) isInvitationCopy(ctx context.Context, eventID string) bool {
	var linked bool
	if err := s.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM event_attendees WHERE attendee_event_id=$1)`, eventID).Scan(&linked); err != nil {
		return false
	}
	return linked
}

func (s *Service) PutEvent(ctx context.Context, r *http.Request, u auth.User, calendarID, href, raw, ifMatch string) (Event, bool, error) {
	role, err := s.Auth.CalendarRole(ctx, u.ID, calendarID)
	if err != nil || !auth.CanCreate(role) {
		return Event{}, false, errors.New("Keine Schreibberechtigung.")
	}
	cal, err := s.GetCalendar(ctx, u, calendarID)
	if err != nil {
		return Event{}, false, errors.New("Kalender wurde nicht gefunden.")
	}
	m, err := ical.Parse(raw)
	if err != nil {
		return Event{}, false, err
	}
	raw = ical.Normalize(raw)
	if cal.Mode == "personal" {
		first := strings.TrimSpace(u.FirstName)
		if first == "" {
			parts := strings.Fields(u.Name)
			if len(parts) > 0 {
				first = parts[0]
			}
		}
		if first != "" && !strings.HasPrefix(m.Summary, first+" | ") {
			raw = ical.SetSummary(raw, first+" | "+m.Summary)
			m, err = ical.Parse(raw)
			if err != nil {
				return Event{}, false, err
			}
		}
	}
	href = path.Base(strings.TrimSpace(href))
	if href == "." || href == "/" || href == "" {
		href = m.UID + ".ics"
	}
	if !strings.HasSuffix(strings.ToLower(href), ".ics") {
		href += ".ics"
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return Event{}, false, err
	}
	defer tx.Rollback(ctx)
	var existing Event
	scanErr := tx.QueryRow(ctx, `SELECT id::text,calendar_id::text,uid,href,summary,dtstart,dtend,ics,etag,coalesce(schedule_tag,''),version,coalesce(created_by::text,''),coalesce(updated_by::text,''),created_at,updated_at FROM events WHERE calendar_id=$1 AND (href=$2 OR uid=$3) FOR UPDATE`, calendarID, href, m.UID).Scan(&existing.ID, &existing.CalendarID, &existing.UID, &existing.Href, &existing.Summary, &existing.Start, &existing.End, &existing.ICS, &existing.ETag, &existing.ScheduleTag, &existing.Version, &existing.CreatedBy, &existing.UpdatedBy, &existing.CreatedAt, &existing.UpdatedAt)
	created := errors.Is(scanErr, pgx.ErrNoRows)
	if scanErr != nil && !created {
		return Event{}, false, scanErr
	}
	if created && strings.TrimSpace(ifMatch) != "" {
		return Event{}, false, errors.New("ETag-Vorbedingung nicht erfüllt.")
	}
	var scheduleChanges []string
	if !created {
		if s.isInvitationCopy(ctx, existing.ID) {
			return Event{}, false, errors.New("Einladungstermine werden über die Zu-/Absagefunktion verwaltet.")
		}
		raw = ical.PreserveAttendeeResponses(raw, existing.ICS)
		if ifMatch != "" && ifMatch != "*" && ifMatch != existing.ETag {
			return Event{}, false, errors.New("ETag stimmt nicht mehr überein.")
		}
		if !canEditEvent(role, cal.Mode, existing.CreatedBy, u.ID) {
			return Event{}, false, errors.New("Du darfst in diesem Kalender nur eigene Termine ändern.")
		}
		if existing.UID == m.UID && existing.Href != href {
			return Event{}, false, errors.New("UID wird bereits von einer anderen Kalender-Ressource verwendet.")
		}
		// Ignore client-only transport metadata such as DTSTAMP/SEQUENCE. A true
		// no-op must not create a version, webhook or scheduling email.
		if ical.EventContentEqual(existing.ICS, raw) {
			return existing, false, nil
		}
		scheduleChanges, err = ical.SchedulingChangeKeys(existing.ICS, raw)
		if err != nil {
			return Event{}, false, err
		}
		oldMeta, parseErr := ical.Parse(existing.ICS)
		if parseErr != nil {
			return Event{}, false, parseErr
		}
		raw, err = ical.EnsureSchedulingFields(raw, u.Name, u.Email, false)
		if err != nil {
			return Event{}, false, err
		}
		newMeta, parseErr := ical.Parse(raw)
		if parseErr != nil {
			return Event{}, false, parseErr
		}
		if len(newMeta.AttendeeDetails) > 0 {
			seq := oldMeta.Sequence
			if len(scheduleChanges) > 0 {
				seq++
			}
			raw = ical.SetSequence(raw, seq)
		}
	} else {
		raw, err = ical.EnsureSchedulingFields(raw, u.Name, u.Email, false)
		if err != nil {
			return Event{}, false, err
		}
		if newMeta, parseErr := ical.Parse(raw); parseErr == nil && len(newMeta.AttendeeDetails) > 0 {
			raw = ical.SetSequence(raw, 0)
		}
	}
	m, err = ical.Parse(raw)
	if err != nil {
		return Event{}, false, err
	}
	etag := ical.ETag(raw)
	scheduleTag := etag
	if !created {
		oldRaw := existing.ICS
		newVersion := existing.Version + 1
		_, err = tx.Exec(ctx, `UPDATE events SET uid=$1,href=$2,summary=$3,dtstart=$4,dtend=$5,ics=$6,etag=$7,schedule_tag=$8,version=$9,updated_by=$10,updated_at=now() WHERE id=$11`, m.UID, href, m.Summary, m.Start, m.End, raw, etag, scheduleTag, newVersion, u.ID, existing.ID)
		if err != nil {
			return Event{}, false, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO event_versions(id,event_id,version,action,ics,actor_user_id) VALUES($1,$2,$3,'updated',$4,$5)`, security.UUID(), existing.ID, newVersion, raw, u.ID)
		if err != nil {
			return Event{}, false, err
		}
		_, err = tx.Exec(ctx, `UPDATE calendars SET updated_at=now() WHERE id=$1`, calendarID)
		if err != nil {
			return Event{}, false, err
		}
		existing.Version = newVersion
		existing.ETag = etag
		existing.ScheduleTag = scheduleTag
		existing.ICS = raw
		existing.Summary = m.Summary
		existing.Start = m.Start
		existing.End = m.End
		existing.UpdatedBy = u.ID
		existing.UpdatedAt = time.Now()
		if err = tx.Commit(ctx); err != nil {
			return Event{}, false, err
		}
		s.Audit.Write(ctx, r, u.ID, "event.updated", "event", existing.ID, map[string]any{"calendar_id": calendarID, "version": newVersion})
		s.Webhooks.Emit(ctx, "event.updated", u.ID, "event", existing.ID, map[string]any{"calendar_id": calendarID, "version": newVersion})
		if s.Scheduling != nil && len(scheduleChanges) > 0 {
			if schedErr := s.Scheduling.SyncEvent(ctx, r, u, existing.ID, calendarID, oldRaw, raw, false, scheduleChanges); schedErr != nil {
				s.Audit.Write(ctx, r, u.ID, "event.scheduling_failed", "event", existing.ID, map[string]any{"error": schedErr.Error()})
			}
		}
		return existing, false, nil
	}
	id := security.UUID()
	_, err = tx.Exec(ctx, `INSERT INTO events(id,calendar_id,uid,href,summary,dtstart,dtend,ics,etag,schedule_tag,created_by,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)`, id, calendarID, m.UID, href, m.Summary, m.Start, m.End, raw, etag, scheduleTag, u.ID)
	if err != nil {
		return Event{}, false, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO event_versions(id,event_id,version,action,ics,actor_user_id) VALUES($1,$2,1,'created',$3,$4)`, security.UUID(), id, raw, u.ID)
	if err != nil {
		return Event{}, false, err
	}
	_, err = tx.Exec(ctx, `DELETE FROM event_tombstones WHERE calendar_id=$1 AND href=$2`, calendarID, href)
	if err != nil {
		return Event{}, false, err
	}
	_, err = tx.Exec(ctx, `UPDATE calendars SET updated_at=now() WHERE id=$1`, calendarID)
	if err != nil {
		return Event{}, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Event{}, false, err
	}
	s.Audit.Write(ctx, r, u.ID, "event.created", "event", id, map[string]any{"calendar_id": calendarID})
	s.Webhooks.Emit(ctx, "event.created", u.ID, "event", id, map[string]any{"calendar_id": calendarID})
	if s.Scheduling != nil {
		if schedErr := s.Scheduling.SyncEvent(ctx, r, u, id, calendarID, "", raw, true, nil); schedErr != nil {
			s.Audit.Write(ctx, r, u.ID, "event.scheduling_failed", "event", id, map[string]any{"error": schedErr.Error()})
		}
	}
	e, getErr := s.GetEvent(ctx, u, id)
	return e, true, getErr
}

func (s *Service) DeleteEvent(ctx context.Context, r *http.Request, u auth.User, calendarID, href string) error {
	role, err := s.Auth.CalendarRole(ctx, u.ID, calendarID)
	if err != nil || !auth.CanCreate(role) {
		return errors.New("Keine Löschberechtigung.")
	}
	cal, err := s.GetCalendar(ctx, u, calendarID)
	if err != nil {
		return errors.New("Kalender wurde nicht gefunden.")
	}
	var id, createdBy, raw string
	var version int
	err = s.DB.QueryRow(ctx, `SELECT id::text,coalesce(created_by::text,''),ics,version FROM events WHERE calendar_id=$1 AND href=$2`, calendarID, href).Scan(&id, &createdBy, &raw, &version)
	if err != nil {
		return err
	}
	if s.isInvitationCopy(ctx, id) {
		return errors.New("Einladungstermine werden über die Zu-/Absagefunktion verwaltet.")
	}
	if !canEditEvent(role, cal.Mode, createdBy, u.ID) {
		return errors.New("Du darfst in diesem Kalender nur eigene Termine löschen.")
	}
	if s.Scheduling != nil {
		if schedErr := s.Scheduling.CancelEvent(ctx, r, u, id, raw); schedErr != nil {
			s.Audit.Write(ctx, r, u.ID, "event.scheduling_failed", "event", id, map[string]any{"error": schedErr.Error()})
		}
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO event_versions(id,event_id,version,action,ics,actor_user_id) VALUES($1,$2,$3,'deleted',$4,$5)`, security.UUID(), id, version+1, raw, u.ID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO event_tombstones(calendar_id,href,deleted_at) VALUES($1,$2,now())`, calendarID, href)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `DELETE FROM events WHERE id=$1`, id)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE calendars SET updated_at=now() WHERE id=$1`, calendarID)
	if err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	s.Audit.Write(ctx, r, u.ID, "event.deleted", "event", id, map[string]any{"calendar_id": calendarID})
	s.Webhooks.Emit(ctx, "event.deleted", u.ID, "event", id, map[string]any{"calendar_id": calendarID})
	return nil
}
