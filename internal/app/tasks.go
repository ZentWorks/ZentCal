package app

import (
	"context"
	"errors"
	"net/http"
	"path"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/zentworks/zentcal/internal/auth"
	"github.com/zentworks/zentcal/internal/ical"
	"github.com/zentworks/zentcal/internal/security"
)

// PutTask stores VTODO without event scheduling, attendee invitations or
// personal-calendar summary rewriting. It shares ETags, tombstones, history
// and synchronization with the established event resource store.
func (s *Service) PutTask(ctx context.Context, r *http.Request, u auth.User, calendarID, href, raw, ifMatch string) (Event, bool, error) {
	c, err := s.GetCalendar(ctx, u, calendarID)
	if err != nil || c.Type != "tasks" || !auth.CanCreate(c.Role) {
		return Event{}, false, errors.New("Keine Schreibberechtigung für Erinnerungen.")
	}
	m, err := ical.ParseTask(raw)
	if err != nil {
		return Event{}, false, err
	}
	raw = ical.Normalize(raw)
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
	// Serialize writes to this calendar: concurrent UID/href changes cannot
	// create duplicates or overwrite another client's task unexpectedly.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, calendarID); err != nil {
		return Event{}, false, err
	}
	var old Event
	err = tx.QueryRow(ctx, `SELECT id::text,calendar_id::text,uid,href,summary,dtstart,dtend,ics,etag,coalesce(schedule_tag,''),version,coalesce(created_by::text,''),coalesce(updated_by::text,''),created_at,updated_at FROM events WHERE calendar_id=$1 AND (href=$2 OR uid=$3) FOR UPDATE`, calendarID, href, m.UID).Scan(&old.ID, &old.CalendarID, &old.UID, &old.Href, &old.Summary, &old.Start, &old.End, &old.ICS, &old.ETag, &old.ScheduleTag, &old.Version, &old.CreatedBy, &old.UpdatedBy, &old.CreatedAt, &old.UpdatedAt)
	created := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !created {
		return Event{}, false, err
	}
	if !created {
		if old.Href != href || old.UID != m.UID {
			return Event{}, false, errors.New("UID oder Pfad bereits vorhanden")
		}
		if ifMatch != "" && ifMatch != "*" && ifMatch != old.ETag {
			return Event{}, false, errors.New("ETag stimmt nicht mehr überein")
		}
		if !canEditEvent(c.Role, c.Mode, old.CreatedBy, u.ID) {
			return Event{}, false, errors.New("Keine Schreibberechtigung")
		}
		if old.ICS == raw {
			return old, false, nil
		}
	} else if ifMatch != "" {
		return Event{}, false, errors.New("ETag-Vorbedingung nicht erfüllt")
	}
	etag := ical.ETag(raw)
	if !created {
		ver := old.Version + 1
		_, err = tx.Exec(ctx, `UPDATE events SET summary=$1,dtstart=$2,dtend=$3,ics=$4,etag=$5,schedule_tag=$5,version=$6,updated_by=$7,updated_at=now() WHERE id=$8`, m.Summary, m.Start, m.End, raw, etag, ver, u.ID, old.ID)
		if err != nil {
			return Event{}, false, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO event_versions(id,event_id,version,action,ics,actor_user_id) VALUES($1,$2,$3,'updated',$4,$5)`, security.UUID(), old.ID, ver, raw, u.ID)
		if err != nil {
			return Event{}, false, err
		}
	} else {
		old.ID = security.UUID()
		_, err = tx.Exec(ctx, `INSERT INTO events(id,calendar_id,uid,href,summary,dtstart,dtend,ics,etag,schedule_tag,created_by,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,$10)`, old.ID, calendarID, m.UID, href, m.Summary, m.Start, m.End, raw, etag, u.ID)
		if err != nil {
			return Event{}, false, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO event_versions(id,event_id,version,action,ics,actor_user_id) VALUES($1,$2,1,'created',$3,$4)`, security.UUID(), old.ID, raw, u.ID)
		if err != nil {
			return Event{}, false, err
		}
		_, err = tx.Exec(ctx, `DELETE FROM event_tombstones WHERE calendar_id=$1 AND href=$2`, calendarID, href)
		if err != nil {
			return Event{}, false, err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE calendars SET updated_at=now() WHERE id=$1`, calendarID)
	if err != nil {
		return Event{}, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Event{}, false, err
	}
	if created {
		s.Audit.Write(ctx, r, u.ID, "task.created", "task", old.ID, map[string]any{"calendar_id": calendarID})
	} else {
		s.Audit.Write(ctx, r, u.ID, "task.updated", "task", old.ID, map[string]any{"calendar_id": calendarID})
	}
	e, getErr := s.GetEvent(ctx, u, old.ID)
	return e, created, getErr
}
