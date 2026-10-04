package db

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zentworks/zentcal/internal/security"
)

type calendarStore interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func personalCalendarName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "Persönlicher Kalender"
	}
	return name
}

// EnsurePersonalCalendar guarantees exactly one non-deletable personal calendar
// for a user. Existing legacy invitation calendars are upgraded in place so
// pending invitation copies are preserved instead of orphaned.
func EnsurePersonalCalendar(ctx context.Context, q calendarStore, userID, name string) (string, error) {
	name = personalCalendarName(name)
	var calendarID string
	err := q.QueryRow(ctx, `SELECT id::text FROM calendars WHERE system_owner_user_id=$1 AND system_kind='personal' AND deleted_at IS NULL`, userID).Scan(&calendarID)
	if err == nil {
		_, err = q.Exec(ctx, `UPDATE calendars SET name=$2,updated_at=CASE WHEN name<>$2 THEN now() ELSE updated_at END WHERE id=$1`, calendarID, name)
		if err != nil {
			return "", err
		}
		_, err = q.Exec(ctx, `INSERT INTO memberships(calendar_id,user_id,role,dav_name) VALUES($1,$2,'owner',$3) ON CONFLICT(calendar_id,user_id) DO UPDATE SET role='owner',dav_name=excluded.dav_name`, calendarID, userID, calendarID)
		return calendarID, err
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	// Reuse the former hidden invitation calendar when present. This keeps all
	// already materialized invitation copies intact while moving to the simpler
	// one-personal-calendar model.
	err = q.QueryRow(ctx, `SELECT id::text FROM calendars WHERE system_owner_user_id=$1 AND system_kind='invitations' AND deleted_at IS NULL`, userID).Scan(&calendarID)
	if err == nil {
		if _, err = q.Exec(ctx, `UPDATE calendars SET system_kind='personal',name=$2,updated_at=now() WHERE id=$1`, calendarID, name); err != nil {
			return "", err
		}
		_, err = q.Exec(ctx, `INSERT INTO memberships(calendar_id,user_id,role,dav_name) VALUES($1,$2,'owner',$3) ON CONFLICT(calendar_id,user_id) DO UPDATE SET role='owner',dav_name=excluded.dav_name`, calendarID, userID, calendarID)
		return calendarID, err
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	calendarID = security.UUID()
	_, err = q.Exec(ctx, `INSERT INTO calendars(id,name,description,color,type,mode,created_by,system_kind,system_owner_user_id,dav_name)
VALUES($1,$2,'','#4f8cff','calendar','normal',$3,'personal',$3,$4)`, calendarID, name, userID, calendarID)
	if err != nil {
		// A concurrent creator may have won the unique (owner, kind) race.
		if scanErr := q.QueryRow(ctx, `SELECT id::text FROM calendars WHERE system_owner_user_id=$1 AND system_kind='personal' AND deleted_at IS NULL`, userID).Scan(&calendarID); scanErr != nil {
			return "", err
		}
	}
	_, err = q.Exec(ctx, `INSERT INTO memberships(calendar_id,user_id,role,dav_name) VALUES($1,$2,'owner',$3) ON CONFLICT(calendar_id,user_id) DO UPDATE SET role='owner',dav_name=excluded.dav_name`, calendarID, userID, calendarID)
	return calendarID, err
}

func EnsurePersonalCalendars(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, `SELECT id::text,name FROM users WHERE status<>'invited' ORDER BY created_at`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type user struct{ id, name string }
	var users []user
	for rows.Next() {
		var u user
		if err := rows.Scan(&u.id, &u.name); err != nil {
			return err
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, u := range users {
		if _, err := EnsurePersonalCalendar(ctx, pool, u.id, u.name); err != nil {
			return err
		}
	}
	return nil
}
