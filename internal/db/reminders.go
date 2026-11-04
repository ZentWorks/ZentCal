package db

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zentworks/zentcal/internal/security"
)

// Keep UUID identifiers and text DAV names in independent bind parameters.
// PostgreSQL cannot infer one parameter as both uuid and text, even when the
// underlying string values are identical.
const remindersCalendarInsertSQL = `INSERT INTO calendars(id,name,description,color,type,mode,created_by,system_kind,system_owner_user_id,dav_name)
VALUES($1,'Erinnerungen','','#e39d42','tasks','normal',$2,'reminders',$2,$3)
ON CONFLICT DO NOTHING`

const remindersMembershipUpsertSQL = `INSERT INTO memberships(calendar_id,user_id,role,dav_name) VALUES($1,$2,'owner',$3)
ON CONFLICT(calendar_id,user_id) DO UPDATE SET role='owner',dav_name=excluded.dav_name
WHERE memberships.role<>'owner' OR memberships.dav_name<>excluded.dav_name`

// EnsureReminders creates a private, non-deletable default VTODO collection.
// The uniqueness constraint on (system_owner_user_id, system_kind) makes
// repeated calls safe when multiple clients discover the account concurrently.
func EnsureReminders(ctx context.Context, q calendarStore, userID string) (string, error) {
	var id string
	err := q.QueryRow(ctx, `SELECT id::text FROM calendars WHERE system_owner_user_id=$1 AND system_kind='reminders' AND deleted_at IS NULL`, userID).Scan(&id)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		id = security.UUID()
		_, err = q.Exec(ctx, remindersCalendarInsertSQL, id, userID, id)
		if err != nil {
			return "", err
		}
		err = q.QueryRow(ctx, `SELECT id::text FROM calendars WHERE system_owner_user_id=$1 AND system_kind='reminders' AND deleted_at IS NULL`, userID).Scan(&id)
		if err != nil {
			return "", err
		}
	}
	_, err = q.Exec(ctx, remindersMembershipUpsertSQL, id, userID, id)
	return id, err
}

func EnsureAllReminders(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, `SELECT id::text FROM users WHERE status<>'invited'`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err = EnsureReminders(ctx, pool, id); err != nil {
			return err
		}
	}
	return nil
}
