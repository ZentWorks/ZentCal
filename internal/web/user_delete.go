package web

import (
	"context"
	"net/http"
	"strings"

	"github.com/zentworks/zentcal/internal/httpx"
)

type ownedCalendarInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (h *Handler) exclusivelyOwnedCalendars(ctx context.Context, userID string) ([]ownedCalendarInfo, error) {
	rows, err := h.DB.Query(ctx, `SELECT c.id::text,c.name
FROM calendars c
JOIN memberships m ON m.calendar_id=c.id AND m.user_id=$1 AND m.role='owner'
WHERE c.deleted_at IS NULL AND coalesce(c.system_kind,'')='' AND NOT c.admin_managed
  AND NOT EXISTS (
    SELECT 1 FROM memberships other
    WHERE other.calendar_id=c.id AND other.user_id<>$1 AND other.role='owner'
  )
ORDER BY lower(c.name)`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ownedCalendarInfo, 0)
	for rows.Next() {
		var item ownedCalendarInfo
		if err := rows.Scan(&item.ID, &item.Name); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (h *Handler) userDeleteInfo(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminJSON(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if id == ss.User.ID {
		httpx.Error(w, 400, "Das eigene Konto kann nicht gelöscht werden.")
		return
	}
	var name, email, role string
	if err := h.DB.QueryRow(r.Context(), `SELECT name,email,role FROM users WHERE id=$1`, id).Scan(&name, &email, &role); err != nil {
		httpx.Error(w, 404, "Benutzer nicht gefunden.")
		return
	}
	if role == "owner" {
		var otherOwners int
		_ = h.DB.QueryRow(r.Context(), `SELECT count(*) FROM users WHERE role='owner' AND status='active' AND id<>$1`, id).Scan(&otherOwners)
		if otherOwners == 0 {
			httpx.Error(w, 400, "Der letzte aktive ZentCal-Owner kann nicht gelöscht werden.")
			return
		}
	}
	owned, err := h.exclusivelyOwnedCalendars(r.Context(), id)
	if err != nil {
		httpx.Error(w, 500, "Kalenderbesitz konnte nicht geprüft werden.")
		return
	}
	rows, err := h.DB.Query(r.Context(), `SELECT id::text,name,email FROM users WHERE id<>$1 AND status='active' ORDER BY lower(name),lower(email) LIMIT 200`, id)
	if err != nil {
		httpx.Error(w, 500, "Mögliche neue Eigentümer konnten nicht geladen werden.")
		return
	}
	defer rows.Close()
	owners := make([]map[string]string, 0)
	for rows.Next() {
		var oid, oname, oemail string
		if rows.Scan(&oid, &oname, &oemail) == nil {
			owners = append(owners, map[string]string{"id": oid, "name": oname, "email": oemail})
		}
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "data": map[string]any{
		"id": id, "name": name, "email": email, "role": role, "owned_calendars": owned, "replacement_users": owners,
	}})
}

func (h *Handler) deleteUserUI(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	id := r.PathValue("id")
	if id == ss.User.ID {
		httpx.Error(w, 400, "Das eigene Konto kann nicht gelöscht werden.")
		return
	}
	var role, name, email string
	if err := h.DB.QueryRow(r.Context(), `SELECT role,name,email FROM users WHERE id=$1`, id).Scan(&role, &name, &email); err != nil {
		httpx.Error(w, 404, "Benutzer nicht gefunden.")
		return
	}
	if role == "owner" {
		var otherOwners int
		_ = h.DB.QueryRow(r.Context(), `SELECT count(*) FROM users WHERE role='owner' AND status='active' AND id<>$1`, id).Scan(&otherOwners)
		if otherOwners == 0 {
			httpx.Error(w, 400, "Der letzte aktive ZentCal-Owner kann nicht gelöscht werden.")
			return
		}
	}
	owned, err := h.exclusivelyOwnedCalendars(r.Context(), id)
	if err != nil {
		httpx.Error(w, 500, "Kalenderbesitz konnte nicht geprüft werden.")
		return
	}
	action := strings.TrimSpace(r.FormValue("calendar_action"))
	newOwnerID := strings.TrimSpace(r.FormValue("new_owner_id"))
	if len(owned) > 0 {
		if action != "transfer" && action != "delete" {
			httpx.Error(w, 400, "Für die allein verwalteten Kalender muss eine Entscheidung getroffen werden.")
			return
		}
		if action == "transfer" {
			if newOwnerID == "" || newOwnerID == id {
				httpx.Error(w, 400, "Bitte einen gültigen neuen Eigentümer auswählen.")
				return
			}
			var active bool
			if err := h.DB.QueryRow(r.Context(), `SELECT status='active' FROM users WHERE id=$1`, newOwnerID).Scan(&active); err != nil || !active {
				httpx.Error(w, 400, "Der neue Eigentümer ist nicht verfügbar.")
				return
			}
		}
	}

	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		httpx.Error(w, 500, "Benutzer konnte nicht gelöscht werden.")
		return
	}
	defer tx.Rollback(r.Context())
	// Serialize destructive user operations so two concurrent deletions cannot
	// both pass the "last active owner" check.
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtext('zentcal:user-delete'))`); err != nil {
		httpx.Error(w, 500, "Benutzer konnte nicht gesperrt werden.")
		return
	}
	if err = tx.QueryRow(r.Context(), `SELECT role FROM users WHERE id=$1 FOR UPDATE`, id).Scan(&role); err != nil {
		httpx.Error(w, 404, "Benutzer nicht gefunden.")
		return
	}
	if role == "owner" {
		var otherOwners int
		if err = tx.QueryRow(r.Context(), `SELECT count(*) FROM users WHERE role='owner' AND status='active' AND id<>$1`, id).Scan(&otherOwners); err != nil {
			httpx.Error(w, 500, "Owner konnten nicht geprüft werden.")
			return
		}
		if otherOwners == 0 {
			httpx.Error(w, 400, "Der letzte aktive ZentCal-Owner kann nicht gelöscht werden.")
			return
		}
	}
	// Serialize against member role changes. Re-evaluate sole ownership only
	// after all calendars currently owned by the account are locked.
	ownerRows, ownerErr := tx.Query(r.Context(), `SELECT c.id::text FROM calendars c JOIN memberships m ON m.calendar_id=c.id WHERE m.user_id=$1 AND m.role='owner' AND c.deleted_at IS NULL AND coalesce(c.system_kind,'')='' AND NOT c.admin_managed ORDER BY c.id::text`, id)
	if ownerErr != nil {
		httpx.Error(w, 500, "Kalenderbesitz konnte nicht geprüft werden.")
		return
	}
	ownerIDs := make([]string, 0)
	for ownerRows.Next() {
		var calendarID string
		if ownerErr = ownerRows.Scan(&calendarID); ownerErr != nil {
			ownerRows.Close()
			httpx.Error(w, 500, "Kalenderbesitz konnte nicht geprüft werden.")
			return
		}
		ownerIDs = append(ownerIDs, calendarID)
	}
	if ownerErr = ownerRows.Err(); ownerErr != nil {
		ownerRows.Close()
		httpx.Error(w, 500, "Kalenderbesitz konnte nicht geprüft werden.")
		return
	}
	ownerRows.Close()
	for _, calendarID := range ownerIDs {
		if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtext($1))`, calendarID); err != nil {
			httpx.Error(w, 500, "Kalender konnten nicht gesperrt werden.")
			return
		}
	}
	currentRows, currentErr := tx.Query(r.Context(), `SELECT c.id::text,c.name
FROM calendars c
JOIN memberships m ON m.calendar_id=c.id AND m.user_id=$1 AND m.role='owner'
WHERE c.deleted_at IS NULL AND coalesce(c.system_kind,'')='' AND NOT c.admin_managed
  AND NOT EXISTS (SELECT 1 FROM memberships other WHERE other.calendar_id=c.id AND other.user_id<>$1 AND other.role='owner')
ORDER BY lower(c.name),c.id::text`, id)
	if currentErr != nil {
		httpx.Error(w, 500, "Kalenderbesitz konnte nicht geprüft werden.")
		return
	}
	owned = owned[:0]
	for currentRows.Next() {
		var item ownedCalendarInfo
		if currentErr = currentRows.Scan(&item.ID, &item.Name); currentErr != nil {
			currentRows.Close()
			httpx.Error(w, 500, "Kalenderbesitz konnte nicht geprüft werden.")
			return
		}
		owned = append(owned, item)
	}
	if currentErr = currentRows.Err(); currentErr != nil {
		currentRows.Close()
		httpx.Error(w, 500, "Kalenderbesitz konnte nicht geprüft werden.")
		return
	}
	currentRows.Close()
	if len(owned) > 0 {
		if action != "transfer" && action != "delete" {
			httpx.Error(w, 409, "Der Kalenderbesitz hat sich geändert. Bitte den Löschdialog neu öffnen.")
			return
		}
		if action == "transfer" {
			if newOwnerID == "" || newOwnerID == id {
				httpx.Error(w, 400, "Bitte einen gültigen neuen Eigentümer auswählen.")
				return
			}
			var active bool
			if err = tx.QueryRow(r.Context(), `SELECT status='active' FROM users WHERE id=$1`, newOwnerID).Scan(&active); err != nil || !active {
				httpx.Error(w, 400, "Der neue Eigentümer ist nicht verfügbar.")
				return
			}
		}
	}

	deletedCalendars := make([]ownedCalendarInfo, 0)
	transferredCalendars := make([]ownedCalendarInfo, 0)
	for _, cal := range owned {
		if action == "delete" {
			if _, err = tx.Exec(r.Context(), `DELETE FROM event_versions WHERE event_id IN (SELECT id FROM events WHERE calendar_id=$1) OR event_id IN (SELECT ea.attendee_event_id FROM event_attendees ea JOIN events e ON e.id=ea.event_id WHERE e.calendar_id=$1 AND ea.attendee_event_id IS NOT NULL)`, cal.ID); err != nil {
				httpx.Error(w, 500, "Kalenderhistorie konnte nicht gelöscht werden.")
				return
			}
			if _, err = tx.Exec(r.Context(), `DELETE FROM scheduling_deliveries WHERE event_id IN (SELECT id FROM events WHERE calendar_id=$1)`, cal.ID); err != nil {
				httpx.Error(w, 500, "Kalenderzustellungen konnten nicht gelöscht werden.")
				return
			}
			if _, err = tx.Exec(r.Context(), `DELETE FROM scheduling_messages WHERE event_id IN (SELECT id FROM events WHERE calendar_id=$1)`, cal.ID); err != nil {
				httpx.Error(w, 500, "Kalendernachrichten konnten nicht gelöscht werden.")
				return
			}
			if _, err = tx.Exec(r.Context(), `DELETE FROM events WHERE id IN (SELECT ea.attendee_event_id FROM event_attendees ea JOIN events e ON e.id=ea.event_id WHERE e.calendar_id=$1 AND ea.attendee_event_id IS NOT NULL)`, cal.ID); err != nil {
				httpx.Error(w, 500, "Einladungskopien konnten nicht gelöscht werden.")
				return
			}
			if _, err = tx.Exec(r.Context(), `DELETE FROM calendars WHERE id=$1 AND deleted_at IS NULL AND coalesce(system_kind,'')=''`, cal.ID); err != nil {
				httpx.Error(w, 500, "Kalender konnten nicht gelöscht werden.")
				return
			}
			deletedCalendars = append(deletedCalendars, cal)
		} else {
			if _, err = tx.Exec(r.Context(), `INSERT INTO memberships(calendar_id,user_id,role,dav_name) VALUES($1,$2,'owner',$3)
ON CONFLICT(calendar_id,user_id) DO UPDATE SET role='owner'`, cal.ID, newOwnerID, cal.ID); err != nil {
				httpx.Error(w, 500, "Kalender konnten nicht übertragen werden.")
				return
			}
			if _, err = tx.Exec(r.Context(), `UPDATE calendars SET created_by=CASE WHEN created_by=$1 THEN $2 ELSE created_by END,updated_at=now() WHERE id=$3`, id, newOwnerID, cal.ID); err != nil {
				httpx.Error(w, 500, "Kalender konnten nicht übertragen werden.")
				return
			}
			transferredCalendars = append(transferredCalendars, cal)
		}
	}

	// Event versions and queued deliveries do not have cascading calendar
	// foreign keys. Remove those copies before deleting the personal calendar
	// so personal event content is not left behind.
	if _, err = tx.Exec(r.Context(), `DELETE FROM event_versions WHERE event_id IN (SELECT e.id FROM events e JOIN calendars c ON c.id=e.calendar_id WHERE c.system_owner_user_id=$1 AND c.system_kind='personal')`, id); err != nil {
		httpx.Error(w, 500, "Persönliche Terminhistorie konnte nicht entfernt werden.")
		return
	}
	if _, err = tx.Exec(r.Context(), `DELETE FROM scheduling_deliveries WHERE event_id IN (SELECT e.id FROM events e JOIN calendars c ON c.id=e.calendar_id WHERE c.system_owner_user_id=$1 AND c.system_kind='personal')`, id); err != nil {
		httpx.Error(w, 500, "Persönliche Zustellungen konnten nicht entfernt werden.")
		return
	}
	if _, err = tx.Exec(r.Context(), `DELETE FROM scheduling_messages WHERE event_id IN (SELECT e.id FROM events e JOIN calendars c ON c.id=e.calendar_id WHERE c.system_owner_user_id=$1 AND c.system_kind='personal')`, id); err != nil {
		httpx.Error(w, 500, "Persönliche Scheduling-Nachrichten konnten nicht entfernt werden.")
		return
	}
	if _, err = tx.Exec(r.Context(), `DELETE FROM calendars WHERE system_owner_user_id=$1 AND system_kind='personal'`, id); err != nil {
		httpx.Error(w, 500, "Persönlicher Kalender konnte nicht entfernt werden.")
		return
	}
	// Centrally managed calendars survive owner/manager deletion without exposing
	// their contents to the acting admin. If the deleted account was the
	// administrative manager, transfer only the administrative responsibility.
	if _, err = tx.Exec(r.Context(), `UPDATE calendars
SET admin_manager_user_id=$1,admin_manager_visible=false,created_by=CASE WHEN created_by=$2 THEN $1 ELSE created_by END,updated_at=now()
WHERE admin_managed AND admin_manager_user_id=$2 AND deleted_at IS NULL`, ss.User.ID, id); err != nil {
		httpx.Error(w, 500, "Administrative Kalenderverwaltung konnte nicht übertragen werden.")
		return
	}
	// Remaining shared calendars stay intact. Reassign only the technical creator
	// reference so deleting the user cannot violate the users foreign key.
	if _, err = tx.Exec(r.Context(), `UPDATE calendars SET created_by=$1 WHERE created_by=$2`, ss.User.ID, id); err != nil {
		httpx.Error(w, 500, "Kalenderreferenzen konnten nicht bereinigt werden.")
		return
	}
	for _, stmt := range []string{
		`UPDATE events SET created_by=NULL WHERE created_by=$1`,
		`UPDATE events SET updated_by=NULL WHERE updated_by=$1`,
		`UPDATE event_versions SET actor_user_id=NULL WHERE actor_user_id=$1`,
		`UPDATE invitations SET invited_by=NULL WHERE invited_by=$1`,
	} {
		if _, err = tx.Exec(r.Context(), stmt, id); err != nil {
			httpx.Error(w, 500, "Benutzerreferenzen konnten nicht bereinigt werden.")
			return
		}
	}
	ct, err := tx.Exec(r.Context(), `DELETE FROM users WHERE id=$1`, id)
	if err != nil || ct.RowsAffected() != 1 {
		httpx.Error(w, 500, "Benutzer konnte nicht gelöscht werden.")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		httpx.Error(w, 500, "Benutzer konnte nicht gelöscht werden.")
		return
	}

	details := map[string]any{"transferred_calendars": transferredCalendars, "deleted_calendars": deletedCalendars}
	h.Audit.Write(r.Context(), r, ss.User.ID, "user.deleted", "user", id, details)
	h.Webhooks.Emit(r.Context(), "user.deleted", ss.User.ID, "user", id, details)
	httpx.JSON(w, 200, map[string]any{"ok": true, "message": "Benutzer wurde gelöscht.", "reload": true})
}
