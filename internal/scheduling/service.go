package scheduling

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zentworks/zentcal/internal/audit"
	"github.com/zentworks/zentcal/internal/auth"
	"github.com/zentworks/zentcal/internal/db"
	"github.com/zentworks/zentcal/internal/ical"
	mailpkg "github.com/zentworks/zentcal/internal/mail"
	"github.com/zentworks/zentcal/internal/security"
)

type Service struct {
	DB           *pgxpool.Pool
	Secrets      *security.SecretBox
	Audit        *audit.Logger
	Log          *slog.Logger
	Paused       func() bool
	MailDelivery *mailpkg.DeliveryService
	BaseURL      string
}

type Message struct {
	ID, UserID, EventID, Direction, Method, Href, ICS, ScheduleTag string
	CreatedAt                                                      time.Time
	ProcessedAt                                                    *time.Time
}

type DeliveryResult struct {
	Recipient string
	Status    string
}

func New(db *pgxpool.Pool, secrets *security.SecretBox, auditLog *audit.Logger, log *slog.Logger, baseURL string) *Service {
	return &Service{DB: db, Secrets: secrets, Audit: auditLog, Log: log, BaseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/")}
}

func (s *Service) Run(ctx context.Context) {
	// A process can stop after a delivery was claimed but before SMTP returned.
	// Requeue those durable jobs on startup instead of leaving them in sending forever.
	_, _ = s.DB.Exec(ctx, `UPDATE scheduling_deliveries SET status='failed',next_attempt_at=now(),last_error=CASE WHEN last_error='' THEN 'Delivery wurde durch Neustart unterbrochen.' ELSE last_error END WHERE status='sending'`)
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.Paused != nil && s.Paused() {
				continue
			}
			s.processDeliveries(ctx)
		}
	}
}

func (s *Service) Cleanup(ctx context.Context) error {
	if _, err := s.DB.Exec(ctx, `DELETE FROM scheduling_deliveries WHERE status IN ('success','failed') AND created_at < now()-interval '30 days'`); err != nil {
		return err
	}
	if _, err := s.DB.Exec(ctx, `DELETE FROM scheduling_messages WHERE processed_at IS NOT NULL AND processed_at < now()-interval '30 days'`); err != nil {
		return err
	}
	if _, err := s.DB.Exec(ctx, `DELETE FROM event_versions WHERE created_at < now()-interval '60 days'`); err != nil {
		return err
	}
	return nil
}
func (s *Service) RegisterPublic(mux *http.ServeMux) {
	mux.HandleFunc("GET /invite/respond/{token}/{action}", s.responsePage)
	mux.HandleFunc("POST /invite/respond/{token}/{action}", s.responseSubmit)
}

func (s *Service) SyncEvent(ctx context.Context, r *http.Request, actor auth.User, eventID, calendarID, oldRaw, newRaw string, created bool, changeKeys []string) error {
	m, err := ical.Parse(newRaw)
	if err != nil {
		return err
	}
	if len(m.AttendeeDetails) == 0 {
		if oldRaw != "" {
			return s.cancelRemovedAttendees(ctx, r, actor, eventID, oldRaw, newRaw)
		}
		return nil
	}
	method := "REQUEST"
	requestICS := ical.SetMethod(newRaw, method)
	baseURL := s.baseURL()
	old := map[string]ical.Attendee{}
	if oldRaw != "" {
		if om, e := ical.Parse(oldRaw); e == nil {
			for _, a := range om.AttendeeDetails {
				old[strings.ToLower(a.Email)] = a
			}
		}
	}
	seen := map[string]bool{}
	for _, a := range m.AttendeeDetails {
		emailAddr := strings.ToLower(strings.TrimSpace(a.Email))
		if emailAddr == "" || strings.EqualFold(emailAddr, m.OrganizerEmail) {
			continue
		}
		seen[emailAddr] = true
		var userID string
		_ = s.DB.QueryRow(ctx, `SELECT id::text FROM users WHERE lower(email)=lower($1) AND status='active'`, emailAddr).Scan(&userID)
		partstat := normalizePartStat(a.PartStat)
		var attendeeID string
		// Preserve an existing response token. Generate one for a new attendee.
		var currentHash, currentSecret string
		qerr := s.DB.QueryRow(ctx, `SELECT id::text,coalesce(response_token_hash,''),coalesce(response_token_secret,'') FROM event_attendees WHERE event_id=$1 AND lower(email)=lower($2)`, eventID, emailAddr).Scan(&attendeeID, &currentHash, &currentSecret)
		isNewAttendee := errors.Is(qerr, pgx.ErrNoRows)
		if qerr != nil && !isNewAttendee {
			return qerr
		}
		if isNewAttendee {
			attendeeID = security.UUID()
			token, e := security.RandomToken(32)
			if e != nil {
				return e
			}
			tokenHash := security.TokenHash(token)
			encryptedToken, e := s.Secrets.Encrypt(token)
			if e != nil {
				return e
			}
			_, err = s.DB.Exec(ctx, `INSERT INTO event_attendees(id,event_id,email,user_id,cn,partstat,rsvp,response_token_hash,response_token_secret,response_expires_at)
VALUES($1,$2,$3,NULLIF($4,'')::uuid,$5,$6,true,$7,$8,now()+interval '180 days')`, attendeeID, eventID, emailAddr, userID, a.CN, partstat, tokenHash, encryptedToken)
		} else {
			_, err = s.DB.Exec(ctx, `UPDATE event_attendees SET user_id=NULLIF($3,'')::uuid,cn=$4,partstat=CASE WHEN $5='NEEDS-ACTION' AND partstat<>'NEEDS-ACTION' THEN partstat ELSE $5 END,rsvp=true,response_expires_at=now()+interval '180 days',updated_at=now() WHERE id=$1 AND event_id=$2`, attendeeID, eventID, userID, a.CN, partstat)
		}
		if err != nil {
			return err
		}
		templateKind := "event_update"
		if created || isNewAttendee {
			templateKind = "event_invite"
		}
		if userID != "" {
			if _, err := s.upsertInvitationCopy(ctx, eventID, userID, emailAddr, requestICS); err != nil {
				return err
			}
			if err := s.enqueueInbox(ctx, userID, eventID, method, requestICS); err != nil {
				return err
			}
			// Local ZentCal users also receive the normal invitation mail when SMTP
			// is enabled. The personal calendar remains the canonical in-app target.
			if err := s.enqueueExternal(ctx, eventID, emailAddr, method, requestICS, baseURL, templateKind, changeKeys); err != nil {
				return err
			}
		} else {
			if err := s.enqueueExternal(ctx, eventID, emailAddr, method, requestICS, baseURL, templateKind, changeKeys); err != nil {
				return err
			}
		}
		action := "invitation.updated"
		if created {
			action = "invitation.sent"
		} else if _, existed := old[emailAddr]; !existed {
			action = "invitation.sent"
		}
		s.Audit.Write(ctx, r, actor.ID, action, "event", eventID, map[string]any{"calendar_id": calendarID, "attendee": emailAddr, "internal": userID != ""})
	}
	if oldRaw != "" {
		if om, e := ical.Parse(oldRaw); e == nil {
			cancelICS, _ := ical.BuildCancel(oldRaw)
			for _, a := range om.AttendeeDetails {
				emailAddr := strings.ToLower(strings.TrimSpace(a.Email))
				if emailAddr == "" || seen[emailAddr] || strings.EqualFold(emailAddr, om.OrganizerEmail) {
					continue
				}
				var userID string
				_ = s.DB.QueryRow(ctx, `SELECT id::text FROM users WHERE lower(email)=lower($1) AND status='active'`, emailAddr).Scan(&userID)
				if userID != "" {
					_ = s.enqueueInbox(ctx, userID, eventID, "CANCEL", cancelICS)
					_ = s.removeInvitationCopy(ctx, eventID, emailAddr)
					_ = s.enqueueExternal(ctx, eventID, emailAddr, "CANCEL", cancelICS, baseURL, "event_cancel", nil)
				} else {
					_ = s.enqueueExternal(ctx, eventID, emailAddr, "CANCEL", cancelICS, baseURL, "event_cancel", nil)
				}
				_, _ = s.DB.Exec(ctx, `DELETE FROM event_attendees WHERE event_id=$1 AND lower(email)=lower($2)`, eventID, emailAddr)
				s.Audit.Write(ctx, r, actor.ID, "invitation.cancelled", "event", eventID, map[string]any{"calendar_id": calendarID, "attendee": emailAddr})
			}
		}
	}
	return nil
}

func (s *Service) cancelRemovedAttendees(ctx context.Context, r *http.Request, actor auth.User, eventID, oldRaw, newRaw string) error {
	om, err := ical.Parse(oldRaw)
	if err != nil || len(om.AttendeeDetails) == 0 {
		return err
	}
	cancelICS, err := ical.BuildCancel(oldRaw)
	if err != nil {
		return err
	}
	baseURL := s.baseURL()
	for _, a := range om.AttendeeDetails {
		emailAddr := strings.ToLower(strings.TrimSpace(a.Email))
		if emailAddr == "" || strings.EqualFold(emailAddr, om.OrganizerEmail) {
			continue
		}
		var userID string
		_ = s.DB.QueryRow(ctx, `SELECT id::text FROM users WHERE lower(email)=lower($1) AND status='active'`, emailAddr).Scan(&userID)
		if userID != "" {
			_ = s.enqueueInbox(ctx, userID, eventID, "CANCEL", cancelICS)
			_ = s.removeInvitationCopy(ctx, eventID, emailAddr)
			_ = s.enqueueExternal(ctx, eventID, emailAddr, "CANCEL", cancelICS, baseURL, "event_cancel", nil)
		} else {
			_ = s.enqueueExternal(ctx, eventID, emailAddr, "CANCEL", cancelICS, baseURL, "event_cancel", nil)
		}
	}
	_, _ = s.DB.Exec(ctx, `DELETE FROM event_attendees WHERE event_id=$1`, eventID)
	return nil
}

func (s *Service) CancelEvent(ctx context.Context, r *http.Request, actor auth.User, eventID, raw string) error {
	m, err := ical.Parse(raw)
	if err != nil || len(m.AttendeeDetails) == 0 {
		return err
	}
	cancelICS, err := ical.BuildCancel(raw)
	if err != nil {
		return err
	}
	baseURL := s.baseURL()
	for _, a := range m.AttendeeDetails {
		emailAddr := strings.ToLower(strings.TrimSpace(a.Email))
		if emailAddr == "" || strings.EqualFold(emailAddr, m.OrganizerEmail) {
			continue
		}
		var userID string
		_ = s.DB.QueryRow(ctx, `SELECT id::text FROM users WHERE lower(email)=lower($1) AND status='active'`, emailAddr).Scan(&userID)
		if userID != "" {
			_ = s.enqueueInbox(ctx, userID, eventID, "CANCEL", cancelICS)
			_ = s.removeInvitationCopy(ctx, eventID, emailAddr)
			_ = s.enqueueExternal(ctx, eventID, emailAddr, "CANCEL", cancelICS, baseURL, "event_cancel", nil)
		} else {
			_ = s.enqueueExternal(ctx, eventID, emailAddr, "CANCEL", cancelICS, baseURL, "event_cancel", nil)
		}
		s.Audit.Write(ctx, r, actor.ID, "invitation.cancelled", "event", eventID, map[string]any{"attendee": emailAddr})
	}
	return nil
}

func (s *Service) enqueueInbox(ctx context.Context, userID, eventID, method, raw string) error {
	method = strings.ToUpper(method)
	if method == "REQUEST" || method == "CANCEL" {
		_, _ = s.DB.Exec(ctx, `DELETE FROM scheduling_messages WHERE user_id=$1 AND event_id=$2 AND direction='inbox' AND method IN ('REQUEST','CANCEL')`, userID, eventID)
	}
	href := security.UUID() + ".ics"
	tag := ical.ETag(raw)
	_, err := s.DB.Exec(ctx, `INSERT INTO scheduling_messages(id,user_id,event_id,direction,method,href,ics,schedule_tag) VALUES($1,$2,$3,'inbox',$4,$5,$6,$7)`, security.UUID(), userID, eventID, method, href, raw, tag)
	return err
}

func (s *Service) enqueueExternal(ctx context.Context, eventID, emailAddr, method, raw, baseURL, templateKind string, changeKeys []string) error {
	_, enabled, err := s.smtpConfig(ctx)
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	method = strings.ToUpper(method)
	// Drop obsolete queued messages for the same attendee. iTIP SEQUENCE protects clients,
	// but avoiding stale queued mail is clearer for human recipients too.
	_, _ = s.DB.Exec(ctx, `DELETE FROM scheduling_deliveries WHERE event_id=$1 AND lower(recipient_email)=lower($2) AND status IN ('pending','failed')`, eventID, emailAddr)
	_, err = s.DB.Exec(ctx, `INSERT INTO scheduling_deliveries(id,event_id,recipient_email,method,ics,base_url,template_kind,change_keys) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, security.UUID(), eventID, emailAddr, method, raw, baseURL, templateKind, strings.Join(changeKeys, ","))
	return err
}

func (s *Service) ListMessages(ctx context.Context, userID, direction string) ([]Message, error) {
	rows, err := s.DB.Query(ctx, `SELECT id::text,user_id::text,coalesce(event_id::text,''),direction,method,href,ics,schedule_tag,created_at,processed_at FROM scheduling_messages WHERE user_id=$1 AND direction=$2 ORDER BY created_at DESC`, userID, direction)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.UserID, &m.EventID, &m.Direction, &m.Method, &m.Href, &m.ICS, &m.ScheduleTag, &m.CreatedAt, &m.ProcessedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Service) GetMessage(ctx context.Context, userID, direction, href string) (Message, error) {
	var m Message
	err := s.DB.QueryRow(ctx, `SELECT id::text,user_id::text,coalesce(event_id::text,''),direction,method,href,ics,schedule_tag,created_at,processed_at FROM scheduling_messages WHERE user_id=$1 AND direction=$2 AND href=$3`, userID, direction, href).Scan(&m.ID, &m.UserID, &m.EventID, &m.Direction, &m.Method, &m.Href, &m.ICS, &m.ScheduleTag, &m.CreatedAt, &m.ProcessedAt)
	return m, err
}

func (s *Service) DeleteMessage(ctx context.Context, userID, direction, href string) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM scheduling_messages WHERE user_id=$1 AND direction=$2 AND href=$3`, userID, direction, href)
	return err
}

func (s *Service) ProcessOutbox(ctx context.Context, r *http.Request, u auth.User, raw string) ([]DeliveryResult, error) {
	m, err := ical.Parse(raw)
	if err != nil {
		return nil, err
	}
	method := strings.ToUpper(m.Method)
	if method == "REPLY" {
		var status string
		for _, a := range m.AttendeeDetails {
			if strings.EqualFold(a.Email, u.Email) {
				status = normalizePartStat(a.PartStat)
				break
			}
		}
		if status == "" || status == "NEEDS-ACTION" {
			return nil, errors.New("REPLY enthält keinen gültigen Teilnehmerstatus")
		}
		var eventID string
		err := s.DB.QueryRow(ctx, `SELECT ea.event_id::text FROM event_attendees ea JOIN events e ON e.id=ea.event_id WHERE ea.user_id=$1 AND e.uid=$2 ORDER BY ea.updated_at DESC LIMIT 1`, u.ID, m.UID).Scan(&eventID)
		if err != nil {
			return nil, err
		}
		if err := s.ApplyResponse(ctx, r, u.ID, eventID, u.Email, status, "caldav"); err != nil {
			return nil, err
		}
		return []DeliveryResult{{Recipient: m.OrganizerEmail, Status: "2.0;Success"}}, nil
	}
	if method == "REQUEST" || method == "CANCEL" {
		results := make([]DeliveryResult, 0, len(m.AttendeeDetails))
		for _, a := range m.AttendeeDetails {
			results = append(results, DeliveryResult{Recipient: a.Email, Status: "2.0;Success"})
		}
		return results, nil
	}
	return nil, fmt.Errorf("iTIP-Methode %s wird nicht unterstützt", method)
}

func (s *Service) ApplyResponse(ctx context.Context, r *http.Request, actorID, eventID, emailAddr, status, source string) error {
	status = normalizePartStat(status)
	if status == "NEEDS-ACTION" {
		return errors.New("Ungültiger Antwortstatus")
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var raw string
	var version int
	var organizerID, organizerEmail string
	var scheduleTag string
	err = tx.QueryRow(ctx, `SELECT e.ics,e.version,coalesce(e.created_by::text,''),coalesce(e.schedule_tag,'') FROM events e WHERE e.id=$1 FOR UPDATE`, eventID).Scan(&raw, &version, &organizerID, &scheduleTag)
	if err != nil {
		return err
	}
	meta, err := ical.Parse(raw)
	if err != nil {
		return err
	}
	organizerEmail = meta.OrganizerEmail
	updated, ok := ical.SetAttendeePartStat(raw, emailAddr, status)
	if !ok {
		return errors.New("Teilnehmer ist nicht mehr im Termin enthalten")
	}
	etag := ical.ETag(updated)
	newVersion := version + 1
	_, err = tx.Exec(ctx, `UPDATE events SET ics=$2,etag=$3,version=$4,updated_at=now() WHERE id=$1`, eventID, updated, etag, newVersion)
	if err != nil {
		return err
	}
	var actor any
	if actorID != "" {
		actor = actorID
	}
	_, err = tx.Exec(ctx, `INSERT INTO event_versions(id,event_id,version,action,ics,actor_user_id) VALUES($1,$2,$3,$4,$5,$6)`, security.UUID(), eventID, newVersion, "attendee."+strings.ToLower(status), updated, actor)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE event_attendees SET partstat=$3,updated_at=now() WHERE event_id=$1 AND lower(email)=lower($2)`, eventID, emailAddr, status)
	if err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	s.syncInvitationCopyResponse(ctx, eventID, emailAddr, status)
	// Keep the schedule-tag unchanged for this inconsequential attendee reply.
	_ = scheduleTag
	reply, _ := ical.BuildReply(updated, emailAddr, status)
	var orgUserID string
	if organizerEmail != "" {
		_ = s.DB.QueryRow(ctx, `SELECT id::text FROM users WHERE lower(email)=lower($1) AND status='active'`, organizerEmail).Scan(&orgUserID)
	}
	if orgUserID == "" {
		orgUserID = organizerID
	}
	if orgUserID != "" {
		_ = s.enqueueInbox(ctx, orgUserID, eventID, "REPLY", reply)
	}
	action := "invitation." + strings.ToLower(status)
	s.Audit.Write(ctx, r, actorID, action, "event", eventID, map[string]any{"attendee": strings.ToLower(emailAddr), "source": source})
	return nil
}

func normalizePartStat(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	switch v {
	case "ACCEPTED", "DECLINED", "TENTATIVE", "NEEDS-ACTION":
		return v
	default:
		return "NEEDS-ACTION"
	}
}

func (s *Service) processDeliveries(ctx context.Context) {
	for i := 0; i < 10; i++ {
		tx, err := s.DB.Begin(ctx)
		if err != nil {
			return
		}
		var j struct {
			id, eventID, email, method, raw, baseURL, templateKind, changeKeys string
			attempt                                                            int
		}
		err = tx.QueryRow(ctx, `SELECT id::text,coalesce(event_id::text,''),recipient_email,method,ics,base_url,template_kind,change_keys,attempt
 FROM scheduling_deliveries
 WHERE status IN ('pending','failed') AND next_attempt_at<=now() AND attempt<8
 ORDER BY next_attempt_at,created_at
 FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&j.id, &j.eventID, &j.email, &j.method, &j.raw, &j.baseURL, &j.templateKind, &j.changeKeys, &j.attempt)
		if errors.Is(err, pgx.ErrNoRows) {
			_ = tx.Rollback(ctx)
			return
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			return
		}
		if _, err = tx.Exec(ctx, `UPDATE scheduling_deliveries SET status='sending',attempt=attempt+1 WHERE id=$1`, j.id); err != nil {
			_ = tx.Rollback(ctx)
			return
		}
		if err = tx.Commit(ctx); err != nil {
			return
		}

		err = s.sendExternal(ctx, j.eventID, j.email, j.method, j.raw, j.baseURL, j.templateKind, strings.FieldsFunc(j.changeKeys, func(r rune) bool { return r == ',' }), j.attempt+1)
		if err == nil {
			_, _ = s.DB.Exec(ctx, `UPDATE scheduling_deliveries SET status='success',last_error='',sent_at=now() WHERE id=$1`, j.id)
			s.Audit.Write(ctx, nil, "", "invitation.delivery_succeeded", "event", j.eventID, map[string]any{"attendee": strings.ToLower(j.email), "method": j.method, "channel": "email"})
			continue
		}
		backoff := time.Duration(1<<min(j.attempt, 6)) * time.Minute
		_, _ = s.DB.Exec(ctx, `UPDATE scheduling_deliveries SET status='failed',last_error=$2,next_attempt_at=now()+($3 * interval '1 second') WHERE id=$1`, j.id, truncate(err.Error(), 800), int(backoff.Seconds()))
		s.Audit.Write(ctx, nil, "", "invitation.delivery_failed", "event", j.eventID, map[string]any{"attendee": strings.ToLower(j.email), "method": j.method, "channel": "email", "attempt": j.attempt + 1})
		if s.Log != nil {
			s.Log.Warn("calendar invitation delivery failed", "delivery_id", j.id, "attempt", j.attempt+1, "error", err)
		}
	}
}

func (s *Service) sendExternal(ctx context.Context, eventID, recipient, method, raw, baseURL, templateKind string, changeKeys []string, attempt int) error {
	cfg, enabled, err := s.smtpConfig(ctx)
	if err != nil {
		return err
	}
	if !enabled {
		return errors.New("SMTP ist nicht aktiviert")
	}
	m, err := ical.Parse(raw)
	if err != nil {
		return err
	}
	organizer := m.OrganizerName
	if organizer == "" {
		organizer = m.OrganizerEmail
	}
	if organizer == "" {
		organizer = "ZentCal"
	}
	lang := s.recipientLanguage(ctx, recipient)
	start, end := formatEventTimes(m, lang)
	location := strings.TrimSpace(m.Location)
	description := strings.TrimSpace(m.Description)
	var actionsHTML, actionsText string
	if method == "REQUEST" {
		var enc string
		err := s.DB.QueryRow(ctx, `SELECT coalesce(response_token_secret,'') FROM event_attendees WHERE event_id=$1 AND lower(email)=lower($2)`, eventID, recipient).Scan(&enc)
		if err == nil && enc != "" && baseURL != "" {
			token, derr := s.Secrets.Decrypt(enc)
			if derr == nil {
				accept := strings.TrimRight(baseURL, "/") + "/invite/respond/" + url.PathEscape(token) + "/accept"
				tentative := strings.TrimRight(baseURL, "/") + "/invite/respond/" + url.PathEscape(token) + "/tentative"
				decline := strings.TrimRight(baseURL, "/") + "/invite/respond/" + url.PathEscape(token) + "/decline"
				labels := []string{"Annehmen", "Vielleicht", "Ablehnen"}
				if lang == "en" {
					labels = []string{"Accept", "Tentative", "Decline"}
				}
				actionsHTML = `<div style="margin-top:24px"><a style="display:inline-block;padding:10px 16px;margin-right:8px;border-radius:8px;background:#4f8cff;color:#fff;text-decoration:none;font-weight:600" href="` + html.EscapeString(accept) + `">` + labels[0] + `</a><a style="display:inline-block;padding:10px 16px;margin-right:8px;border-radius:8px;background:#242b35;color:#fff;text-decoration:none;font-weight:600" href="` + html.EscapeString(tentative) + `">` + labels[1] + `</a><a style="display:inline-block;padding:10px 16px;border-radius:8px;background:#3a2025;color:#ffb2b9;text-decoration:none;font-weight:600" href="` + html.EscapeString(decline) + `">` + labels[2] + `</a></div>`
				actionsText = labels[0] + ": " + accept + "\n" + labels[1] + ": " + tentative + "\n" + labels[2] + ": " + decline
			}
		}
	}
	kind := strings.TrimSpace(templateKind)
	if kind != "event_invite" && kind != "event_update" && kind != "event_cancel" {
		kind = "event_invite"
		if method == "CANCEL" {
			kind = "event_cancel"
		}
	}
	defaultSubject := "Einladung: {{event_title}}"
	defaultBody := "{{organizer_name}} hat dich zu „{{event_title}}“ eingeladen.\n\nDatum: {{event_start}}{{event_end_line}}{{event_location_line}}{{event_description_line}}"
	if lang == "en" {
		defaultSubject = "Invitation: {{event_title}}"
		defaultBody = "{{organizer_name}} invited you to “{{event_title}}”.\n\nDate: {{event_start}}{{event_end_line}}{{event_location_line}}{{event_description_line}}"
	}
	if kind == "event_cancel" {
		defaultSubject = "Abgesagt: {{event_title}}"
		defaultBody = "Der Termin „{{event_title}}“ wurde abgesagt.\n\nDatum: {{event_start}}"
		if lang == "en" {
			defaultSubject = "Cancelled: {{event_title}}"
			defaultBody = "The event “{{event_title}}” was cancelled.\n\nDate: {{event_start}}"
		}
	} else if kind == "event_update" {
		defaultSubject = "Aktualisiert: {{event_title}}"
		defaultBody = "Der Termin „{{event_title}}“ wurde aktualisiert.\n\nDatum: {{event_start}}{{event_end_line}}{{event_location_line}}{{event_description_line}}"
		if lang == "en" {
			defaultSubject = "Updated: {{event_title}}"
			defaultBody = "The event “{{event_title}}” was updated.\n\nDate: {{event_start}}{{event_end_line}}{{event_location_line}}{{event_description_line}}"
		}
	}
	subjectTpl, bodyTpl := s.mailTemplate(ctx, kind, lang, defaultSubject, defaultBody)
	vars := map[string]string{
		"organizer_name":         organizer,
		"event_title":            m.Summary,
		"event_start":            start,
		"event_end_line":         "",
		"event_location_line":    "",
		"event_description_line": "",
	}
	if end != "" {
		vars["event_end_line"] = " – " + end
	}
	if location != "" {
		label := "Ort / Link: "
		if lang == "en" {
			label = "Location / link: "
		}
		vars["event_location_line"] = "\n" + label + location
	}
	if description != "" {
		vars["event_description_line"] = "\n\n" + description
	}
	if kind == "event_update" && len(changeKeys) > 0 {
		labelsDE := map[string]string{"title": "Titel", "start": "Beginn", "end": "Ende", "location": "Ort / Link", "description": "Beschreibung", "recurrence": "Wiederholung", "attendees": "Teilnehmer", "details": "Termindetails"}
		labelsEN := map[string]string{"title": "Title", "start": "Start", "end": "End", "location": "Location / link", "description": "Description", "recurrence": "Recurrence", "attendees": "Attendees", "details": "Event details"}
		labels := labelsDE
		heading := "Geändert:"
		if lang == "en" {
			labels = labelsEN
			heading = "Changed:"
		}
		parts := make([]string, 0, len(changeKeys))
		for _, key := range changeKeys {
			if label := labels[key]; label != "" {
				parts = append(parts, label)
			}
		}
		if len(parts) > 0 {
			changeText := heading + " " + strings.Join(parts, ", ")
			changeHTML := `<div style="margin-top:18px"><strong>` + html.EscapeString(heading) + `</strong> ` + html.EscapeString(strings.Join(parts, ", ")) + `</div>`
			if actionsText != "" {
				actionsText = changeText + "\n\n" + actionsText
			} else {
				actionsText = changeText
			}
			if actionsHTML != "" {
				actionsHTML = changeHTML + actionsHTML
			} else {
				actionsHTML = changeHTML
			}
		}
	}
	instanceName := "ZentCal"
	htmlEnabled := s.setting(ctx, "mail_html_enabled", "false") == "true"
	htmlTemplate := s.setting(ctx, "mail_html_template", mailpkg.DefaultHTMLLayout)
	subject, textBody, htmlBody := mailpkg.RenderTemplate(mailpkg.TemplateData{InstanceName: instanceName, BaseURL: baseURL, Language: lang, Subject: subjectTpl, Body: bodyTpl, Variables: vars, ExtraText: actionsText, ExtraHTML: actionsHTML, HTMLEnabled: htmlEnabled, HTMLTemplate: htmlTemplate})
	if s.MailDelivery != nil {
		return s.MailDelivery.SendCalendarAttempt(ctx, kind, cfg, recipient, subject, textBody, htmlBody, method, raw, attempt)
	}
	return mailpkg.SendCalendar(cfg, recipient, subject, textBody, htmlBody, method, raw)
}

func (s *Service) setting(ctx context.Context, key, def string) string {
	var v string
	if err := s.DB.QueryRow(ctx, `SELECT value FROM settings WHERE key=$1`, key).Scan(&v); err != nil || strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func (s *Service) recipientLanguage(ctx context.Context, recipient string) string {
	var lang string
	if err := s.DB.QueryRow(ctx, `SELECT language FROM users WHERE lower(email)=lower($1) AND status='active'`, recipient).Scan(&lang); err != nil {
		lang = s.setting(ctx, "language", "de")
	}
	if strings.EqualFold(strings.TrimSpace(lang), "en") {
		return "en"
	}
	return "de"
}

func (s *Service) mailTemplate(ctx context.Context, kind, lang, defaultSubject, defaultBody string) (string, string) {
	suffix := "de"
	if lang == "en" {
		suffix = "en"
	}
	subject := s.setting(ctx, "mail_"+kind+"_subject_"+suffix, defaultSubject)
	body := s.setting(ctx, "mail_"+kind+"_body_"+suffix, defaultBody)
	return subject, body
}

func formatEventTimes(m ical.Meta, lang string) (string, string) {
	if m.Start == nil {
		if lang == "en" {
			return "Time not specified", ""
		}
		return "Zeit nicht angegeben", ""
	}
	start := m.Start.Format("02.01.2006 15:04 MST")
	end := ""
	if m.End != nil {
		end = m.End.Format("02.01.2006 15:04 MST")
	}
	return start, end
}

func linkify(v string) string {
	escaped := html.EscapeString(v)
	if u, err := url.Parse(strings.TrimSpace(v)); err == nil && (u.Scheme == "https" || u.Scheme == "http") {
		return `<a style="color:#7ea8ff" href="` + html.EscapeString(u.String()) + `">` + escaped + `</a>`
	}
	return escaped
}

func (s *Service) smtpConfig(ctx context.Context) (mailpkg.SMTPConfig, bool, error) {
	vals := map[string]string{}
	rows, err := s.DB.Query(ctx, `SELECT key,value,secret FROM settings WHERE key LIKE 'smtp_%'`)
	if err != nil {
		return mailpkg.SMTPConfig{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var key, value string
		var secret bool
		if err := rows.Scan(&key, &value, &secret); err != nil {
			return mailpkg.SMTPConfig{}, false, err
		}
		if secret && value != "" {
			value, err = s.Secrets.Decrypt(value)
			if err != nil {
				return mailpkg.SMTPConfig{}, false, err
			}
		}
		vals[key] = value
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

func (s *Service) baseURL() string {
	return s.BaseURL
}

func (s *Service) responsePage(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	action := r.PathValue("action")
	status, label := actionStatus(action)
	if status == "" {
		http.NotFound(w, r)
		return
	}
	var summary, emailAddr string
	var start *time.Time
	err := s.DB.QueryRow(r.Context(), `SELECT e.summary,e.dtstart,ea.email FROM event_attendees ea JOIN events e ON e.id=ea.event_id WHERE ea.response_token_hash=$1 AND ea.response_expires_at>now()`, security.TokenHash(token)).Scan(&summary, &start, &emailAddr)
	if err != nil {
		http.Error(w, "Dieser Einladungslink ist ungültig oder abgelaufen.", http.StatusGone)
		return
	}
	when := ""
	if start != nil {
		when = `<p class="muted">` + html.EscapeString(start.Format("02.01.2006 15:04 MST")) + `</p>`
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ZentCal Einladung</title><link rel="icon" href="/static/icons/favicon.ico"><link rel="stylesheet" href="/static/css/app.css"></head><body class="auth-bg"><main class="login-wrap"><section class="auth-card"><div class="setup-brand"><img class="brand-logo" src="/static/icons/zentcal-logo.png" alt=""><div><h1>ZentCal</h1><p>Einladung</p></div></div><h2>`+html.EscapeString(summary)+`</h2><p class="muted">`+html.EscapeString(emailAddr)+`</p>`+when+`<p>Möchtest du diese Einladung wirklich <strong>`+html.EscapeString(strings.ToLower(label))+`</strong>?</p><form method="post"><button class="btn primary" type="submit">`+html.EscapeString(label)+`</button></form></section></main></body></html>`)
}

func (s *Service) responseSubmit(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	status, label := actionStatus(r.PathValue("action"))
	if status == "" {
		http.NotFound(w, r)
		return
	}
	var eventID, emailAddr string
	err := s.DB.QueryRow(r.Context(), `SELECT event_id::text,email FROM event_attendees WHERE response_token_hash=$1 AND response_expires_at>now()`, security.TokenHash(token)).Scan(&eventID, &emailAddr)
	if err != nil {
		http.Error(w, "Dieser Einladungslink ist ungültig oder abgelaufen.", http.StatusGone)
		return
	}
	if err := s.ApplyResponse(r.Context(), r, "", eventID, emailAddr, status, "web-link"); err != nil {
		http.Error(w, "Antwort konnte nicht gespeichert werden.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ZentCal</title><link rel="icon" href="/static/icons/favicon.ico"><link rel="stylesheet" href="/static/css/app.css"></head><body class="auth-bg"><main class="login-wrap"><section class="auth-card"><div class="setup-brand"><img class="brand-logo" src="/static/icons/zentcal-logo.png" alt=""><div><h1>ZentCal</h1></div></div><h2>Antwort gespeichert</h2><p>Die Einladung wurde als <strong>`+html.EscapeString(strings.ToLower(label))+`</strong> markiert.</p></section></main></body></html>`)
}

func actionStatus(action string) (string, string) {
	switch strings.ToLower(action) {
	case "accept":
		return "ACCEPTED", "Annehmen"
	case "tentative":
		return "TENTATIVE", "Vielleicht"
	case "decline":
		return "DECLINED", "Ablehnen"
	default:
		return "", ""
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func truncate(v string, n int) string {
	if len(v) <= n {
		return v
	}
	return v[:n]
}

func (s *Service) upsertInvitationCopy(ctx context.Context, sourceEventID, userID, emailAddr, raw string) (string, error) {
	var userName string
	if err := s.DB.QueryRow(ctx, `SELECT name FROM users WHERE id=$1 AND status='active'`, userID).Scan(&userName); err != nil {
		return "", err
	}
	calendarID, err := db.EnsurePersonalCalendar(ctx, s.DB, userID, userName)
	if err != nil {
		return "", err
	}
	copyRaw := ical.WithoutMethod(raw)
	meta, err := ical.Parse(copyRaw)
	if err != nil {
		return "", err
	}
	var copyID, href string
	err = s.DB.QueryRow(ctx, `SELECT coalesce(attendee_event_id::text,'') FROM event_attendees WHERE event_id=$1 AND lower(email)=lower($2)`, sourceEventID, emailAddr).Scan(&copyID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	etag := ical.ETag(copyRaw)
	if copyID != "" {
		_, err = s.DB.Exec(ctx, `UPDATE events SET summary=$2,dtstart=$3,dtend=$4,ics=$5,etag=$6,schedule_tag=$6,version=version+1,updated_at=now(),updated_by=$7 WHERE id=$1`, copyID, meta.Summary, meta.Start, meta.End, copyRaw, etag, userID)
		if err != nil {
			return "", err
		}
		return copyID, nil
	}
	// A UID is globally stable for an invitation. Reuse an existing copy if a previous
	// scheduling message already materialized it in this user's invitation calendar.
	err = s.DB.QueryRow(ctx, `SELECT id::text,href FROM events WHERE calendar_id=$1 AND uid=$2`, calendarID, meta.UID).Scan(&copyID, &href)
	if errors.Is(err, pgx.ErrNoRows) {
		copyID = security.UUID()
		href = security.UUID() + ".ics"
		_, err = s.DB.Exec(ctx, `INSERT INTO events(id,calendar_id,uid,href,summary,dtstart,dtend,ics,etag,schedule_tag,created_by,updated_by)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,$10)`, copyID, calendarID, meta.UID, href, meta.Summary, meta.Start, meta.End, copyRaw, etag, userID)
	} else if err == nil {
		_, err = s.DB.Exec(ctx, `UPDATE events SET summary=$2,dtstart=$3,dtend=$4,ics=$5,etag=$6,schedule_tag=$6,version=version+1,updated_at=now(),updated_by=$7 WHERE id=$1`, copyID, meta.Summary, meta.Start, meta.End, copyRaw, etag, userID)
	}
	if err != nil {
		return "", err
	}
	_, _ = s.DB.Exec(ctx, `UPDATE calendars SET updated_at=now() WHERE id=$1`, calendarID)
	_, err = s.DB.Exec(ctx, `UPDATE event_attendees SET attendee_event_id=$3 WHERE event_id=$1 AND lower(email)=lower($2)`, sourceEventID, emailAddr, copyID)
	return copyID, err
}

func (s *Service) removeInvitationCopy(ctx context.Context, sourceEventID, emailAddr string) error {
	var copyID, calendarID, href string
	err := s.DB.QueryRow(ctx, `SELECT e.id::text,e.calendar_id::text,e.href FROM event_attendees ea JOIN events e ON e.id=ea.attendee_event_id WHERE ea.event_id=$1 AND lower(ea.email)=lower($2)`, sourceEventID, emailAddr).Scan(&copyID, &calendarID, &href)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO event_tombstones(calendar_id,href) VALUES($1,$2)`, calendarID, href); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM events WHERE id=$1`, copyID); err != nil {
		return err
	}
	_, _ = tx.Exec(ctx, `UPDATE calendars SET updated_at=now() WHERE id=$1`, calendarID)
	return tx.Commit(ctx)
}

func (s *Service) syncInvitationCopyResponse(ctx context.Context, sourceEventID, emailAddr, status string) {
	var copyID, raw string
	if err := s.DB.QueryRow(ctx, `SELECT e.id::text,e.ics FROM event_attendees ea JOIN events e ON e.id=ea.attendee_event_id WHERE ea.event_id=$1 AND lower(ea.email)=lower($2)`, sourceEventID, emailAddr).Scan(&copyID, &raw); err != nil {
		return
	}
	updated, ok := ical.SetAttendeePartStat(raw, emailAddr, status)
	if !ok {
		return
	}
	etag := ical.ETag(updated)
	_, _ = s.DB.Exec(ctx, `UPDATE events SET ics=$2,etag=$3,schedule_tag=$3,version=version+1,updated_at=now() WHERE id=$1`, copyID, updated, etag)
}
