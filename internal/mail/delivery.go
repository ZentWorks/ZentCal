package mail

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zentworks/zentcal/internal/security"
	"github.com/zentworks/zentcal/internal/webhook"
)

var deliveryEmailRE = regexp.MustCompile("[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}")

type DeliveryService struct {
	DB       *pgxpool.Pool
	Webhooks *webhook.Service
}

type Delivery struct {
	ID          string     `json:"id"`
	UserID      string     `json:"-"`
	Type        string     `json:"type"`
	Recipient   string     `json:"recipient"`
	Status      string     `json:"status"`
	Error       string     `json:"error,omitempty"`
	Attempt     int        `json:"attempt"`
	CreatedAt   time.Time  `json:"created_at"`
	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
}

func NewDeliveryService(db *pgxpool.Pool, webhooks *webhook.Service) *DeliveryService {
	return &DeliveryService{DB: db, Webhooks: webhooks}
}

func (s *DeliveryService) SendMessage(ctx context.Context, kind string, cfg SMTPConfig, recipient, subject, textBody, htmlBody string) error {
	return s.SendMessageAttempt(ctx, kind, cfg, recipient, subject, textBody, htmlBody, 1)
}

func (s *DeliveryService) SendMessageAttempt(ctx context.Context, kind string, cfg SMTPConfig, recipient, subject, textBody, htmlBody string, attempt int) error {
	err := SendMessage(cfg, recipient, subject, textBody, htmlBody)
	s.record(ctx, kind, recipient, attempt, err)
	return err
}

func (s *DeliveryService) SendCalendar(ctx context.Context, kind string, cfg SMTPConfig, recipient, subject, textBody, htmlBody, method, calendarData string) error {
	return s.SendCalendarAttempt(ctx, kind, cfg, recipient, subject, textBody, htmlBody, method, calendarData, 1)
}

func (s *DeliveryService) SendCalendarAttempt(ctx context.Context, kind string, cfg SMTPConfig, recipient, subject, textBody, htmlBody, method, calendarData string, attempt int) error {
	err := SendCalendar(cfg, recipient, subject, textBody, htmlBody, method, calendarData)
	s.record(ctx, kind, recipient, attempt, err)
	return err
}

func (s *DeliveryService) record(ctx context.Context, kind, recipient string, attempt int, sendErr error) {
	if s == nil || s.DB == nil {
		return
	}
	ctx = context.WithoutCancel(ctx)
	kind = strings.TrimSpace(kind)
	if kind == "" {
		kind = "generic"
	}
	masked := MaskRecipient(recipient)
	status := "success"
	errText := ""
	if sendErr != nil {
		status = "failed"
		errText = sanitizeDeliveryError(sendErr.Error())
		errText = deliveryEmailRE.ReplaceAllStringFunc(errText, MaskRecipient)
	}
	var userID *string
	var uid string
	if err := s.DB.QueryRow(ctx, `SELECT id::text FROM users WHERE lower(email)=lower($1)`, strings.TrimSpace(recipient)).Scan(&uid); err == nil {
		userID = &uid
	}
	if attempt < 1 {
		attempt = 1
	}
	id := security.UUID()
	_, _ = s.DB.Exec(ctx, `INSERT INTO email_deliveries(id,user_id,mail_type,recipient_masked,status,attempt,last_error,delivered_at) VALUES($1,NULLIF($2,'')::uuid,$3,$4,$5,$6,$7,CASE WHEN $5='success' THEN now() ELSE NULL END)`, id, deref(userID), kind, masked, status, attempt, errText)
	if sendErr != nil && s.Webhooks != nil {
		s.Webhooks.Emit(ctx, "email.failed", "", "email_delivery", id, map[string]any{"type": kind, "recipient": masked, "error": errText})
	}
}

func (s *DeliveryService) Cleanup(ctx context.Context) error {
	if s == nil || s.DB == nil {
		return nil
	}
	_, err := s.DB.Exec(ctx, `DELETE FROM email_deliveries WHERE created_at < now() - interval '30 days'`)
	return err
}

func (s *DeliveryService) List(ctx context.Context, status, kind, query string, limit int) ([]Delivery, error) {
	if limit < 1 || limit > 500 {
		limit = 200
	}
	rows, err := s.DB.Query(ctx, `SELECT id::text,coalesce(user_id::text,''),mail_type,recipient_masked,status,attempt,last_error,created_at,delivered_at
FROM email_deliveries
WHERE ($1='' OR status=$1) AND ($2='' OR mail_type=$2) AND ($3='' OR recipient_masked ILIKE '%'||$3||'%')
ORDER BY created_at DESC LIMIT $4`, strings.TrimSpace(status), strings.TrimSpace(kind), strings.TrimSpace(query), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Delivery{}
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(&d.ID, &d.UserID, &d.Type, &d.Recipient, &d.Status, &d.Attempt, &d.Error, &d.CreatedAt, &d.DeliveredAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func MaskRecipient(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	at := strings.LastIndex(v, "@")
	if at <= 0 || at == len(v)-1 {
		return "***"
	}
	local, domain := v[:at], v[at+1:]
	prefix := "*"
	if len(local) >= 1 {
		prefix = local[:1]
	}
	if len(local) >= 2 {
		prefix = local[:2]
	}
	return prefix + "***@" + domain
}

func sanitizeDeliveryError(v string) string {
	v = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(v, "\r", " "), "\n", " "))
	if len(v) > 500 {
		v = v[:500]
	}
	return v
}

func deref(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
