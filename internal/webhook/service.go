package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zentworks/zentcal/internal/security"
)

type Service struct {
	DB      *pgxpool.Pool
	Secrets *security.SecretBox
	Log     *slog.Logger
	Client  *http.Client
	Paused  func() bool
}

type Hook struct {
	ID, Name, TargetURL, AuthType string
	Active, AllowPrivate          bool
	Events                        []string
	CreatedAt, UpdatedAt          time.Time
}

type Delivery struct {
	ID, WebhookID, WebhookName, Event, Status, LastError string
	Attempt, HTTPStatus                                  int
	ResponseMS                                           int64
	CreatedAt                                            time.Time
	DeliveredAt                                          *time.Time
}

type payload struct {
	Event     string            `json:"event"`
	EventID   string            `json:"event_id"`
	Timestamp string            `json:"timestamp"`
	Actor     string            `json:"actor,omitempty"`
	Resource  map[string]string `json:"resource"`
	Instance  string            `json:"instance"`
	Data      any               `json:"data,omitempty"`
}

func New(db *pgxpool.Pool, secrets *security.SecretBox, log *slog.Logger) *Service {
	return &Service{DB: db, Secrets: secrets, Log: log, Client: &http.Client{Timeout: 12 * time.Second}}
}

func (s *Service) List(ctx context.Context) ([]Hook, error) {
	rows, err := s.DB.Query(ctx, `SELECT id::text,name,target_url,auth_type,active,allow_private,events,created_at,updated_at FROM webhooks ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Hook
	for rows.Next() {
		var h Hook
		if err := rows.Scan(&h.ID, &h.Name, &h.TargetURL, &h.AuthType, &h.Active, &h.AllowPrivate, &h.Events, &h.CreatedAt, &h.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Service) Deliveries(ctx context.Context, limit int) ([]Delivery, error) {
	rows, err := s.DB.Query(ctx, `SELECT d.id::text,d.webhook_id::text,w.name,d.event,d.status,d.attempt,coalesce(d.http_status,0),coalesce(d.response_ms,0),coalesce(d.last_error,''),d.created_at,d.delivered_at FROM webhook_deliveries d JOIN webhooks w ON w.id=d.webhook_id ORDER BY d.created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Delivery
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.WebhookName, &d.Event, &d.Status, &d.Attempt, &d.HTTPStatus, &d.ResponseMS, &d.LastError, &d.CreatedAt, &d.DeliveredAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Service) Create(ctx context.Context, name, target, authType string, events []string, active, allowPrivate bool, createdBy string) (Hook, string, error) {
	name = strings.TrimSpace(name)
	target = strings.TrimSpace(target)
	authType = normalizeAuthType(authType)
	if name == "" {
		return Hook{}, "", errors.New("Name ist erforderlich.")
	}
	if err := ValidateTarget(ctx, target, allowPrivate); err != nil {
		return Hook{}, "", err
	}
	events = normalizeEvents(events)
	if len(events) == 0 {
		return Hook{}, "", errors.New("Mindestens ein Webhook-Event auswählen.")
	}
	secret, err := newCredential(authType)
	if err != nil {
		return Hook{}, "", err
	}
	enc, err := s.Secrets.Encrypt(secret)
	if err != nil {
		return Hook{}, "", err
	}
	id := security.UUID()
	_, err = s.DB.Exec(ctx, `INSERT INTO webhooks(id,name,target_url,secret,auth_type,active,allow_private,events,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, name, target, enc, authType, active, allowPrivate, events, createdBy)
	if err != nil {
		return Hook{}, "", err
	}
	var h Hook
	err = s.DB.QueryRow(ctx, `SELECT id::text,name,target_url,auth_type,active,allow_private,events,created_at,updated_at FROM webhooks WHERE id=$1`, id).Scan(&h.ID, &h.Name, &h.TargetURL, &h.AuthType, &h.Active, &h.AllowPrivate, &h.Events, &h.CreatedAt, &h.UpdatedAt)
	return h, secret, err
}

func (s *Service) Update(ctx context.Context, id, name, target, authType string, events []string, active, allowPrivate bool) error {
	name = strings.TrimSpace(name)
	authType = normalizeAuthType(authType)
	if name == "" {
		return errors.New("Name ist erforderlich.")
	}
	if err := ValidateTarget(ctx, target, allowPrivate); err != nil {
		return err
	}
	events = normalizeEvents(events)
	if len(events) == 0 {
		return errors.New("Mindestens ein Webhook-Event auswählen.")
	}
	ct, err := s.DB.Exec(ctx, `UPDATE webhooks SET name=$1,target_url=$2,auth_type=$3,events=$4,active=$5,allow_private=$6,updated_at=now() WHERE id=$7`, name, strings.TrimSpace(target), authType, events, active, allowPrivate, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Service) Delete(ctx context.Context, id string) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM webhooks WHERE id=$1`, id)
	return err
}
func (s *Service) RotateSecret(ctx context.Context, id string) (string, error) {
	var authType string
	if err := s.DB.QueryRow(ctx, `SELECT auth_type FROM webhooks WHERE id=$1`, id).Scan(&authType); err != nil {
		return "", err
	}
	sec, err := newCredential(authType)
	if err != nil {
		return "", err
	}
	enc, err := s.Secrets.Encrypt(sec)
	if err != nil {
		return "", err
	}
	_, err = s.DB.Exec(ctx, `UPDATE webhooks SET secret=$1,updated_at=now() WHERE id=$2`, enc, id)
	return sec, err
}

func normalizeEvents(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, e := range in {
		e = strings.TrimSpace(e)
		if e == "" || seen[e] {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	return out
}

func (s *Service) Emit(ctx context.Context, event, actor, resourceType, resourceID string, data any) {
	if s == nil || s.DB == nil {
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT id::text FROM webhooks WHERE active AND ($1 = ANY(events) OR '*' = ANY(events))`, event)
	if err != nil {
		if s.Log != nil {
			s.Log.Error("webhook lookup failed", "error", err)
		}
		return
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	for _, id := range ids {
		if err := s.enqueue(ctx, id, event, actor, resourceType, resourceID, data); err != nil && s.Log != nil {
			s.Log.Error("webhook enqueue failed", "error", err, "webhook_id", id)
		}
	}
}

func (s *Service) Test(ctx context.Context, id, actor string) (string, error) {
	did := security.UUID()
	p := payload{Event: "webhook.test", EventID: did, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Actor: actor, Resource: map[string]string{"type": "webhook", "id": id}, Instance: s.instanceName(ctx), Data: map[string]any{"message": "ZentCal webhook test"}}
	raw, _ := json.Marshal(p)
	_, err := s.DB.Exec(ctx, `INSERT INTO webhook_deliveries(id,webhook_id,event,payload,status,next_attempt_at) VALUES($1,$2,$3,$4,'pending',now())`, did, id, p.Event, raw)
	return did, err
}

func (s *Service) enqueue(ctx context.Context, id, event, actor, rt, rid string, data any) error {
	did := security.UUID()
	p := payload{Event: event, EventID: did, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Actor: actor, Resource: map[string]string{"type": rt, "id": rid}, Instance: s.instanceName(ctx), Data: data}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO webhook_deliveries(id,webhook_id,event,payload,status,next_attempt_at) VALUES($1,$2,$3,$4,'pending',now())`, did, id, event, raw)
	return err
}
func (s *Service) instanceName(ctx context.Context) string {
	_ = ctx
	return "ZentCal"
}

func (s *Service) Cleanup(ctx context.Context) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM webhook_deliveries WHERE status IN ('success','failed') AND created_at < now()-interval '30 days'`)
	return err
}
func (s *Service) Run(ctx context.Context) {
	_, _ = s.DB.Exec(ctx, `UPDATE webhook_deliveries SET status='failed',next_attempt_at=now(),last_error=CASE WHEN last_error='' THEN 'Delivery wurde durch Neustart unterbrochen.' ELSE last_error END WHERE status='sending'`)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.Paused != nil && s.Paused() {
				continue
			}
			s.processBatch(ctx)
		}
	}
}
func (s *Service) processBatch(ctx context.Context) {
	for i := 0; i < 10; i++ {
		ok, err := s.processOne(ctx)
		if err != nil && s.Log != nil {
			s.Log.Error("webhook delivery processing failed", "error", err)
		}
		if !ok {
			return
		}
	}
}

func (s *Service) processOne(ctx context.Context) (bool, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var id, wid, event string
	var body []byte
	var attempt int
	err = tx.QueryRow(ctx, `SELECT id::text,webhook_id::text,event,payload,attempt FROM webhook_deliveries WHERE status IN ('pending','failed') AND next_attempt_at<=now() AND attempt<6 ORDER BY next_attempt_at,created_at FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&id, &wid, &event, &body, &attempt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE webhook_deliveries SET status='sending',attempt=attempt+1 WHERE id=$1`, id); err != nil {
		return false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return false, err
	}
	var target, enc, authType string
	var allow bool
	err = s.DB.QueryRow(ctx, `SELECT target_url,secret,auth_type,allow_private FROM webhooks WHERE id=$1`, wid).Scan(&target, &enc, &authType, &allow)
	if err != nil {
		return true, err
	}
	secret, err := s.Secrets.Decrypt(enc)
	if err != nil {
		return true, s.fail(ctx, id, attempt+1, 0, 0, "Webhook-Secret konnte nicht entschlüsselt werden.")
	}
	started := time.Now()
	status, sendErr := s.send(ctx, target, allow, authType, event, id, body, secret)
	ms := time.Since(started).Milliseconds()
	if sendErr == nil && status >= 200 && status < 300 {
		_, err = s.DB.Exec(ctx, `UPDATE webhook_deliveries SET status='success',http_status=$1,response_ms=$2,last_error='',delivered_at=now() WHERE id=$3`, status, ms, id)
		return true, err
	}
	msg := "HTTP " + strconv.Itoa(status)
	if sendErr != nil {
		msg = sendErr.Error()
	}
	return true, s.fail(ctx, id, attempt+1, status, ms, msg)
}
func (s *Service) fail(ctx context.Context, id string, attempt, status int, ms int64, msg string) error {
	shift := attempt - 1
	if shift < 0 {
		shift = 0
	}
	delay := time.Duration(1<<min(shift, 5)) * time.Minute
	final := attempt >= 6
	st := "failed"
	var next any = time.Now().Add(delay)
	if final {
		next = time.Now().Add(365 * 24 * time.Hour)
	}
	_, err := s.DB.Exec(ctx, `UPDATE webhook_deliveries SET status=$1,http_status=$2,response_ms=$3,last_error=$4,next_attempt_at=$5 WHERE id=$6`, st, status, ms, truncate(msg, 500), next, id)
	return err
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (s *Service) send(ctx context.Context, target string, allowPrivate bool, authType, event, deliveryID string, body []byte, secret string) (int, error) {
	if err := ValidateTarget(ctx, target, allowPrivate); err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(string(body)))
	if err != nil {
		return 0, err
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ZentCal-Webhook/1")
	req.Header.Set("X-ZentCal-Event", event)
	req.Header.Set("X-ZentCal-Delivery", deliveryID)
	req.Header.Set("X-ZentCal-Timestamp", ts)
	switch normalizeAuthType(authType) {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+secret)
	case "hmac":
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(ts + "." + string(body)))
		req.Header.Set("X-ZentCal-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	c := *s.Client
	c.Transport = &http.Transport{DialContext: safeDialContext(allowPrivate), TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 64<<10)
	return resp.StatusCode, nil
}

func newCredential(authType string) (string, error) {
	token, err := security.RandomToken(32)
	if err != nil {
		return "", err
	}
	if normalizeAuthType(authType) == "bearer" {
		return "zcwh_" + token, nil
	}
	return token, nil
}

func normalizeAuthType(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "hmac", "none":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return "bearer"
	}
}

func ValidateTarget(ctx context.Context, raw string, allowPrivate bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return errors.New("Ungültige Webhook-URL.")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("Webhook-URL muss http oder https verwenden.")
	}
	if u.User != nil {
		return errors.New("Benutzerdaten in der Webhook-URL sind nicht erlaubt.")
	}
	if allowPrivate {
		return nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", u.Hostname())
	if err != nil {
		return fmt.Errorf("Webhook-Ziel konnte nicht aufgelöst werden: %w", err)
	}
	for _, ip := range ips {
		if unsafeIP(ip) {
			return errors.New("Private, lokale oder Link-Local Webhook-Ziele sind blockiert.")
		}
	}
	return nil
}
func safeDialContext(allowPrivate bool) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		d := net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
		var last error
		for _, ip := range ips {
			if !allowPrivate && unsafeIP(ip) {
				continue
			}
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		if last != nil {
			return nil, last
		}
		return nil, errors.New("Webhook-Ziel wurde durch SSRF-Schutz blockiert.")
	}
}
func unsafeIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
