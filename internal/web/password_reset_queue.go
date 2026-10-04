package web

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zentworks/zentcal/internal/security"
)

type passwordResetJob struct {
	ID              string
	UserID          string
	PasswordHash    string
	TemporarySecret string
	BaseURL         string
	Attempt         int
}

func (h *Handler) enqueuePasswordReset(ctx context.Context, userID, baseURL string) (bool, error) {
	if strings.TrimSpace(userID) == "" {
		return false, errors.New("user id is required")
	}
	ct, err := h.DB.Exec(ctx, `INSERT INTO password_reset_jobs(id,user_id,base_url)
VALUES($1,$2,$3)
ON CONFLICT (user_id) WHERE status IN ('pending','sending') DO NOTHING`, security.UUID(), userID, strings.TrimSuffix(strings.TrimSpace(baseURL), "/"))
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

// RunPasswordResetQueue processes public forgot-password requests outside the HTTP
// request path. Jobs are persisted so SMTP delays, retries and container restarts
// do not block or lose the request.
func (h *Handler) RunPasswordResetQueue(ctx context.Context) {
	if h == nil || h.DB == nil || h.Secrets == nil {
		return
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	cleanupTicker := time.NewTicker(time.Hour)
	defer cleanupTicker.Stop()

	for {
		if err := h.processOnePasswordReset(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Warn("password reset queue processing failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-cleanupTicker.C:
			_, _ = h.DB.Exec(context.Background(), `DELETE FROM password_reset_jobs WHERE status IN ('success','failed') AND COALESCE(processed_at,created_at) < now()-interval '7 days'`)
		case <-ticker.C:
		}
	}
}

func (h *Handler) processOnePasswordReset(ctx context.Context) error {
	job, ok, err := h.claimPasswordResetJob(ctx)
	if err != nil || !ok {
		return err
	}
	if err := h.ensurePasswordResetSecret(ctx, &job); err != nil {
		h.failPasswordResetJob(ctx, job, err)
		return err
	}

	var name, email, language, authType, status string
	if err := h.DB.QueryRow(ctx, `SELECT name,email,language,auth_type,status FROM users WHERE id=$1`, job.UserID).Scan(&name, &email, &language, &authType, &status); err != nil {
		h.finishPasswordResetJob(ctx, job.ID, "failed", "Benutzerkonto wurde nicht gefunden.", true)
		return err
	}
	if authType != "local" || status != "active" {
		h.finishPasswordResetJob(ctx, job.ID, "failed", "Benutzerkonto ist nicht für lokalen Passwort-Reset verfügbar.", true)
		return nil
	}

	cfg, enabled, err := h.loadSMTPConfig(ctx)
	if err != nil || !enabled {
		if err == nil {
			err = errors.New("SMTP ist nicht aktiviert")
		}
		h.failPasswordResetJob(ctx, job, err)
		return err
	}
	temporary, err := h.Secrets.Decrypt(job.TemporarySecret)
	if err != nil {
		h.finishPasswordResetJob(ctx, job.ID, "failed", "Temporäres Passwort konnte nicht entschlüsselt werden.", true)
		return err
	}
	vars := map[string]string{"user_name": name, "email": email, "temporary_password": temporary}
	if err := h.sendTemplatedMailWithBaseURLAttempt(ctx, cfg, email, language, "password_reset", vars, "", "", job.BaseURL, job.Attempt); err != nil {
		h.failPasswordResetJob(ctx, job, err)
		return err
	}

	tx, err := h.DB.Begin(ctx)
	if err != nil {
		h.failPasswordResetJob(ctx, job, err)
		return err
	}
	defer tx.Rollback(ctx)
	ct, err := tx.Exec(ctx, `UPDATE users SET password_hash=$1,must_change_password=true,updated_at=now()
WHERE id=$2 AND auth_type='local' AND status='active'`, job.PasswordHash, job.UserID)
	if err != nil {
		h.failPasswordResetJob(ctx, job, err)
		return err
	}
	if ct.RowsAffected() != 1 {
		_ = tx.Rollback(ctx)
		h.finishPasswordResetJob(ctx, job.ID, "failed", "Benutzerkonto ist nicht mehr für lokalen Passwort-Reset verfügbar.", true)
		return nil
	}
	if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, job.UserID); err != nil {
		h.failPasswordResetJob(ctx, job, err)
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE password_reset_jobs SET status='success',processed_at=now(),locked_at=NULL,last_error='',password_hash='',temporary_password_secret='' WHERE id=$1`, job.ID); err != nil {
		h.failPasswordResetJob(ctx, job, err)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		h.failPasswordResetJob(ctx, job, err)
		return err
	}
	h.Audit.Write(ctx, nil, "", "auth.password_reset_completed", "user", job.UserID, map[string]any{"delivery": "smtp_queue"})
	return nil
}

func (h *Handler) claimPasswordResetJob(ctx context.Context) (passwordResetJob, bool, error) {
	var job passwordResetJob
	tx, err := h.DB.Begin(ctx)
	if err != nil {
		return job, false, err
	}
	defer tx.Rollback(ctx)
	row := tx.QueryRow(ctx, `SELECT id::text,user_id::text,password_hash,temporary_password_secret,base_url,attempt
FROM password_reset_jobs
WHERE (status='pending' AND next_attempt_at<=now())
   OR (status='sending' AND locked_at < now()-interval '5 minutes')
ORDER BY created_at
FOR UPDATE SKIP LOCKED
LIMIT 1`)
	if err := row.Scan(&job.ID, &job.UserID, &job.PasswordHash, &job.TemporarySecret, &job.BaseURL, &job.Attempt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return job, false, nil
		}
		return job, false, err
	}
	job.Attempt++
	if _, err := tx.Exec(ctx, `UPDATE password_reset_jobs SET status='sending',attempt=$2,locked_at=now(),last_error='' WHERE id=$1`, job.ID, job.Attempt); err != nil {
		return job, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return job, false, err
	}
	return job, true, nil
}

func (h *Handler) ensurePasswordResetSecret(ctx context.Context, job *passwordResetJob) error {
	if job.PasswordHash != "" && job.TemporarySecret != "" {
		return nil
	}
	temporary, err := security.RandomToken(12)
	if err != nil {
		return err
	}
	hash, err := security.PasswordHash(temporary)
	if err != nil {
		return err
	}
	secret, err := h.Secrets.Encrypt(temporary)
	if err != nil {
		return err
	}
	if _, err := h.DB.Exec(ctx, `UPDATE password_reset_jobs SET password_hash=$2,temporary_password_secret=$3 WHERE id=$1`, job.ID, hash, secret); err != nil {
		return err
	}
	job.PasswordHash = hash
	job.TemporarySecret = secret
	return nil
}

func (h *Handler) failPasswordResetJob(ctx context.Context, job passwordResetJob, cause error) {
	msg := "Unbekannter Fehler"
	if cause != nil {
		msg = cause.Error()
	}
	if job.Attempt >= 5 {
		h.finishPasswordResetJob(ctx, job.ID, "failed", msg, true)
		h.Audit.Write(ctx, nil, "", "auth.password_reset_delivery_failed", "user", job.UserID, map[string]any{"attempts": job.Attempt})
		return
	}
	delay := passwordResetRetryDelay(job.Attempt)
	_, _ = h.DB.Exec(ctx, `UPDATE password_reset_jobs SET status='pending',next_attempt_at=now()+($2::bigint * interval '1 second'),locked_at=NULL,last_error=$3 WHERE id=$1`, job.ID, int64(delay/time.Second), msg)
}

func (h *Handler) finishPasswordResetJob(ctx context.Context, id, status, message string, clearSecret bool) {
	if clearSecret {
		_, _ = h.DB.Exec(ctx, `UPDATE password_reset_jobs SET status=$2,processed_at=now(),locked_at=NULL,last_error=$3,password_hash='',temporary_password_secret='' WHERE id=$1`, id, status, message)
		return
	}
	_, _ = h.DB.Exec(ctx, `UPDATE password_reset_jobs SET status=$2,processed_at=now(),locked_at=NULL,last_error=$3 WHERE id=$1`, id, status, message)
}

func passwordResetRetryDelay(attempt int) time.Duration {
	switch attempt {
	case 1:
		return 30 * time.Second
	case 2:
		return 2 * time.Minute
	case 3:
		return 10 * time.Minute
	default:
		return 30 * time.Minute
	}
}
