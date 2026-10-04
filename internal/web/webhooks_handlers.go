package web

import (
	"net/http"
	"strings"

	"github.com/zentworks/zentcal/internal/httpx"
)

var webhookEventOptions = []string{
	"calendar.created", "calendar.updated", "event.created", "event.updated", "event.deleted",
	"member.added", "member.updated", "member.removed", "user.created", "user.disabled", "user.deleted", "settings.updated",
	"backup.succeeded", "backup.failed", "backup.verify.failed", "backup.restore.started", "backup.restore.failed", "email.failed",
}

func (h *Handler) webhooksPage(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminPage(w, r, "webhooks")
	if !ok {
		return
	}
	hooks, _ := h.Webhooks.List(r.Context())
	deliveries, _ := h.Webhooks.Deliveries(r.Context(), 100)
	h.render(w, "webhooks", ss, pageData{Title: "Webhooks", Page: "webhooks", Data: map[string]any{"Hooks": hooks, "Deliveries": deliveries, "Events": webhookEventOptions}})
}

func (h *Handler) createWebhook(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	hook, secret, err := h.Webhooks.Create(r.Context(), r.FormValue("name"), r.FormValue("target_url"), r.FormValue("auth_type"), r.Form["events"], r.FormValue("active") == "true", r.FormValue("allow_private") == "true", ss.User.ID)
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "webhook.created", "webhook", hook.ID, map[string]any{"name": hook.Name, "auth_type": hook.AuthType})
	if hook.AuthType == "none" {
		httpx.JSON(w, 201, map[string]any{"ok": true, "message": "Webhook erstellt.", "reload": true})
		return
	}
	label := "Token"
	if hook.AuthType == "hmac" {
		label = "HMAC-Secret"
	}
	httpx.JSON(w, 201, map[string]any{"ok": true, "secret": secret, "message": label + " wurde erstellt und wird nur einmal angezeigt.", "reload_after_secret": true})
}

func (h *Handler) updateWebhook(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	id := r.PathValue("id")
	if err := h.Webhooks.Update(r.Context(), id, r.FormValue("name"), r.FormValue("target_url"), r.FormValue("auth_type"), r.Form["events"], r.FormValue("active") == "true", r.FormValue("allow_private") == "true"); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "webhook.updated", "webhook", id, nil)
	httpx.JSON(w, 200, map[string]any{"ok": true, "message": "Webhook gespeichert.", "reload": true})
}

func (h *Handler) deleteWebhook(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := h.Webhooks.Delete(r.Context(), id); err != nil {
		httpx.Error(w, 500, "Webhook konnte nicht gelöscht werden.")
		return
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "webhook.deleted", "webhook", id, nil)
	httpx.JSON(w, 200, map[string]any{"ok": true, "reload": true})
}

func (h *Handler) rotateWebhookSecret(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	secret, err := h.Webhooks.RotateSecret(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.Error(w, 500, "Webhook-Secret konnte nicht rotiert werden.")
		return
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "webhook.secret_rotated", "webhook", r.PathValue("id"), nil)
	httpx.JSON(w, 200, map[string]any{"ok": true, "secret": secret, "message": "Neues Webhook-Token/Secret. Es wird nur einmal angezeigt."})
}

func (h *Handler) testWebhook(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	deliveryID, err := h.Webhooks.Test(r.Context(), id, ss.User.ID)
	if err != nil {
		httpx.Error(w, 500, "Webhook-Test konnte nicht eingeplant werden.")
		return
	}
	httpx.JSON(w, 202, map[string]any{"ok": true, "message": "Test-Delivery wurde eingeplant.", "delivery_id": deliveryID, "reload": true})
}

func (h *Handler) retryWebhookDelivery(w http.ResponseWriter, r *http.Request) {
	_, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	ct, err := h.DB.Exec(r.Context(), `UPDATE webhook_deliveries SET status='pending',attempt=0,next_attempt_at=now(),last_error='' WHERE id=$1 AND status='failed'`, id)
	if err != nil || ct.RowsAffected() == 0 {
		httpx.Error(w, 400, "Delivery kann nicht erneut eingeplant werden.")
		return
	}
	httpx.JSON(w, 202, map[string]any{"ok": true, "message": "Delivery wurde erneut eingeplant.", "reload": true})
}
