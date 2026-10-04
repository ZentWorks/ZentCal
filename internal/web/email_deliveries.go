package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/zentworks/zentcal/internal/httpx"
	mailpkg "github.com/zentworks/zentcal/internal/mail"
)

func (h *Handler) emailDeliveriesPage(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminPage(w, r, "email-deliveries")
	if !ok {
		return
	}
	rows, err := h.MailDelivery.List(r.Context(), "", "", "", 200)
	if err != nil {
		h.render(w, "email_deliveries", ss, pageData{Title: "E-Mail-Zustellungen", Page: "email-deliveries", Error: "E-Mail-Zustellungen konnten nicht geladen werden.", Data: map[string]any{"Deliveries": []mailpkg.Delivery{}}})
		return
	}
	h.render(w, "email_deliveries", ss, pageData{Title: "E-Mail-Zustellungen", Page: "email-deliveries", Data: map[string]any{"Deliveries": rows}})
}

func (h *Handler) emailDeliveriesData(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.adminPage(w, r, "email-deliveries")
	if !ok {
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	kind := strings.TrimSpace(r.URL.Query().Get("type"))
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	rows, err := h.MailDelivery.List(r.Context(), status, kind, query, 200)
	if err != nil {
		httpx.Error(w, 500, "E-Mail-Zustellungen konnten nicht geladen werden.")
		return
	}
	loc := h.location()
	if strings.TrimSpace(ss.User.Timezone) != "" {
		if userLoc, loadErr := time.LoadLocation(ss.User.Timezone); loadErr == nil {
			loc = userLoc
		}
	}
	out := make([]map[string]any, 0, len(rows))
	for _, d := range rows {
		out = append(out, map[string]any{
			"id": d.ID, "type": d.Type, "recipient": d.Recipient, "status": d.Status,
			"attempt": d.Attempt, "error": d.Error, "created_at": d.CreatedAt,
			"created_at_display": d.CreatedAt.In(loc).Format("02.01.2006 15:04"),
		})
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "data": out})
}
