package web

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/zentworks/zentcal/internal/app"
	"github.com/zentworks/zentcal/internal/auth"
	mailpkg "github.com/zentworks/zentcal/internal/mail"
	"github.com/zentworks/zentcal/internal/webhook"
)

func TestSettingsTemplateRendersTimezoneAndOIDC(t *testing.T) {
	h, err := New(nil, nil, nil, nil, "../../web", "test", nil, nil, nil, "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	vals := map[string]string{
		"timezone": "Europe/Berlin", "session_lifetime_hours": "720", "login_max_failures": "5", "lockout_minutes": "5",
		"smtp_port": "587", "smtp_security": "starttls", "oidc_enabled": "false", "oidc_scopes": "openid profile email", "oidc_groups_claim": "groups", "oidc_auth_method": "client_secret_post", "oidc_auto_provision": "true", "oidc_sync_name": "true", "oidc_sync_email": "true", "oidc_sync_groups": "false", "oidc_local_login": "true",
	}
	var out bytes.Buffer
	d := pageData{Title: "Einstellungen", Page: "settings", InstanceName: "ZentCal", CSRF: "csrf", Version: "test", User: &auth.User{Name: "Admin", Email: "admin@example.com", Role: "owner"}, Data: vals}
	if err := h.templates["settings"].ExecuteTemplate(&out, "base", d); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`value="Europe/Berlin" selected`)) {
		t.Fatal("selected timezone missing")
	}
	if !bytes.Contains(out.Bytes(), []byte("Single Sign-On / OIDC")) {
		t.Fatal("OIDC section missing")
	}
}

func TestWebhooksTemplateRenders(t *testing.T) {
	h, err := New(nil, nil, nil, nil, "../../web", "test", nil, nil, nil, "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]any{
		"Hooks":      []webhook.Hook{{ID: "11111111-1111-1111-1111-111111111111", Name: "Test", TargetURL: "https://example.com/hook", AuthType: "bearer", Active: true, Events: []string{"event.created"}}},
		"Deliveries": []webhook.Delivery{{ID: "22222222-2222-2222-2222-222222222222", WebhookName: "Test", Event: "event.created", Status: "failed", CreatedAt: time.Now()}},
		"Events":     webhookEventOptions,
	}
	var out bytes.Buffer
	d := pageData{Title: "Webhooks", Page: "webhooks", InstanceName: "ZentCal", CSRF: "csrf", Version: "test", User: &auth.User{Name: "Admin", Email: "admin@example.com", Role: "owner"}, Data: data}
	if err := h.templates["webhooks"].ExecuteTemplate(&out, "base", d); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte("Erneut senden")) {
		t.Fatal("retry action missing")
	}
	if !bytes.Contains(out.Bytes(), []byte(`value="event.created" checked`)) {
		t.Fatal("selected webhook event missing")
	}
	if !bytes.Contains(out.Bytes(), []byte(`value="bearer" selected`)) {
		t.Fatal("selected webhook auth type missing")
	}
}

func TestEmailDeliveriesTemplateRendersMaskedRecipient(t *testing.T) {
	h, err := New(nil, nil, nil, nil, "../../web", "test", nil, nil, nil, "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]any{"Deliveries": []mailpkg.Delivery{{ID: "1", Type: "event_invite", Recipient: "st***@example.com", Status: "failed", Attempt: 1, Error: "SMTP rejected", CreatedAt: time.Now()}}}
	var out bytes.Buffer
	d := pageData{Title: "E-Mail-Zustellungen", Page: "email-deliveries", InstanceName: "ZentCal", CSRF: "csrf", Version: "test", User: &auth.User{Name: "Admin", Email: "admin@example.com", Role: "owner", Timezone: "Europe/Berlin"}, Data: data}
	if err := h.templates["email_deliveries"].ExecuteTemplate(&out, "base", d); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte("st***@example.com")) {
		t.Fatal("masked recipient missing")
	}
	if bytes.Contains(out.Bytes(), []byte("steffen@example.com")) {
		t.Fatal("full recipient must not be rendered")
	}
}

func TestCalendarTemplateHidesEventContentFromNonMember(t *testing.T) {
	h, err := New(nil, nil, nil, nil, "../../web", "test", nil, nil, nil, "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]any{
		"Calendar": app.Calendar{ID: "11111111-1111-1111-1111-111111111111", Name: "Intern", Description: "Metadaten", Color: "#4f8cff", Access: "overview", CanReadEvents: false, CanManage: false},
		"Events":   []app.Event{{Summary: "SECRET EVENT TITLE", UID: "secret-uid"}},
		"Members":  []Member{{ID: "22222222-2222-2222-2222-222222222222", Name: "Lisa", Email: "lisa@example.com", Role: "viewer"}},
	}
	var out bytes.Buffer
	d := pageData{Title: "Intern", Page: "calendars", InstanceName: "ZentCal", CSRF: "csrf", Version: "test", User: &auth.User{ID: "33333333-3333-3333-3333-333333333333", Name: "Max", Email: "max@example.com", Role: "user"}, Data: data}
	if err := h.templates["calendar"].ExecuteTemplate(&out, "base", d); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), []byte("SECRET EVENT TITLE")) || bytes.Contains(out.Bytes(), []byte("secret-uid")) {
		t.Fatal("event content leaked to non-member calendar view")
	}
	if !bytes.Contains(out.Bytes(), []byte("lisa@example.com")) {
		t.Fatal("member list should remain visible")
	}
}

func TestCalendarTemplateManagerCanEditMetadata(t *testing.T) {
	h, err := New(nil, nil, nil, nil, "../../web", "test", nil, nil, nil, "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]any{
		"Calendar": app.Calendar{ID: "11111111-1111-1111-1111-111111111111", Name: "Team", Description: "Beschreibung", Color: "#123456", Access: "owner", Role: "owner", CanReadEvents: true, CanManage: true},
		"Events":   []app.Event{}, "Members": []Member{}, "Users": []UserRow{},
		"DAVHost": "localhost", "DAVPort": "8080", "DAVSSL": false, "DAVRoot": "http://localhost:8080/dav/", "DAVPrincipal": "http://localhost:8080/dav/principals/u/", "DAVURL": "http://localhost:8080/dav/calendars/u/c/",
	}
	var out bytes.Buffer
	d := pageData{Title: "Team", Page: "calendars", InstanceName: "ZentCal", CSRF: "csrf", Version: "test", User: &auth.User{ID: "u", Name: "Owner", Email: "owner@example.com", Role: "user"}, Data: data}
	if err := h.templates["calendar"].ExecuteTemplate(&out, "base", d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`id="edit-calendar"`, `name="description"`, `name="color"`, `id="edit-member"`} {
		if !bytes.Contains(out.Bytes(), []byte(want)) {
			t.Fatalf("calendar manager UI missing %s", want)
		}
	}
}

func TestAttendeeDiff(t *testing.T) {
	added, removed := attendeeDiff([]string{"a@example.com", "b@example.com"}, []string{"b@example.com", "c@example.com"})
	if len(added) != 1 || added[0] != "c@example.com" || len(removed) != 1 || removed[0] != "a@example.com" {
		t.Fatalf("unexpected attendee diff: added=%v removed=%v", added, removed)
	}
}

func TestBaseRendersAccountModalAndNoAccountNav(t *testing.T) {
	h, err := New(nil, nil, nil, nil, "../../web", "test", nil, nil, nil, "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	d := pageData{
		Title: "Dashboard", Page: "dashboard", Lang: "de", InstanceName: "ZentCal", CSRF: "csrf", Version: "test",
		User:                &auth.User{Name: "Max", Email: "max@example.com", Role: "user", Language: "de", Timezone: "Europe/Berlin", AuthType: "local"},
		AccountAppPasswords: []AppPasswordRow{{ID: "app-1", Name: "MacBook", Prefix: "zca_test", CreatedAt: time.Now()}},
		Data:                dashboardTestData(),
	}
	if err := h.templates["dashboard"].ExecuteTemplate(&out, "base", d); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	for _, want := range []string{`data-modal-open="account-modal"`, `id="account-modal"`, `name="language"`, `name="timezone"`, `MacBook`} {
		if !strings.Contains(html, want) {
			t.Fatalf("account modal missing %q", want)
		}
	}
	if strings.Contains(html, `href="/account" class=`) {
		t.Fatal("account must no longer be a primary sidebar navigation item")
	}
}

func TestSettingsTemplateShowsDirectOIDCLoginWhenConfigured(t *testing.T) {
	h, err := New(nil, nil, nil, nil, "../../web", "test", nil, nil, nil, "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	vals := map[string]string{
		"timezone": "Europe/Berlin", "session_lifetime_hours": "720", "login_max_failures": "5", "lockout_minutes": "5",
		"smtp_port": "587", "smtp_security": "starttls", "oidc_enabled": "true", "oidc_scopes": "openid profile email", "oidc_groups_claim": "groups", "oidc_auth_method": "client_secret_post", "oidc_auto_provision": "true", "oidc_sync_name": "true", "oidc_sync_email": "true", "oidc_sync_groups": "false", "oidc_local_login": "true",
		"oidc_issuer": "https://sso.example.test", "oidc_client_id": "zentcal", "oidc_client_secret_set": "true", "oidc_login_url": "https://cal.example.test/auth/oidc/start",
	}
	var out bytes.Buffer
	d := pageData{Title: "Einstellungen", Page: "settings", InstanceName: "ZentCal", CSRF: "csrf", Version: "test", User: &auth.User{Name: "Admin", Email: "admin@example.com", Role: "owner"}, Data: vals}
	if err := h.templates["settings"].ExecuteTemplate(&out, "base", d); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	if !strings.Contains(html, "Direkter SSO-Login") || !strings.Contains(html, `href="https://cal.example.test/auth/oidc/start"`) {
		t.Fatal("direct OIDC login link missing")
	}
}

func TestBaseRendersAdminCalendarManagementWithoutTagline(t *testing.T) {
	h, err := New(nil, nil, nil, nil, "../../web", "test", nil, nil, nil, "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	d := pageData{
		Title: "Dashboard", Page: "dashboard", Lang: "de", InstanceName: "ZentCal", CSRF: "csrf", Version: "test",
		User: &auth.User{Name: "Admin", Email: "admin@example.com", Role: "owner", Language: "de", Timezone: "Europe/Berlin", AuthType: "local"},
		Data: dashboardTestData(),
	}
	if err := h.templates["dashboard"].ExecuteTemplate(&out, "base", d); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	if !strings.Contains(html, `href="/admin/calendars"`) || !strings.Contains(html, "Kalenderverwaltung") {
		t.Fatal("admin calendar management navigation missing")
	}
	if strings.Contains(html, "Calendar Infrastructure") {
		t.Fatal("obsolete brand tagline must not be rendered")
	}
}

func TestSettingsMailTemplatesUsePersistentEditorModal(t *testing.T) {
	h, err := New(nil, nil, nil, nil, "../../web", "test", nil, nil, nil, "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	vals := map[string]string{
		"timezone": "Europe/Berlin", "session_lifetime_hours": "720", "login_max_failures": "5", "lockout_minutes": "5",
		"smtp_port": "587", "smtp_security": "starttls", "oidc_enabled": "false", "oidc_scopes": "openid profile email", "oidc_groups_claim": "groups", "oidc_auth_method": "client_secret_post", "oidc_auto_provision": "true", "oidc_sync_name": "true", "oidc_sync_email": "true", "oidc_sync_groups": "false", "oidc_local_login": "true",
	}
	for k, v := range mailTemplateDefaultsForSettings() {
		vals[k] = v
	}
	var out bytes.Buffer
	d := pageData{Title: "Einstellungen", Page: "settings", InstanceName: "ZentCal", CSRF: "csrf", Version: "test", User: &auth.User{Name: "Admin", Email: "admin@example.com", Role: "owner"}, Data: vals}
	if err := h.templates["settings"].ExecuteTemplate(&out, "base", d); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	if !strings.Contains(html, `id="mail-templates-modal"`) || !strings.Contains(html, `data-mail-template-tab="calendar_shared"`) {
		t.Fatal("mail template editor modal missing")
	}
	start := strings.Index(html, `id="mail-templates-modal"`)
	if start < 0 {
		t.Fatal("mail template modal missing")
	}
	chunk := html[start:]
	backdrop := strings.Index(chunk, `class="modal-backdrop"`)
	if backdrop < 0 {
		t.Fatal("mail template modal backdrop missing")
	}
	if strings.Contains(chunk[backdrop:backdrop+minInt(120, len(chunk)-backdrop)], "data-modal-close") {
		t.Fatal("mail template modal must not close when clicking the backdrop")
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestLoginTemplateUsesEmailFirstFlow(t *testing.T) {
	h, err := New(nil, nil, nil, nil, "../../web", "0.1.23", nil, nil, nil, "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	var emailStep bytes.Buffer
	if err := h.templates["login"].ExecuteTemplate(&emailStep, "login.html", pageData{Title: "Anmelden", Version: "0.1.23", Lang: "de", Data: map[string]any{"Step": "email"}}); err != nil {
		t.Fatal(err)
	}
	html := emailStep.String()
	for _, unwanted := range []string{"Mit Single Sign-On anmelden", "oder lokal", `name="password"`, "Passwort vergessen?"} {
		if strings.Contains(html, unwanted) {
			t.Fatalf("email-first login unexpectedly contains %q", unwanted)
		}
	}
	if !strings.Contains(html, `name="email"`) || !strings.Contains(html, `name="step" value="identify"`) || !strings.Contains(html, ">Weiter</button>") {
		t.Fatal("email-first login controls missing")
	}

	var passwordStep bytes.Buffer
	if err := h.templates["login"].ExecuteTemplate(&passwordStep, "login.html", pageData{Title: "Anmelden", Version: "0.1.23", Lang: "de", Data: map[string]any{"Step": "password", "Email": "user@example.com", "ForgotPassword": true}}); err != nil {
		t.Fatal(err)
	}
	html = passwordStep.String()
	for _, want := range []string{`name="step" value="password"`, `name="email" value="user@example.com"`, `name="password"`, "Passwort vergessen?", "Andere E-Mail verwenden"} {
		if !strings.Contains(html, want) {
			t.Fatalf("password login step missing %q", want)
		}
	}
}
