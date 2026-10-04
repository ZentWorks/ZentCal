package web

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/zentworks/zentcal/internal/auth"
)

func TestBrowserLanguage(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"de-DE,de;q=0.9,en;q=0.8", "de"},
		{"de-AT,de;q=0.9", "de"},
		{"fr-CH,fr;q=0.9", "de"},
		{"en-US,en;q=0.9", "en"},
		{"fr-FR,fr;q=0.9", "en"},
		{"", "en"},
	}
	for _, tc := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		if tc.header != "" {
			r.Header.Set("Accept-Language", tc.header)
		}
		if got := browserLanguage(r); got != tc.want {
			t.Fatalf("header %q: got %q want %q", tc.header, got, tc.want)
		}
	}
}

func TestEnglishAccountTemplateIsServerRendered(t *testing.T) {
	h, err := New(nil, nil, nil, nil, "../../web", "test", nil, nil, nil, "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	tpl := h.templates["account|en"]
	if tpl == nil {
		t.Fatal("english account template missing")
	}
	var out bytes.Buffer
	d := pageData{
		Title: "My Account", Page: "account", Lang: "en", InstanceName: "ZentCal", CSRF: "csrf", Version: "test",
		User: &auth.User{Name: "Test", Email: "test@example.com", Role: "user", Language: "en", Timezone: "Europe/Berlin", AuthType: "local"},
		Data: map[string]any{"AppPasswords": []AppPasswordRow{}, "PasswordChangeRequired": false},
	}
	if err := tpl.ExecuteTemplate(&out, "base", d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"My Account", "Profile", "Language", "Timezone", "App Passwords", "Sign out"} {
		if !bytes.Contains(out.Bytes(), []byte(want)) {
			t.Fatalf("english UI missing %q", want)
		}
	}
	if bytes.Contains(out.Bytes(), []byte(">Mein Konto<")) || bytes.Contains(out.Bytes(), []byte(">Sprache<")) {
		t.Fatal("german navigation/profile labels leaked into english account page")
	}
}

func TestAdminNavigationGrouping(t *testing.T) {
	h, err := New(nil, nil, nil, nil, "../../web", "test", nil, nil, nil, "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	d := pageData{
		Title: "Dashboard", Page: "dashboard", Lang: "de", InstanceName: "ZentCal", CSRF: "csrf", Version: "test",
		User: &auth.User{Name: "Admin", Email: "admin@example.com", Role: "administrator", Language: "de", Timezone: "Europe/Berlin"},
		Data: dashboardTestData(),
	}
	if err := h.templates["dashboard"].ExecuteTemplate(&out, "base", d); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	if !bytes.Contains(out.Bytes(), []byte(`class="nav-label">Admin`)) {
		t.Fatal("admin navigation group missing")
	}
	if !bytes.Contains(out.Bytes(), []byte(`/static/icons/sprite.svg#users`)) || !bytes.Contains(out.Bytes(), []byte(`/static/icons/sprite.svg#calendar`)) {
		t.Fatal("new SVG navigation icons missing")
	}
	if html == "" {
		t.Fatal("empty rendered page")
	}
}
