package web

import (
	"bytes"
	"mime/multipart"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestParseRequestFormURLEncoded(t *testing.T) {
	values := url.Values{"name": {"Test"}, "email": {"info@example.com"}}
	r := httptest.NewRequest("POST", "/", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := parseRequestForm(r); err != nil {
		t.Fatal(err)
	}
	if got := r.FormValue("name"); got != "Test" {
		t.Fatalf("name = %q", got)
	}
}

func TestParseRequestFormMultipart(t *testing.T) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if err := w.WriteField("name", "Test"); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteField("email", "info@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/", &body)
	r.Header.Set("Content-Type", w.FormDataContentType())
	if err := parseRequestForm(r); err != nil {
		t.Fatal(err)
	}
	if got := r.FormValue("email"); got != "info@example.com" {
		t.Fatalf("email = %q", got)
	}
}
