package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateTargetBlocksLoopbackByDefault(t *testing.T) {
	if err := ValidateTarget(context.Background(), "http://127.0.0.1:8080/hook", false); err == nil {
		t.Fatal("loopback target should be blocked")
	}
	if err := ValidateTarget(context.Background(), "http://127.0.0.1:8080/hook", true); err != nil {
		t.Fatalf("explicit private target should be allowed: %v", err)
	}
}

func TestSendSignsPayload(t *testing.T) {
	secret := "test-secret"
	body := []byte(`{"event":"event.created"}`)
	var signature, timestamp string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signature = r.Header.Get("X-ZentCal-Signature")
		timestamp = r.Header.Get("X-ZentCal-Timestamp")
		got, _ := io.ReadAll(r.Body)
		if string(got) != string(body) {
			t.Errorf("body = %s", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	s := &Service{Log: slog.Default(), Client: &http.Client{Timeout: 2 * time.Second}}
	status, err := s.send(context.Background(), server.URL, true, "hmac", "event.created", "delivery-1", body, secret)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusNoContent {
		t.Fatalf("status=%d", status)
	}
	if timestamp == "" || signature == "" {
		t.Fatal("signature headers missing")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp + "." + string(body)))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(strings.TrimSpace(signature)), []byte(want)) {
		t.Fatalf("signature mismatch")
	}
}

func TestSendBearerToken(t *testing.T) {
	secret := "zcw_test_token"
	body := []byte(`{"event":"calendar.created"}`)
	var authHeader, sig string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		sig = r.Header.Get("X-ZentCal-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	s := &Service{Log: slog.Default(), Client: &http.Client{Timeout: 2 * time.Second}}
	status, err := s.send(context.Background(), server.URL, true, "bearer", "calendar.created", "delivery-2", body, secret)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	if authHeader != "Bearer "+secret {
		t.Fatalf("authorization=%q", authHeader)
	}
	if sig != "" {
		t.Fatalf("unexpected HMAC signature for bearer auth: %q", sig)
	}
}
