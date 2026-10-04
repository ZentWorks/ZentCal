package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zentworks/zentcal/internal/api"
	"github.com/zentworks/zentcal/internal/caldav"
	webui "github.com/zentworks/zentcal/internal/web"
)

func buildTestMux() *http.ServeMux {
	mux := http.NewServeMux()
	web := &webui.Handler{WebDir: "../../web"}
	web.Register(mux)
	(&api.Handler{}).Register(mux)
	(&caldav.Handler{}).Register(mux)
	mux.HandleFunc("GET /health", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("GET /sw.js", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("GET /ready", func(http.ResponseWriter, *http.Request) {})
	return mux
}

func TestAllRoutesRegisterWithoutServeMuxConflict(t *testing.T) {
	_ = buildTestMux()
}

func TestCalDAVWellKnownIsNotShadowedByDashboard(t *testing.T) {
	mux := buildTestMux()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/caldav", nil)
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusTemporaryRedirect)
	}
	if got := rr.Header().Get("Location"); got != "/dav/" {
		t.Fatalf("Location = %q, want %q", got, "/dav/")
	}
}

func TestUnknownGETDoesNotFallThroughToDashboard(t *testing.T) {
	mux := buildTestMux()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/does-not-exist", nil)
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}
