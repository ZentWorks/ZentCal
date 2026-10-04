package httpx

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/zentworks/zentcal/internal/security"
)

type Middleware struct {
	Log              *slog.Logger
	MaxBytes         int64
	LargeUploadPaths map[string]int64
}

func (m Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := "req_" + strings.ToLower(security.UUID()[:8])
		r.Header.Set("X-Request-ID", id)
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", ContentSecurityPolicy())
		w.Header().Set("X-Frame-Options", "DENY")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			limit := m.MaxBytes
			if large, ok := m.LargeUploadPaths[r.URL.Path]; ok && large > limit {
				limit = large
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		sw := &statusWriter{ResponseWriter: w, status: 200}
		defer func() {
			if v := recover(); v != nil {
				m.Log.Error("request panic", "request_id", id, "panic", v, "stack", string(debug.Stack()))
				if !sw.wrote {
					http.Error(sw, "Internal Server Error", http.StatusInternalServerError)
				}
			}
			// Normal access logging is deliberately disabled. Docker logs should contain
			// actionable failures, not every browser, healthcheck or CalDAV sync request.
			if sw.status >= http.StatusInternalServerError {
				logPath := r.URL.Path
				if strings.HasPrefix(logPath, "/invite/respond/") {
					logPath = "/invite/respond/[redacted]"
				}
				m.Log.Error("request failed", "method", r.Method, "path", logPath, "status", sw.status, "request_id", id)
			}
		}()
		next.ServeHTTP(sw, r)
	})
}

func ContentSecurityPolicy(formActionOrigins ...string) string {
	formAction := "form-action 'self'"
	for _, origin := range formActionOrigins {
		if origin = strings.TrimSpace(origin); origin != "" {
			formAction += " " + origin
		}
	}
	return "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; " + formAction
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.wrote = true
	s.ResponseWriter.WriteHeader(code)
}
func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.wrote {
		s.WriteHeader(200)
	}
	return s.ResponseWriter.Write(b)
}

func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func Error(w http.ResponseWriter, status int, msg string) {
	payload := map[string]any{"ok": false, "error": msg}
	if id := w.Header().Get("X-Request-ID"); id != "" {
		payload["request_id"] = id
	}
	JSON(w, status, payload)
}
