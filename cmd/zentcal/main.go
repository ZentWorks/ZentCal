package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zentworks/zentcal/internal/adminapi"
	"github.com/zentworks/zentcal/internal/api"
	appsvc "github.com/zentworks/zentcal/internal/app"
	"github.com/zentworks/zentcal/internal/audit"
	"github.com/zentworks/zentcal/internal/auth"
	"github.com/zentworks/zentcal/internal/backup"
	"github.com/zentworks/zentcal/internal/caldav"
	"github.com/zentworks/zentcal/internal/config"
	"github.com/zentworks/zentcal/internal/db"
	"github.com/zentworks/zentcal/internal/httpx"
	mailpkg "github.com/zentworks/zentcal/internal/mail"
	"github.com/zentworks/zentcal/internal/oidc"
	"github.com/zentworks/zentcal/internal/scheduling"
	"github.com/zentworks/zentcal/internal/security"
	webui "github.com/zentworks/zentcal/internal/web"
	"github.com/zentworks/zentcal/internal/webhook"
)

const version = "0.1.33"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		healthcheck()
		return
	}
	cfg := config.Load()
	must(cfg.Validate())
	baseURL := cfg.CanonicalBaseURL()
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	runtimeCfg := backup.RuntimeConfig{DBHost: cfg.DBHost, DBPort: cfg.DBPort, DBName: cfg.DBName, DBUser: cfg.DBUser, DBPasswordFile: cfg.DBPasswordFile, DataDir: "/data"}
	// A requested restore is applied before any application DB pool or background
	// worker exists. This keeps restore isolated from concurrent application writes.
	must(backup.ApplyPendingDatabaseRestore(ctx, runtimeCfg))
	dsn, err := cfg.DSN()
	must(err)
	pool, err := db.Open(ctx, dsn)
	must(err)
	defer pool.Close()
	must(db.Migrate(ctx, pool))
	must(db.EnsurePersonalCalendars(ctx, pool))
	secretBox, err := security.LoadSecretBox(cfg.SettingsKeyFile)
	must(err)
	var tz string
	if err := pool.QueryRow(ctx, `SELECT value FROM settings WHERE key='timezone'`).Scan(&tz); err == nil {
		if loc, e := time.LoadLocation(tz); e == nil {
			time.Local = loc
		}
	}
	authSvc := &auth.Service{DB: pool, Lifetime: cfg.SessionLifetime}
	authSvc.Cleanup(ctx)
	auditLog := &audit.Logger{DB: pool}
	must(auditLog.Cleanup(ctx))
	webhookSvc := webhook.New(pool, secretBox, log)
	mailDelivery := mailpkg.NewDeliveryService(pool, webhookSvc)
	must(mailDelivery.Cleanup(ctx))
	schedulingSvc := scheduling.New(pool, secretBox, auditLog, log, baseURL)
	schedulingSvc.MailDelivery = mailDelivery
	must(schedulingSvc.Cleanup(ctx))
	must(webhookSvc.Cleanup(ctx))
	oidcClient := oidc.New(pool, secretBox)
	backupSvc := backup.New(pool, secretBox, log, runtimeCfg, version)
	backupSvc.Webhooks = webhookSvc
	must(backupSvc.CompletePendingRestore(ctx))
	must(backupSvc.RecoverInterrupted(ctx))
	webhookSvc.Paused = backupSvc.Maintenance
	schedulingSvc.Paused = backupSvc.Maintenance
	core := &appsvc.Service{DB: pool, Auth: authSvc, Audit: auditLog, Webhooks: webhookSvc, Scheduling: schedulingSvc}
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := auditLog.Cleanup(ctx); err != nil {
					log.Warn("audit retention cleanup failed", "error", err)
				}
				if err := mailDelivery.Cleanup(ctx); err != nil {
					log.Warn("email delivery retention cleanup failed", "error", err)
				}
				if err := schedulingSvc.Cleanup(ctx); err != nil {
					log.Warn("scheduling retention cleanup failed", "error", err)
				}
				if err := webhookSvc.Cleanup(ctx); err != nil {
					log.Warn("webhook retention cleanup failed", "error", err)
				}
			}
		}
	}()
	mux := http.NewServeMux()
	web, err := webui.New(core, authSvc, auditLog, pool, cfg.WebDir, version, secretBox, oidcClient, webhookSvc, baseURL)
	must(err)
	web.Backup = backupSvc
	web.MailDelivery = mailDelivery
	web.Register(mux)
	go web.RunPasswordResetQueue(ctx)
	schedulingSvc.RegisterPublic(mux)
	(&api.Handler{App: core, Auth: authSvc, DB: pool}).Register(mux)
	(&adminapi.Handler{DB: pool, App: core, Audit: auditLog, Webhooks: webhookSvc, Backup: backupSvc, MailDelivery: mailDelivery, Restart: func() {
		time.Sleep(250 * time.Millisecond)
		if p, e := os.FindProcess(os.Getpid()); e == nil {
			_ = p.Signal(syscall.SIGTERM)
		}
	}}).Register(mux)
	(&caldav.Handler{App: core, Auth: authSvc, Scheduling: schedulingSvc}).Register(mux)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /sw.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Service-Worker-Allowed", "/")
		_, _ = w.Write([]byte(`self.addEventListener("install",()=>self.skipWaiting());self.addEventListener("activate",event=>event.waitUntil(self.clients.claim()));`))
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		c, cn := context.WithTimeout(r.Context(), 2*time.Second)
		defer cn()
		if err := pool.Ping(c); err != nil {
			http.Error(w, "not ready", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})
	guarded := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if backupSvc.Maintenance() && r.URL.Path != "/health" && r.URL.Path != "/ready" {
			http.Error(w, "ZentCal restore in progress", http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	})
	root := httpx.Middleware{Log: log, MaxBytes: cfg.MaxRequestBytes, LargeUploadPaths: map[string]int64{"/ui/backups/upload-restore": 8 << 30}}.Wrap(guarded)
	srv := &http.Server{Addr: cfg.Addr, Handler: root, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Minute, WriteTimeout: 30 * time.Minute, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20}
	go webhookSvc.Run(ctx)
	go schedulingSvc.Run(ctx)
	go backupSvc.Run(ctx)
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				authSvc.Cleanup(context.Background())
			}
		}
	}()
	go func() {
		<-ctx.Done()
		c, cn := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cn()
		_ = srv.Shutdown(c)
	}()
	log.Info("ZentCal started", "version", version, "addr", cfg.Addr)
	err = srv.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "zentcal:", err)
		os.Exit(1)
	}
}
func healthcheck() {
	c := http.Client{Timeout: 3 * time.Second}
	r, err := c.Get("http://127.0.0.1:8080/health")
	if err != nil || r.StatusCode != 200 {
		os.Exit(1)
	}
	_ = r.Body.Close()
}
