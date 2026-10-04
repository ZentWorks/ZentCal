package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	Addr            string
	BaseURL         string
	DBHost          string
	DBPort          string
	DBName          string
	DBUser          string
	DBPasswordFile  string
	SettingsKeyFile string
	WebDir          string
	ShutdownTimeout time.Duration
	SessionLifetime time.Duration
	MaxRequestBytes int64
}

func Load() Config {
	webDir := env("ZENTCAL_WEB_DIR", "/app/web")
	if _, err := os.Stat(webDir); err != nil {
		if _, e := os.Stat("./web"); e == nil {
			webDir = "./web"
		}
	}
	return Config{
		Addr:            env("ZENTCAL_ADDR", ":8080"),
		BaseURL:         env("ZENTCAL_BASE_URL", "http://localhost:8080"),
		DBHost:          env("ZENTCAL_DB_HOST", "db"),
		DBPort:          env("ZENTCAL_DB_PORT", "5432"),
		DBName:          env("ZENTCAL_DB_NAME", "zentcal"),
		DBUser:          env("ZENTCAL_DB_USER", "zentcal"),
		DBPasswordFile:  env("ZENTCAL_DB_PASSWORD_FILE", "/run/zentcal/postgres_password"),
		SettingsKeyFile: env("ZENTCAL_SETTINGS_KEY_FILE", "/run/zentcal/settings_key"),
		WebDir:          webDir,
		ShutdownTimeout: 15 * time.Second,
		SessionLifetime: 30 * 24 * time.Hour,
		MaxRequestBytes: 10 << 20,
	}
}

func (c Config) Validate() error {
	raw := strings.TrimSpace(c.BaseURL)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("ZENTCAL_BASE_URL must be a complete http(s) URL")
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("ZENTCAL_BASE_URL must not contain credentials, a path, query, or fragment")
	}
	if strings.ContainsAny(u.Host, "\r\n\t ") {
		return errors.New("ZENTCAL_BASE_URL contains an invalid host")
	}
	return nil
}

func (c Config) CanonicalBaseURL() string {
	return strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
}

func (c Config) DSN() (string, error) {
	b, err := os.ReadFile(c.DBPasswordFile)
	if err != nil {
		return "", fmt.Errorf("read database password: %w", err)
	}
	password := strings.TrimSpace(string(b))
	u := &url.URL{Scheme: "postgres", User: url.UserPassword(c.DBUser, password), Host: c.DBHost + ":" + c.DBPort, Path: c.DBName}
	q := u.Query()
	q.Set("sslmode", "disable")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
