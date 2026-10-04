package config

import "testing"

func TestConfigValidatesCanonicalBaseURL(t *testing.T) {
	valid := []string{
		"http://localhost:8080",
		"https://calendar.example.com",
		"https://calendar.example.com:8443/",
	}
	for _, raw := range valid {
		cfg := Config{BaseURL: raw}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("valid base URL %q rejected: %v", raw, err)
		}
	}
}

func TestConfigRejectsUnsafeBaseURL(t *testing.T) {
	invalid := []string{
		"",
		"calendar.example.com",
		"ftp://calendar.example.com",
		"https://user:pass@calendar.example.com",
		"https://calendar.example.com/path",
		"https://calendar.example.com/?q=1",
		"https://calendar.example.com/#fragment",
	}
	for _, raw := range invalid {
		cfg := Config{BaseURL: raw}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("unsafe base URL %q was accepted", raw)
		}
	}
}

func TestCanonicalBaseURLTrimsTrailingSlash(t *testing.T) {
	cfg := Config{BaseURL: "https://calendar.example.com/"}
	if got := cfg.CanonicalBaseURL(); got != "https://calendar.example.com" {
		t.Fatalf("unexpected canonical base URL: %q", got)
	}
}
