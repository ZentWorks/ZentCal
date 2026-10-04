package httpx

import (
	"strings"
	"testing"
)

func TestContentSecurityPolicyFormAction(t *testing.T) {
	base := ContentSecurityPolicy()
	if !strings.Contains(base, "form-action 'self'") {
		t.Fatalf("default CSP must restrict forms to self: %s", base)
	}
	withOIDC := ContentSecurityPolicy("https://sso.example.test")
	if !strings.Contains(withOIDC, "form-action 'self' https://sso.example.test") {
		t.Fatalf("OIDC authorization origin missing from form-action: %s", withOIDC)
	}
	if strings.Contains(withOIDC, "form-action *") || strings.Contains(withOIDC, "form-action 'self' https:") {
		t.Fatalf("form-action was widened beyond the configured OIDC origin: %s", withOIDC)
	}
}
