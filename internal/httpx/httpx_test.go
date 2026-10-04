package httpx

import (
	"strings"
	"testing"
)

func formActionTokens(csp string) []string {
	for _, directive := range strings.Split(csp, ";") {
		fields := strings.Fields(strings.TrimSpace(directive))
		if len(fields) > 0 && fields[0] == "form-action" {
			return fields[1:]
		}
	}
	return nil
}

func containsToken(tokens []string, want string) bool {
	for _, token := range tokens {
		if token == want {
			return true
		}
	}
	return false
}

func TestContentSecurityPolicyFormAction(t *testing.T) {
	baseTokens := formActionTokens(ContentSecurityPolicy())
	if len(baseTokens) != 1 || baseTokens[0] != "'self'" {
		t.Fatalf("default form-action must be exactly self, got %v", baseTokens)
	}

	const oidcOrigin = "https://sso.example.test"
	withOIDCTokens := formActionTokens(ContentSecurityPolicy(oidcOrigin))
	if len(withOIDCTokens) != 2 || withOIDCTokens[0] != "'self'" || withOIDCTokens[1] != oidcOrigin {
		t.Fatalf("OIDC form-action must contain only self and the configured origin, got %v", withOIDCTokens)
	}
	if containsToken(withOIDCTokens, "*") || containsToken(withOIDCTokens, "https:") {
		t.Fatalf("form-action was widened beyond the configured OIDC origin: %v", withOIDCTokens)
	}
}
