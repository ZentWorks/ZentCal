package oidc

import "testing"

func TestRoleForGroups(t *testing.T) {
	mapping := "employees=user\ncalendar-admins=administrator"
	if got := RoleForGroups(mapping, []string{"employees"}); got != "user" {
		t.Fatalf("got %q", got)
	}
	if got := RoleForGroups(mapping, []string{"employees", "calendar-admins"}); got != "administrator" {
		t.Fatalf("got %q", got)
	}
}

func TestExtractGroupsSupportsNestedClaim(t *testing.T) {
	m := map[string]any{"realm_access": map[string]any{"roles": []any{"one", "two"}}}
	got := extractGroups(m, "realm_access.roles")
	if len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("unexpected groups: %#v", got)
	}
}

func TestAudienceMatching(t *testing.T) {
	if !audHas("zentcal", "zentcal") {
		t.Fatal("string audience should match")
	}
	if !audHas([]any{"other", "zentcal"}, "zentcal") {
		t.Fatal("array audience should match")
	}
	if audHas([]any{"other"}, "zentcal") {
		t.Fatal("unexpected match")
	}
}

func TestVerifyJWTRS256(t *testing.T) {
	// Kept in a helper file below via standard-library crypto only; no OIDC dependency.
	testVerifyRS256(t)
}
