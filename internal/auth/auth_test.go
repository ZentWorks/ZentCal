package auth

import "testing"

func TestCalendarPermissions(t *testing.T) {
	if !CanRead("viewer") || CanCreate("viewer") {
		t.Fatal("viewer permissions wrong")
	}
	if !CanCreate("contributor") || !CanEditAll("contributor") || CanManage("contributor") {
		t.Fatal("contributor permissions wrong")
	}
	if CanRead("editor") || CanCreate("editor") || CanEditAll("editor") || CanManage("editor") {
		t.Fatal("legacy editor role must no longer grant permissions")
	}
	if !CanManage("owner") {
		t.Fatal("owner permissions wrong")
	}
}

func TestCalendarAdministrationIsSeparateFromMembership(t *testing.T) {
	admin := User{Role: "administrator"}
	regular := User{Role: "user"}
	if CanAdministerCalendar(admin, "") {
		t.Fatal("global administrator must not gain calendar ownership from the global role")
	}
	if CanRead("") {
		t.Fatal("non-member must not receive event read access")
	}
	if !CanAdministerCalendar(regular, "owner") {
		t.Fatal("calendar owner must be able to administer own calendar")
	}
	if CanAdministerCalendar(regular, "viewer") {
		t.Fatal("viewer must not administer calendar")
	}
}

func TestSSOAccountsRejectLocalPasswords(t *testing.T) {
	if AllowsLocalPassword(User{AuthType: "oidc"}) {
		t.Fatal("OIDC users must not use local passwords")
	}
	if !AllowsLocalPassword(User{AuthType: "local"}) {
		t.Fatal("local users must keep local password support")
	}
}
