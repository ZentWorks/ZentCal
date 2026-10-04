package app

import (
	"strings"
	"testing"
)

func TestCanEditEventPersonalOnlyOwn(t *testing.T) {
	if !canEditEvent("owner", "personal", "u1", "u1") {
		t.Fatal("owner must be able to edit own personal event")
	}
	if canEditEvent("owner", "personal", "u2", "u1") {
		t.Fatal("calendar owner must not edit another user's personal event")
	}
	if canEditEvent("contributor", "personal", "u2", "u1") {
		t.Fatal("contributor must not edit another user's event in personal mode")
	}
	if canEditEvent("viewer", "personal", "u1", "u1") {
		t.Fatal("viewer must not edit events in personal mode")
	}
}

func TestCanEditEventNormalHonorsRole(t *testing.T) {
	if !canEditEvent("contributor", "normal", "u2", "u1") {
		t.Fatal("contributor should edit all events in normal mode")
	}
	if canEditEvent("viewer", "normal", "u1", "u1") {
		t.Fatal("viewer must not edit events")
	}
}

func TestAdminCalendarViewerMembershipSQLUsesSeparateDavNameParameter(t *testing.T) {
	if !strings.Contains(adminCalendarViewerMembershipUpsertSQL, "VALUES($1,$2,'viewer',$3)") {
		t.Fatal("admin calendar viewer membership must use a separate text parameter for dav_name")
	}
	if strings.Contains(adminCalendarViewerMembershipUpsertSQL, "VALUES($1,$2,'viewer',$1)") {
		t.Fatal("calendar UUID parameter must not be reused as the text dav_name parameter")
	}
}
