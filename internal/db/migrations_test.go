package db

import (
	"strings"
	"testing"
)

// A fresh database must contain every field referenced by the admin calendar
// queries, and an upgraded database must receive them in a new migration.
func TestAdminCalendarSchemaRecoveryMigration(t *testing.T) {
	if len(migrations) < 2 {
		t.Fatal("missing schema migrations")
	}
	tail := migrations[len(migrations)-1]
	for _, field := range []string{
		"ADD COLUMN IF NOT EXISTS admin_managed boolean NOT NULL DEFAULT false",
		"ADD COLUMN IF NOT EXISTS admin_manager_user_id uuid REFERENCES users(id) ON DELETE SET NULL",
		"ADD COLUMN IF NOT EXISTS admin_manager_visible boolean NOT NULL DEFAULT false",
	} {
		if !strings.Contains(tail, field) {
			t.Errorf("admin-calendar recovery migration missing %q", field)
		}
	}
	if !strings.Contains(tail, "CREATE INDEX IF NOT EXISTS calendars_admin_manager_idx") {
		t.Error("missing admin manager index")
	}
	for i, earlier := range migrations[:len(migrations)-1] {
		if strings.Contains(earlier, "calendars_admin_manager_idx") {
			t.Errorf("recovery migration was inserted at earlier index %d; it must remain appended", i)
		}
	}
}
