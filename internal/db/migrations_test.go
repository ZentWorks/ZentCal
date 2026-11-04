package db

import (
	"strings"
	"testing"
)

// A fresh database must contain every field referenced by the admin calendar
// queries, and an upgraded database must receive them in a new migration.
func TestAdminCalendarSchemaRecoveryMigration(t *testing.T) {
	if len(migrations) < 3 {
		t.Fatal("missing schema migrations")
	}
	tail := migrations[len(migrations)-2]
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
	for i, earlier := range migrations[:len(migrations)-2] {
		if strings.Contains(earlier, "calendars_admin_manager_idx") {
			t.Errorf("recovery migration was inserted at earlier index %d; it must remain appended", i)
		}
	}
}

// VTODO must survive upgrades from databases initialized before task support.
// A new appended migration is essential: editing an already-recorded version
// does not rerun it on existing installations.
func TestTasksTypeConstraintRecoveryIsLastMigration(t *testing.T) {
	if len(migrations) < 3 {
		t.Fatal("missing schema migrations")
	}
	last := migrations[len(migrations)-1]
	for _, snippet := range []string{
		"DROP CONSTRAINT IF EXISTS calendars_type_check",
		"ADD CONSTRAINT calendars_type_check CHECK (type IN ('calendar','resource','tasks'))",
	} {
		if !strings.Contains(last, snippet) {
			t.Errorf("task collection recovery migration missing %q", snippet)
		}
	}
	if !strings.Contains(migrations[len(migrations)-2], "calendars_admin_manager_idx") {
		t.Error("previous admin calendar recovery migration moved or changed")
	}
}
