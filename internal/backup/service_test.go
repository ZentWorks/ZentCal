package backup

import (
	"slices"
	"testing"
)

func TestPGDumpArgsExcludeBackupCatalogData(t *testing.T) {
	runtime := RuntimeConfig{
		DBHost: "db",
		DBPort: "5432",
		DBName: "zentcal",
		DBUser: "zentcal",
	}
	args := pgDumpArgs(runtime, "/tmp/database.dump")
	if !slices.Contains(args, "--exclude-table-data=public.backups") {
		t.Fatalf("backup catalog data must not be embedded in database dumps: %v", args)
	}
	if !slices.Contains(args, "--format=custom") {
		t.Fatalf("database backup must remain a custom-format pg_dump: %v", args)
	}
	if !slices.Contains(args, "/tmp/database.dump") {
		t.Fatalf("database dump destination missing: %v", args)
	}
}
