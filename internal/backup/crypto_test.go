package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupEncryptionRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.bin")
	enc := filepath.Join(dir, "backup.zcbak")
	dst := filepath.Join(dir, "restored.bin")
	payload := bytes.Repeat([]byte("ZentCal backup payload\n"), 60000)
	if err := os.WriteFile(src, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := encryptFile(src, enc, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if err := decryptFile(enc, dst, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("decrypted backup differs from source")
	}
}

func TestBackupEncryptionRejectsWrongPassword(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.txt")
	enc := filepath.Join(dir, "backup.zcbak")
	dst := filepath.Join(dir, "restored.txt")
	if err := os.WriteFile(src, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := encryptFile(src, enc, "correct-password"); err != nil {
		t.Fatal(err)
	}
	if err := decryptFile(enc, dst, "wrong-password-xx"); err == nil {
		t.Fatal("wrong password unexpectedly decrypted backup")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("partial plaintext file should be removed, stat err=%v", err)
	}
}

func writeTestArchive(t *testing.T, path string, entries []struct {
	name string
	size int64
	data []byte
}) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		size := entry.size
		if size == 0 {
			size = int64(len(entry.data))
		}
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0600, Size: size, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if len(entry.data) > 0 {
			if _, err := tw.Write(entry.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func validBackupEntries() []struct {
	name string
	size int64
	data []byte
} {
	return []struct {
		name string
		size int64
		data []byte
	}{
		{name: "database.dump", data: []byte("db")},
		{name: "secrets.json", data: []byte(`{"settings":{},"webhooks":{}}`)},
		{name: "manifest.json", data: []byte(`{"product":"ZentCal"}`)},
	}
}

func TestExtractTarGzAcceptsExpectedBackupLayout(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "archive.tar.gz")
	writeTestArchive(t, archive, validBackupEntries())
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	if err := extractTarGz(archive, out); err != nil {
		t.Fatalf("valid backup rejected: %v", err)
	}
}

func TestExtractTarGzRejectsUnexpectedEntry(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "archive.tar.gz")
	entries := validBackupEntries()
	entries = append(entries, struct {
		name string
		size int64
		data []byte
	}{name: "extra.txt", data: []byte("no")})
	writeTestArchive(t, archive, entries)
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	if err := extractTarGz(archive, out); err == nil {
		t.Fatal("unexpected archive entry was accepted")
	}
}

func TestExtractTarGzRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "archive.tar.gz")
	entries := validBackupEntries()
	entries[0].name = "../database.dump"
	writeTestArchive(t, archive, entries)
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	if err := extractTarGz(archive, out); err == nil {
		t.Fatal("path traversal was accepted")
	}
}

func TestExtractTarGzRejectsMissingRequiredEntry(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "archive.tar.gz")
	entries := validBackupEntries()[:2]
	writeTestArchive(t, archive, entries)
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	if err := extractTarGz(archive, out); err == nil {
		t.Fatal("incomplete backup was accepted")
	}
}

func TestExtractTarGzRejectsOversizedEntryFromHeader(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "archive.tar.gz")
	entries := validBackupEntries()
	entries[1].data = bytes.Repeat([]byte("x"), int(maxRestoreSecretsSize+1))
	writeTestArchive(t, archive, entries)
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	if err := extractTarGz(archive, out); err == nil {
		t.Fatal("oversized backup entry was accepted")
	}
}
