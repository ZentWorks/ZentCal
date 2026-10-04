package security

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestSecretBoxRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	path := filepath.Join(dir, "settings_key")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0600); err != nil {
		t.Fatal(err)
	}
	box, err := LoadSecretBox(path)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := box.Encrypt("super-secret")
	if err != nil {
		t.Fatal(err)
	}
	if enc == "super-secret" || enc == "" {
		t.Fatalf("secret was not encrypted")
	}
	plain, err := box.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "super-secret" {
		t.Fatalf("got %q", plain)
	}
}
