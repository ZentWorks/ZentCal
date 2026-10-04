package security

import "testing"

func TestTokenHashStable(t *testing.T) {
	if TokenHash("abc") != TokenHash("abc") {
		t.Fatal("hash must be stable")
	}
	if TokenHash("abc") == TokenHash("abcd") {
		t.Fatal("different tokens must hash differently")
	}
}

func TestUUIDShape(t *testing.T) {
	u := UUID()
	if len(u) != 36 || u[8] != '-' || u[13] != '-' || u[18] != '-' || u[23] != '-' {
		t.Fatalf("bad uuid %q", u)
	}
}

func TestDigestHA1RFCExample(t *testing.T) {
	if got := DigestHA1("Mufasa", "testrealm@host.com", "Circle Of Life"); got != "939e7578ed9e3c518a452acee763bce9" {
		t.Fatalf("ha1=%s", got)
	}
}
