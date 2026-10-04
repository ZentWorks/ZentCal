package mail

import "testing"

func TestMaskRecipient(t *testing.T) {
	cases := map[string]string{
		"steffen@example.com": "st***@example.com",
		"a@example.com":       "a***@example.com",
		"":                    "***",
	}
	for in, want := range cases {
		if got := MaskRecipient(in); got != want {
			t.Fatalf("MaskRecipient(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSanitizeDeliveryError(t *testing.T) {
	got := sanitizeDeliveryError("recipient steffen@example.com rejected\r\nby server")
	got = deliveryEmailRE.ReplaceAllStringFunc(got, MaskRecipient)
	if got != "recipient st***@example.com rejected  by server" {
		t.Fatalf("unexpected sanitized error: %q", got)
	}
}
