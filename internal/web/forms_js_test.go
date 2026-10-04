package web

import (
	"os"
	"strings"
	"testing"
)

func TestAJAXSerializesWholeFormAndUsesExplicitSubmitOverrides(t *testing.T) {
	b, err := os.ReadFile("../../web/static/js/forms.js")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"new FormData(form, submitter)", "new FormData(form)", "getAttribute('formaction')", "getAttribute('formmethod')", "new URLSearchParams(formData)"} {
		if !strings.Contains(s, want) {
			t.Fatalf("forms.js missing %q", want)
		}
	}
	if strings.Contains(s, "submitter?.formAction") || strings.Contains(s, "submitter?.formMethod") {
		t.Fatal("forms.js must not use browser-expanded formAction/formMethod defaults")
	}
}
