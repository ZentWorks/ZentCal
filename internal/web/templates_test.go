package web

import "testing"

func TestTemplatesParse(t *testing.T) {
	if _, err := New(nil, nil, nil, nil, "../../web", "test", nil, nil, nil, "http://localhost:8080"); err != nil {
		t.Fatal(err)
	}
}
