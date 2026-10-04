package mail

import (
	"strings"
	"testing"
)

func TestRenderTemplateEscapesValuesAndAddsUIURL(t *testing.T) {
	subject, textBody, htmlBody := RenderTemplate(TemplateData{
		InstanceName: "ZentCal",
		BaseURL:      "https://cal.example.test",
		Subject:      "Einladung: {{event_title}}",
		Body:         "Hallo {{user_name}}\n{{event_title}}",
		Variables: map[string]string{
			"user_name":   "<script>alert(1)</script>",
			"event_title": "Planung",
		},
		HTMLEnabled:  true,
		HTMLTemplate: DefaultHTMLLayout,
	})
	if subject != "Einladung: Planung" {
		t.Fatalf("unexpected subject: %q", subject)
	}
	if !strings.Contains(textBody, "https://cal.example.test") {
		t.Fatal("UI URL missing from text body")
	}
	if strings.Contains(htmlBody, "<script>") || !strings.Contains(htmlBody, "&lt;script&gt;") {
		t.Fatal("template variables were not HTML escaped")
	}
	if !strings.Contains(htmlBody, `href="https://cal.example.test"`) {
		t.Fatal("UI URL missing from HTML footer")
	}
	if !strings.Contains(htmlBody, "<br>") {
		t.Fatal("plain text line break was not converted to HTML br")
	}
}

func TestRenderTemplatePlainTextOnlyWhenHTMLDisabled(t *testing.T) {
	_, textBody, htmlBody := RenderTemplate(TemplateData{
		InstanceName: "ZentCal",
		BaseURL:      "https://cal.example.test",
		Subject:      "Test",
		Body:         "Line one\nLine two",
	})
	if htmlBody != "" {
		t.Fatalf("expected no HTML body, got %q", htmlBody)
	}
	if !strings.Contains(textBody, "Line one\nLine two") {
		t.Fatal("plain text body changed unexpectedly")
	}
}

func TestRenderTemplateUsesCustomHTMLWrapper(t *testing.T) {
	_, _, htmlBody := RenderTemplate(TemplateData{
		InstanceName: "My Cal",
		BaseURL:      "https://cal.example.test",
		Subject:      "Test",
		Body:         "A\nB",
		HTMLEnabled:  true,
		HTMLTemplate: `<html><body><main>{{email_template}}</main><footer>{{instance_name}} · {{zentcal_url}}</footer></body></html>`,
	})
	if !strings.Contains(htmlBody, "<main>A<br>\nB") {
		t.Fatalf("email template not inserted: %q", htmlBody)
	}
	if !strings.Contains(htmlBody, "<footer>My Cal · https://cal.example.test</footer>") {
		t.Fatal("wrapper placeholders were not replaced")
	}
}

func TestRenderTemplateSanitizesSubject(t *testing.T) {
	subject, _, _ := RenderTemplate(TemplateData{InstanceName: "ZentCal", Subject: "Hello\r\nBcc: x@example.com", Body: "Test"})
	if strings.ContainsAny(subject, "\r\n") {
		t.Fatal("subject contains a line break")
	}
}

func TestRenderTemplateDoesNotRecursivelyExpandVariableValues(t *testing.T) {
	_, textBody, _ := RenderTemplate(TemplateData{
		InstanceName: "ZentCal", BaseURL: "https://cal.example.test",
		Subject: "Test", Body: "{{user_name}}",
		Variables: map[string]string{"user_name": "{{zentcal_url}}"},
	})
	if !strings.Contains(textBody, "{{zentcal_url}}") {
		t.Fatal("variable values must not be recursively interpreted as placeholders")
	}
}
