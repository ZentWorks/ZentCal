package mail

import (
	"html"
	"strings"
)

const DefaultHTMLLayout = `<!doctype html>
<html>
<body style="margin:0;background:#0f1319;color:#eef2f7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
  <div style="max-width:640px;margin:0 auto;padding:32px 20px">
    <div style="font-size:18px;font-weight:700;margin-bottom:22px">{{instance_name}}</div>
    <div style="background:#171d25;border:1px solid #2c3542;border-radius:12px;padding:24px;line-height:1.65">{{email_template}}</div>
  </div>
</body>
</html>`

type TemplateDefinition struct {
	Subject string
	Body    string
}

type TemplateData struct {
	InstanceName string
	BaseURL      string
	Language     string
	Subject      string
	Body         string
	Variables    map[string]string
	ExtraText    string
	ExtraHTML    string
	HTMLEnabled  bool
	HTMLTemplate string
}

// RenderTemplate renders administrator-editable mail copy with a deliberately
// small placeholder language. The per-message body is always plain text. When
// the optional HTML wrapper is enabled, body values are escaped and line breaks
// are converted to <br> before being inserted into {{email_template}}.
func RenderTemplate(d TemplateData) (subject, textBody, htmlBody string) {
	vars := make(map[string]string, len(d.Variables)+2)
	for k, v := range d.Variables {
		vars[k] = v
	}
	vars["instance_name"] = d.InstanceName
	vars["zentcal_url"] = d.BaseURL

	pairs := make([]string, 0, len(vars)*2)
	for k, v := range vars {
		pairs = append(pairs, "{{"+k+"}}", v)
	}
	replacer := strings.NewReplacer(pairs...)
	subject = sanitizeHeader(replacer.Replace(d.Subject))
	body := strings.TrimSpace(replacer.Replace(d.Body))
	textBody = body
	if strings.TrimSpace(d.ExtraText) != "" {
		textBody += "\n\n" + strings.TrimSpace(d.ExtraText)
	}
	if strings.TrimSpace(d.BaseURL) != "" {
		openLabel := " öffnen: "
		if strings.EqualFold(strings.TrimSpace(d.Language), "en") {
			openLabel = " open: "
		}
		textBody += "\n\n" + displayInstanceName(d.InstanceName) + openLabel + strings.TrimSpace(d.BaseURL)
	}

	if !d.HTMLEnabled {
		return subject, textBody, ""
	}
	wrapper := strings.TrimSpace(d.HTMLTemplate)
	if wrapper == "" || !strings.Contains(wrapper, "{{email_template}}") {
		wrapper = DefaultHTMLLayout
	}

	contentHTML := strings.ReplaceAll(html.EscapeString(body), "\n", "<br>\n")
	if strings.TrimSpace(d.ExtraHTML) != "" {
		contentHTML += strings.TrimSpace(d.ExtraHTML)
	}
	if strings.TrimSpace(d.BaseURL) != "" {
		label := displayInstanceName(d.InstanceName) + " öffnen"
		if strings.EqualFold(strings.TrimSpace(d.Language), "en") {
			label = displayInstanceName(d.InstanceName) + " open"
		}
		u := html.EscapeString(strings.TrimSpace(d.BaseURL))
		contentHTML += `<div style="margin-top:24px;padding-top:16px;border-top:1px solid #303846;font-size:13px"><a href="` + u + `">` + html.EscapeString(label) + `</a><br><span style="word-break:break-all">` + u + `</span></div>`
	}

	// Replace wrapper placeholders in one pass. email_template is intentionally
	// inserted as generated HTML; instance name and URL are always escaped.
	htmlBody = strings.NewReplacer(
		"{{email_template}}", contentHTML,
		"{{instance_name}}", html.EscapeString(displayInstanceName(d.InstanceName)),
		"{{zentcal_url}}", html.EscapeString(strings.TrimSpace(d.BaseURL)),
	).Replace(wrapper)
	return subject, textBody, htmlBody
}

func displayInstanceName(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "ZentCal"
	}
	return v
}

func sanitizeHeader(v string) string {
	v = strings.ReplaceAll(v, "\r", " ")
	v = strings.ReplaceAll(v, "\n", " ")
	return strings.TrimSpace(v)
}
