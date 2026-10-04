package web

import (
	"context"
	"net/http"
	"strings"

	mailpkg "github.com/zentworks/zentcal/internal/mail"
)

type mailTemplateDefaults struct {
	SubjectDE, BodyDE string
	SubjectEN, BodyEN string
}

var defaultMailTemplates = map[string]mailTemplateDefaults{
	"account_created": {
		SubjectDE: "Dein {{instance_name}}-Zugang",
		BodyDE:    "Hallo {{user_name}},\n\nfür dein Konto wurde ein temporäres Passwort erstellt.\n\nE-Mail: {{email}}\nTemporäres Passwort: {{temporary_password}}\n\nNach der ersten Anmeldung musst du ein neues Passwort festlegen.",
		SubjectEN: "Your {{instance_name}} account",
		BodyEN:    "Hello {{user_name}},\n\na temporary password was created for your account.\n\nEmail: {{email}}\nTemporary password: {{temporary_password}}\n\nYou must choose a new password after your first sign-in.",
	},
	"password_reset": {
		SubjectDE: "{{instance_name}} Passwort zurückgesetzt",
		BodyDE:    "Hallo {{user_name}},\n\nfür dein Konto wurde ein temporäres Passwort erstellt.\n\nE-Mail: {{email}}\nTemporäres Passwort: {{temporary_password}}\n\nNach der nächsten Anmeldung musst du ein neues Passwort festlegen.",
		SubjectEN: "{{instance_name}} password reset",
		BodyEN:    "Hello {{user_name}},\n\na temporary password was created for your account.\n\nEmail: {{email}}\nTemporary password: {{temporary_password}}\n\nYou must choose a new password after your next sign-in.",
	},

	"sso_unlinked": {
		SubjectDE: "{{instance_name}}: SSO-Verbindung getrennt",
		BodyDE:    "Hallo {{user_name}},\n\ndie Single-Sign-On-Verbindung deines Kontos wurde getrennt.\n\nE-Mail: {{email}}\nTemporäres Passwort: {{temporary_password}}\n\nMelde dich mit diesem temporären Passwort an und lege anschließend ein neues Passwort fest.",
		SubjectEN: "{{instance_name}}: SSO connection removed",
		BodyEN:    "Hello {{user_name}},\n\nthe Single Sign-On connection for your account was removed.\n\nEmail: {{email}}\nTemporary password: {{temporary_password}}\n\nSign in with this temporary password and then choose a new password.",
	},
	"calendar_shared": {
		SubjectDE: "{{instance_name}}: Kalender freigegeben",
		BodyDE:    "Hallo {{user_name}},\n\n{{inviter_name}} hat den Kalender „{{calendar_name}}“ für dich freigegeben.\nRolle: {{role}}\n\nDer Kalender ist nach der Anmeldung und über CalDAV verfügbar.",
		SubjectEN: "{{instance_name}}: Calendar shared with you",
		BodyEN:    "Hello {{user_name}},\n\n{{inviter_name}} shared the calendar “{{calendar_name}}” with you.\nRole: {{role}}\n\nThe calendar is available after signing in and via CalDAV.",
	},
	"event_invite": {
		SubjectDE: "Einladung: {{event_title}}",
		BodyDE:    "{{organizer_name}} hat dich zu „{{event_title}}“ eingeladen.\n\nDatum: {{event_start}}{{event_end_line}}{{event_location_line}}{{event_description_line}}",
		SubjectEN: "Invitation: {{event_title}}",
		BodyEN:    "{{organizer_name}} invited you to “{{event_title}}”.\n\nDate: {{event_start}}{{event_end_line}}{{event_location_line}}{{event_description_line}}",
	},
	"event_update": {
		SubjectDE: "Aktualisiert: {{event_title}}",
		BodyDE:    "Der Termin „{{event_title}}“ wurde aktualisiert.\n\nDatum: {{event_start}}{{event_end_line}}{{event_location_line}}{{event_description_line}}",
		SubjectEN: "Updated: {{event_title}}",
		BodyEN:    "The event “{{event_title}}” was updated.\n\nDate: {{event_start}}{{event_end_line}}{{event_location_line}}{{event_description_line}}",
	},
	"event_cancel": {
		SubjectDE: "Abgesagt: {{event_title}}",
		BodyDE:    "Der Termin „{{event_title}}“ wurde abgesagt.\n\nDatum: {{event_start}}",
		SubjectEN: "Cancelled: {{event_title}}",
		BodyEN:    "The event “{{event_title}}” was cancelled.\n\nDate: {{event_start}}",
	},
}

func mailTemplateSettingKeys(kind, lang string) (string, string) {
	lang = normalizeLanguage(lang)
	return "mail_" + kind + "_subject_" + lang, "mail_" + kind + "_body_" + lang
}

func (h *Handler) mailTemplate(ctx context.Context, kind, lang string) (string, string) {
	lang = normalizeLanguage(lang)
	d, ok := defaultMailTemplates[kind]
	if !ok {
		return "", ""
	}
	defSubject, defBody := d.SubjectDE, d.BodyDE
	if lang == "en" {
		defSubject, defBody = d.SubjectEN, d.BodyEN
	}
	subjectKey, bodyKey := mailTemplateSettingKeys(kind, lang)
	return h.setting(ctx, subjectKey, defSubject), h.setting(ctx, bodyKey, defBody)
}

func (h *Handler) sendTemplatedMail(ctx context.Context, r *http.Request, cfg mailpkg.SMTPConfig, recipient, lang, kind string, vars map[string]string, extraText, extraHTML string) error {
	return h.sendTemplatedMailWithBaseURL(ctx, cfg, recipient, lang, kind, vars, extraText, extraHTML, h.externalBaseURL())
}

func (h *Handler) sendTemplatedMailWithBaseURL(ctx context.Context, cfg mailpkg.SMTPConfig, recipient, lang, kind string, vars map[string]string, extraText, extraHTML, baseURL string) error {
	return h.sendTemplatedMailWithBaseURLAttempt(ctx, cfg, recipient, lang, kind, vars, extraText, extraHTML, baseURL, 1)
}

func (h *Handler) sendTemplatedMailWithBaseURLAttempt(ctx context.Context, cfg mailpkg.SMTPConfig, recipient, lang, kind string, vars map[string]string, extraText, extraHTML, baseURL string, attempt int) error {
	subjectTpl, bodyTpl := h.mailTemplate(ctx, kind, lang)
	htmlEnabled := h.setting(ctx, "mail_html_enabled", "false") == "true"
	htmlTemplate := h.setting(ctx, "mail_html_template", mailpkg.DefaultHTMLLayout)
	subject, textBody, htmlBody := mailpkg.RenderTemplate(mailpkg.TemplateData{
		InstanceName: "ZentCal",
		BaseURL:      strings.TrimSuffix(strings.TrimSpace(baseURL), "/"),
		Language:     normalizeLanguage(lang),
		Subject:      subjectTpl,
		Body:         bodyTpl,
		Variables:    vars,
		ExtraText:    extraText,
		ExtraHTML:    extraHTML,
		HTMLEnabled:  htmlEnabled,
		HTMLTemplate: htmlTemplate,
	})
	if h.MailDelivery != nil {
		return h.MailDelivery.SendMessageAttempt(ctx, kind, cfg, recipient, subject, textBody, htmlBody, attempt)
	}
	return mailpkg.SendMessage(cfg, recipient, subject, textBody, htmlBody)
}

func mailTemplateDefaultsForSettings() map[string]string {
	out := map[string]string{"mail_html_enabled": "false", "mail_html_template": mailpkg.DefaultHTMLLayout}
	for kind, d := range defaultMailTemplates {
		out["mail_"+kind+"_subject_de"] = d.SubjectDE
		out["mail_"+kind+"_body_de"] = d.BodyDE
		out["mail_"+kind+"_subject_en"] = d.SubjectEN
		out["mail_"+kind+"_body_en"] = d.BodyEN
	}
	return out
}

func trimMailTemplateValue(v string, max int) string {
	v = strings.TrimSpace(v)
	r := []rune(v)
	if len(r) > max {
		v = string(r[:max])
	}
	return v
}
