package mail

import (
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

type SMTPConfig struct {
	Host      string
	Port      int
	Security  string
	Username  string
	Password  string
	FromName  string
	FromEmail string
}

func (c SMTPConfig) Validate() error {
	if strings.TrimSpace(c.Host) == "" {
		return fmt.Errorf("SMTP-Host ist erforderlich.")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("Ungültiger SMTP-Port.")
	}
	if c.Security != "none" && c.Security != "starttls" && c.Security != "tls" {
		return fmt.Errorf("Ungültiger SMTP-Sicherheitsmodus.")
	}
	if _, err := mail.ParseAddress(c.FromEmail); err != nil {
		return fmt.Errorf("Gültige Absender-E-Mail ist erforderlich.")
	}
	return nil
}

// SendMessage sends a UTF-8 text message and, when htmlBody is non-empty,
// a multipart/alternative text+HTML message.
func SendMessage(c SMTPConfig, recipient, subject, textBody, htmlBody string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	to, err := mail.ParseAddress(strings.TrimSpace(recipient))
	if err != nil {
		return fmt.Errorf("Gültige Empfänger-E-Mail ist erforderlich.")
	}
	subject = sanitizeHeader(subject)
	from := (&mail.Address{Name: c.FromName, Address: c.FromEmail}).String()
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to.String() + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("UTF-8", subject) + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	if strings.TrimSpace(htmlBody) == "" {
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(strings.ReplaceAll(textBody, "\n", "\r\n"))
		b.WriteString("\r\n")
		return sendRaw(c, to.Address, []byte(b.String()))
	}
	boundary := "zentcal-alt-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	b.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n")
	b.WriteString("--" + boundary + "\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(strings.ReplaceAll(textBody, "\n", "\r\n"))
	b.WriteString("\r\n--" + boundary + "\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(htmlBody)
	b.WriteString("\r\n--" + boundary + "--\r\n")
	return sendRaw(c, to.Address, []byte(b.String()))
}

// SendCalendar sends a multipart iMIP message with a human-readable HTML/text body
// and a standards-compatible text/calendar part.
func SendCalendar(c SMTPConfig, recipient, subject, textBody, htmlBody, method, calendarData string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	to, err := mail.ParseAddress(strings.TrimSpace(recipient))
	if err != nil {
		return fmt.Errorf("Gültige Empfänger-E-Mail ist erforderlich.")
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "REQUEST"
	}
	// Header injection must never be possible from event/user content.
	subject = strings.ReplaceAll(strings.ReplaceAll(subject, "\r", " "), "\n", " ")
	from := (&mail.Address{Name: c.FromName, Address: c.FromEmail}).String()
	boundary := "zentcal-alt-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to.String() + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("UTF-8", subject) + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n")
	b.WriteString("--" + boundary + "\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(strings.ReplaceAll(textBody, "\n", "\r\n"))
	if strings.TrimSpace(htmlBody) != "" {
		b.WriteString("\r\n--" + boundary + "\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(htmlBody)
	}
	b.WriteString("\r\n--" + boundary + "\r\nContent-Type: text/calendar; method=" + method + "; charset=UTF-8; component=vevent\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(strings.ReplaceAll(calendarData, "\n", "\r\n"))
	b.WriteString("\r\n--" + boundary + "--\r\n")
	return sendRaw(c, to.Address, []byte(b.String()))
}

func sendRaw(c SMTPConfig, recipient string, msg []byte) error {
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	tlsCfg := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}
	var client *smtp.Client
	if c.Security == "tls" {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("SMTP TLS-Verbindung fehlgeschlagen: %w", err)
		}
		client, err = smtp.NewClient(conn, c.Host)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("SMTP-Verbindung fehlgeschlagen: %w", err)
		}
	} else {
		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			return fmt.Errorf("SMTP-Verbindung fehlgeschlagen: %w", err)
		}
		client, err = smtp.NewClient(conn, c.Host)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("SMTP-Verbindung fehlgeschlagen: %w", err)
		}
		if c.Security == "starttls" {
			ok, _ := client.Extension("STARTTLS")
			if !ok {
				_ = client.Close()
				return fmt.Errorf("SMTP-Server bietet STARTTLS nicht an.")
			}
			if err := client.StartTLS(tlsCfg); err != nil {
				_ = client.Close()
				return fmt.Errorf("SMTP STARTTLS fehlgeschlagen: %w", err)
			}
		}
	}
	defer client.Close()
	if c.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
			return fmt.Errorf("SMTP-Anmeldung fehlgeschlagen: %w", err)
		}
	}
	if err := client.Mail(c.FromEmail); err != nil {
		return fmt.Errorf("SMTP-Absender abgelehnt: %w", err)
	}
	if err := client.Rcpt(recipient); err != nil {
		return fmt.Errorf("SMTP-Empfänger abgelehnt: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA fehlgeschlagen: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}
