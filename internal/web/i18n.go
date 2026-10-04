package web

import (
	"net/http"
	"sort"
	"strings"
)

func normalizeLanguage(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "de" || strings.HasPrefix(v, "de-") || strings.HasSuffix(v, "-at") || strings.HasSuffix(v, "-ch") {
		return "de"
	}
	if v == "en" || strings.HasPrefix(v, "en-") {
		return "en"
	}
	return "en"
}

func browserLanguage(r *http.Request) string {
	if r == nil {
		return "en"
	}
	raw := r.Header.Get("Accept-Language")
	if raw == "" {
		return "en"
	}
	first := strings.TrimSpace(strings.Split(raw, ",")[0])
	if i := strings.Index(first, ";"); i >= 0 {
		first = first[:i]
	}
	return normalizeLanguage(first)
}

var enTranslations = map[string]string{

	"SSO":                     "SSO",
	"SSO verbunden":           "SSO linked",
	"Nicht mit SSO verbunden": "Not linked to SSO",
	"Erlaubt diesem Benutzer, zusätzliche Kalender selbst anzulegen.": "Allows this user to create additional calendars.",
	"Automatische Backups aktivieren":                                 "Enable automatic backups",
	"ZentCal erstellt Backups nach dem festgelegten Zeitplan.":        "ZentCal creates backups according to the configured schedule.",
	"Anmeldung mit Benutzername und Passwort.":                        "Sign in with username and password.",
	"SSH Private Key": "SSH private key",
	"Anmeldung mit einem privaten SSH-Schlüssel.":                                                   "Sign in with a private SSH key.",
	"Beim ersten Kontakt wird der Host-Schlüssel gespeichert. Spätere Änderungen werden abgelehnt.": "The host key is stored on first contact. Later changes are rejected.",
	"Backup läuft":          "Backup running",
	"Backup wird gestartet": "Starting backup",
	"Bestätige zuerst mit deinem aktuellen ZentCal-Passwort. Danach wirst du zum Identity Provider weitergeleitet.": "Confirm with your current ZentCal password first. You will then be redirected to the identity provider.",
	"Weiter zu SSO": "Continue to SSO",
	"Du wirst zur erneuten Bestätigung zum Identity Provider weitergeleitet. Nur dieselbe SSO-Identität kann die Verbindung lösen.":         "You will be redirected to the identity provider for confirmation. Only the same SSO identity can unlink the connection.",
	"Nach erfolgreicher Bestätigung erhältst du ein temporäres Passwort per E-Mail, alle Sitzungen werden beendet und du wirst abgemeldet.": "After successful confirmation, you will receive a temporary password by email, all sessions will be ended and you will be signed out.",
	"Dashboard":            "Dashboard",
	"Kalender":             "Calendars",
	"Kalenderverwaltung":   "Calendar management",
	"Benutzer":             "Users",
	"Aktivität":            "Activity",
	"Mein Konto":           "My Account",
	"Integrationen":        "Integrations",
	"Admin":                "Admin",
	"API & Geräte":         "API & Devices",
	"Webhooks":             "Webhooks",
	"System":               "System",
	"Backups":              "Backups",
	"Einstellungen":        "Settings",
	"Abmelden":             "Sign out",
	"Bestätigen":           "Confirm",
	"Abbrechen":            "Cancel",
	"Schließen":            "Close",
	"Einmaliger Schlüssel": "One-time secret",
	"Kopieren":             "Copy",
	"Dieser Wert wird nach dem Schließen nicht erneut angezeigt.": "This value will not be shown again after closing.",
	"Fertig": "Done",
	"Profil": "Profile",
	"Persönliche Einstellungen für dein ZentCal-Konto.": "Personal settings for your ZentCal account.",
	"Name":     "Name",
	"Vorname":  "First name",
	"Nachname": "Last name",
	"E-Mail":   "Email",
	"Die E-Mail-Adresse wird durch einen Administrator bzw. den Identity Provider verwaltet.":        "The email address is managed by an administrator or the identity provider.",
	"Name und E-Mail-Adresse werden durch einen Administrator bzw. den Identity Provider verwaltet.": "Name and email address are managed by an administrator or the identity provider.",
	"Sprache":                          "Language",
	"Zeitzone":                         "Timezone",
	"Speichern":                        "Save",
	"Speichern…":                       "Saving…",
	"Passwort":                         "Password",
	"Lokales ZentCal-Passwort ändern.": "Change the local ZentCal password.",
	"Dieses Konto wird über Single Sign-On verwaltet.": "This account is managed through Single Sign-On.",
	"Single Sign-On aktiv.":                            "Single Sign-On active.",
	"Das lokale Passwort kann für diesen Account weder geändert noch für CalDAV/WebDAV verwendet werden. Für DAV ausschließlich App-Passwörter nutzen.": "The local password cannot be changed or used for CalDAV/WebDAV for this account. Use app passwords for DAV only.",
	"Aktuelles Passwort":            "Current password",
	"Neues Passwort":                "New password",
	"Neues Passwort wiederholen":    "Repeat new password",
	"Passwort ändern":               "Change password",
	"Ändern…":                       "Changing…",
	"Passwort ändern erforderlich.": "Password change required.",
	"Das temporäre Passwort muss vor der weiteren Nutzung ersetzt werden.": "The temporary password must be replaced before continuing.",
	"App-Passwörter": "App Passwords",
	"Separate Zugangsdaten für macOS, iPhone, DAVx⁵, Thunderbird und andere DAV-Clients.": "Separate credentials for macOS, iPhone, DAVx⁵, Thunderbird and other DAV clients.",
	"App-Passwort erstellen":       "Create app password",
	"Für SSO-Konten erforderlich:": "Required for SSO accounts:",
	"CalDAV/WebDAV akzeptiert ausschließlich App-Passwörter. Dein SSO- oder früheres lokales Passwort funktioniert dort nicht.":  "CalDAV/WebDAV accepts app passwords only. Your SSO or former local password will not work there.",
	"Für CalDAV/WebDAV ist ein App-Passwort erforderlich. Es kann einzeln widerrufen werden, ohne dein Hauptpasswort zu ändern.": "CalDAV/WebDAV requires an app password. It can be revoked individually without changing your main password.",
	"erstellt":                   "created",
	"zuletzt":                    "last used",
	"Widerrufen":                 "Revoke",
	"Noch keine App-Passwörter.": "No app passwords yet.",
	"Gerätename":                 "Device name",
	"Generieren":                 "Generate",
	"Generieren…":                "Generating…",
	"Kalender erstellen":         "Create calendar",
	"Gemeinsame Kalender und Ressourcen zentral verwalten.": "Manage shared calendars and resources centrally.",
	"Beschreibung":        "Description",
	"Typ":                 "Type",
	"Farbe":               "Color",
	"Ressource":           "Resource",
	"Zugriff":             "Access",
	"Mitglieder":          "Members",
	"Events":              "Events",
	"Übersicht":           "Overview",
	"Administration":      "Administration",
	"Noch keine Kalender": "No calendars yet",
	"Erstelle deinen ersten Kalender und füge anschließend Mitglieder hinzu.": "Create your first calendar and then add members.",
	"Erstellen":                            "Create",
	"Erstellen…":                           "Creating…",
	"Konten und Zugriffsstatus verwalten.": "Manage accounts and access status.",
	"Einladen":                             "Invite",
	"Direkt erstellen":                     "Create directly",
	"Rolle":                                "Role",
	"Status":                               "Status",
	"Letzter Login":                        "Last login",
	"Letzter Sync":                         "Last sync",
	"Noch keine Benutzer vorhanden.":       "No users yet.",
	"Benutzer bearbeiten":                  "Edit user",
	"Benutzer erstellen":                   "Create user",
	"Benutzer einladen":                    "Invite user",
	"Einladungslink erstellen":             "Create invitation link",
	"Nach dem Anlegen wird ein temporäres Passwort einmalig angezeigt.": "A temporary password is shown once after the account is created.",
	"Der Benutzer meldet sich über Single Sign-On an.":                  "The user signs in through Single Sign-On.",
	"Der Benutzer erhält ein temporäres Passwort per E-Mail.":           "The user receives a temporary password by email.",
	"Passwort zurücksetzen":                                             "Reset password",
	"Das aktuelle lokale Passwort des Benutzers wird ungültig. Beim nächsten Login muss das temporäre Passwort geändert werden.": "The user's current local password will become invalid. The temporary password must be changed at the next sign-in.",
	"Vor dem Zurücksetzen wird deine Administrator-Anmeldung bei Bedarf erneut über SSO bestätigt.":                              "Before resetting, your administrator sign-in will be confirmed again through SSO if required.",
	"Dein Administrator-Passwort": "Your administrator password",
	"Ja, Passwort zurücksetzen":   "Yes, reset password",
	"Zurücksetzen…":               "Resetting…",
	"Passwort vergessen?":         "Forgot password?",
	"Passwort vergessen":          "Forgot password",
	"Gib deine E-Mail-Adresse ein. Du erhältst ein temporäres Passwort und musst es nach der nächsten Anmeldung ändern.": "Enter your email address. You will receive a temporary password and must change it after your next sign-in.",
	"Temporäres Passwort senden": "Send temporary password",
	"Wenn ein lokales Konto mit dieser E-Mail-Adresse existiert, wurde ein temporäres Passwort gesendet.": "If a local account with this email address exists, a temporary password has been sent.",
	"Zur Anmeldung":        "Back to sign in",
	"Zurück zur Anmeldung": "Back to sign in",
	"Mehr laden":           "Load more",
	"Lade…":                "Loading…",
	"Aktiv":                "Active",
	"Inaktiv":              "Inactive",
	"Letzte Aktivitäten":   "Recent activity",
	"Änderungen an Kalendern, Benutzern und Terminen.": "Changes to calendars, users and events.",
	"Alle anzeigen":                "Show all",
	"Zeit":                         "Time",
	"Akteur":                       "Actor",
	"Aktion":                       "Action",
	"Noch keine Aktivitäten.":      "No activity yet.",
	"API Tokens":                   "API Tokens",
	"Admin API":                    "Admin API",
	"Admin API Tokens":             "Admin API Tokens",
	"Admin API Token erstellen":    "Create Admin API token",
	"Noch keine Admin API Tokens.": "No Admin API tokens yet.",
	"Separate administrative API-Zugänge für Automatisierung und externe Verwaltung.": "Separate administrative API credentials for automation and external management.",
	"Berechtigungen":                             "Permissions",
	"Backups lesen":                              "Read backups",
	"Backups erstellen/löschen":                  "Create/delete backups",
	"Backups wiederherstellen":                   "Restore backups",
	"Destruktive Berechtigung, bewusst separat.": "Destructive permission, intentionally separate.",
	"Ablauf":                              "Expiration",
	"0 = kein Ablauf, sonst Anzahl Tage.": "0 = no expiration, otherwise number of days.",
	"API Token erstellen":                 "Create API token",
	"API Kurzreferenz":                    "API quick reference",
	"CalDAV Geräte-Setup":                 "CalDAV device setup",
	"Serveradresse":                       "Server address",
	"Port":                                "Port",
	"Passwort:":                           "Password:",
	"App-Passwort aus deinen Kontoeinstellungen.": "App password from your account settings.",
	"Serverpfad":             "Server path",
	"Benutzername":           "Username",
	"Ja":                     "Yes",
	"Nein":                   "No",
	"Noch keine API Tokens.": "No API tokens yet.",
	"Webhook hinzufügen":     "Add webhook",
	"HTTP-Benachrichtigungen bei Änderungen in ZentCal.": "HTTP notifications for changes in ZentCal.",
	"Ziel":                           "Target",
	"Auth":                           "Auth",
	"Aktionen":                       "Actions",
	"Bearbeiten":                     "Edit",
	"Eigentümer":                     "Owner",
	"Betrachter":                     "Viewer",
	"Persönlich":                     "Personal",
	"Test":                           "Test",
	"Löschen":                        "Delete",
	"Authentifizierung":              "Authentication",
	"Delivery Log":                   "Delivery Log",
	"Erneut senden":                  "Retry",
	"Webhook bearbeiten":             "Edit webhook",
	"Ziel-URL":                       "Target URL",
	"Keine Authentifizierung":        "No authentication",
	"Private/interne Ziele erlauben": "Allow private/internal targets",
	"Application":                    "Application",
	"Database":                       "Database",
	"Healthy":                        "Healthy",
	"Ready":                          "Ready",
	"Uptime":                         "Uptime",
	"Aktive Sessions":                "Active sessions",
	"Systeminformationen":            "System information",
	"Laufzeit- und Datenbankinformationen der aktuellen Instanz.": "Runtime and database information for the current instance.",
	"Datenbankgröße": "Database size",
	"Serverzeit":     "Server time",
	"Allgemein":      "General",
	"Grundlegende Instanz- und Darstellungseinstellungen.": "Basic instance and display settings.",
	"E-Mail / SMTP":        "Email / SMTP",
	"Sicherheit":           "Security",
	"Backup-Einstellungen": "Backup settings",
	"Verschlüsselte Backups auf lokalem Speicher, SFTP oder S3-kompatiblem Object Storage.": "Encrypted backups to local storage, SFTP or S3-compatible object storage.",
	"Automatische Backups": "Automatic backups",
	"Geplante Backups laufen persistent innerhalb von ZentCal.": "Scheduled backups run persistently inside ZentCal.",
	"Speicherziel":                           "Storage target",
	"Retention":                              "Retention",
	"Maximale Anzahl erfolgreicher Backups.": "Maximum number of successful backups.",
	"Zeitplan":                               "Schedule",
	"Täglich":                                "Daily",
	"Wöchentlich":                            "Weekly",
	"Uhrzeit":                                "Time",
	"Wochentag":                              "Weekday",
	"Montag":                                 "Monday",
	"Dienstag":                               "Tuesday",
	"Mittwoch":                               "Wednesday",
	"Donnerstag":                             "Thursday",
	"Freitag":                                "Friday",
	"Samstag":                                "Saturday",
	"Sonntag":                                "Sunday",
	"Backup-Verschlüsselungspasswort":        "Backup encryption password",
	"Local Storage":                          "Local Storage",
	"Backups werden im persistenten Docker-Volume unter": "Backups are stored in the persistent Docker volume at",
	"Verbindung testen":                   "Test connection",
	"Backup jetzt":                        "Backup now",
	"Letztes Backup":                      "Last backup",
	"Nächstes Backup":                     "Next backup",
	"Datenbank":                           "Database",
	"Datei":                               "File",
	"Größe":                               "Size",
	"Noch keine Backups vorhanden.":       "No backups yet.",
	"Backup hochladen & wiederherstellen": "Upload & restore backup",
	"Backup prüfen":                       "Verify backup",
	"Backup wiederherstellen":             "Restore backup",
	"Wiederherstellen":                    "Restore",
	"Backup-Datei":                        "Backup file",
	"Zur Bestätigung":                     "To confirm",
	"Ja, aktuellen Datenbestand überschreiben": "Yes, overwrite the current data",
	"Anmelden":              "Sign in",
	"ZentCal einrichten":    "Set up ZentCal",
	"Ersteinrichtung":       "Initial setup",
	"Administrator anlegen": "Create administrator",
	"Dieser Account wird Eigentümer der ZentCal-Instanz. Weitere Einstellungen erledigst du anschließend in der Weboberfläche.": "This account becomes the owner of the ZentCal instance. Configure additional settings afterwards in the web interface.",
	"Mindestens 10 Zeichen.": "At least 10 characters.",
	"Einladung":              "Invitation",
	"Konto aktivieren":       "Activate account",
	"Eingeladen als":         "Invited as",
	"Einladung annehmen":     "Accept invitation",
	"Dokumentation":          "Documentation",
}

func tr(lang, key string) string {
	if normalizeLanguage(lang) != "en" {
		return key
	}
	if v, ok := enTranslations[key]; ok {
		return v
	}
	if v, ok := enExtraTranslations[key]; ok {
		return v
	}
	return key
}

func pageIcon(page string) string {
	switch page {
	case "dashboard":
		return "home"
	case "calendars", "admin-calendars":
		return "calendar"
	case "users":
		return "users"
	case "activity", "email-deliveries":
		return "activity"
	case "account":
		return "account"
	case "api", "admin-api":
		return "devices"
	case "documentation":
		return "book"
	case "webhooks":
		return "webhook"
	case "system":
		return "server"
	case "backups":
		return "backup"
	case "settings":
		return "settings"
	default:
		return "home"
	}
}

func translateTemplateSource(source string) string {
	all := make(map[string]string, len(enTranslations)+len(enExtraTranslations))
	for key, value := range enTranslations {
		all[key] = value
	}
	for key, value := range enExtraTranslations {
		all[key] = value
	}
	keys := make([]string, 0, len(all))
	for key := range all {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	translateLiteral := func(literal string) string {
		for _, key := range keys {
			literal = strings.ReplaceAll(literal, key, all[key])
		}
		return literal
	}

	// Never translate inside Go template actions. Apart from avoiding needless
	// work, this is important because UI words such as "Typ" can be substrings
	// of field names such as .User.AuthType.
	var out strings.Builder
	for len(source) > 0 {
		open := strings.Index(source, "{{")
		if open < 0 {
			out.WriteString(translateLiteral(source))
			break
		}
		out.WriteString(translateLiteral(source[:open]))
		source = source[open:]
		close := strings.Index(source, "}}")
		if close < 0 {
			out.WriteString(source)
			break
		}
		close += 2
		out.WriteString(source[:close])
		source = source[close:]
	}
	return out.String()
}

var enExtraTranslations = map[string]string{
	"Zentral verwaltete gemeinsame Kalender für Teams und Abteilungen.":                            "Centrally managed shared calendars for teams and departments.",
	"Temporäre Verwaltung · Owner fehlt":                                                           "Temporary administration · Owner missing",
	"Noch keine zentral verwalteten Kalender":                                                      "No centrally managed calendars yet",
	"Hier erscheinen nur Kalender, die du über diese Verwaltung erstellst.":                        "Only calendars you create through this administration view appear here.",
	"Administrative Verwaltung":                                                                    "Administrative management",
	"Die Verwaltung dieses Kalenders ist von dessen Inhalten getrennt.":                            "Administration of this calendar is separate from its content.",
	"Temporäre Verwaltung:":                                                                        "Temporary administration:",
	"Dieser Kalender hat aktuell keinen Eigentümer. Weise einem Mitglied die Rolle Eigentümer zu.": "This calendar currently has no Owner. Assign the Owner role to a member.",
	"In meinen Kalendern anzeigen":                                                                 "Show in my calendars",
	"Optional schreibgeschützt als Betrachter anzeigen. Ohne Aktivierung bleiben Termine und Teilnehmer für dich verborgen.": "Optionally show it read-only as a Viewer. Without this setting, events and participants remain hidden from you.",

	"E-Mail-Zustellungen": "Email deliveries",
	"Technischer Zustellstatus der letzten 30 Tage. Inhalte und vollständige Empfängeradressen werden nicht gespeichert.": "Technical delivery status for the last 30 days. Message content and full recipient addresses are not stored.",
	"Zugestellt":     "Delivered",
	"Fehlgeschlagen": "Failed",
	"Noch keine E-Mail-Zustellungen vorhanden.": "No email deliveries yet.",
	"Keine passenden Zustellungen gefunden.":    "No matching deliveries found.",
	"Versuche":                                  "Attempts",
	"Empfänger":                                 "Recipient",
	"Weiter":                                    "Continue",
	"Andere E-Mail verwenden":                   "Use a different email",
	"Single Sign-On verbunden.":                 "Single Sign-On connected.",
	"Dein ZentCal-Konto ist jetzt mit dem Identity Provider verknüpft.":                                                                         "Your ZentCal account is now linked to the identity provider.",
	"Das lokale Passwort ist für diesen Account deaktiviert. Für CalDAV/WebDAV ausschließlich App-Passwörter verwenden.":                        "The local password is disabled for this account. Use app passwords only for CalDAV/WebDAV.",
	"Zum Trennen meldest du dich erneut beim Identity Provider an. Danach erhältst du ein temporäres Passwort per E-Mail und wirst abgemeldet.": "To disconnect SSO, sign in to the identity provider again. You will then receive a temporary password by email and be signed out.",
	"SSO-Verbindung lösen": "Disconnect SSO",
	"SSO kann nur getrennt werden, wenn OIDC, lokaler Login und SMTP aktiviert sind.":                                                                            "SSO can only be disconnected when OIDC, local login and SMTP are enabled.",
	"Du kannst dieses bestehende ZentCal-Konto bewusst mit deinem SSO-Konto verbinden. Die Verknüpfung erfolgt nicht automatisch nur anhand der E-Mail-Adresse.": "You can explicitly link this existing ZentCal account to your SSO account. It is not linked automatically based only on the email address.",
	"Dieses bestehende Konto kann bewusst mit SSO verbunden werden. Eine automatische Verknüpfung nur über die E-Mail-Adresse findet nicht statt.":               "This existing account can be explicitly linked to SSO. It is not linked automatically based only on the email address.",
	"Mit SSO verbinden": "Connect with SSO",
	"Verbinde…":         "Connecting…",
	"Redirect URI":      "Redirect URI",
	"Diese URI exakt beim Identity Provider als OIDC Redirect/Callback URI hinterlegen.": "Register this exact URI with the identity provider as the OIDC redirect/callback URI.",
	"E-Mail-Vorlagen": "Email templates",
	"Textvorlagen plus optionales gemeinsames HTML-Layout. Die ZentCal-URL wird automatisch mitgesendet.": "Text templates plus an optional shared HTML layout. The ZentCal URL is included automatically.",
	"SSO-Verbindung getrennt":           "SSO connection removed",
	"Optionales HTML-Layout":            "Optional HTML layout",
	"HTML-Version zusätzlich versenden": "Send an additional HTML version",
	"Text/plain wird immer mitgesendet; Termine behalten zusätzlich ihren text/calendar-Anhang.": "Text/plain is always sent; event messages also keep their text/calendar attachment.",
	"HTML-Layout": "HTML layout",
	"Pflichtplatzhalter bei aktiviertem HTML:":                      "Required placeholder when HTML is enabled:",
	"Kontoeinstellungen öffnen":                                     "Open account settings",
	"Kontoeinstellungen":                                            "Account settings",
	"Nur für Datums- und Zeitangaben in der ZentCal-Weboberfläche.": "Only affects date and time display in the ZentCal web interface.",
	"Sicherheit": "Security",
	"Das Passwort wird über deinen Identity Provider verwaltet. Für CalDAV/WebDAV ausschließlich App-Passwörter verwenden.": "Your password is managed by your identity provider. Use app passwords only for CalDAV/WebDAV.",
	"Separate Zugangsdaten für DAV-Clients und Geräte.":                                                                     "Separate credentials for DAV clients and devices.",
	"Neu":                      "New",
	"App-Passwort widerrufen?": "Revoke app password?",
	"Direkter SSO-Login":       "Direct SSO login",
	"Startet unmittelbar die Anmeldung über den konfigurierten Identity Provider.":                                                                         "Starts sign-in immediately through the configured identity provider.",
	"Startet unmittelbar die Anmeldung über den konfigurierten Identity Provider. Neue Konten werden hier nur bei aktiviertem Auto-Provisioning angelegt.": "Starts sign-in immediately through the configured identity provider. New accounts are created here only when auto-provisioning is enabled.",
	"Neue SSO-Benutzer ausschließlich über den direkten SSO-Login automatisch anlegen.":                                                                    "Automatically create new SSO users only through the direct SSO login.",
	"SSO-Login starten": "Start SSO login",
	"Backups werden im persistenten Docker-Volume unter <code>/data/backups</code> gespeichert.": "Backups are stored in the persistent Docker volume at <code>/data/backups</code>.",
	"Für Integrationen über": "For integrations via",
	"Token erstellen":        "Create token",
	"SSO-Konto:":             "SSO account:",
	"Für CalDAV/WebDAV funktioniert ausschließlich ein App-Passwort aus": "For CalDAV/WebDAV, only an app password from",
	"Passwort:": "Password:",
	"Technische Übersicht der aktuell gespeicherten Termine. Die eigentliche Kalenderansicht bleibt im gewohnten Client.": "Technical overview of the currently stored events. The actual calendar view remains in your usual client.",
	"Technische DAV-Details":       "Technical DAV details",
	"Termin":                       "Event",
	"Beginn":                       "Start",
	"Version":                      "Version",
	"ohne Titel":                   "untitled",
	"Mitglied wirklich entfernen?": "Remove this member?",
	"Mitglied entfernen":           "Remove member",
	"Zugriff(e)":                   "access entries",
	"Der Owner kann hier nicht herabgestuft, deaktiviert oder gesperrt werden.":                                                                                                      "The owner cannot be demoted, disabled or locked here.",
	"ZentCal legt den Erstzugang automatisch fest: bei SSO ohne lokales Passwort, bei aktivem SMTP per E-Mail, ansonsten wird dem Admin einmalig ein temporäres Passwort angezeigt.": "ZentCal determines initial access automatically: with SSO without a local password, with active SMTP by email, otherwise a temporary password is shown to the admin once.",
	"Session-Laufzeit und Schutz vor wiederholten Login-Versuchen.":                                                                                                                  "Session lifetime and protection against repeated login attempts.",
	"Session-Laufzeit (Stunden)": "Session lifetime (hours)",
	"Sperrdauer (Minuten)":       "Lockout duration (minutes)",
	"Aktivieren, sobald die Verbindung vollständig konfiguriert ist.": "Enable once the connection is fully configured.",
	"Wird verschlüsselt gespeichert und nie wieder angezeigt.":        "Stored encrypted and never shown again.",
	"Verschlüsselt gespeichert.":                                      "Stored encrypted.",
	"Testmail an":                                                     "Send test email to",
	"Testmail senden":                                                 "Send test email",
	"Sende Testmail…":                                                 "Sending test email…",
	"Provider testen":                                                 "Test provider",
	"Prüfe…":                                                          "Checking…",
	"Single Sign-On / OIDC":                                           "Single Sign-On / OIDC",
	"Token-Endpoint Auth":                                             "Token endpoint auth",
	"Kalender-Collection":                                             "Calendar collection",
	"Login:":                                                          "Login:",
	"HTTP-Benachrichtigungen bei Änderungen in ZentCal.":                                       "HTTP notifications for changes in ZentCal.",
	"Secrets werden verschlüsselt gespeichert und nach der Erstellung nicht erneut angezeigt.": "Secrets are stored encrypted and are not shown again after creation.",
	"Interne Ziele erlaubt":             "Internal targets allowed",
	"Noch keine Webhooks eingerichtet.": "No webhooks configured yet.",
	"Keine Auth":                        "No auth",
	"Nur verwenden, wenn der Empfänger selbst anderweitig geschützt ist.":      "Use only when the receiver is otherwise protected.",
	"Letzte Zustellversuche inklusive HTTP-Status, Laufzeit und Retry-Status.": "Recent delivery attempts including HTTP status, duration and retry status.",
	"Versuch":                  "Attempt",
	"Dauer":                    "Duration",
	"Fehler":                   "Error",
	"Noch keine Deliveries.":   "No deliveries yet.",
	"Bearer Token (empfohlen)": "Bearer Token (recommended)",
	"HMAC-Signatur":            "HMAC signature",
	"Bearer sendet":            "Bearer sends",
	"Events sofort zustellen.": "Deliver events immediately.",
	"Standardmäßig blockiert ZentCal Loopback, private und Link-Local Ziele als SSRF-Schutz.": "By default, ZentCal blocks loopback, private and link-local targets as SSRF protection.",
	"Erstelle…":                 "Creating…",
	"Speichere…":                "Saving…",
	"Teste…":                    "Testing…",
	"Rotiere…":                  "Rotating…",
	"Plane ein…":                "Scheduling…",
	"Token rotieren":            "Rotate token",
	"Secret rotieren":           "Rotate secret",
	"Webhook wirklich löschen?": "Delete this webhook?",
	"Verschlüsselte Backups auf lokalem Speicher, SFTP oder S3-kompatiblem Object Storage.": "Encrypted backups on local storage, SFTP or S3-compatible object storage.",
	"S3 kompatibel":                   "S3 compatible",
	"Backup-Verschlüsselungspasswort": "Backup encryption password",
	"Wird einmal festgelegt. ZentCal speichert es intern verschlüsselt für automatische Backups. Für Restore muss es erneut eingegeben werden.": "Set once. ZentCal stores it internally encrypted for automatic backups. It must be entered again for restore.",
	"Benutzer":                  "Users",
	"Zielpfad":                  "Target path",
	"Gespeichert – leer lassen": "Stored – leave empty",
	"Optional bei SSH-Key":      "Optional with SSH key",
	"SSH Host Key prüfen":       "Verify SSH host key",
	"TOFU: erster Schlüssel wird gespeichert, spätere Änderungen werden abgelehnt.": "TOFU: the first key is stored; later changes are rejected.",
	"TLS-Zertifikat prüfen":     "Verify TLS certificate",
	"Backup endgültig löschen?": "Permanently delete backup?",
	"Achtung:":                  "Warning:",
	"Der aktuelle ZentCal-Datenbestand wird durch den Stand des Backups ersetzt. Nach erfolgreichem Restore startet ZentCal neu.": "The current ZentCal data will be replaced by the backup. ZentCal restarts after a successful restore.",
	"Admin-App-Passwort": "Admin app password",
	"Admin-Passwort":     "Admin password",
	"Bei SSO wird zur erneuten Bestätigung ein App-Passwort dieses Admin-Kontos verlangt.": "With SSO, an app password for this admin account is required for confirmation.",
	"Erneute Bestätigung deiner Admin-Identität.":                                          "Confirm your admin identity again.",
	"Zur Bestätigung":    "To confirm",
	"eingeben":           "enter",
	"Stelle wieder her…": "Restoring…",
	"Der aktuelle Datenbestand wird überschrieben. Verwende ausschließlich ein vertrauenswürdiges ZentCal-Backup.": "The current data will be overwritten. Use only a trusted ZentCal backup.",
	"Lade & stelle wieder her…":                                            "Uploading & restoring…",
	"Grundlegende Instanz- und Darstellungseinstellungen.":                 "Basic instance and display settings.",
	"Optional. Wird für Einladungs-, SSO- und CalDAV-Links verwendet.":     "Optional. Used for invitation, SSO and CalDAV links.",
	"Für Benutzer- und Termin-Einladungen sowie Systembenachrichtigungen.": "For user and event invitations as well as system notifications.",
	"SMTP aktivieren":                  "Enable SMTP",
	"Absendername":                     "Sender name",
	"Absender-E-Mail":                  "Sender email",
	"Gespeichertes Passwort entfernen": "Remove stored password",
	"Fehlversuche bis Sperre":          "Failed attempts before lockout",
	"Gilt für neu erstellte Sessions.": "Applies to newly created sessions.",
	"OIDC aktivieren":                  "Enable OIDC",
	"Issuer URL":                       "Issuer URL",
	"Client ID":                        "Client ID",
	"Client Secret":                    "Client Secret",
	"Scopes":                           "Scopes",
	"Mindestens openid; empfohlen: openid profile email.": "At least openid; recommended: openid profile email.",
	"Auto-Provisioning":                      "Auto-provisioning",
	"Neue SSO-Benutzer automatisch anlegen.": "Automatically create new SSO users.",
	"Name bei Auto-Provisioning übernehmen":  "Use name during auto-provisioning",
	"Vor- und Nachname nur beim erstmaligen Anlegen eines SSO-Benutzers übernehmen. Bestehende Konten bleiben unverändert.": "Import first and last name only when an SSO user is created for the first time. Existing accounts remain unchanged.",
	"E-Mail synchronisieren":         "Sync email",
	"Gruppen/Rollen synchronisieren": "Sync groups/roles",
	"Gruppen-Claim":                  "Groups claim",
	"Gruppen-Mapping":                "Group mapping",
	"Eine Zuordnung pro Zeile: Provider-Gruppe=administrator oder user.": "One mapping per line: provider-group=administrator or user.",
	"Lokalen Login erlauben": "Allow local login",
	"Deaktivieren erst, nachdem mit dieser Konfiguration mindestens eine echte SSO-Anmeldung erfolgreich war. ZentCal verhindert sonst das Abschalten.": "Disable only after at least one real SSO login succeeded with this configuration. ZentCal otherwise prevents disabling it.",
	"Gespeichertes Client Secret entfernen":                                              "Remove stored client secret",
	"Die Konfiguration wird beim Speichern per Discovery geprüft.":                       "The configuration is validated by discovery when saved.",
	"Kalender-Metadaten und Mitglieder sind sichtbar, Event-Inhalte nur für Mitglieder.": "Calendar metadata and members are visible; event content is visible to members only.",
	"Kalenderinhalt geschützt":                                                           "Calendar content protected",
	"Du bist kein Mitglied dieses Kalenders. Termine, Titel, Beschreibungen, Teilnehmer und Event-Historie werden daher nicht angezeigt.": "You are not a member of this calendar. Events, titles, descriptions, attendees and event history are therefore not shown.",
	"Kalender bearbeiten":                   "Edit calendar",
	"Mitglied hinzufügen":                   "Add member",
	"Mitglied bearbeiten":                   "Edit member",
	"Noch keine Mitglieder.":                "No members yet.",
	"Noch keine Events in diesem Kalender.": "No events in this calendar yet.",
	"Event-Historie":                        "Event history",
	"Historie":                              "History",
	"Lade Historie…":                        "Loading history…",
	"Der Client erkennt die verfügbaren Kalender über den Account automatisch.":                         "The client automatically discovers available calendars through the account.",
	"Der Client soll ZentCal über die Serveradresse erkennen. Eine lange Kalender-URL ist nicht nötig.": "The client should discover ZentCal through the server address. A long calendar URL is not required.",
	"Bei macOS/iPhone reicht normalerweise die Serveradresse; falls ein Serverpfad verlangt wird,":      "On macOS/iPhone the server address is normally sufficient; if a server path is required,",
	"verwenden. ZentCal wird anschließend automatisch über CalDAV Discovery gefunden.":                  "use it. ZentCal is then discovered automatically through CalDAV discovery.",
	"JSON API, Authentifizierung mit": "JSON API, authentication with",
	"Noch keine Audit-Einträge.":      "No audit entries yet.",
	"Request-ID":                      "Request ID",
	"Ressource":                       "Resource",
	"Benutzer erstellen":              "Create user",
	"Benutzer einladen":               "Invite user",
	"Systemrolle":                     "System role",
	"Direkt erstellen":                "Create directly",
	"Einladung":                       "Invitation",
	"Owner":                           "Owner",
	"Administrator":                   "Administrator",
	"Disabled":                        "Disabled",
	"Locked":                          "Locked",
	"Profil gespeichert.":             "Profile saved.",
}
