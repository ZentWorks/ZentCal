package web

type adminAPIDoc struct {
	ID          string
	Group       string
	Method      string
	Path        string
	Title       string
	Description string
	Scope       string
	Request     string
	Response    string
	Notes       []string
	Destructive bool
}

type adminAPIDocGroup struct {
	Name      string
	Endpoints []adminAPIDoc
}

func adminAPIDocs() []adminAPIDocGroup {
	return []adminAPIDocGroup{
		{Name: "Übersicht", Endpoints: []adminAPIDoc{
			{ID: "meta", Group: "Übersicht", Method: "GET", Path: "/api/admin/v1", Title: "API Status", Description: "Prüft, ob der Admin API Token gültig ist und die API erreichbar ist.", Scope: "admin:meta:read", Response: `{
  "ok": true,
  "name": "ZentCal Admin API",
  "version": "v1"
}`},
		}},
		{Name: "Benutzer", Endpoints: []adminAPIDoc{
			{ID: "users-list", Group: "Benutzer", Method: "GET", Path: "/api/admin/v1/users", Title: "Benutzer auflisten", Description: "Gibt alle ZentCal-Benutzer zurück.", Scope: "admin:users:read", Response: `{
  "ok": true,
  "data": [
    {
      "id": "8c1e…",
      "name": "Max Mustermann",
      "first_name": "Max",
      "last_name": "Mustermann",
      "email": "max@example.com",
      "role": "user",
      "status": "active",
      "auth_type": "local",
      "language": "de",
      "timezone": "Europe/Berlin",
      "must_change_password": true,
      "can_create_calendars": false,
      "created_at": "2026-10-03T12:00:00Z"
    }
  ]
}`},
			{ID: "users-create", Group: "Benutzer", Method: "POST", Path: "/api/admin/v1/users", Title: "Benutzer erstellen", Description: "Erstellt einen lokalen Benutzer und dessen persönlichen Kalender. Wird kein Passwort mitgesendet, erzeugt ZentCal ein temporäres Passwort.", Scope: "admin:users:write", Request: `{
  "first_name": "Max",
  "last_name": "Mustermann",
  "email": "max@example.com",
  "role": "user",
  "status": "active",
  "language": "de",
  "timezone": "Europe/Berlin",
  "must_change_password": true,
  "can_create_calendars": false
}`, Response: `{
  "ok": true,
  "data": {
    "id": "8c1e…",
    "name": "Max Mustermann",
    "email": "max@example.com",
    "role": "user",
    "status": "active",
    "auth_type": "local",
    "can_create_calendars": false
  },
  "temporary_password": "<einmalig erzeugtes zufälliges Passwort>"
}`, Notes: []string{"Rollen beim Erstellen: user oder administrator.", "Status: active, disabled oder locked.", "can_create_calendars steuert, ob der Benutzer über UI, Benutzer-API oder CalDAV zusätzliche eigene Kalender anlegen darf. Standard ist true.", "Das automatisch erzeugte temporäre Passwort wird nur in dieser Response angezeigt."}},
			{ID: "users-get", Group: "Benutzer", Method: "GET", Path: "/api/admin/v1/users/{id}", Title: "Benutzer abrufen", Description: "Lädt einen Benutzer anhand seiner UUID.", Scope: "admin:users:read", Response: `{
  "ok": true,
  "data": {
    "id": "8c1e…",
    "name": "Max Mustermann",
    "first_name": "Max",
    "last_name": "Mustermann",
    "email": "max@example.com",
    "role": "user",
    "status": "active",
    "auth_type": "local",
    "language": "de",
    "timezone": "Europe/Berlin",
    "must_change_password": true,
    "can_create_calendars": false,
    "created_at": "2026-10-03T12:00:00Z"
  }
}`},
			{ID: "users-update", Group: "Benutzer", Method: "PATCH", Path: "/api/admin/v1/users/{id}", Title: "Benutzer bearbeiten", Description: "Ändert einzelne Benutzereigenschaften. Nicht angegebene Felder bleiben unverändert.", Scope: "admin:users:write", Request: `{
  "first_name": "Max",
  "last_name": "Muster",
  "email": "max.muster@example.com",
  "role": "administrator",
  "status": "active",
  "language": "de",
  "timezone": "Europe/Berlin",
  "can_create_calendars": false
}`, Response: `{
  "ok": true,
  "data": {
    "id": "8c1e…",
    "name": "Max Muster",
    "email": "max.muster@example.com",
    "role": "administrator",
    "status": "active",
    "can_create_calendars": false
  }
}`, Notes: []string{"Die Owner-Rolle kann nicht über die Admin API vergeben werden.", "can_create_calendars kann jederzeit geändert werden und entfernt keine bereits vorhandenen Kalender.", "Wird die E-Mail geändert, widerruft ZentCal vorhandene App-Passwörter des Benutzers."}},
			{ID: "users-delete", Group: "Benutzer", Method: "DELETE", Path: "/api/admin/v1/users/{id}", Title: "Benutzer löschen", Description: "Löscht einen Benutzer und dessen persönlichen Kalender. Benutzerverwaltete Kalender bleiben bestehen; zentral verwaltete Kalender bleiben beim administrativen Verwalter.", Scope: "admin:users:write", Response: `(204 No Content)`, Destructive: true, Notes: []string{"Der letzte aktive ZentCal-Owner kann nicht gelöscht werden.", "Alleinige Eigentümerschaften an benutzerverwalteten Kalendern werden vor dem Löschen an den Administrator des verwendeten Tokens übertragen; zentral verwaltete Kalender können vorübergehend ohne Owner bleiben.", "Der Ersteller des verwendeten Admin API Tokens kann sich nicht selbst löschen."}},
		}},
		{Name: "Kalender", Endpoints: []adminAPIDoc{
			{ID: "calendars-list", Group: "Kalender", Method: "GET", Path: "/api/admin/v1/calendars", Title: "Kalender auflisten", Description: "Listet administrativ verwaltbare normale Kalender auf. Persönliche Systemkalender werden nicht ausgegeben.", Scope: "admin:calendars:read", Response: `{
  "ok": true,
  "data": [
    {
      "ID": "5c31…",
      "Name": "Team",
      "Description": "Teamkalender",
      "Color": "#4f8cff",
      "Type": "calendar",
      "Mode": "normal",
      "Members": 4,
      "Events": 12,
      "Access": "administration"
    }
  ]
}`},
			{ID: "calendars-create", Group: "Kalender", Method: "POST", Path: "/api/admin/v1/calendars", Title: "Kalender erstellen", Description: "Erstellt einen zentral verwalteten Kalender oder eine Ressource. Der Token-Ersteller wird administrativer Verwalter, aber nicht automatisch Kalender-Mitglied.", Scope: "admin:calendars:write", Request: `{
  "name": "Team",
  "description": "Teamkalender",
  "color": "#4f8cff",
  "type": "calendar",
  "mode": "normal"
}`, Response: `{
  "ok": true,
  "data": {
    "ID": "5c31…",
    "Name": "Team",
    "Description": "Teamkalender",
    "Color": "#4f8cff",
    "Type": "calendar",
    "Mode": "normal"
  }
}`, Notes: []string{"type unterstützt calendar und resource.", "mode unterstützt normal und personal; für normale Admin-Kalender wird üblicherweise normal verwendet."}},
			{ID: "calendars-get", Group: "Kalender", Method: "GET", Path: "/api/admin/v1/calendars/{id}", Title: "Kalender abrufen", Description: "Lädt einen vom Token-Ersteller zentral verwalteten Kalender. Persönliche, interne und benutzerverwaltete Kalender sind über diesen Endpoint nicht abrufbar.", Scope: "admin:calendars:read", Response: `{
  "ok": true,
  "data": {
    "ID": "5c31…",
    "Name": "Team",
    "Color": "#4f8cff",
    "Type": "calendar",
    "Mode": "normal",
    "Members": 4,
    "Events": 12
  }
}`},
			{ID: "calendars-update", Group: "Kalender", Method: "PATCH", Path: "/api/admin/v1/calendars/{id}", Title: "Kalender bearbeiten", Description: "Ändert Name, Beschreibung, Farbe oder Modus eines vom Token-Ersteller zentral verwalteten Kalenders.", Scope: "admin:calendars:write", Request: `{
  "name": "Team Kalender",
  "description": "Intern",
  "color": "#7c5cff",
  "mode": "normal"
}`, Response: `{
  "ok": true,
  "data": {
    "ID": "5c31…",
    "Name": "Team Kalender",
    "Description": "Intern",
    "Color": "#7c5cff",
    "Mode": "normal"
  }
}`},
			{ID: "calendars-delete", Group: "Kalender", Method: "DELETE", Path: "/api/admin/v1/calendars/{id}", Title: "Kalender löschen", Description: "Löscht einen vom Token-Ersteller zentral verwalteten Kalender. Benutzerkalender, persönliche und interne Kalender sind geschützt.", Scope: "admin:calendars:write", Response: `(204 No Content)`, Destructive: true},
			{ID: "members-list", Group: "Kalender", Method: "GET", Path: "/api/admin/v1/calendars/{id}/members", Title: "Mitglieder auflisten", Description: "Listet die Mitglieder eines vom Token-Ersteller zentral verwalteten Kalenders auf.", Scope: "admin:calendars:read", Response: `{
  "ok": true,
  "data": [
    {
      "user_id": "8c1e…",
      "name": "Max Mustermann",
      "email": "max@example.com",
      "role": "contributor",
      "created_at": "2026-10-03T12:00:00Z"
    }
  ]
}`},
			{ID: "members-put", Group: "Kalender", Method: "PUT", Path: "/api/admin/v1/calendars/{id}/members/{user_id}", Title: "Mitglied hinzufügen oder ändern", Description: "Fügt einen Benutzer zu einem Kalender hinzu oder aktualisiert dessen Kalenderrolle.", Scope: "admin:calendars:write", Request: `{
  "role": "contributor"
}`, Response: `{
  "ok": true
}`, Notes: []string{"Erlaubte Rollen: owner, contributor, viewer."}},
			{ID: "members-delete", Group: "Kalender", Method: "DELETE", Path: "/api/admin/v1/calendars/{id}/members/{user_id}", Title: "Mitglied entfernen", Description: "Entfernt einen Benutzer aus einem normalen Kalender.", Scope: "admin:calendars:write", Response: `(204 No Content)`, Destructive: true},
		}},
		{Name: "Webhooks", Endpoints: []adminAPIDoc{
			{ID: "webhooks-list", Group: "Webhooks", Method: "GET", Path: "/api/admin/v1/webhooks", Title: "Webhooks auflisten", Description: "Listet konfigurierte Webhooks auf.", Scope: "admin:webhooks:read", Response: `{
  "ok": true,
  "data": [
    {
      "ID": "2f70…",
      "Name": "Automation",
      "TargetURL": "https://example.com/hook",
      "AuthType": "hmac",
      "Active": true,
      "AllowPrivate": false,
      "Events": ["calendar.created"]
    }
  ]
}`},
			{ID: "webhooks-create", Group: "Webhooks", Method: "POST", Path: "/api/admin/v1/webhooks", Title: "Webhook erstellen", Description: "Erstellt einen Webhook und gibt das zugehörige Secret einmalig zurück.", Scope: "admin:webhooks:write", Request: `{
  "name": "Automation",
  "target_url": "https://example.com/hook",
  "auth_type": "hmac",
  "events": ["calendar.created", "backup.failed", "email.failed"],
  "active": true,
  "allow_private": false
}`, Response: `{
  "ok": true,
  "data": {
    "ID": "2f70…",
    "Name": "Automation",
    "TargetURL": "https://example.com/hook",
    "AuthType": "hmac",
    "Active": true,
    "Events": ["calendar.created", "calendar.updated"]
  },
  "secret": "…"
}`, Notes: []string{"Das Secret wird nur in dieser Response zurückgegeben.", "Backup-Events: backup.succeeded, backup.failed, backup.verify.failed, backup.restore.started und backup.restore.failed. E-Mail-Fehler werden über email.failed gemeldet."}},
			{ID: "webhooks-get", Group: "Webhooks", Method: "GET", Path: "/api/admin/v1/webhooks/{id}", Title: "Webhook abrufen", Description: "Lädt einen einzelnen Webhook.", Scope: "admin:webhooks:read", Response: `{
  "ok": true,
  "data": {
    "ID": "2f70…",
    "Name": "Automation",
    "TargetURL": "https://example.com/hook",
    "AuthType": "hmac",
    "Active": true,
    "AllowPrivate": false,
    "Events": ["calendar.created"]
  }
}`},
			{ID: "webhooks-update", Group: "Webhooks", Method: "PATCH", Path: "/api/admin/v1/webhooks/{id}", Title: "Webhook bearbeiten", Description: "Ändert einzelne Webhook-Eigenschaften.", Scope: "admin:webhooks:write", Request: `{
  "name": "Automation Prod",
  "active": true,
  "events": ["calendar.created", "user.created"]
}`, Response: `{
  "ok": true,
  "data": {
    "ID": "2f70…",
    "Name": "Automation Prod",
    "Active": true,
    "Events": ["calendar.created", "user.created"]
  }
}`},
			{ID: "webhooks-delete", Group: "Webhooks", Method: "DELETE", Path: "/api/admin/v1/webhooks/{id}", Title: "Webhook löschen", Description: "Löscht einen Webhook.", Scope: "admin:webhooks:write", Response: `(204 No Content)`, Destructive: true},
			{ID: "webhooks-rotate", Group: "Webhooks", Method: "POST", Path: "/api/admin/v1/webhooks/{id}/rotate-secret", Title: "Webhook Secret rotieren", Description: "Erzeugt ein neues Webhook-Secret und gibt es einmalig zurück.", Scope: "admin:webhooks:write", Response: `{
  "ok": true,
  "secret": "…"
}`, Destructive: true, Notes: []string{"Das bisherige Secret ist danach ungültig."}},
			{ID: "webhooks-test", Group: "Webhooks", Method: "POST", Path: "/api/admin/v1/webhooks/{id}/test", Title: "Webhook testen", Description: "Sendet eine Testzustellung an den konfigurierten Webhook.", Scope: "admin:webhooks:write", Response: `{
  "ok": true,
  "message": "Test-WebHook wurde versendet."
}`},
			{ID: "webhooks-deliveries", Group: "Webhooks", Method: "GET", Path: "/api/admin/v1/webhook-deliveries", Title: "Webhook Zustellungen", Description: "Gibt die letzten bis zu 200 Webhook-Zustellungen zurück.", Scope: "admin:webhooks:read", Response: `{
  "ok": true,
  "data": [
    {
      "ID": "54be…",
      "WebhookName": "Automation",
      "Event": "calendar.created",
      "Status": "delivered",
      "Attempt": 1,
      "HTTPStatus": 200,
      "ResponseMS": 84
    }
  ]
}`},
		}},

		{Name: "E-Mail", Endpoints: []adminAPIDoc{
			{ID: "email-deliveries", Group: "E-Mail", Method: "GET", Path: "/api/admin/v1/email-deliveries", Title: "E-Mail-Zustellungen", Description: "Listet die technischen E-Mail-Zustellstatus der letzten 30 Tage auf. Inhalte und vollständige Empfängeradressen werden nicht gespeichert.", Scope: "admin:mail:read", Response: `{
  "ok": true,
  "data": [
    {
      "id": "9b7a…",
      "type": "event_invite",
      "recipient": "st***@example.com",
      "status": "success",
      "attempt": 1,
      "created_at": "2026-10-03T19:00:00Z",
      "delivered_at": "2026-10-03T19:00:01Z"
    }
  ]
}`, Notes: []string{"Optionale Filter: ?status=failed, ?type=event_invite und ?q=st***.", "Es werden keine Betreffzeilen, Inhalte, HTML/ICS-Daten, Passwörter oder vollständigen externen Empfängeradressen gespeichert."}},
		}},
		{Name: "Backups", Endpoints: []adminAPIDoc{
			{ID: "backup-settings-get", Group: "Backups", Method: "GET", Path: "/api/admin/v1/backup-settings", Title: "Backup-Einstellungen abrufen", Description: "Lädt die Backup-Konfiguration ohne geheime Werte offenzulegen.", Scope: "admin:backups:read", Response: `{
  "ok": true,
  "data": {
    "enabled": true,
    "provider": "s3",
    "schedule": "daily",
    "time": "03:00",
    "weekdays": [0],
    "retention": 14,
    "encryption_password_set": true,
    "s3_endpoint": "https://s3.example.com",
    "s3_region": "eu-central-1",
    "s3_bucket": "zentcal",
    "s3_secret_key_set": true
  }
}`},
			{ID: "backup-settings-patch", Group: "Backups", Method: "PATCH", Path: "/api/admin/v1/backup-settings", Title: "Backup-Einstellungen ändern", Description: "Ändert einzelne Backup-Einstellungen. Nicht angegebene Werte bleiben unverändert.", Scope: "admin:backups:write", Request: `{
  "enabled": true,
  "provider": "s3",
  "schedule": "daily",
  "time": "03:00",
  "retention": 14,
  "s3_endpoint": "https://s3.example.com",
  "s3_region": "eu-central-1",
  "s3_bucket": "zentcal",
  "s3_access_key": "ACCESS_KEY",
  "s3_secret_key": "SECRET_KEY",
  "s3_prefix": "zentcal",
  "s3_tls_verify": true
}`, Response: `{
  "ok": true,
  "data": {
    "enabled": true,
    "provider": "s3",
    "schedule": "daily",
    "time": "03:00",
    "retention": 14,
    "s3_secret_key_set": true
  }
}`, Notes: []string{"Provider: local, sftp oder s3. Bei SFTP wählst du mit sftp_auth_method genau password oder key.", "Secrets werden in GET/PATCH-Responses niemals im Klartext zurückgegeben.", "Ein bereits gesetztes Backup-Verschlüsselungspasswort kann nicht durch einen anderen Wert ersetzt werden."}},
			{ID: "backup-settings-test", Group: "Backups", Method: "POST", Path: "/api/admin/v1/backup-settings/test", Title: "Backup-Ziel testen", Description: "Testet die aktuell gespeicherte Backup-Konfiguration, optional mit temporär überschriebenen Request-Werten.", Scope: "admin:backups:write", Request: `{
  "provider": "sftp",
  "sftp_host": "backup.example.com",
  "sftp_port": 22,
  "sftp_user": "zentcal",
  "sftp_auth_method": "password",
  "sftp_password": "SECRET",
  "sftp_path": "zentcal",
  "sftp_verify_host": true
}`, Response: `{
  "ok": true,
  "message": "Backup-Ziel erfolgreich geprüft."
}`},
			{ID: "backups-list", Group: "Backups", Method: "GET", Path: "/api/admin/v1/backups", Title: "Backups auflisten", Description: "Listet die letzten bis zu 200 Backups auf.", Scope: "admin:backups:read", Response: `{
  "ok": true,
  "data": [
    {
      "ID": "9a81…",
      "Filename": "zentcal-20261003-030000.tar.gz.enc",
      "Provider": "s3",
      "Status": "success",
      "Stage": "done",
      "Size": 1843200,
      "Checksum": "…",
      "CreatedAt": "2026-10-03T03:00:00Z"
    }
  ]
}`},
			{ID: "backups-create", Group: "Backups", Method: "POST", Path: "/api/admin/v1/backups", Title: "Backup starten", Description: "Startet asynchron ein neues Backup.", Scope: "admin:backups:write", Response: `{
  "ok": true,
  "message": "Backup wurde gestartet."
}`},
			{ID: "backups-verify", Group: "Backups", Method: "POST", Path: "/api/admin/v1/backups/{id}/verify", Title: "Backup verifizieren", Description: "Prüft Integrität und Lesbarkeit eines Backups.", Scope: "admin:backups:read", Request: `{
  "encryption_password": "optional-wenn-erforderlich"
}`, Response: `{
  "ok": true
}`},
			{ID: "backups-restore", Group: "Backups", Method: "POST", Path: "/api/admin/v1/backups/{id}/restore", Title: "Backup wiederherstellen", Description: "Bereitet ein Backup zur Wiederherstellung vor und startet ZentCal anschließend neu.", Scope: "admin:backups:restore", Request: `{
  "confirm": "RESTORE",
  "encryption_password": "optional-wenn-erforderlich"
}`, Response: `{
  "ok": true,
  "message": "Backup wurde für die Wiederherstellung vorbereitet. ZentCal wird neu gestartet."
}`, Destructive: true, Notes: []string{"confirm muss exakt RESTORE enthalten.", "Dieser Scope ist absichtlich separat und sollte nur gezielt vergeben werden."}},
			{ID: "backups-delete", Group: "Backups", Method: "DELETE", Path: "/api/admin/v1/backups/{id}", Title: "Backup löschen", Description: "Löscht ein Backup aus dem konfigurierten Backup-Ziel.", Scope: "admin:backups:write", Response: `(204 No Content)`, Destructive: true},
		}},
	}
}
