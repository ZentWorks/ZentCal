package web

func userAPIDocs() []adminAPIDocGroup {
	return []adminAPIDocGroup{
		{Name: "Allgemein", Endpoints: []adminAPIDoc{
			{ID: "user-meta", Group: "Allgemein", Method: "GET", Path: "/api/v1", Title: "API Status", Description: "Prüft, ob die ZentCal Benutzer-API erreichbar ist.", Scope: "–", Response: `{
  "name": "ZentCal API",
  "version": "v1",
  "ok": true
}`},
			{ID: "user-me", Group: "Allgemein", Method: "GET", Path: "/api/v1/me", Title: "Eigenes Konto abrufen", Description: "Gibt den zum API-Token gehörenden Benutzer und die Berechtigung zum Erstellen eigener Kalender zurück.", Scope: "–", Response: `{
  "ok": true,
  "data": {
    "ID": "8c1e…",
    "Name": "Max Mustermann",
    "Email": "max@example.com",
    "Role": "user",
    "Status": "active",
    "AuthType": "local",
    "CanCreateCalendars": true
  }
}`},
		}},
		{Name: "Kalender", Endpoints: []adminAPIDoc{
			{ID: "user-calendars-list", Group: "Kalender", Method: "GET", Path: "/api/v1/calendars", Title: "Kalender auflisten", Description: "Listet den persönlichen Kalender und alle Kalender auf, die dem Benutzer freigegeben wurden.", Scope: "calendar:read", Response: `{
  "ok": true,
  "data": [
    {
      "ID": "5c31…",
      "Name": "Privat",
      "Color": "#4f8cff",
      "Type": "calendar",
      "Mode": "normal",
      "Role": "owner",
      "Members": 1,
      "Events": 8
    }
  ]
}`},
			{ID: "user-calendars-create", Group: "Kalender", Method: "POST", Path: "/api/v1/calendars", Title: "Kalender erstellen", Description: "Erstellt einen normalen Kalender für den Benutzer.", Scope: "calendar:write", Request: `{
  "Name": "Projekt",
  "Description": "Projekttermine",
  "Color": "#7c5cff",
  "Type": "calendar",
  "Mode": "normal"
}`, Response: `{
  "ok": true,
  "data": {
    "ID": "5c31…",
    "Name": "Projekt",
    "Description": "Projekttermine",
    "Color": "#7c5cff",
    "Type": "calendar",
    "Mode": "normal",
    "Role": "owner"
  }
}`, Notes: []string{"Funktioniert nur, wenn für den Benutzer „Eigene Kalender erstellen“ erlaubt ist.", "Persönliche Benutzerkalender werden nicht über diesen Endpoint erstellt."}},
			{ID: "user-calendar-get", Group: "Kalender", Method: "GET", Path: "/api/v1/calendars/{id}", Title: "Kalender abrufen", Description: "Lädt einen Kalender, auf den der Benutzer Zugriff hat.", Scope: "calendar:read", Response: `{
  "ok": true,
  "data": {
    "ID": "5c31…",
    "Name": "Projekt",
    "Color": "#7c5cff",
    "Role": "owner",
    "Members": 2,
    "Events": 12
  }
}`},
			{ID: "user-calendar-update", Group: "Kalender", Method: "PATCH", Path: "/api/v1/calendars/{id}", Title: "Kalender bearbeiten", Description: "Ändert Name, Beschreibung, Farbe oder Modus eines Kalenders, wenn der Benutzer ihn verwalten darf.", Scope: "calendar:write", Request: `{
  "Name": "Projekt Intern",
  "Description": "Aktualisiert",
  "Color": "#3fae7a",
  "Mode": "normal"
}`, Response: `{
  "ok": true,
  "data": {
    "ID": "5c31…",
    "Name": "Projekt Intern",
    "Description": "Aktualisiert",
    "Color": "#3fae7a"
  }
}`},
			{ID: "user-calendar-delete", Group: "Kalender", Method: "DELETE", Path: "/api/v1/calendars/{id}", Title: "Kalender löschen", Description: "Löscht einen normalen Kalender, wenn der Benutzer dazu berechtigt ist.", Scope: "calendar:write", Response: `(204 No Content)`, Destructive: true, Notes: []string{"Persönliche Kalender können nicht gelöscht werden."}},
		}},
		{Name: "Termine", Endpoints: []adminAPIDoc{
			{ID: "user-events-list", Group: "Termine", Method: "GET", Path: "/api/v1/calendars/{id}/events", Title: "Termine auflisten", Description: "Listet die Termine eines lesbaren Kalenders auf.", Scope: "event:read", Response: `{
  "ok": true,
  "data": [
    {
      "ID": "a7d2…",
      "CalendarID": "5c31…",
      "UID": "meeting-123@example.com",
      "Href": "meeting-123.ics",
      "Summary": "Besprechung",
      "Version": 1
    }
  ]
}`},
			{ID: "user-events-create", Group: "Termine", Method: "POST", Path: "/api/v1/calendars/{id}/events", Title: "Termin erstellen oder aktualisieren", Description: "Schreibt einen Termin als iCalendar-Daten in einen Kalender.", Scope: "event:write", Request: `{
  "Href": "meeting-123.ics",
  "ICS": "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:meeting-123@example.com\r\nDTSTART:20261010T090000Z\r\nDTEND:20261010T100000Z\r\nSUMMARY:Besprechung\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
}`, Response: `{
  "ok": true,
  "data": {
    "ID": "a7d2…",
    "CalendarID": "5c31…",
    "UID": "meeting-123@example.com",
    "Href": "meeting-123.ics",
    "Summary": "Besprechung"
  }
}`, Notes: []string{"Bei einem neuen Href antwortet ZentCal mit HTTP 201, bei einer Aktualisierung mit HTTP 200."}},
			{ID: "user-event-get", Group: "Termine", Method: "GET", Path: "/api/v1/events/{id}", Title: "Termin abrufen", Description: "Lädt einen einzelnen Termin, sofern der Benutzer Zugriff auf dessen Kalender hat.", Scope: "event:read", Response: `{
  "ok": true,
  "data": {
    "ID": "a7d2…",
    "CalendarID": "5c31…",
    "Summary": "Besprechung",
    "ICS": "BEGIN:VCALENDAR…"
  }
}`},
			{ID: "user-event-delete", Group: "Termine", Method: "DELETE", Path: "/api/v1/events/{id}", Title: "Termin löschen", Description: "Löscht einen Termin, wenn der Benutzer ihn im zugehörigen Kalender bearbeiten darf.", Scope: "event:write", Response: `(204 No Content)`, Destructive: true},
		}},
	}
}
