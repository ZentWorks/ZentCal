package web

import "github.com/zentworks/zentcal/internal/app"

// dashboardTestData mirrors the complete data contract expected by dashboard.html.
// Keep direct dashboard template tests on this shared fixture so template additions
// do not leave individual tests with incomplete map data.
func dashboardTestData() map[string]any {
	return map[string]any{
		"Calendars":          0,
		"Users":              0,
		"Events":             0,
		"PendingInvites":     0,
		"Upcoming":           []DashboardEventRow{},
		"CalendarList":       []app.Calendar{},
		"Activity":           []AuditRow{},
		"CanCreateCalendars": false,
	}
}
