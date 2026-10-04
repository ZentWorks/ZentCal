package ical

import (
	"strings"
	"testing"
)

func TestParseAndNormalize(t *testing.T) {
	raw := "BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\nUID:test-1\nSUMMARY:Team Meeting\nDTSTART:20261001T120000Z\nDTEND:20261001T130000Z\nEND:VEVENT\nEND:VCALENDAR\n"
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.UID != "test-1" || m.Summary != "Team Meeting" {
		t.Fatalf("unexpected metadata: %#v", m)
	}
	if m.Start == nil || m.End == nil || !m.End.After(*m.Start) {
		t.Fatalf("invalid times: %#v", m)
	}
	if !strings.Contains(Normalize(raw), "\r\n") {
		t.Fatal("expected CRLF normalization")
	}
	if ETag(raw) != ETag(Normalize(raw)) {
		t.Fatal("etag must be stable after normalization")
	}
}

func TestParseRejectsMissingUID(t *testing.T) {
	_, err := Parse("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:X\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
	if err == nil {
		t.Fatal("expected missing UID error")
	}
}

func TestParseAttendeesAndPreserveVALARM(t *testing.T) {
	raw := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:test-attendees\r\nSUMMARY:Planung\r\nDESCRIPTION:Intern\r\nLOCATION:Raum 1\r\nATTENDEE;CN=Max Mustermann:mailto:max@example.com\r\nATTENDEE:mailto:lisa@example.com\r\nBEGIN:VALARM\r\nTRIGGER:-PT15M\r\nACTION:DISPLAY\r\nDESCRIPTION:Reminder\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Description != "Intern" || m.Location != "Raum 1" {
		t.Fatalf("description/location not parsed: %#v", m)
	}
	if len(m.Attendees) != 2 || m.Attendees[0] != "Max Mustermann <max@example.com>" || m.Attendees[1] != "lisa@example.com" {
		t.Fatalf("unexpected attendees: %#v", m.Attendees)
	}
	n := Normalize(raw)
	for _, want := range []string{"BEGIN:VALARM", "TRIGGER:-PT15M", "ACTION:DISPLAY", "END:VALARM"} {
		if !strings.Contains(n, want) {
			t.Fatalf("VALARM lost during normalization: %s", want)
		}
	}
}

func TestSchedulingFieldsAndReply(t *testing.T) {
	raw := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:invite-1\r\nSUMMARY:Planung\r\nDTSTART:20261004T120000Z\r\nATTENDEE;CN=Lisa:mailto:lisa@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	updated, err := EnsureSchedulingFields(raw, "Max", "max@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(updated)
	if err != nil {
		t.Fatal(err)
	}
	if m.OrganizerEmail != "max@example.com" || len(m.AttendeeDetails) != 1 {
		t.Fatalf("unexpected scheduling metadata: %#v", m)
	}
	if m.AttendeeDetails[0].PartStat != "NEEDS-ACTION" || !m.AttendeeDetails[0].RSVP {
		t.Fatalf("attendee defaults missing: %#v", m.AttendeeDetails[0])
	}
	reply, err := BuildReply(updated, "lisa@example.com", "ACCEPTED")
	if err != nil {
		t.Fatal(err)
	}
	rm, err := Parse(reply)
	if err != nil {
		t.Fatal(err)
	}
	if rm.Method != "REPLY" || rm.AttendeeDetails[0].PartStat != "ACCEPTED" {
		t.Fatalf("unexpected reply: %#v", rm)
	}
}

func TestCancelAndWithoutMethod(t *testing.T) {
	raw := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:invite-2\r\nSUMMARY:Planung\r\nSEQUENCE:2\r\nDTSTART:20261004T120000Z\r\nORGANIZER:mailto:max@example.com\r\nATTENDEE:mailto:lisa@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	plain := WithoutMethod(raw)
	if strings.Contains(plain, "METHOD:") {
		t.Fatal("METHOD must not be persisted in attendee calendar object")
	}
	cancel, err := BuildCancel(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(cancel)
	if err != nil {
		t.Fatal(err)
	}
	if m.Method != "CANCEL" || m.Sequence != 3 || !strings.Contains(cancel, "STATUS:CANCELLED") {
		t.Fatalf("invalid cancel message: %s", cancel)
	}
}

func TestPreserveAttendeeResponsesOnOrganizerUpdate(t *testing.T) {
	previous := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:invite-3\r\nSUMMARY:Alt\r\nORGANIZER:mailto:max@example.com\r\nATTENDEE;PARTSTAT=ACCEPTED;RSVP=TRUE:mailto:lisa@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	incoming := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:invite-3\r\nSUMMARY:Neu\r\nORGANIZER:mailto:max@example.com\r\nATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:lisa@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	updated := PreserveAttendeeResponses(incoming, previous)
	m, err := Parse(updated)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.AttendeeDetails) != 1 || m.AttendeeDetails[0].PartStat != "ACCEPTED" {
		t.Fatalf("accepted response was lost: %#v", m.AttendeeDetails)
	}
}

func TestSetSummaryPreservesEventAndNestedAlarm(t *testing.T) {
	raw := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:personal-1\r\nSUMMARY:Zahnarzt\r\nDTSTART:20261003T120000Z\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Reminder\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	got := SetSummary(raw, "Steffen | Zahnarzt")
	meta, err := Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Summary != "Steffen | Zahnarzt" {
		t.Fatalf("unexpected summary: %q", meta.Summary)
	}
	if !strings.Contains(got, "DESCRIPTION:Reminder") {
		t.Fatal("VALARM content was lost")
	}
}

func TestEnsureSchedulingFieldsEnforcesAuthenticatedOrganizer(t *testing.T) {
	raw := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:organizer-security\r\nSUMMARY:Test\r\nDTSTART:20261004T120000Z\r\nORGANIZER:mailto:spoofed@example.com\r\nATTENDEE:mailto:lisa@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	got, err := EnsureSchedulingFields(raw, "Steffen", "steffen@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "spoofed@example.com") {
		t.Fatalf("client supplied organizer survived: %s", got)
	}
	meta, err := Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if meta.OrganizerEmail != "steffen@example.com" || meta.OrganizerName != "Steffen" {
		t.Fatalf("authenticated organizer missing: %#v", meta)
	}
}

func TestHasRecurrence(t *testing.T) {
	recurring := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:r1\r\nDTSTART:20260101T100000Z\r\nRRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	if !HasRecurrence(recurring) {
		t.Fatal("expected recurring event to be detected")
	}
	single := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:s1\r\nDTSTART:20260101T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	if HasRecurrence(single) {
		t.Fatal("single event must not be detected as recurring")
	}
}

func TestEventContentEqualIgnoresSchedulingTransportMetadata(t *testing.T) {
	a := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:x\r\nDTSTAMP:20261004T100000Z\r\nSEQUENCE:3\r\nORGANIZER:mailto:a@example.com\r\nSUMMARY:Meeting\r\nDTSTART:20261005T100000Z\r\nATTENDEE;PARTSTAT=ACCEPTED:mailto:b@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	b := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:x\r\nDTSTAMP:20261004T110000Z\r\nSEQUENCE:99\r\nORGANIZER:mailto:other@example.com\r\nDTSTART:20261005T100000Z\r\nSUMMARY:Meeting\r\nATTENDEE;PARTSTAT=ACCEPTED:mailto:b@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	if !EventContentEqual(a, b) {
		t.Fatal("transport-only changes must be a semantic no-op")
	}
}

func TestSchedulingChangeKeys(t *testing.T) {
	oldRaw := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:x\r\nSUMMARY:Alt\r\nDTSTART:20261005T100000Z\r\nLOCATION:Raum 1\r\nATTENDEE:mailto:b@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	newRaw := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:x\r\nSUMMARY:Neu\r\nDTSTART:20261005T110000Z\r\nLOCATION:Raum 2\r\nATTENDEE:mailto:b@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	keys, err := SchedulingChangeKeys(oldRaw, newRaw)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(keys, ",")
	if got != "title,start,location" {
		t.Fatalf("unexpected keys: %s", got)
	}
}

func TestSetSequenceIsServerAuthoritative(t *testing.T) {
	raw := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:x\r\nSEQUENCE:999\r\nSUMMARY:Meeting\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	got := SetSequence(raw, 4)
	m, err := Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if m.Sequence != 4 {
		t.Fatalf("sequence=%d", m.Sequence)
	}
}

func TestEventContentEqualCanonicalizesPropertyParameterOrder(t *testing.T) {
	a := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:param-order\r\nSUMMARY:Meeting\r\nATTENDEE;CN=Max;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:max@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	b := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:param-order\r\nATTENDEE;RSVP=TRUE;PARTSTAT=NEEDS-ACTION;CN=Max:mailto:max@example.com\r\nSUMMARY:Meeting\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	if !EventContentEqual(a, b) {
		t.Fatal("parameter ordering must not create a semantic event change")
	}
}

func TestAlarmOnlyChangeIsStoredButDoesNotNotifyAttendees(t *testing.T) {
	oldRaw := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:alarm-only\r\nSUMMARY:Meeting\r\nDTSTART:20261005T100000Z\r\nATTENDEE:mailto:max@example.com\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nDESCRIPTION:Reminder\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	newRaw := strings.Replace(oldRaw, "TRIGGER:-PT15M", "TRIGGER:-PT30M", 1)
	if EventContentEqual(oldRaw, newRaw) {
		t.Fatal("alarm change must be persisted as an event content change")
	}
	keys, err := SchedulingChangeKeys(oldRaw, newRaw)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("alarm-only change must not notify attendees, got %v", keys)
	}
}

func TestRecurrenceOrderingDoesNotCreateFalseChange(t *testing.T) {
	a := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:rrule-order\r\nSUMMARY:Serie\r\nDTSTART:20261005T100000Z\r\nRRULE:FREQ=WEEKLY;COUNT=5;BYDAY=MO,WE\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	b := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:rrule-order\r\nRRULE:BYDAY=WE,MO;COUNT=5;FREQ=WEEKLY\r\nDTSTART:20261005T100000Z\r\nSUMMARY:Serie\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	if !EventContentEqual(a, b) {
		t.Fatal("equivalent RRULE component ordering must be a semantic no-op")
	}
	keys, err := SchedulingChangeKeys(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("equivalent recurrence ordering must not notify attendees: %v", keys)
	}
}
