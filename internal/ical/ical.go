package ical

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Attendee struct {
	Email    string
	CN       string
	PartStat string
	RSVP     bool
}

type Meta struct {
	UID, Summary, Description, Location string
	OrganizerEmail, OrganizerName       string
	Method                              string
	Sequence                            int
	Start, End                          *time.Time
	Attendees                           []string
	AttendeeDetails                     []Attendee
}

func Normalize(raw string) string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\r\n") + "\r\n"
}

func Parse(raw string) (Meta, error) {
	n := Normalize(raw)
	if !strings.Contains(n, "BEGIN:VCALENDAR") || !strings.Contains(n, "BEGIN:VEVENT") {
		return Meta{}, fmt.Errorf("ICS muss einen VCALENDAR/VEVENT enthalten")
	}
	lines := unfold(strings.Split(strings.ReplaceAll(n, "\r\n", "\n"), "\n"))
	var m Meta
	inEvent := false
	nested := 0
	for _, line := range lines {
		name, val, ok := splitLine(line)
		if !ok {
			continue
		}
		base := strings.ToUpper(strings.Split(name, ";")[0])
		component := strings.ToUpper(strings.TrimSpace(val))
		if !inEvent && base == "METHOD" {
			m.Method = component
			continue
		}
		if base == "BEGIN" {
			if component == "VEVENT" && !inEvent {
				inEvent = true
				nested = 0
			} else if inEvent {
				nested++
			}
			continue
		}
		if base == "END" {
			if inEvent && nested > 0 {
				nested--
				continue
			}
			if inEvent && component == "VEVENT" {
				break
			}
			continue
		}
		if !inEvent || nested > 0 {
			continue
		}
		switch base {
		case "UID":
			m.UID = strings.TrimSpace(val)
		case "SUMMARY":
			m.Summary = unescape(val)
		case "DESCRIPTION":
			m.Description = unescape(val)
		case "LOCATION":
			m.Location = unescape(val)
		case "ORGANIZER":
			m.OrganizerEmail = calendarAddress(val)
			m.OrganizerName = param(name, "CN")
		case "ATTENDEE":
			a := parseAttendee(name, val)
			if a.Email != "" {
				m.AttendeeDetails = append(m.AttendeeDetails, a)
				m.Attendees = append(m.Attendees, attendeeDisplay(a))
			}
		case "SEQUENCE":
			if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil && n >= 0 {
				m.Sequence = n
			}
		case "DTSTART":
			if t, err := parseTime(name, val); err == nil {
				m.Start = &t
			}
		case "DTEND":
			if t, err := parseTime(name, val); err == nil {
				m.End = &t
			}
		}
	}
	if m.UID == "" {
		return Meta{}, fmt.Errorf("VEVENT benötigt UID")
	}
	return m, nil
}

func parseAttendee(name, val string) Attendee {
	a := Attendee{Email: calendarAddress(val), CN: unescape(param(name, "CN")), PartStat: strings.ToUpper(param(name, "PARTSTAT"))}
	if a.PartStat == "" {
		a.PartStat = "NEEDS-ACTION"
	}
	a.RSVP = strings.EqualFold(param(name, "RSVP"), "TRUE")
	return a
}

func attendeeDisplay(a Attendee) string {
	if a.CN != "" && !strings.EqualFold(a.CN, a.Email) {
		return a.CN + " <" + a.Email + ">"
	}
	return a.Email
}

func calendarAddress(val string) string {
	addr := strings.TrimSpace(val)
	if strings.HasPrefix(strings.ToLower(addr), "mailto:") {
		addr = strings.TrimSpace(addr[len("mailto:"):])
	}
	return strings.ToLower(addr)
}

func param(name, key string) string {
	parts := strings.Split(name, ";")
	for _, part := range parts[1:] {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), key) {
			return strings.Trim(strings.TrimSpace(kv[1]), `"`)
		}
	}
	return ""
}

func attendeeLabel(name, val string) string {
	return attendeeDisplay(parseAttendee(name, val))
}

func SetSummary(raw, summary string) string {
	lines := unfold(strings.Split(strings.ReplaceAll(Normalize(raw), "\r\n", "\n"), "\n"))
	out := make([]string, 0, len(lines)+1)
	inEvent := false
	nested := 0
	replaced := false
	for _, line := range lines {
		name, val, ok := splitLine(line)
		if !ok {
			out = append(out, line)
			continue
		}
		base := strings.ToUpper(strings.Split(name, ";")[0])
		comp := strings.ToUpper(strings.TrimSpace(val))
		if base == "BEGIN" {
			if comp == "VEVENT" && !inEvent {
				inEvent = true
				nested = 0
			} else if inEvent {
				nested++
			}
			out = append(out, line)
			continue
		}
		if base == "END" {
			if inEvent && nested > 0 {
				nested--
			} else if inEvent && comp == "VEVENT" {
				if !replaced {
					out = append(out, "SUMMARY:"+EscapeText(summary))
					replaced = true
				}
				inEvent = false
			}
			out = append(out, line)
			continue
		}
		if inEvent && nested == 0 && base == "SUMMARY" {
			if !replaced {
				out = append(out, "SUMMARY:"+EscapeText(summary))
				replaced = true
			}
			continue
		}
		out = append(out, line)
	}
	return Normalize(strings.Join(out, "\r\n"))
}

// HasRecurrence reports whether the VEVENT contains recurrence rules or dates.
// CalDAV range queries must not hide such objects solely because the master
// DTSTART lies outside the requested window; clients can expand the recurrence.
func HasRecurrence(raw string) bool {
	lines := unfold(strings.Split(strings.ReplaceAll(Normalize(raw), "\r\n", "\n"), "\n"))
	inEvent := false
	nested := 0
	for _, line := range lines {
		name, val, ok := splitLine(line)
		if !ok {
			continue
		}
		base := strings.ToUpper(strings.Split(name, ";")[0])
		comp := strings.ToUpper(strings.TrimSpace(val))
		if base == "BEGIN" {
			if comp == "VEVENT" && !inEvent {
				inEvent = true
				nested = 0
			} else if inEvent {
				nested++
			}
			continue
		}
		if base == "END" {
			if inEvent && nested > 0 {
				nested--
			} else if inEvent && comp == "VEVENT" {
				inEvent = false
			}
			continue
		}
		if inEvent && nested == 0 && (base == "RRULE" || base == "RDATE" || base == "EXRULE") {
			return true
		}
	}
	return false
}

func ETag(raw string) string {
	s := sha256.Sum256([]byte(Normalize(raw)))
	return `"` + hex.EncodeToString(s[:16]) + `"`
}

// EnsureSchedulingFields makes a calendar object suitable for server-side scheduling.
// It never changes event times or timezone data.
func EnsureSchedulingFields(raw, organizerName, organizerEmail string, incrementSequence bool) (string, error) {
	m, err := Parse(raw)
	if err != nil {
		return "", err
	}
	if len(m.AttendeeDetails) == 0 {
		return Normalize(raw), nil
	}
	lines := unfold(strings.Split(strings.ReplaceAll(Normalize(raw), "\r\n", "\n"), "\n"))
	out := make([]string, 0, len(lines)+3)
	inEvent := false
	organizerSeen := false
	sequenceSeen := false
	for _, line := range lines {
		name, val, ok := splitLine(line)
		if !ok {
			out = append(out, line)
			continue
		}
		base := strings.ToUpper(strings.Split(name, ";")[0])
		comp := strings.ToUpper(strings.TrimSpace(val))
		if base == "BEGIN" && comp == "VEVENT" {
			inEvent = true
			out = append(out, line)
			continue
		}
		if inEvent && base == "END" && comp == "VEVENT" {
			if !organizerSeen && strings.TrimSpace(organizerEmail) != "" {
				out = append(out, organizerLine(organizerName, organizerEmail))
			}
			if !sequenceSeen {
				seq := m.Sequence
				if incrementSequence {
					seq++
				}
				out = append(out, "SEQUENCE:"+strconv.Itoa(seq))
			}
			inEvent = false
			out = append(out, line)
			continue
		}
		if inEvent && base == "ORGANIZER" {
			// The authenticated ZentCal user is authoritative. Never allow a DAV/API
			// client to impersonate another organizer by supplying its own ORGANIZER.
			if !organizerSeen && strings.TrimSpace(organizerEmail) != "" {
				out = append(out, organizerLine(organizerName, organizerEmail))
				organizerSeen = true
			}
			continue
		}
		if inEvent && base == "SEQUENCE" {
			sequenceSeen = true
			seq := m.Sequence
			if incrementSequence {
				seq++
			}
			out = append(out, "SEQUENCE:"+strconv.Itoa(seq))
			continue
		}
		if inEvent && base == "ATTENDEE" {
			// Scheduling defaults: server handles delivery, and a new attendee needs a reply.
			if param(name, "PARTSTAT") == "" {
				name += ";PARTSTAT=NEEDS-ACTION"
			}
			if param(name, "RSVP") == "" {
				name += ";RSVP=TRUE"
			}
			out = append(out, name+":"+val)
			continue
		}
		out = append(out, line)
	}
	return Normalize(strings.Join(out, "\r\n")), nil
}

func organizerLine(name, email string) string {
	email = strings.TrimSpace(strings.ToLower(email))
	if strings.TrimSpace(name) == "" {
		return "ORGANIZER:mailto:" + email
	}
	return "ORGANIZER;CN=" + escapeParam(name) + ":mailto:" + email
}

func WithoutMethod(raw string) string {
	lines := unfold(strings.Split(strings.ReplaceAll(Normalize(raw), "\r\n", "\n"), "\n"))
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		name, _, ok := splitLine(line)
		if ok && strings.EqualFold(strings.Split(name, ";")[0], "METHOD") {
			continue
		}
		out = append(out, line)
	}
	return Normalize(strings.Join(out, "\r\n"))
}

func SetMethod(raw, method string) string {
	lines := unfold(strings.Split(strings.ReplaceAll(Normalize(raw), "\r\n", "\n"), "\n"))
	out := make([]string, 0, len(lines)+1)
	seen := false
	for _, line := range lines {
		name, _, ok := splitLine(line)
		if ok && strings.EqualFold(strings.Split(name, ";")[0], "METHOD") {
			if !seen {
				out = append(out, "METHOD:"+strings.ToUpper(method))
				seen = true
			}
			continue
		}
		out = append(out, line)
		if strings.EqualFold(strings.TrimSpace(line), "VERSION:2.0") && !seen {
			out = append(out, "METHOD:"+strings.ToUpper(method))
			seen = true
		}
	}
	return Normalize(strings.Join(out, "\r\n"))
}

// PreserveAttendeeResponses keeps already-known attendee participation states when a
// calendar client sends an update with the same attendees reset to NEEDS-ACTION.
func PreserveAttendeeResponses(raw, previous string) string {
	pm, err := Parse(previous)
	if err != nil {
		return Normalize(raw)
	}
	out := Normalize(raw)
	for _, a := range pm.AttendeeDetails {
		status := strings.ToUpper(strings.TrimSpace(a.PartStat))
		if status == "" || status == "NEEDS-ACTION" {
			continue
		}
		cm, err := Parse(out)
		if err != nil {
			return Normalize(raw)
		}
		for _, current := range cm.AttendeeDetails {
			if strings.EqualFold(current.Email, a.Email) && (current.PartStat == "" || current.PartStat == "NEEDS-ACTION") {
				if updated, ok := SetAttendeePartStat(out, a.Email, status); ok {
					out = updated
				}
				break
			}
		}
	}
	return Normalize(out)
}

func SetAttendeePartStat(raw, email, status string) (string, bool) {
	email = strings.ToLower(strings.TrimSpace(email))
	status = strings.ToUpper(strings.TrimSpace(status))
	if status != "ACCEPTED" && status != "DECLINED" && status != "TENTATIVE" && status != "NEEDS-ACTION" {
		return Normalize(raw), false
	}
	lines := unfold(strings.Split(strings.ReplaceAll(Normalize(raw), "\r\n", "\n"), "\n"))
	changed := false
	inEvent := false
	nested := 0
	for i, line := range lines {
		name, val, ok := splitLine(line)
		if !ok {
			continue
		}
		base := strings.ToUpper(strings.Split(name, ";")[0])
		comp := strings.ToUpper(strings.TrimSpace(val))
		if base == "BEGIN" {
			if comp == "VEVENT" && !inEvent {
				inEvent = true
				nested = 0
			} else if inEvent {
				nested++
			}
			continue
		}
		if base == "END" {
			if inEvent && nested > 0 {
				nested--
			} else if inEvent && comp == "VEVENT" {
				inEvent = false
			}
			continue
		}
		if !inEvent || nested > 0 || base != "ATTENDEE" || !strings.EqualFold(calendarAddress(val), email) {
			continue
		}
		parts := strings.Split(name, ";")
		newParts := []string{parts[0]}
		found := false
		for _, p := range parts[1:] {
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(p)), "PARTSTAT=") {
				newParts = append(newParts, "PARTSTAT="+status)
				found = true
			} else {
				newParts = append(newParts, p)
			}
		}
		if !found {
			newParts = append(newParts, "PARTSTAT="+status)
		}
		lines[i] = strings.Join(newParts, ";") + ":" + val
		changed = true
	}
	return Normalize(strings.Join(lines, "\r\n")), changed
}

func BuildReply(raw, attendeeEmail, status string) (string, error) {
	m, err := Parse(raw)
	if err != nil {
		return "", err
	}
	updated, ok := SetAttendeePartStat(raw, attendeeEmail, status)
	if !ok {
		return "", fmt.Errorf("Teilnehmer ist nicht im Termin enthalten")
	}
	// iTIP REPLY contains only the replying attendee. Keep core VEVENT fields and timezone blocks.
	lines := unfold(strings.Split(strings.ReplaceAll(SetMethod(updated, "REPLY"), "\r\n", "\n"), "\n"))
	out := make([]string, 0, len(lines))
	inEvent := false
	nested := 0
	for _, line := range lines {
		name, val, ok := splitLine(line)
		if !ok {
			out = append(out, line)
			continue
		}
		base := strings.ToUpper(strings.Split(name, ";")[0])
		comp := strings.ToUpper(strings.TrimSpace(val))
		if base == "BEGIN" {
			if comp == "VEVENT" && !inEvent {
				inEvent = true
				nested = 0
			} else if inEvent {
				nested++
			}
			out = append(out, line)
			continue
		}
		if base == "END" {
			if inEvent && nested > 0 {
				nested--
			} else if inEvent && comp == "VEVENT" {
				inEvent = false
			}
			out = append(out, line)
			continue
		}
		if inEvent && nested == 0 && base == "ATTENDEE" && !strings.EqualFold(calendarAddress(val), attendeeEmail) {
			continue
		}
		if inEvent && nested == 0 {
			switch base {
			case "UID", "DTSTAMP", "DTSTART", "DTEND", "RECURRENCE-ID", "SEQUENCE", "ORGANIZER", "ATTENDEE", "COMMENT", "SUMMARY", "LOCATION":
				out = append(out, line)
			default:
				// Nested components are kept above; non-essential top-level event data is omitted.
			}
			continue
		}
		out = append(out, line)
	}
	_ = m
	return Normalize(strings.Join(out, "\r\n")), nil
}

func BuildCancel(raw string) (string, error) {
	m, err := Parse(raw)
	if err != nil {
		return "", err
	}
	withSeq := setSequence(raw, m.Sequence+1)
	lines := unfold(strings.Split(strings.ReplaceAll(SetMethod(withSeq, "CANCEL"), "\r\n", "\n"), "\n"))
	out := make([]string, 0, len(lines)+1)
	inEvent := false
	statusSeen := false
	for _, line := range lines {
		name, val, ok := splitLine(line)
		if ok {
			base := strings.ToUpper(strings.Split(name, ";")[0])
			comp := strings.ToUpper(strings.TrimSpace(val))
			if base == "BEGIN" && comp == "VEVENT" {
				inEvent = true
			}
			if inEvent && base == "STATUS" {
				out = append(out, "STATUS:CANCELLED")
				statusSeen = true
				continue
			}
			if inEvent && base == "END" && comp == "VEVENT" {
				if !statusSeen {
					out = append(out, "STATUS:CANCELLED")
				}
				inEvent = false
			}
		}
		out = append(out, line)
	}
	return Normalize(strings.Join(out, "\r\n")), nil
}

func setSequence(raw string, seq int) string {
	lines := unfold(strings.Split(strings.ReplaceAll(Normalize(raw), "\r\n", "\n"), "\n"))
	out := make([]string, 0, len(lines)+1)
	inEvent := false
	seen := false
	for _, line := range lines {
		name, val, ok := splitLine(line)
		if ok {
			base := strings.ToUpper(strings.Split(name, ";")[0])
			comp := strings.ToUpper(strings.TrimSpace(val))
			if base == "BEGIN" && comp == "VEVENT" {
				inEvent = true
			}
			if inEvent && base == "SEQUENCE" {
				out = append(out, "SEQUENCE:"+strconv.Itoa(seq))
				seen = true
				continue
			}
			if inEvent && base == "END" && comp == "VEVENT" {
				if !seen {
					out = append(out, "SEQUENCE:"+strconv.Itoa(seq))
				}
				inEvent = false
			}
		}
		out = append(out, line)
	}
	return Normalize(strings.Join(out, "\r\n"))
}

func EscapeText(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, ";", "\\;")
	s = strings.ReplaceAll(s, ",", "\\,")
	return s
}

func escapeParam(s string) string {
	s = strings.ReplaceAll(s, `"`, `'`)
	return `"` + s + `"`
}

func unfold(lines []string) []string {
	out := []string{}
	for _, l := range lines {
		if len(out) > 0 && (strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t")) {
			out[len(out)-1] += strings.TrimLeft(l, " \t")
		} else {
			out = append(out, l)
		}
	}
	return out
}
func splitLine(l string) (string, string, bool) {
	i := strings.IndexByte(l, ':')
	if i < 1 {
		return "", "", false
	}
	return l[:i], l[i+1:], true
}
func unescape(s string) string {
	s = strings.ReplaceAll(s, "\\n", "\n")
	s = strings.ReplaceAll(s, "\\N", "\n")
	s = strings.ReplaceAll(s, "\\,", ",")
	s = strings.ReplaceAll(s, "\\;", ";")
	s = strings.ReplaceAll(s, "\\\\", "\\")
	return s
}
func parseTime(name, val string) (time.Time, error) {
	val = strings.TrimSpace(val)
	if strings.Contains(strings.ToUpper(name), "VALUE=DATE") || len(val) == 8 {
		return time.ParseInLocation("20060102", val, time.Local)
	}
	loc := time.Local
	up := strings.ToUpper(name)
	if i := strings.Index(up, "TZID="); i >= 0 {
		tz := name[i+5:]
		if j := strings.IndexByte(tz, ';'); j >= 0 {
			tz = tz[:j]
		}
		if l, e := time.LoadLocation(tz); e == nil {
			loc = l
		}
	}
	if strings.HasSuffix(val, "Z") {
		return time.Parse("20060102T150405Z", val)
	}
	return time.ParseInLocation("20060102T150405", val, loc)
}

// EventContentEqual compares the semantic VEVENT content while ignoring
// transport/server-maintained metadata such as DTSTAMP, LAST-MODIFIED,
// CREATED, SEQUENCE and ORGANIZER. Property ordering is ignored.
func EventContentEqual(a, b string) bool {
	aa := semanticEventTokens(a)
	bb := semanticEventTokens(b)
	if len(aa) != len(bb) {
		return false
	}
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

// SchedulingChangeKeys returns the attendee-visible categories changed between
// two VEVENTs. It deliberately ignores attendee response state (PARTSTAT/RSVP).
func SchedulingChangeKeys(oldRaw, newRaw string) ([]string, error) {
	oldM, err := Parse(oldRaw)
	if err != nil {
		return nil, err
	}
	newM, err := Parse(newRaw)
	if err != nil {
		return nil, err
	}
	keys := []string{}
	add := func(k string) {
		for _, v := range keys {
			if v == k {
				return
			}
		}
		keys = append(keys, k)
	}
	if oldM.Summary != newM.Summary {
		add("title")
	}
	if !sameTime(oldM.Start, newM.Start) {
		add("start")
	}
	if !sameTime(oldM.End, newM.End) {
		add("end")
	}
	if oldM.Location != newM.Location {
		add("location")
	}
	if oldM.Description != newM.Description {
		add("description")
	}
	if strings.Join(recurrenceTokens(oldRaw), "\n") != strings.Join(recurrenceTokens(newRaw), "\n") {
		add("recurrence")
	}
	if strings.Join(attendeeIdentityTokens(oldRaw), "\n") != strings.Join(attendeeIdentityTokens(newRaw), "\n") {
		add("attendees")
	}
	if strings.Join(schedulingTokens(oldRaw), "\n") != strings.Join(schedulingTokens(newRaw), "\n") && len(keys) == 0 {
		add("details")
	}
	return keys, nil
}

func SetSequence(raw string, sequence int) string {
	if sequence < 0 {
		sequence = 0
	}
	lines := unfold(strings.Split(strings.ReplaceAll(Normalize(raw), "\r\n", "\n"), "\n"))
	out := make([]string, 0, len(lines)+1)
	inEvent := false
	nested := 0
	seen := false
	for _, line := range lines {
		name, val, ok := splitLine(line)
		if !ok {
			out = append(out, line)
			continue
		}
		base := strings.ToUpper(strings.Split(name, ";")[0])
		comp := strings.ToUpper(strings.TrimSpace(val))
		if base == "BEGIN" {
			if comp == "VEVENT" && !inEvent {
				inEvent = true
				nested = 0
			} else if inEvent {
				nested++
			}
			out = append(out, line)
			continue
		}
		if base == "END" {
			if inEvent && nested > 0 {
				nested--
			} else if inEvent && comp == "VEVENT" {
				if !seen {
					out = append(out, "SEQUENCE:"+strconv.Itoa(sequence))
					seen = true
				}
				inEvent = false
			}
			out = append(out, line)
			continue
		}
		if inEvent && nested == 0 && base == "SEQUENCE" {
			if !seen {
				out = append(out, "SEQUENCE:"+strconv.Itoa(sequence))
				seen = true
			}
			continue
		}
		out = append(out, line)
	}
	return Normalize(strings.Join(out, "\r\n"))
}

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func semanticEventTokens(raw string) []string {
	return eventTokens(raw, map[string]bool{"DTSTAMP": true, "LAST-MODIFIED": true, "CREATED": true, "SEQUENCE": true, "ORGANIZER": true})
}
func schedulingTokens(raw string) []string {
	allowed := map[string]bool{"STATUS": true, "TRANSP": true, "URL": true, "GEO": true, "CLASS": true, "PRIORITY": true, "CATEGORIES": true, "ATTACH": true, "CONTACT": true}
	all := eventTokens(raw, nil)
	out := []string{}
	for _, t := range all {
		p := strings.SplitN(t, "|", 3)
		if len(p) == 3 && allowed[p[1]] {
			out = append(out, t)
		}
	}
	return out
}
func recurrenceTokens(raw string) []string {
	allowed := map[string]bool{"RRULE": true, "RDATE": true, "EXDATE": true, "EXRULE": true, "RECURRENCE-ID": true}
	all := eventTokens(raw, nil)
	out := []string{}
	for _, t := range all {
		p := strings.SplitN(t, "|", 3)
		if len(p) == 3 && allowed[p[1]] {
			out = append(out, t)
		}
	}
	return out
}
func attendeeIdentityTokens(raw string) []string {
	m, err := Parse(raw)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(m.AttendeeDetails))
	for _, a := range m.AttendeeDetails {
		out = append(out, strings.ToLower(strings.TrimSpace(a.Email))+"|"+strings.TrimSpace(a.CN))
	}
	sort.Strings(out)
	return out
}
func eventTokens(raw string, ignore map[string]bool) []string {
	lines := unfold(strings.Split(strings.ReplaceAll(Normalize(raw), "\r\n", "\n"), "\n"))
	out := []string{}
	inEvent := false
	nested := 0
	path := []string{}
	for _, line := range lines {
		name, val, ok := splitLine(line)
		if !ok {
			continue
		}
		base := strings.ToUpper(strings.Split(name, ";")[0])
		comp := strings.ToUpper(strings.TrimSpace(val))
		if base == "BEGIN" {
			if comp == "VEVENT" && !inEvent {
				inEvent = true
				nested = 0
				path = nil
			} else if inEvent {
				nested++
				path = append(path, comp)
			}
			continue
		}
		if base == "END" {
			if inEvent && nested > 0 {
				nested--
				if len(path) > 0 {
					path = path[:len(path)-1]
				}
			} else if inEvent && comp == "VEVENT" {
				inEvent = false
			}
			continue
		}
		if !inEvent {
			continue
		}
		if nested == 0 && ignore != nil && ignore[base] {
			continue
		}
		canon := canonicalPropertyName(name) + ":" + canonicalPropertyValue(base, val)
		out = append(out, strings.Join(path, "/")+"|"+base+"|"+canon)
	}
	sort.Strings(out)
	return out
}

func canonicalPropertyValue(base, value string) string {
	value = strings.TrimSpace(value)
	switch strings.ToUpper(strings.TrimSpace(base)) {
	case "RRULE", "EXRULE":
		parts := strings.Split(value, ";")
		items := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			key, val, found := strings.Cut(part, "=")
			if !found {
				items = append(items, strings.ToUpper(part))
				continue
			}
			key = strings.ToUpper(strings.TrimSpace(key))
			val = strings.TrimSpace(val)
			switch key {
			case "BYSECOND", "BYMINUTE", "BYHOUR", "BYDAY", "BYMONTHDAY", "BYYEARDAY", "BYWEEKNO", "BYMONTH", "BYSETPOS":
				values := strings.Split(val, ",")
				for i := range values {
					values[i] = strings.ToUpper(strings.TrimSpace(values[i]))
				}
				sort.Strings(values)
				val = strings.Join(values, ",")
			case "FREQ", "WKST":
				val = strings.ToUpper(val)
			}
			items = append(items, key+"="+val)
		}
		sort.Slice(items, func(i, j int) bool { return strings.ToUpper(items[i]) < strings.ToUpper(items[j]) })
		return strings.Join(items, ";")
	case "RDATE", "EXDATE", "CATEGORIES":
		parts := strings.Split(value, ",")
		items := make([]string, 0, len(parts))
		for _, part := range parts {
			if part = strings.TrimSpace(part); part != "" {
				items = append(items, part)
			}
		}
		sort.Slice(items, func(i, j int) bool { return strings.ToUpper(items[i]) < strings.ToUpper(items[j]) })
		return strings.Join(items, ",")
	default:
		return value
	}
}

func canonicalPropertyName(name string) string {
	parts := strings.Split(strings.TrimSpace(name), ";")
	if len(parts) == 0 {
		return ""
	}
	base := strings.ToUpper(strings.TrimSpace(parts[0]))
	params := make([]string, 0, len(parts)-1)
	for _, p := range parts[1:] {
		if v := strings.TrimSpace(p); v != "" {
			params = append(params, v)
		}
	}
	sort.Slice(params, func(i, j int) bool { return strings.ToUpper(params[i]) < strings.ToUpper(params[j]) })
	if len(params) == 0 {
		return base
	}
	return base + ";" + strings.Join(params, ";")
}
