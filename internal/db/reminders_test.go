package db

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type reminderRow struct {
	id  string
	err error
}

func (r reminderRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*string)) = r.id
	return nil
}

type reminderStoreSpy struct {
	id             string
	lookupCount    int
	calendarArgs   []any
	membershipArgs []any
	calendarCalls  int
	memberCalls    int
}

func (s *reminderStoreSpy) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	if len(args) != 1 || query == "" {
		return reminderRow{err: errors.New("unexpected lookup")}
	}
	s.lookupCount++
	if s.id == "" {
		return reminderRow{err: pgx.ErrNoRows}
	}
	return reminderRow{id: s.id}
}

func (s *reminderStoreSpy) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	switch query {
	case remindersCalendarInsertSQL:
		s.calendarCalls++
		s.calendarArgs = append([]any(nil), args...)
		if len(args) == 3 {
			s.id, _ = args[0].(string)
		}
	case remindersMembershipUpsertSQL:
		s.memberCalls++
		s.membershipArgs = append([]any(nil), args...)
	default:
		return pgconn.CommandTag{}, errors.New("unexpected write")
	}
	return pgconn.CommandTag{}, nil
}

func TestEnsureRemindersFreshAndRepeated(t *testing.T) {
	ctx := context.Background()
	userID := "6d5687e3-3cda-478a-9c53-9353f8aa9288"
	s := &reminderStoreSpy{}
	id, err := EnsureReminders(ctx, s, userID)
	if err != nil {
		t.Fatal(err)
	}
	if s.calendarCalls != 1 || s.memberCalls != 1 || s.lookupCount != 2 {
		t.Fatalf("fresh list flow: %d inserts, %d memberships, %d lookups", s.calendarCalls, s.memberCalls, s.lookupCount)
	}
	want := []any{id, userID, id}
	if !reflect.DeepEqual(s.calendarArgs, want) || !reflect.DeepEqual(s.membershipArgs, want) {
		t.Fatalf("UUID and DAV name must bind separately: calendars=%v memberships=%v want=%v", s.calendarArgs, s.membershipArgs, want)
	}
	secondID, err := EnsureReminders(ctx, s, userID)
	if err != nil || secondID != id || s.calendarCalls != 1 || s.memberCalls != 2 {
		t.Fatalf("repeated discovery changed the list: id=%q err=%v inserts=%d memberships=%d", secondID, err, s.calendarCalls, s.memberCalls)
	}
}

func TestReminderSQLSeparatesUUIDAndTextParameters(t *testing.T) {
	if !strings.Contains(remindersCalendarInsertSQL, "'reminders',$2,$3") {
		t.Fatal("calendar insert must bind dav_name separately")
	}
	if !strings.Contains(remindersMembershipUpsertSQL, "'owner',$3)") {
		t.Fatal("membership insert must bind dav_name separately")
	}
}
