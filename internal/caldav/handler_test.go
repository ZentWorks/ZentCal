package caldav

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zentworks/zentcal/internal/app"
	"github.com/zentworks/zentcal/internal/auth"
)

func TestWellKnownRedirectUsesDAVContextPath(t *testing.T) {
	mux := http.NewServeMux()
	(&Handler{}).Register(mux)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PROPFIND", "/.well-known/caldav", nil)
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusTemporaryRedirect)
	}
	if got := rr.Header().Get("Location"); got != "/dav/" {
		t.Fatalf("location=%q", got)
	}
	if !strings.Contains(rr.Header().Get("DAV"), "calendar-access") {
		t.Fatalf("DAV header=%q", rr.Header().Get("DAV"))
	}
}

func TestDavWithoutTrailingSlashPreservesMethodVia307(t *testing.T) {
	mux := http.NewServeMux()
	(&Handler{}).Register(mux)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PROPFIND", "/dav", nil)
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusTemporaryRedirect || rr.Header().Get("Location") != "/dav/" {
		t.Fatalf("status=%d location=%q", rr.Code, rr.Header().Get("Location"))
	}
}

func TestRootDiscoveryPropertiesContainPrincipal(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PROPFIND", "/dav/", strings.NewReader(`<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/><d:principal-URL/><d:principal-collection-set/></d:prop></d:propfind>`))
	h.root(rr, req, auth.User{ID: "11111111-1111-1111-1111-111111111111", Name: "Test", Email: "test@example.com"})
	if rr.Code != http.StatusMultiStatus {
		t.Fatalf("status=%d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"current-user-principal", "principal-URL", "principal-collection-set", "/dav/principals/11111111-1111-1111-1111-111111111111/"} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %q: %s", want, body)
		}
	}
	assertValidXML(t, body)
}

func TestPrincipalDiscoveryContainsCalendarHomeAndPrivileges(t *testing.T) {
	h := &Handler{}
	u := auth.User{ID: "11111111-1111-1111-1111-111111111111", Name: "Test", Email: "test@example.com"}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PROPFIND", principalURL(u.ID), strings.NewReader(`<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-home-set/><c:calendar-user-address-set/><c:schedule-inbox-URL/><c:schedule-outbox-URL/><d:current-user-privilege-set/></d:prop></d:propfind>`))
	h.principal(rr, req, u, []string{"dav", "principals", u.ID})
	if rr.Code != http.StatusMultiStatus {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{calendarHomeURL(u.ID), "mailto:test@example.com", inboxURL(u.ID), outboxURL(u.ID), "current-user-privilege-set"} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %q: %s", want, body)
		}
	}
	assertValidXML(t, body)
}

func TestRequestedUnknownPropertyGets404Propstat(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PROPFIND", "/dav/", strings.NewReader(`<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:x="urn:example"><d:prop><d:displayname/><x:nope/></d:prop></d:propfind>`))
	h.root(rr, req, auth.User{ID: "u", Name: "Test", Email: "test@example.com"})
	body := rr.Body.String()
	if !strings.Contains(body, "200 OK") || !strings.Contains(body, "404 Not Found") || !strings.Contains(body, "nope") {
		t.Fatalf("expected mixed propstats: %s", body)
	}
	assertValidXML(t, body)
}

func TestCalendarPropertiesAdvertiseAppleAndSyncSupport(t *testing.T) {
	u := auth.User{ID: "u"}
	c := app.Calendar{ID: "c", Name: "Team", Color: "#4f8cff", Role: "contributor", UpdatedAt: time.Unix(1700000000, 0)}
	pr := propRequest{Names: []xml.Name{{Space: nsDAV, Local: "resourcetype"}, {Space: nsApple, Local: "calendar-color"}, {Space: nsCS, Local: "getctag"}, {Space: nsDAV, Local: "sync-token"}, {Space: nsDAV, Local: "supported-report-set"}}}
	body := `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav" xmlns:a="http://apple.com/ns/ical/" xmlns:cs="http://calendarserver.org/ns/">` + propResponse(calendarURL(u.ID, c.ID), pr, calendarProps(u, c)) + `</d:multistatus>`
	for _, want := range []string{"calendar-color", "#4F8CFFFF", "getctag", "sync-token", "calendar-query", "calendar-multiget", "sync-collection"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q: %s", want, body)
		}
	}
	assertValidXML(t, body)
}

func TestCalendarAllPropertiesAreWellFormedXML(t *testing.T) {
	u := auth.User{ID: "u"}
	c := app.Calendar{ID: "c", Name: "Team & Ops", Color: "#4f8cff", Role: "owner", UpdatedAt: time.Unix(1700000000, 0)}
	body := `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav" xmlns:a="http://apple.com/ns/ical/" xmlns:cs="http://calendarserver.org/ns/">` + propResponse(calendarURL(u.ID, c.ID), propRequest{All: true}, calendarProps(u, c)) + `</d:multistatus>`
	assertValidXML(t, body)
	for _, want := range []string{"supported-privilege-set", "supported-collation-set", "free-busy-query", "calendar-access"} {
		if want == "calendar-access" {
			continue
		}
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q: %s", want, body)
		}
	}
}

func TestParseCalendarMultigetReport(t *testing.T) {
	body := []byte(`<?xml version="1.0"?><c:calendar-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/><c:calendar-data/></d:prop><d:href>/dav/calendars/u/c/one.ics</d:href></c:calendar-multiget>`)
	name, pr, err := parseReport(body)
	if err != nil {
		t.Fatal(err)
	}
	if name != "calendar-multiget" || len(pr.Names) != 2 {
		t.Fatalf("name=%q props=%v", name, pr.Names)
	}
	hrefs := extractHrefs(body)
	if !hrefs["/dav/calendars/u/c/one.ics"] || !hrefs["one.ics"] {
		t.Fatalf("hrefs=%v", hrefs)
	}
}

func TestParseAppleStyleCalendarQueryTimeRange(t *testing.T) {
	body := []byte(`<?xml version="1.0"?><c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/><c:calendar-data/></d:prop><c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VEVENT"><c:time-range start="20261001T000000Z" end="20261101T000000Z"/></c:comp-filter></c:comp-filter></c:filter></c:calendar-query>`)
	start, end, ok := extractTimeRange(body)
	if !ok || start.UTC().Format("20060102T150405Z") != "20261001T000000Z" || end.UTC().Format("20060102T150405Z") != "20261101T000000Z" {
		t.Fatalf("start=%v end=%v ok=%v", start, end, ok)
	}
}

func TestOptionsAdvertisesCalDAVWithoutAuthentication(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/dav/", nil)
	h.serve(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rr.Code)
	}
	for _, token := range []string{"calendar-access", "calendar-auto-schedule", "sync-collection"} {
		if !strings.Contains(rr.Header().Get("DAV"), token) {
			t.Fatalf("DAV header=%q missing=%q", rr.Header().Get("DAV"), token)
		}
	}
}

func TestUnauthorizedHTTPAdvertisesDigestWithoutBasic(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PROPFIND", "http://example.test/dav/", nil)
	h.unauthorized(rr, req, false)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
	values := rr.Header().Values("WWW-Authenticate")
	joined := strings.Join(values, " | ")
	if !strings.Contains(joined, `Digest realm="ZentCal"`) || !strings.Contains(joined, `qop="auth"`) {
		t.Fatalf("challenge=%q", joined)
	}
	if strings.Contains(joined, `Basic realm=`) {
		t.Fatalf("plain HTTP must not advertise Basic: %q", joined)
	}
}

func TestUnauthorizedHTTPSAdvertisesDigestAndBasic(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PROPFIND", "https://example.test/dav/", nil)
	h.unauthorized(rr, req, false)
	joined := strings.Join(rr.Header().Values("WWW-Authenticate"), " | ")
	if !strings.Contains(joined, `Digest realm="ZentCal"`) || !strings.Contains(joined, `Basic realm="ZentCal"`) {
		t.Fatalf("challenge=%q", joined)
	}
}

func TestDigestResponseMatchesRFCExample(t *testing.T) {
	d := map[string]string{
		"nonce":  "dcd98b7102dd2f0e8b11d0f600bfb0c093",
		"nc":     "00000001",
		"cnonce": "0a4f113b",
		"qop":    "auth",
		"uri":    "/dir/index.html",
	}
	if got := digestResponse("939e7578ed9e3c518a452acee763bce9", "GET", d); got != "6629fae49393a05397450978507c4ef1" {
		t.Fatalf("response=%s", got)
	}
}

func TestDigestNonceRoundTripAndReplay(t *testing.T) {
	h := &Handler{}
	nonce := h.newNonce()
	if ok, stale := h.validateNonce(nonce); !ok || stale {
		t.Fatalf("nonce valid=%v stale=%v", ok, stale)
	}
	if h.replayed("u", nonce, "c", "00000001", false) {
		t.Fatal("fresh digest request marked as replay")
	}
	h.replayed("u", nonce, "c", "00000001", true)
	if !h.replayed("u", nonce, "c", "00000001", false) {
		t.Fatal("replayed digest request not detected")
	}
}

func TestParseDigestAuthorization(t *testing.T) {
	d, err := parseDigestAuthorization(`Digest username="user@example.com", realm="ZentCal", nonce="abc", uri="/dav/", response="deadbeef", algorithm=MD5, qop=auth, nc=00000001, cnonce="xyz"`)
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"username": "user@example.com", "realm": "ZentCal", "uri": "/dav/", "nc": "00000001", "cnonce": "xyz"} {
		if d[k] != want {
			t.Fatalf("%s=%q want=%q", k, d[k], want)
		}
	}
}

func assertValidXML(t *testing.T, body string) {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(body))
	for {
		_, err := dec.Token()
		if err == nil {
			continue
		}
		if err.Error() == "EOF" {
			return
		}
		t.Fatalf("invalid XML: %v\n%s", err, body)
	}
}

type fakeDAVAuth struct {
	user auth.User
	ha1  string
}

func (f *fakeDAVAuth) AuthenticateDAV(ctx context.Context, username, password, source string) (auth.User, error) {
	return auth.User{}, errors.New("basic disabled in test")
}

func (f *fakeDAVAuth) AuthenticateDAVDigest(ctx context.Context, username, source string, verify func(string) bool) (auth.User, error) {
	if username == strings.ToLower(f.user.Email) && verify(f.ha1) {
		return f.user, nil
	}
	return auth.User{}, errors.New("invalid credentials")
}

func TestPlainHTTPDigestHandshakeReachesDAVRoot(t *testing.T) {
	u := auth.User{ID: "11111111-1111-1111-1111-111111111111", Name: "Test", Email: "user@example.com"}
	h := &Handler{Auth: &fakeDAVAuth{user: u, ha1: digestHA1ForTest(u.Email, auth.DAVRealm, "secret-password")}}

	body := `<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>`
	first := httptest.NewRecorder()
	req1 := httptest.NewRequest("PROPFIND", "http://example.test/dav/", strings.NewReader(body))
	h.serve(first, req1)
	if first.Code != http.StatusUnauthorized {
		t.Fatalf("first status=%d", first.Code)
	}
	challenge := first.Header().Get("WWW-Authenticate")
	d, err := parseDigestAuthorization(challenge)
	if err != nil {
		t.Fatalf("challenge parse: %v (%q)", err, challenge)
	}
	d["username"] = u.Email
	d["uri"] = "/dav/"
	d["qop"] = "auth"
	d["nc"] = "00000001"
	d["cnonce"] = "clientnonce"
	d["response"] = digestResponse(digestHA1ForTest(u.Email, auth.DAVRealm, "secret-password"), "PROPFIND", d)
	authorization := `Digest username="` + u.Email + `", realm="` + d["realm"] + `", nonce="` + d["nonce"] + `", uri="/dav/", response="` + d["response"] + `", algorithm=MD5, qop=auth, nc=00000001, cnonce="clientnonce", opaque="zentcal-dav"`

	second := httptest.NewRecorder()
	req2 := httptest.NewRequest("PROPFIND", "http://example.test/dav/", strings.NewReader(body))
	req2.Header.Set("Authorization", authorization)
	h.serve(second, req2)
	if second.Code != http.StatusMultiStatus {
		t.Fatalf("second status=%d body=%s", second.Code, second.Body.String())
	}
	if !strings.Contains(second.Body.String(), "current-user-principal") {
		t.Fatalf("missing DAV discovery response: %s", second.Body.String())
	}
}

func digestHA1ForTest(username, realm, password string) string {
	s := md5.Sum([]byte(username + ":" + realm + ":" + password))
	return hex.EncodeToString(s[:])
}

func TestSchedulingOutboxAdvertisesAppleCompatiblePrivileges(t *testing.T) {
	body := `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:response><d:propstat><d:prop>` +
		schedulingPrivilegeSet("outbox") + schedulingSupportedPrivilegeSet("outbox") + schedulingACL("u", "outbox") +
		`</d:prop></d:propstat></d:response></d:multistatus>`
	for _, want := range []string{
		"schedule-send", "schedule-send-invite", "schedule-send-reply", "schedule-send-freebusy", "schedule-post-vevent",
		"read-current-user-privilege-set", "<d:acl>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("outbox scheduling properties missing %q: %s", want, body)
		}
	}
	assertValidXML(t, body)
}

func TestSchedulingInboxAdvertisesCalendarReports(t *testing.T) {
	body := schedulingSupportedReports("inbox")
	for _, want := range []string{"calendar-query", "calendar-multiget"} {
		if !strings.Contains(body, want) {
			t.Fatalf("inbox report set missing %q: %s", want, body)
		}
	}
	wrapped := `<?xml version="1.0"?><d:prop xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">` + body + `</d:prop>`
	assertValidXML(t, wrapped)
}

func TestCalendarPropertiesAdvertiseSchedulingTransparency(t *testing.T) {
	u := auth.User{ID: "u"}
	c := app.Calendar{ID: "c", Name: "Team", Description: "Shared", Color: "#4f8cff", Role: "contributor", UpdatedAt: time.Unix(1700000000, 0)}
	pr := propRequest{Names: []xml.Name{{Space: nsCal, Local: "calendar-description"}, {Space: nsCal, Local: "schedule-calendar-transp"}}}
	body := `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">` + propResponse(calendarURL(u.ID, c.ID), pr, calendarProps(u, c)) + `</d:multistatus>`
	for _, want := range []string{"calendar-description", "Shared", "schedule-calendar-transp", "opaque"} {
		if !strings.Contains(body, want) {
			t.Fatalf("calendar scheduling property missing %q: %s", want, body)
		}
	}
	assertValidXML(t, body)
}

func TestOptionsAdvertisesAutoScheduleAndMKCalendar(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/dav/calendars/u/", nil)
	h.serve(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rr.Code)
	}
	dav := rr.Header().Get("DAV")
	if !strings.Contains(dav, "calendar-auto-schedule") {
		t.Fatalf("DAV header=%q missing calendar-auto-schedule", dav)
	}
	if strings.Contains(dav, "calendar-schedule") {
		t.Fatalf("DAV header still advertises obsolete calendar-schedule token: %q", dav)
	}
	if !strings.Contains(rr.Header().Get("Allow"), "MKCALENDAR") {
		t.Fatalf("Allow header=%q missing MKCALENDAR", rr.Header().Get("Allow"))
	}
}

func TestParseAppleMKCalendarProperties(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="utf-8"?>
<c:mkcalendar xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav" xmlns:a="http://apple.com/ns/ical/">
  <d:set><d:prop>
    <d:displayname>Privat</d:displayname>
    <c:calendar-description>Mein Kalender</c:calendar-description>
    <a:calendar-color>#12AABBFF</a:calendar-color>
    <c:supported-calendar-component-set><c:comp name="VEVENT"/></c:supported-calendar-component-set>
    <c:calendar-timezone><![CDATA[BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VTIMEZONE
TZID:Europe/Berlin
END:VTIMEZONE
END:VCALENDAR]]></c:calendar-timezone>
  </d:prop></d:set>
</c:mkcalendar>`)
	p, err := parseMKCalendar(body)
	if err != nil {
		t.Fatal(err)
	}
	if p.DisplayName != "Privat" || p.Description != "Mein Kalender" || p.Color != "#12AABBFF" {
		t.Fatalf("unexpected properties: %+v", p)
	}
	if len(p.Components) != 1 || p.Components[0] != "VEVENT" {
		t.Fatalf("components=%v", p.Components)
	}
	if !strings.Contains(p.Timezone, "TZID:Europe/Berlin") {
		t.Fatalf("timezone=%q", p.Timezone)
	}
}

func TestParseMKCalendarRejectsWrongRoot(t *testing.T) {
	_, err := parseMKCalendar([]byte(`<d:propfind xmlns:d="DAV:"/>`))
	if err == nil {
		t.Fatal("expected wrong root to fail")
	}
}

func TestCalendarHrefUsesDAVCollectionName(t *testing.T) {
	c := app.Calendar{ID: "11111111-1111-1111-1111-111111111111", DAVName: "91307E84-BB63-45B6-8D79-22B5A2957DE7"}
	got := calendarHref("user", c)
	want := "/dav/calendars/user/91307E84-BB63-45B6-8D79-22B5A2957DE7/"
	if got != want {
		t.Fatalf("href=%q want=%q", got, want)
	}
}
