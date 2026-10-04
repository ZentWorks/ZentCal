package caldav

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zentworks/zentcal/internal/app"
	"github.com/zentworks/zentcal/internal/auth"
	"github.com/zentworks/zentcal/internal/db"
	"github.com/zentworks/zentcal/internal/ical"
	"github.com/zentworks/zentcal/internal/scheduling"
)

const (
	nsDAV   = "DAV:"
	nsCal   = "urn:ietf:params:xml:ns:caldav"
	nsApple = "http://apple.com/ns/ical/"
	nsCS    = "http://calendarserver.org/ns/"
)

type DAVAuthenticator interface {
	AuthenticateDAV(ctx context.Context, username, password, source string) (auth.User, error)
	AuthenticateDAVDigest(ctx context.Context, username, source string, verify func(string) bool) (auth.User, error)
}

type Handler struct {
	App        *app.Service
	Auth       DAVAuthenticator
	Scheduling *scheduling.Service

	nonceOnce   sync.Once
	nonceSecret []byte
	nonceMu     sync.Mutex
	replay      map[string]time.Time
}

type propRequest struct {
	All      bool
	PropName bool
	Names    []xml.Name
}

type propValue struct {
	Name xml.Name
	XML  string
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/caldav", h.wellKnown)
	mux.HandleFunc("/.well-known/webdav", h.wellKnown)
	mux.HandleFunc("/dav", func(w http.ResponseWriter, r *http.Request) {
		setDAVHeaders(w)
		http.Redirect(w, r, "/dav/", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/dav/", h.serve)
}

func (h *Handler) wellKnown(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("DAV", "1, access-control, calendar-access, calendar-auto-schedule, sync-collection")
	http.Redirect(w, r, "/dav/", http.StatusTemporaryRedirect)
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	setDAVHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	u, ok := h.user(w, r)
	if !ok {
		return
	}

	parts := splitPath(r.URL.Path)
	if len(parts) == 0 || parts[0] != "dav" {
		http.NotFound(w, r)
		return
	}

	if len(parts) == 1 { // /dav/
		h.root(w, r, u)
		return
	}

	switch parts[1] {
	case "principals":
		h.principal(w, r, u, parts)
	case "calendars":
		h.calendars(w, r, u, parts)
	case "inbox", "outbox":
		h.schedulingCollection(w, r, u, parts)
	default:
		http.NotFound(w, r)
	}
}

func setDAVHeaders(w http.ResponseWriter) {
	w.Header().Set("DAV", "1, access-control, calendar-access, calendar-auto-schedule, sync-collection")
	w.Header().Set("Allow", "OPTIONS, PROPFIND, REPORT, GET, HEAD, PUT, DELETE, PROPPATCH, MKCALENDAR, ACL, POST")
	w.Header().Set("MS-Author-Via", "DAV")
	w.Header().Set("Cache-Control", "no-store")
}

func (h *Handler) user(w http.ResponseWriter, r *http.Request) (auth.User, bool) {
	h.initDigest()
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(header), "digest ") {
		d, err := parseDigestAuthorization(header)
		if err != nil || !strings.EqualFold(d["realm"], auth.DAVRealm) || !strings.EqualFold(d["qop"], "auth") || (d["algorithm"] != "" && !strings.EqualFold(d["algorithm"], "MD5")) {
			h.unauthorized(w, r, false)
			return auth.User{}, false
		}
		if d["username"] == "" || d["nonce"] == "" || d["uri"] == "" || d["response"] == "" || d["cnonce"] == "" || d["nc"] == "" || (d["opaque"] != "" && d["opaque"] != "zentcal-dav") {
			h.unauthorized(w, r, false)
			return auth.User{}, false
		}
		if len(d["nc"]) != 8 {
			h.unauthorized(w, r, false)
			return auth.User{}, false
		}
		if _, err := strconv.ParseUint(d["nc"], 16, 32); err != nil {
			h.unauthorized(w, r, false)
			return auth.User{}, false
		}
		if !sameDigestURI(d["uri"], r.URL.RequestURI()) {
			h.unauthorized(w, r, false)
			return auth.User{}, false
		}
		validNonce, stale := h.validateNonce(d["nonce"])
		if !validNonce {
			h.unauthorized(w, r, stale)
			return auth.User{}, false
		}
		if h.replayed(d["username"], d["nonce"], d["cnonce"], d["nc"], false) {
			h.unauthorized(w, r, false)
			return auth.User{}, false
		}
		username := normalizeDAVUsername(d["username"])
		u, err := h.Auth.AuthenticateDAVDigest(r.Context(), username, auth.ClientIP(r), func(ha1 string) bool {
			return hmac.Equal([]byte(strings.ToLower(digestResponse(ha1, r.Method, d))), []byte(strings.ToLower(d["response"])))
		})
		if err != nil {
			h.unauthorized(w, r, false)
			return auth.User{}, false
		}
		h.replayed(d["username"], d["nonce"], d["cnonce"], d["nc"], true)
		return u, true
	}

	// Basic is only offered when ZentCal itself receives TLS. Behind a TLS-terminating
	// reverse proxy clients can use Digest; the application does not blindly trust
	// forwarded scheme headers. Plain HTTP never receives a Basic challenge.
	if isSecureRequest(r) && strings.HasPrefix(strings.ToLower(header), "basic ") {
		name, pass, ok := r.BasicAuth()
		if ok {
			u, err := h.Auth.AuthenticateDAV(r.Context(), normalizeDAVUsername(name), pass, auth.ClientIP(r))
			if err == nil {
				return u, true
			}
		}
	}
	h.unauthorized(w, r, false)
	return auth.User{}, false
}

func normalizeDAVUsername(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(strings.ToLower(v), "mailto:")
	return v
}

func isSecureRequest(r *http.Request) bool {
	return r.TLS != nil
}

func (h *Handler) unauthorized(w http.ResponseWriter, r *http.Request, stale bool) {
	challenge := `Digest realm="` + auth.DAVRealm + `", nonce="` + h.newNonce() + `", opaque="zentcal-dav", algorithm=MD5, qop="auth", charset=UTF-8`
	if stale {
		challenge += `, stale=true`
	}
	w.Header().Add("WWW-Authenticate", challenge)
	if isSecureRequest(r) {
		w.Header().Add("WWW-Authenticate", `Basic realm="ZentCal", charset="UTF-8"`)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, "Unauthorized")
}

func (h *Handler) initDigest() {
	h.nonceOnce.Do(func() {
		h.nonceSecret = make([]byte, 32)
		if _, err := rand.Read(h.nonceSecret); err != nil {
			panic("caldav: cannot initialize digest nonce secret")
		}
		h.replay = make(map[string]time.Time)
	})
}

func (h *Handler) newNonce() string {
	h.initDigest()
	random := make([]byte, 12)
	_, _ = rand.Read(random)
	raw := strconv.FormatInt(time.Now().Unix(), 10) + ":" + base64.RawURLEncoding.EncodeToString(random)
	mac := hmac.New(sha256.New, h.nonceSecret)
	_, _ = mac.Write([]byte(raw))
	return base64.RawURLEncoding.EncodeToString([]byte(raw + ":" + hex.EncodeToString(mac.Sum(nil))))
}

func (h *Handler) validateNonce(nonce string) (bool, bool) {
	h.initDigest()
	decoded, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return false, false
	}
	parts := strings.Split(string(decoded), ":")
	if len(parts) != 3 {
		return false, false
	}
	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false, false
	}
	raw := parts[0] + ":" + parts[1]
	mac := hmac.New(sha256.New, h.nonceSecret)
	_, _ = mac.Write([]byte(raw))
	want, err := hex.DecodeString(parts[2])
	if err != nil || !hmac.Equal(want, mac.Sum(nil)) {
		return false, false
	}
	age := time.Since(time.Unix(ts, 0))
	if age < -30*time.Second || age > 5*time.Minute {
		return false, true
	}
	return true, false
}

func (h *Handler) replayed(username, nonce, cnonce, nc string, mark bool) bool {
	h.nonceMu.Lock()
	defer h.nonceMu.Unlock()
	now := time.Now()
	for k, expiry := range h.replay {
		if now.After(expiry) {
			delete(h.replay, k)
		}
	}
	key := username + "\x00" + nonce + "\x00" + cnonce + "\x00" + strings.ToLower(nc)
	if _, ok := h.replay[key]; ok {
		return true
	}
	if mark {
		h.replay[key] = now.Add(6 * time.Minute)
	}
	return false
}

func parseDigestAuthorization(header string) (map[string]string, error) {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(header)), "digest ") {
		return nil, errors.New("not digest")
	}
	s := strings.TrimSpace(strings.TrimSpace(header)[7:])
	out := make(map[string]string)
	for len(s) > 0 {
		s = strings.TrimLeft(s, " ,\t")
		if s == "" {
			break
		}
		eq := strings.IndexByte(s, '=')
		if eq <= 0 {
			return nil, errors.New("invalid digest parameter")
		}
		key := strings.ToLower(strings.TrimSpace(s[:eq]))
		s = strings.TrimSpace(s[eq+1:])
		var value string
		if strings.HasPrefix(s, `"`) {
			s = s[1:]
			var b strings.Builder
			escaped := false
			found := false
			for i, r := range s {
				if escaped {
					b.WriteRune(r)
					escaped = false
					continue
				}
				if r == '\\' {
					escaped = true
					continue
				}
				if r == '"' {
					value = b.String()
					s = s[i+1:]
					found = true
					break
				}
				b.WriteRune(r)
			}
			if !found {
				return nil, errors.New("unterminated digest value")
			}
		} else {
			comma := strings.IndexByte(s, ',')
			if comma < 0 {
				value, s = strings.TrimSpace(s), ""
			} else {
				value, s = strings.TrimSpace(s[:comma]), s[comma+1:]
			}
		}
		out[key] = value
		s = strings.TrimLeft(s, " ,\t")
	}
	return out, nil
}

func digestResponse(ha1, method string, d map[string]string) string {
	ha2sum := md5.Sum([]byte(method + ":" + d["uri"]))
	ha2 := hex.EncodeToString(ha2sum[:])
	sum := md5.Sum([]byte(ha1 + ":" + d["nonce"] + ":" + d["nc"] + ":" + d["cnonce"] + ":" + d["qop"] + ":" + ha2))
	return hex.EncodeToString(sum[:])
}

func sameDigestURI(got, want string) bool {
	if got == want {
		return true
	}
	u, err := url.Parse(got)
	return err == nil && u.IsAbs() && u.RequestURI() == want
}

func (h *Handler) root(w http.ResponseWriter, r *http.Request, u auth.User) {
	switch r.Method {
	case "PROPFIND":
		pr, err := parsePropfind(r)
		if err != nil {
			writeDAVError(w, http.StatusBadRequest, "valid-xml")
			return
		}
		principal := principalURL(u.ID)
		available := []propValue{
			pv(nsDAV, "resourcetype", `<d:resourcetype><d:collection/></d:resourcetype>`),
			pv(nsDAV, "displayname", `<d:displayname>ZentCal</d:displayname>`),
			pv(nsDAV, "current-user-principal", `<d:current-user-principal><d:href>`+x(principal)+`</d:href></d:current-user-principal>`),
			pv(nsDAV, "principal-URL", `<d:principal-URL><d:href>`+x(principal)+`</d:href></d:principal-URL>`),
			pv(nsDAV, "principal-collection-set", `<d:principal-collection-set><d:href>/dav/principals/</d:href></d:principal-collection-set>`),
			pv(nsDAV, "supported-report-set", supportedReports(false)),
		}
		writeMulti(w, []string{propResponse("/dav/", pr, available)}, "")
	case http.MethodGet, http.MethodHead:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, "ZentCal CalDAV")
		}
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) principal(w http.ResponseWriter, r *http.Request, u auth.User, parts []string) {
	if r.Method != "PROPFIND" {
		methodNotAllowed(w)
		return
	}
	pr, err := parsePropfind(r)
	if err != nil {
		writeDAVError(w, http.StatusBadRequest, "valid-xml")
		return
	}

	// /dav/principals/ is intentionally privacy-preserving: authenticated users
	// only discover their own principal.
	if len(parts) == 2 {
		available := []propValue{
			pv(nsDAV, "resourcetype", `<d:resourcetype><d:collection/></d:resourcetype>`),
			pv(nsDAV, "displayname", `<d:displayname>Principals</d:displayname>`),
		}
		res := []string{propResponse("/dav/principals/", pr, available)}
		if depth(r) != "0" {
			res = append(res, propResponse(principalURL(u.ID), pr, h.principalProps(u)))
		}
		writeMulti(w, res, "")
		return
	}

	if len(parts) != 3 || parts[2] != u.ID {
		http.NotFound(w, r)
		return
	}
	writeMulti(w, []string{propResponse(principalURL(u.ID), pr, h.principalProps(u))}, "")
}

func (h *Handler) principalProps(u auth.User) []propValue {
	p := principalURL(u.ID)
	return []propValue{
		pv(nsDAV, "resourcetype", `<d:resourcetype><d:principal/></d:resourcetype>`),
		pv(nsDAV, "displayname", `<d:displayname>`+x(u.Name)+`</d:displayname>`),
		pv(nsDAV, "current-user-principal", `<d:current-user-principal><d:href>`+x(p)+`</d:href></d:current-user-principal>`),
		pv(nsDAV, "principal-URL", `<d:principal-URL><d:href>`+x(p)+`</d:href></d:principal-URL>`),
		pv(nsDAV, "principal-collection-set", `<d:principal-collection-set><d:href>/dav/principals/</d:href></d:principal-collection-set>`),
		pv(nsCal, "calendar-home-set", `<c:calendar-home-set><d:href>`+x(calendarHomeURL(u.ID))+`</d:href></c:calendar-home-set>`),
		pv(nsCal, "calendar-user-address-set", `<c:calendar-user-address-set><d:href>mailto:`+x(u.Email)+`</d:href><d:href>`+x(p)+`</d:href></c:calendar-user-address-set>`),
		pv(nsCal, "schedule-inbox-URL", `<c:schedule-inbox-URL><d:href>`+x(inboxURL(u.ID))+`</d:href></c:schedule-inbox-URL>`),
		pv(nsCal, "schedule-outbox-URL", `<c:schedule-outbox-URL><d:href>`+x(outboxURL(u.ID))+`</d:href></c:schedule-outbox-URL>`),
		pv(nsCal, "calendar-user-type", `<c:calendar-user-type>INDIVIDUAL</c:calendar-user-type>`),
		pv(nsCS, "email-address-set", `<cs:email-address-set><cs:email-address>`+x(u.Email)+`</cs:email-address></cs:email-address-set>`),
		pv(nsDAV, "resource-id", `<d:resource-id><d:href>urn:uuid:`+x(u.ID)+`</d:href></d:resource-id>`),
		pv(nsDAV, "current-user-privilege-set", privilegeSet("owner")),
		pv(nsDAV, "acl", aclProperty(u.ID, "owner")),
		pv(nsDAV, "acl-restrictions", `<d:acl-restrictions><d:no-invert/></d:acl-restrictions>`),
		pv(nsDAV, "supported-privilege-set", supportedPrivilegeSet()),
		pv(nsDAV, "supported-report-set", supportedReports(false)),
	}
}

func (h *Handler) calendars(w http.ResponseWriter, r *http.Request, u auth.User, parts []string) {
	if len(parts) < 3 || parts[2] != u.ID {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 3 {
		h.calendarHome(w, r, u)
		return
	}

	calName, err := url.PathUnescape(parts[3])
	if err != nil || calName == "" || strings.Contains(calName, "/") {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 4 && r.Method == "MKCALENDAR" {
		h.mkCalendar(w, r, u, calName)
		return
	}
	c, err := h.App.GetCalendarByDAVName(r.Context(), u, calName)
	if err != nil || !c.CanReadEvents {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 4 {
		h.calendarCollection(w, r, u, c)
		return
	}
	if len(parts) != 5 {
		http.NotFound(w, r)
		return
	}
	h.eventResource(w, r, u, c, parts[4])
}

func (h *Handler) calendarHome(w http.ResponseWriter, r *http.Request, u auth.User) {
	if r.Method != "PROPFIND" {
		methodNotAllowed(w)
		return
	}
	pr, err := parsePropfind(r)
	if err != nil {
		writeDAVError(w, http.StatusBadRequest, "valid-xml")
		return
	}
	cs, err := h.App.ListCalendars(r.Context(), u)
	if err != nil {
		writeDAVError(w, http.StatusInternalServerError, "server-error")
		return
	}
	home := calendarHomeURL(u.ID)
	res := []string{propResponse(home, pr, []propValue{
		pv(nsDAV, "resourcetype", `<d:resourcetype><d:collection/></d:resourcetype>`),
		pv(nsDAV, "displayname", `<d:displayname>Calendars</d:displayname>`),
		pv(nsDAV, "owner", `<d:owner><d:href>`+x(principalURL(u.ID))+`</d:href></d:owner>`),
		pv(nsDAV, "current-user-privilege-set", privilegeSet("owner")),
		pv(nsDAV, "acl", aclProperty(u.ID, "owner")),
		pv(nsDAV, "supported-privilege-set", supportedPrivilegeSet()),
	})}
	if depth(r) != "0" {
		for _, c := range cs {
			if !c.CanReadEvents {
				continue
			}
			res = append(res, propResponse(calendarHref(u.ID, c), pr, calendarProps(u, c)))
		}
	}
	writeMulti(w, res, "")
}

type mkCalendarProperties struct {
	DisplayName string
	Description string
	Color       string
	Timezone    string
	Components  []string
}

func (h *Handler) mkCalendar(w http.ResponseWriter, r *http.Request, u auth.User, davName string) {
	// MKCALENDAR is only valid directly below the authenticated user's calendar home.
	if _, err := h.App.GetCalendarByDAVName(r.Context(), u, davName); err == nil {
		writeDAVError(w, http.StatusForbidden, "resource-must-be-null")
		return
	} else if !errors.Is(err, pgx.ErrNoRows) {
		writeDAVError(w, http.StatusInternalServerError, "server-error")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 256<<10))
	if err != nil {
		writeDAVError(w, http.StatusBadRequest, "valid-xml")
		return
	}
	props, err := parseMKCalendar(body)
	if err != nil {
		writeDAVError(w, http.StatusBadRequest, "valid-xml")
		return
	}
	for _, component := range props.Components {
		if component != "" && !strings.EqualFold(component, "VEVENT") {
			writeDAVError(w, http.StatusForbidden, "supported-calendar-component")
			return
		}
	}
	color := strings.TrimSpace(props.Color)
	if len(color) == 9 && strings.HasPrefix(color, "#") {
		color = color[:7]
	}
	c, err := h.App.CreateDAVCalendar(r.Context(), r, u, davName, props.DisplayName, props.Description, color, props.Timezone)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "existiert") {
			writeDAVError(w, http.StatusForbidden, "resource-must-be-null")
			return
		}
		if strings.Contains(strings.ToLower(err.Error()), "ungültig") || strings.Contains(strings.ToLower(err.Error()), "maximal") || strings.Contains(strings.ToLower(err.Error()), "zu groß") {
			writeDAVError(w, http.StatusConflict, "calendar-collection-location-ok")
			return
		}
		writeDAVError(w, http.StatusInternalServerError, "server-error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Location", calendarHref(u.ID, c))
	w.WriteHeader(http.StatusCreated)
}

func parseMKCalendar(body []byte) (mkCalendarProperties, error) {
	var out mkCalendarProperties
	if len(bytes.TrimSpace(body)) == 0 {
		return out, nil
	}
	dec := xml.NewDecoder(bytes.NewReader(body))
	seenRoot := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if !seenRoot {
			seenRoot = true
			if se.Name.Space != nsCal || se.Name.Local != "mkcalendar" {
				return out, fmt.Errorf("unexpected MKCALENDAR root")
			}
			continue
		}
		switch {
		case se.Name.Space == nsDAV && se.Name.Local == "displayname":
			if err := dec.DecodeElement(&out.DisplayName, &se); err != nil {
				return out, err
			}
			out.DisplayName = strings.TrimSpace(out.DisplayName)
		case se.Name.Space == nsCal && se.Name.Local == "calendar-description":
			if err := dec.DecodeElement(&out.Description, &se); err != nil {
				return out, err
			}
			out.Description = strings.TrimSpace(out.Description)
		case se.Name.Space == nsApple && se.Name.Local == "calendar-color":
			if err := dec.DecodeElement(&out.Color, &se); err != nil {
				return out, err
			}
			out.Color = strings.TrimSpace(out.Color)
		case se.Name.Space == nsCal && se.Name.Local == "calendar-timezone":
			if err := dec.DecodeElement(&out.Timezone, &se); err != nil {
				return out, err
			}
			out.Timezone = strings.TrimSpace(out.Timezone)
		case se.Name.Space == nsCal && se.Name.Local == "comp":
			for _, a := range se.Attr {
				if a.Name.Local == "name" {
					out.Components = append(out.Components, strings.ToUpper(strings.TrimSpace(a.Value)))
				}
			}
		}
	}
	if !seenRoot {
		return out, fmt.Errorf("empty MKCALENDAR body")
	}
	return out, nil
}

func (h *Handler) calendarCollection(w http.ResponseWriter, r *http.Request, u auth.User, c app.Calendar) {
	switch r.Method {
	case "PROPFIND":
		pr, err := parsePropfind(r)
		if err != nil {
			writeDAVError(w, http.StatusBadRequest, "valid-xml")
			return
		}
		base := calendarHref(u.ID, c)
		res := []string{propResponse(base, pr, calendarProps(u, c))}
		if depth(r) != "0" {
			es, err := h.App.ListEventsDAV(r.Context(), u, c.ID)
			if err != nil {
				writeDAVError(w, http.StatusInternalServerError, "server-error")
				return
			}
			for _, e := range es {
				res = append(res, propResponse(base+url.PathEscape(e.Href), pr, eventPropertyValues(u, c, e, false)))
			}
		}
		writeMulti(w, res, "")
	case "REPORT":
		h.report(w, r, u, c)
	case "PROPPATCH":
		h.calendarPropPatch(w, r, u, c)
	case "ACL":
		writeDAVError(w, http.StatusForbidden, "need-privileges")
	default:
		methodNotAllowed(w)
	}
}

func calendarProps(u auth.User, c app.Calendar) []propValue {
	return []propValue{
		pv(nsDAV, "resourcetype", `<d:resourcetype><d:collection/><c:calendar/></d:resourcetype>`),
		pv(nsDAV, "displayname", `<d:displayname>`+x(c.Name)+`</d:displayname>`),
		pv(nsCal, "calendar-description", `<c:calendar-description>`+x(c.Description)+`</c:calendar-description>`),
		pv(nsCal, "schedule-calendar-transp", `<c:schedule-calendar-transp><c:opaque/></c:schedule-calendar-transp>`),
		pv(nsDAV, "owner", `<d:owner><d:href>`+x(principalURL(u.ID))+`</d:href></d:owner>`),
		pv(nsDAV, "current-user-privilege-set", privilegeSet(c.Role)),
		pv(nsDAV, "acl", aclProperty(u.ID, c.Role)),
		pv(nsDAV, "acl-restrictions", `<d:acl-restrictions><d:no-invert/></d:acl-restrictions>`),
		pv(nsDAV, "supported-privilege-set", supportedPrivilegeSet()),
		pv(nsDAV, "getlastmodified", `<d:getlastmodified>`+x(c.UpdatedAt.UTC().Format(http.TimeFormat))+`</d:getlastmodified>`),
		calendarTimezoneProp(c.CalendarTimezone),
		pv(nsCal, "supported-calendar-component-set", `<c:supported-calendar-component-set><c:comp name="VEVENT"/></c:supported-calendar-component-set>`),
		pv(nsCal, "supported-calendar-data", `<c:supported-calendar-data><c:calendar-data content-type="text/calendar" version="2.0"/></c:supported-calendar-data>`),
		pv(nsCal, "max-resource-size", `<c:max-resource-size>10485760</c:max-resource-size>`),
		pv(nsCal, "supported-collation-set", `<c:supported-collation-set><c:supported-collation>i;ascii-casemap</c:supported-collation><c:supported-collation>i;octet</c:supported-collation></c:supported-collation-set>`),
		pv(nsApple, "calendar-color", `<a:calendar-color>`+x(normalizeCalendarColor(c.Color))+`</a:calendar-color>`),
		pv(nsApple, "calendar-order", `<a:calendar-order>1</a:calendar-order>`),
		pv(nsCS, "getctag", `<cs:getctag>`+x(syncToken(c.UpdatedAt))+`</cs:getctag>`),
		pv(nsDAV, "sync-token", `<d:sync-token>`+x(syncToken(c.UpdatedAt))+`</d:sync-token>`),
		pv(nsDAV, "supported-report-set", supportedReports(true)),
	}
}

func calendarTimezoneProp(tz string) propValue {
	if strings.TrimSpace(tz) == "" {
		return pv(nsCal, "calendar-timezone", `<c:calendar-timezone/>`)
	}
	return pv(nsCal, "calendar-timezone", `<c:calendar-timezone>`+x(tz)+`</c:calendar-timezone>`)
}

func normalizeCalendarColor(c string) string {
	c = strings.TrimSpace(c)
	if len(c) == 7 && strings.HasPrefix(c, "#") {
		return strings.ToUpper(c) + "FF"
	}
	if len(c) == 9 && strings.HasPrefix(c, "#") {
		return strings.ToUpper(c)
	}
	return "#4F8CFFFF"
}

func privilegeSet(role string) string {
	items := []string{
		`<d:privilege><d:read/></d:privilege>`,
		`<d:privilege><d:read-acl/></d:privilege>`,
		`<d:privilege><d:read-current-user-privilege-set/></d:privilege>`,
	}
	if role == "owner" || role == "contributor" {
		items = append(items, `<d:privilege><d:write-content/></d:privilege>`)
	}
	if role == "owner" {
		items = append(items, `<d:privilege><d:write-properties/></d:privilege>`, `<d:privilege><d:bind/></d:privilege>`, `<d:privilege><d:unbind/></d:privilege>`)
	}
	return `<d:current-user-privilege-set>` + strings.Join(items, "") + `</d:current-user-privilege-set>`
}

func schedulingPrivilegeSet(name string) string {
	items := []string{
		`<d:privilege><d:read/></d:privilege>`,
		`<d:privilege><d:read-acl/></d:privilege>`,
		`<d:privilege><d:read-current-user-privilege-set/></d:privilege>`,
	}
	if name == "inbox" {
		items = append(items,
			`<d:privilege><c:schedule-deliver/></d:privilege>`,
			`<d:privilege><c:schedule-deliver-invite/></d:privilege>`,
			`<d:privilege><c:schedule-deliver-reply/></d:privilege>`,
			`<d:privilege><c:schedule-query-freebusy/></d:privilege>`,
		)
	} else {
		items = append(items,
			`<d:privilege><c:schedule-send/></d:privilege>`,
			`<d:privilege><c:schedule-send-invite/></d:privilege>`,
			`<d:privilege><c:schedule-send-reply/></d:privilege>`,
			`<d:privilege><c:schedule-send-freebusy/></d:privilege>`,
			// Legacy CalendarServer/SabreDAV privilege kept for Apple/iCal compatibility.
			`<d:privilege><c:schedule-post-vevent/></d:privilege>`,
		)
	}
	return `<d:current-user-privilege-set>` + strings.Join(items, "") + `</d:current-user-privilege-set>`
}

func schedulingACL(userID, name string) string {
	privs := []string{
		`<d:privilege><d:read/></d:privilege>`,
		`<d:privilege><d:read-acl/></d:privilege>`,
		`<d:privilege><d:read-current-user-privilege-set/></d:privilege>`,
	}
	if name == "inbox" {
		privs = append(privs,
			`<d:privilege><c:schedule-deliver/></d:privilege>`,
			`<d:privilege><c:schedule-deliver-invite/></d:privilege>`,
			`<d:privilege><c:schedule-deliver-reply/></d:privilege>`,
			`<d:privilege><c:schedule-query-freebusy/></d:privilege>`,
		)
	} else {
		privs = append(privs,
			`<d:privilege><c:schedule-send/></d:privilege>`,
			`<d:privilege><c:schedule-send-invite/></d:privilege>`,
			`<d:privilege><c:schedule-send-reply/></d:privilege>`,
			`<d:privilege><c:schedule-send-freebusy/></d:privilege>`,
			`<d:privilege><c:schedule-post-vevent/></d:privilege>`,
		)
	}
	return `<d:acl><d:ace><d:principal><d:href>` + x(principalURL(userID)) + `</d:href></d:principal><d:grant>` + strings.Join(privs, "") + `</d:grant><d:protected/></d:ace></d:acl>`
}

func aclProperty(userID, role string) string {
	privs := []string{`<d:privilege><d:read/></d:privilege>`, `<d:privilege><c:read-free-busy/></d:privilege>`}
	if role == "owner" || role == "contributor" {
		privs = append(privs, `<d:privilege><d:write-content/></d:privilege>`)
	}
	if role == "owner" {
		privs = append(privs, `<d:privilege><d:write-properties/></d:privilege>`, `<d:privilege><d:bind/></d:privilege>`, `<d:privilege><d:unbind/></d:privilege>`)
	}
	return `<d:acl><d:ace><d:principal><d:href>` + x(principalURL(userID)) + `</d:href></d:principal><d:grant>` + strings.Join(privs, "") + `</d:grant><d:protected/></d:ace></d:acl>`
}

func supportedPrivilegeSet() string {
	return `<d:supported-privilege-set>` +
		`<d:supported-privilege><d:privilege><d:all/></d:privilege><d:description xml:lang="en">All privileges</d:description>` +
		`<d:supported-privilege><d:privilege><d:read/></d:privilege><d:description xml:lang="en">Read</d:description>` +
		`<d:supported-privilege><d:privilege><d:read-acl/></d:privilege><d:description xml:lang="en">Read ACL</d:description></d:supported-privilege>` +
		`<d:supported-privilege><d:privilege><d:read-current-user-privilege-set/></d:privilege><d:description xml:lang="en">Read current privileges</d:description></d:supported-privilege>` +
		`<d:supported-privilege><d:privilege><c:read-free-busy/></d:privilege><d:description xml:lang="en">Read free/busy</d:description></d:supported-privilege>` +
		`</d:supported-privilege>` +
		`<d:supported-privilege><d:privilege><d:write/></d:privilege><d:description xml:lang="en">Write</d:description>` +
		`<d:supported-privilege><d:privilege><d:write-content/></d:privilege><d:description xml:lang="en">Write content</d:description></d:supported-privilege>` +
		`<d:supported-privilege><d:privilege><d:write-properties/></d:privilege><d:description xml:lang="en">Write properties</d:description></d:supported-privilege>` +
		`<d:supported-privilege><d:privilege><d:bind/></d:privilege><d:description xml:lang="en">Bind</d:description></d:supported-privilege>` +
		`<d:supported-privilege><d:privilege><d:unbind/></d:privilege><d:description xml:lang="en">Unbind</d:description></d:supported-privilege>` +
		`</d:supported-privilege>` +
		`</d:supported-privilege>` +
		`</d:supported-privilege-set>`
}

func schedulingSupportedPrivilegeSet(name string) string {
	var schedule string
	if name == "inbox" {
		schedule = `<d:supported-privilege><d:privilege><c:schedule-deliver/></d:privilege><d:description xml:lang="en">Deliver scheduling messages</d:description>` +
			`<d:supported-privilege><d:privilege><c:schedule-deliver-invite/></d:privilege><d:description xml:lang="en">Deliver invitations</d:description></d:supported-privilege>` +
			`<d:supported-privilege><d:privilege><c:schedule-deliver-reply/></d:privilege><d:description xml:lang="en">Deliver replies</d:description></d:supported-privilege>` +
			`<d:supported-privilege><d:privilege><c:schedule-query-freebusy/></d:privilege><d:description xml:lang="en">Query free/busy</d:description></d:supported-privilege>` +
			`</d:supported-privilege>`
	} else {
		schedule = `<d:supported-privilege><d:privilege><c:schedule-send/></d:privilege><d:description xml:lang="en">Send scheduling messages</d:description>` +
			`<d:supported-privilege><d:privilege><c:schedule-send-invite/></d:privilege><d:description xml:lang="en">Send invitations</d:description></d:supported-privilege>` +
			`<d:supported-privilege><d:privilege><c:schedule-send-reply/></d:privilege><d:description xml:lang="en">Send replies</d:description></d:supported-privilege>` +
			`<d:supported-privilege><d:privilege><c:schedule-send-freebusy/></d:privilege><d:description xml:lang="en">Send free/busy requests</d:description></d:supported-privilege>` +
			`<d:supported-privilege><d:privilege><c:schedule-post-vevent/></d:privilege><d:description xml:lang="en">Post VEVENT scheduling messages</d:description></d:supported-privilege>` +
			`</d:supported-privilege>`
	}
	return `<d:supported-privilege-set>` +
		`<d:supported-privilege><d:privilege><d:all/></d:privilege><d:description xml:lang="en">All privileges</d:description>` +
		`<d:supported-privilege><d:privilege><d:read/></d:privilege><d:description xml:lang="en">Read</d:description>` +
		`<d:supported-privilege><d:privilege><d:read-acl/></d:privilege><d:description xml:lang="en">Read ACL</d:description></d:supported-privilege>` +
		`<d:supported-privilege><d:privilege><d:read-current-user-privilege-set/></d:privilege><d:description xml:lang="en">Read current privileges</d:description></d:supported-privilege>` +
		`</d:supported-privilege>` +
		schedule +
		`</d:supported-privilege>` +
		`</d:supported-privilege-set>`
}

func schedulingSupportedReports(name string) string {
	if name != "inbox" {
		return `<d:supported-report-set/>`
	}
	return `<d:supported-report-set>` +
		`<d:supported-report><d:report><c:calendar-query/></d:report></d:supported-report>` +
		`<d:supported-report><d:report><c:calendar-multiget/></d:report></d:supported-report>` +
		`</d:supported-report-set>`
}

func writeFreeBusy(w http.ResponseWriter, events []app.Event, start, end time.Time) {
	var periods []string
	for _, e := range events {
		if e.Start == nil {
			continue
		}
		es := e.Start.UTC()
		ee := es.Add(time.Hour)
		if e.End != nil {
			ee = e.End.UTC()
		}
		if !es.Before(end) || !ee.After(start) {
			continue
		}
		periods = append(periods, es.Format("20060102T150405Z")+"/"+ee.Format("20060102T150405Z"))
	}
	var b strings.Builder
	b.WriteString("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//ZentWorks//ZentCal//EN\r\nBEGIN:VFREEBUSY\r\n")
	b.WriteString("DTSTAMP:" + time.Now().UTC().Format("20060102T150405Z") + "\r\n")
	b.WriteString("DTSTART:" + start.UTC().Format("20060102T150405Z") + "\r\n")
	b.WriteString("DTEND:" + end.UTC().Format("20060102T150405Z") + "\r\n")
	for _, period := range periods {
		b.WriteString("FREEBUSY:" + period + "\r\n")
	}
	b.WriteString("END:VFREEBUSY\r\nEND:VCALENDAR\r\n")
	w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, b.String())
}

func supportedReports(calendar bool) string {
	reports := []string{`<d:supported-report><d:report><d:sync-collection/></d:report></d:supported-report>`}
	if calendar {
		reports = append(reports,
			`<d:supported-report><d:report><c:calendar-query/></d:report></d:supported-report>`,
			`<d:supported-report><d:report><c:calendar-multiget/></d:report></d:supported-report>`,
			`<d:supported-report><d:report><c:free-busy-query/></d:report></d:supported-report>`,
		)
	}
	return `<d:supported-report-set>` + strings.Join(reports, "") + `</d:supported-report-set>`
}

func (h *Handler) eventResource(w http.ResponseWriter, r *http.Request, u auth.User, c app.Calendar, href string) {
	href, err := url.PathUnescape(href)
	if err != nil || href == "" || href == "." || strings.Contains(href, "/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		e, err := h.App.GetEventByHref(r.Context(), u, c.ID, href)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
		w.Header().Set("ETag", e.ETag)
		if e.ScheduleTag != "" {
			w.Header().Set("Schedule-Tag", e.ScheduleTag)
		}
		w.Header().Set("Last-Modified", e.UpdatedAt.UTC().Format(http.TimeFormat))
		w.Header().Set("Content-Length", strconv.Itoa(len([]byte(e.ICS))))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, e.ICS)
		}
	case http.MethodPut:
		if scheduleMatch := strings.TrimSpace(r.Header.Get("If-Schedule-Tag-Match")); scheduleMatch != "" {
			if current, err := h.App.GetEventByHref(r.Context(), u, c.ID, href); err != nil || current.ScheduleTag != scheduleMatch {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
		}
		if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(ct), "text/calendar") {
			writeDAVError(w, http.StatusUnsupportedMediaType, "supported-calendar-data")
			return
		}
		if r.Header.Get("If-None-Match") == "*" {
			if _, err := h.App.GetEventByHref(r.Context(), u, c.ID, href); err == nil {
				writeDAVError(w, http.StatusPreconditionFailed, "resource-must-be-null")
				return
			}
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
		if err != nil {
			writeDAVError(w, http.StatusBadRequest, "valid-calendar-data")
			return
		}
		e, created, err := h.App.PutEvent(r.Context(), r, u, c.ID, href, string(b), r.Header.Get("If-Match"))
		if err != nil {
			status := http.StatusForbidden
			precondition := "valid-calendar-object-resource"
			if strings.Contains(strings.ToLower(err.Error()), "etag") {
				status = http.StatusPreconditionFailed
				precondition = ""
			}
			if precondition != "" {
				writeDAVError(w, status, precondition)
			} else {
				http.Error(w, http.StatusText(status), status)
			}
			return
		}
		w.Header().Set("ETag", e.ETag)
		if e.ScheduleTag != "" {
			w.Header().Set("Schedule-Tag", e.ScheduleTag)
		}
		w.Header().Set("Location", calendarHref(u.ID, c)+url.PathEscape(e.Href))
		if created {
			w.WriteHeader(http.StatusCreated)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	case http.MethodDelete:
		if scheduleMatch := strings.TrimSpace(r.Header.Get("If-Schedule-Tag-Match")); scheduleMatch != "" {
			e, err := h.App.GetEventByHref(r.Context(), u, c.ID, href)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			if e.ScheduleTag != scheduleMatch {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
		}
		if ifMatch := strings.TrimSpace(r.Header.Get("If-Match")); ifMatch != "" {
			e, err := h.App.GetEventByHref(r.Context(), u, c.ID, href)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			if ifMatch != e.ETag && ifMatch != "*" {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
		}
		if err := h.App.DeleteEvent(r.Context(), r, u, c.ID, href); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.NotFound(w, r)
			} else {
				http.Error(w, "Forbidden", http.StatusForbidden)
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "PROPFIND":
		pr, err := parsePropfind(r)
		if err != nil {
			writeDAVError(w, http.StatusBadRequest, "valid-xml")
			return
		}
		e, err := h.App.GetEventByHref(r.Context(), u, c.ID, href)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		full := calendarHref(u.ID, c) + url.PathEscape(e.Href)
		writeMulti(w, []string{propResponse(full, pr, eventPropertyValues(u, c, e, false))}, "")
	default:
		methodNotAllowed(w)
	}
}

func eventPropertyValues(u auth.User, c app.Calendar, e app.Event, withData bool) []propValue {
	props := []propValue{
		pv(nsDAV, "resourcetype", `<d:resourcetype/>`),
		pv(nsDAV, "getetag", `<d:getetag>`+x(e.ETag)+`</d:getetag>`),
		pv(nsCal, "schedule-tag", `<c:schedule-tag>`+x(e.ScheduleTag)+`</c:schedule-tag>`),
		pv(nsDAV, "getcontenttype", `<d:getcontenttype>text/calendar; charset=utf-8</d:getcontenttype>`),
		pv(nsDAV, "getcontentlength", `<d:getcontentlength>`+strconv.Itoa(len([]byte(e.ICS)))+`</d:getcontentlength>`),
		pv(nsDAV, "getlastmodified", `<d:getlastmodified>`+x(e.UpdatedAt.UTC().Format(http.TimeFormat))+`</d:getlastmodified>`),
		pv(nsDAV, "owner", `<d:owner><d:href>`+x(principalURL(u.ID))+`</d:href></d:owner>`),
		pv(nsDAV, "current-user-privilege-set", privilegeSet(c.Role)),
		pv(nsDAV, "acl", aclProperty(u.ID, c.Role)),
		pv(nsDAV, "supported-privilege-set", supportedPrivilegeSet()),
		pv(nsDAV, "supported-report-set", supportedReports(true)),
	}
	if withData {
		props = append(props, pv(nsCal, "calendar-data", `<c:calendar-data content-type="text/calendar" version="2.0">`+x(e.ICS)+`</c:calendar-data>`))
	}
	return props
}

func (h *Handler) report(w http.ResponseWriter, r *http.Request, u auth.User, c app.Calendar) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		writeDAVError(w, http.StatusBadRequest, "valid-xml")
		return
	}
	reportName, pr, err := parseReport(body)
	if err != nil {
		writeDAVError(w, http.StatusBadRequest, "valid-xml")
		return
	}
	if reportName != "calendar-query" && reportName != "calendar-multiget" && reportName != "sync-collection" && reportName != "free-busy-query" {
		writeDAVError(w, http.StatusForbidden, "supported-report")
		return
	}

	es, err := h.App.ListEventsDAV(r.Context(), u, c.ID)
	if err != nil {
		writeDAVError(w, http.StatusInternalServerError, "server-error")
		return
	}
	if reportName == "free-busy-query" {
		start, end, ok := extractTimeRange(body)
		if !ok || start.IsZero() || end.IsZero() {
			writeDAVError(w, http.StatusBadRequest, "valid-filter")
			return
		}
		writeFreeBusy(w, es, start, end)
		return
	}

	wanted := extractHrefs(body)
	start, end, hasRange := extractTimeRange(body)
	base := calendarHref(u.ID, c)
	res := make([]string, 0, len(es))
	for _, e := range es {
		full := base + url.PathEscape(e.Href)
		if reportName == "calendar-multiget" && len(wanted) > 0 && !hrefWanted(wanted, full, e.Href) {
			continue
		}
		if reportName == "calendar-query" && hasRange && !eventIntersects(e, start, end) {
			continue
		}
		res = append(res, propResponse(full, pr, eventPropertyValues(u, c, e, true)))
	}

	if reportName == "calendar-multiget" && len(wanted) > 0 {
		found := map[string]bool{}
		for _, e := range es {
			found[e.Href] = true
			found[base+url.PathEscape(e.Href)] = true
		}
		for raw := range wanted {
			if raw == "" || found[raw] || found[path.Base(raw)] {
				continue
			}
			if strings.HasPrefix(raw, base) {
				res = append(res, `<d:response><d:href>`+x(raw)+`</d:href><d:status>HTTP/1.1 404 Not Found</d:status></d:response>`)
			}
		}
	}

	token := ""
	if reportName == "sync-collection" {
		token = syncToken(c.UpdatedAt)
		if since, ok := requestSyncSince(body); ok {
			rows, qerr := h.App.DB.Query(r.Context(), `SELECT href FROM event_tombstones WHERE calendar_id=$1 AND deleted_at>$2 ORDER BY deleted_at`, c.ID, since)
			if qerr == nil {
				defer rows.Close()
				for rows.Next() {
					var href string
					if rows.Scan(&href) == nil {
						full := base + url.PathEscape(href)
						res = append(res, `<d:response><d:href>`+x(full)+`</d:href><d:status>HTTP/1.1 404 Not Found</d:status></d:response>`)
					}
				}
			}
		}
	}
	writeMulti(w, res, token)
}

func hrefWanted(wanted map[string]bool, full, href string) bool {
	if wanted[full] || wanted[href] {
		return true
	}
	if unescaped, err := url.PathUnescape(full); err == nil && wanted[unescaped] {
		return true
	}
	return false
}

func eventIntersects(e app.Event, start, end time.Time) bool {
	if e.Start == nil {
		return true // Undated content must not be silently hidden.
	}
	es := *e.Start
	ee := es
	if e.End != nil {
		ee = *e.End
	}
	intersects := false
	if end.IsZero() {
		intersects = !ee.Before(start)
	} else {
		intersects = es.Before(end) && !ee.Before(start)
	}
	if intersects {
		return true
	}
	// A master recurring component may have DTSTART long before the requested
	// range while one of its instances lies inside it. Returning the object is
	// conservative and standards-safe: the CalDAV client can expand RRULE/RDATE
	// itself, whereas omitting it would cause missing events.
	return ical.HasRecurrence(e.ICS)
}

func (h *Handler) calendarPropPatch(w http.ResponseWriter, r *http.Request, u auth.User, c app.Calendar) {
	if c.Role != "owner" {
		writeDAVError(w, http.StatusForbidden, "need-privileges")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 256<<10))
	if err != nil {
		writeDAVError(w, http.StatusBadRequest, "valid-xml")
		return
	}
	color, display := extractCalendarPatch(body)
	if color == "" && display == "" {
		writeMulti(w, []string{`<d:response><d:href>` + x(calendarHref(u.ID, c)) + `</d:href><d:propstat><d:prop/><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>`}, "")
		return
	}
	newColor := c.Color
	newName := c.Name
	if color != "" {
		color = strings.TrimSuffix(color, "FF")
		if len(color) == 7 && strings.HasPrefix(color, "#") {
			newColor = color
		}
	}
	if strings.TrimSpace(display) != "" {
		newName = strings.TrimSpace(display)
	}
	if _, err := h.App.UpdateCalendar(r.Context(), r, u, c.ID, newName, c.Description, newColor, c.Mode); err != nil {
		writeDAVError(w, http.StatusForbidden, "need-privileges")
		return
	}
	writeMulti(w, []string{`<d:response><d:href>` + x(calendarHref(u.ID, c)) + `</d:href><d:propstat><d:prop><d:displayname/><a:calendar-color/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>`}, "")
}

func (h *Handler) schedulingCollection(w http.ResponseWriter, r *http.Request, u auth.User, parts []string) {
	if h.Scheduling == nil {
		writeDAVError(w, http.StatusServiceUnavailable, "server-error")
		return
	}
	if len(parts) < 3 || parts[2] != u.ID {
		http.NotFound(w, r)
		return
	}
	name := parts[1]
	if name != "inbox" && name != "outbox" {
		http.NotFound(w, r)
		return
	}
	base := "/dav/" + name + "/" + u.ID + "/"
	if len(parts) == 3 {
		switch r.Method {
		case "PROPFIND":
			pr, err := parsePropfind(r)
			if err != nil {
				writeDAVError(w, http.StatusBadRequest, "valid-xml")
				return
			}
			rt := `<d:resourcetype><d:collection/><c:schedule-` + name + `/></d:resourcetype>`
			available := []propValue{
				pv(nsDAV, "resourcetype", rt),
				pv(nsDAV, "displayname", `<d:displayname>`+x(strings.Title(name))+`</d:displayname>`),
				pv(nsDAV, "owner", `<d:owner><d:href>`+x(principalURL(u.ID))+`</d:href></d:owner>`),
				pv(nsDAV, "current-user-privilege-set", schedulingPrivilegeSet(name)),
				pv(nsDAV, "acl", schedulingACL(u.ID, name)),
				pv(nsDAV, "acl-restrictions", `<d:acl-restrictions><d:no-invert/></d:acl-restrictions>`),
				pv(nsDAV, "supported-privilege-set", schedulingSupportedPrivilegeSet(name)),
				pv(nsDAV, "supported-report-set", schedulingSupportedReports(name)),
				pv(nsCal, "supported-calendar-component-set", `<c:supported-calendar-component-set><c:comp name="VEVENT"/></c:supported-calendar-component-set>`),
				pv(nsCal, "supported-calendar-data", `<c:supported-calendar-data><c:calendar-data content-type="text/calendar" version="2.0"/></c:supported-calendar-data>`),
				pv(nsCal, "max-resource-size", `<c:max-resource-size>10485760</c:max-resource-size>`),
				pv(nsCal, "max-attendees-per-instance", `<c:max-attendees-per-instance>100</c:max-attendees-per-instance>`),
			}
			if name == "inbox" {
				if calID, err := db.EnsurePersonalCalendar(r.Context(), h.App.DB, u.ID, u.Name); err == nil {
					available = append(available, pv(nsCal, "schedule-default-calendar-URL", `<c:schedule-default-calendar-URL><d:href>`+x(calendarURL(u.ID, calID))+`</d:href></c:schedule-default-calendar-URL>`))
				}
			}
			res := []string{propResponse(base, pr, available)}
			if name == "inbox" && depth(r) != "0" {
				messages, err := h.Scheduling.ListMessages(r.Context(), u.ID, "inbox")
				if err != nil {
					writeDAVError(w, http.StatusInternalServerError, "server-error")
					return
				}
				for _, msg := range messages {
					res = append(res, propResponse(base+url.PathEscape(msg.Href), pr, schedulingMessageProps(msg, false)))
				}
			}
			writeMulti(w, res, "")
		case "REPORT":
			if name != "inbox" {
				writeDAVError(w, http.StatusForbidden, "supported-report")
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 256<<10))
			if err != nil {
				writeDAVError(w, http.StatusBadRequest, "valid-xml")
				return
			}
			reportName, pr, err := parseReport(body)
			if err != nil || (reportName != "calendar-query" && reportName != "calendar-multiget") {
				writeDAVError(w, http.StatusForbidden, "supported-report")
				return
			}
			messages, err := h.Scheduling.ListMessages(r.Context(), u.ID, name)
			if err != nil {
				writeDAVError(w, http.StatusInternalServerError, "server-error")
				return
			}
			requested := map[string]bool{}
			if reportName == "calendar-multiget" {
				requested = extractHrefs(body)
			}
			res := make([]string, 0, len(messages))
			for _, msg := range messages {
				if reportName == "calendar-multiget" && !requested[msg.Href] && !requested[base+url.PathEscape(msg.Href)] {
					continue
				}
				res = append(res, propResponse(base+url.PathEscape(msg.Href), pr, schedulingMessageProps(msg, true)))
			}
			writeMulti(w, res, "")
		case http.MethodPost:
			if name != "outbox" {
				methodNotAllowed(w)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
			if err != nil {
				writeDAVError(w, http.StatusBadRequest, "valid-scheduling-message")
				return
			}
			results, err := h.Scheduling.ProcessOutbox(r.Context(), r, u, string(body))
			if err != nil {
				writeDAVError(w, http.StatusForbidden, "valid-scheduling-message")
				return
			}
			w.Header().Set("Content-Type", "application/xml; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			var b strings.Builder
			b.WriteString(`<?xml version="1.0" encoding="utf-8"?><c:schedule-response xmlns:c="urn:ietf:params:xml:ns:caldav" xmlns:d="DAV:">`)
			for _, result := range results {
				b.WriteString(`<c:response><c:recipient><d:href>mailto:` + x(result.Recipient) + `</d:href></c:recipient><c:request-status>` + x(result.Status) + `</c:request-status></c:response>`)
			}
			b.WriteString(`</c:schedule-response>`)
			_, _ = io.WriteString(w, b.String())
		default:
			methodNotAllowed(w)
		}
		return
	}
	if len(parts) != 4 || name != "inbox" {
		http.NotFound(w, r)
		return
	}
	href, err := url.PathUnescape(parts[3])
	if err != nil || href == "" || strings.Contains(href, "/") {
		http.NotFound(w, r)
		return
	}
	msg, err := h.Scheduling.GetMessage(r.Context(), u.ID, "inbox", href)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
		w.Header().Set("ETag", ical.ETag(msg.ICS))
		w.Header().Set("Schedule-Tag", msg.ScheduleTag)
		w.Header().Set("Content-Length", strconv.Itoa(len([]byte(msg.ICS))))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, msg.ICS)
		}
	case "PROPFIND":
		pr, err := parsePropfind(r)
		if err != nil {
			writeDAVError(w, http.StatusBadRequest, "valid-xml")
			return
		}
		writeMulti(w, []string{propResponse(base+url.PathEscape(msg.Href), pr, schedulingMessageProps(msg, false))}, "")
	case http.MethodDelete:
		if err := h.Scheduling.DeleteMessage(r.Context(), u.ID, "inbox", href); err != nil {
			writeDAVError(w, http.StatusInternalServerError, "server-error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func schedulingMessageProps(msg scheduling.Message, withData bool) []propValue {
	props := []propValue{
		pv(nsDAV, "resourcetype", `<d:resourcetype/>`),
		pv(nsDAV, "getetag", `<d:getetag>`+x(ical.ETag(msg.ICS))+`</d:getetag>`),
		pv(nsDAV, "getcontenttype", `<d:getcontenttype>text/calendar; charset=utf-8</d:getcontenttype>`),
		pv(nsDAV, "getcontentlength", `<d:getcontentlength>`+strconv.Itoa(len([]byte(msg.ICS)))+`</d:getcontentlength>`),
		pv(nsCal, "schedule-tag", `<c:schedule-tag>`+x(msg.ScheduleTag)+`</c:schedule-tag>`),
	}
	if withData {
		props = append(props, pv(nsCal, "calendar-data", `<c:calendar-data content-type="text/calendar" version="2.0">`+x(msg.ICS)+`</c:calendar-data>`))
	}
	return props
}

func parsePropfind(r *http.Request) (propRequest, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 256<<10))
	if err != nil {
		return propRequest{}, err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return propRequest{All: true}, nil
	}
	dec := xml.NewDecoder(bytes.NewReader(body))
	var out propRequest
	inProp := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return propRequest{}, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "allprop":
				out.All = true
			case "propname":
				out.PropName = true
			case "prop":
				inProp = true
			default:
				if inProp {
					out.Names = append(out.Names, t.Name)
					if err := dec.Skip(); err != nil {
						return propRequest{}, err
					}
				}
			}
		case xml.EndElement:
			if t.Name.Local == "prop" {
				inProp = false
			}
		}
	}
	if !out.All && !out.PropName && len(out.Names) == 0 {
		out.All = true
	}
	return out, nil
}

func parseReport(body []byte) (string, propRequest, error) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	var report string
	var pr propRequest
	inProp := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", propRequest{}, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if report == "" {
				report = t.Name.Local
			}
			if t.Name.Local == "allprop" {
				pr.All = true
			} else if t.Name.Local == "propname" {
				pr.PropName = true
			} else if t.Name.Local == "prop" {
				inProp = true
			} else if inProp {
				pr.Names = append(pr.Names, t.Name)
				if err := dec.Skip(); err != nil {
					return "", propRequest{}, err
				}
			}
		case xml.EndElement:
			if t.Name.Local == "prop" {
				inProp = false
			}
		}
	}
	if report == "" {
		return "", propRequest{}, fmt.Errorf("empty report")
	}
	if !pr.All && !pr.PropName && len(pr.Names) == 0 {
		pr.Names = []xml.Name{{Space: nsDAV, Local: "getetag"}, {Space: nsCal, Local: "calendar-data"}}
	}
	return report, pr, nil
}

func pv(space, local, raw string) propValue {
	return propValue{Name: xml.Name{Space: space, Local: local}, XML: raw}
}

func propResponse(href string, pr propRequest, available []propValue) string {
	lookup := make(map[string]propValue, len(available))
	for _, p := range available {
		lookup[propKey(p.Name)] = p
	}

	var okProps, missing []string
	if pr.All || (len(pr.Names) == 0 && !pr.PropName) {
		for _, p := range available {
			okProps = append(okProps, p.XML)
		}
	} else if pr.PropName {
		for _, p := range available {
			okProps = append(okProps, emptyKnownProp(p.Name))
		}
	} else {
		for _, name := range pr.Names {
			if p, ok := lookup[propKey(name)]; ok {
				okProps = append(okProps, p.XML)
			} else {
				missing = append(missing, emptyUnknownProp(name))
			}
		}
	}

	var b strings.Builder
	b.WriteString(`<d:response><d:href>` + x(href) + `</d:href>`)
	if len(okProps) > 0 {
		b.WriteString(`<d:propstat><d:prop>` + strings.Join(okProps, "") + `</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>`)
	}
	if len(missing) > 0 {
		b.WriteString(`<d:propstat><d:prop>` + strings.Join(missing, "") + `</d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>`)
	}
	b.WriteString(`</d:response>`)
	return b.String()
}

func propKey(n xml.Name) string { return n.Space + "\x00" + n.Local }

func emptyKnownProp(n xml.Name) string {
	prefix := "d"
	switch n.Space {
	case nsCal:
		prefix = "c"
	case nsApple:
		prefix = "a"
	case nsCS:
		prefix = "cs"
	}
	return `<` + prefix + `:` + safeXMLName(n.Local) + `/>`
}

func emptyUnknownProp(n xml.Name) string {
	if n.Space == "" {
		return `<d:` + safeXMLName(n.Local) + `/>`
	}
	return `<x:` + safeXMLName(n.Local) + ` xmlns:x="` + x(n.Space) + `"/>`
}

func safeXMLName(s string) string {
	if s == "" {
		return "unknown"
	}
	for _, r := range s {
		if !(r == '-' || r == '_' || r == '.' || r == ':' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return "unknown"
		}
	}
	return s
}

func writeMulti(w http.ResponseWriter, res []string, token string) {
	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.WriteHeader(http.StatusMultiStatus)
	_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav" xmlns:a="http://apple.com/ns/ical/" xmlns:cs="http://calendarserver.org/ns/">`+strings.Join(res, "")+func() string {
		if token != "" {
			return `<d:sync-token>` + x(token) + `</d:sync-token>`
		}
		return ""
	}()+`</d:multistatus>`)
}

func writeDAVError(w http.ResponseWriter, status int, local string) {
	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.WriteHeader(status)
	if local == "" {
		return
	}
	ns := "c"
	if local == "need-privileges" || local == "valid-xml" || local == "supported-report" || local == "resource-must-be-null" {
		ns = "d"
	}
	_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><d:error xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><`+ns+`:`+safeXMLName(local)+`/></d:error>`)
}

func methodNotAllowed(w http.ResponseWriter) {
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func depth(r *http.Request) string {
	d := strings.TrimSpace(r.Header.Get("Depth"))
	if d == "" {
		return "0"
	}
	return d
}

func principalURL(userID string) string    { return "/dav/principals/" + userID + "/" }
func calendarHomeURL(userID string) string { return "/dav/calendars/" + userID + "/" }
func calendarURL(userID, calName string) string {
	return calendarHomeURL(userID) + url.PathEscape(calName) + "/"
}
func calendarHref(userID string, c app.Calendar) string {
	name := c.DAVName
	if name == "" {
		name = c.ID
	}
	return calendarURL(userID, name)
}
func inboxURL(userID string) string  { return "/dav/inbox/" + userID + "/" }
func outboxURL(userID string) string { return "/dav/outbox/" + userID + "/" }

func syncToken(t time.Time) string { return "urn:zentcal:sync:" + strconv.FormatInt(t.UnixNano(), 10) }

func x(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func extractHrefs(body []byte) map[string]bool {
	m := map[string]bool{}
	dec := xml.NewDecoder(bytes.NewReader(body))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Space != nsDAV || se.Name.Local != "href" {
			continue
		}
		var v string
		if dec.DecodeElement(&v, &se) == nil {
			v = strings.TrimSpace(v)
			m[v] = true
			if u, err := url.PathUnescape(v); err == nil {
				m[u] = true
			}
			m[path.Base(v)] = true
		}
	}
	return m
}

func requestSyncSince(body []byte) (time.Time, bool) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	for {
		tok, err := dec.Token()
		if err != nil {
			return time.Time{}, false
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Space != nsDAV || se.Name.Local != "sync-token" {
			continue
		}
		var v string
		if dec.DecodeElement(&v, &se) != nil {
			return time.Time{}, false
		}
		const prefix = "urn:zentcal:sync:"
		v = strings.TrimSpace(v)
		if v == "" || !strings.HasPrefix(v, prefix) {
			return time.Time{}, false
		}
		n, err := strconv.ParseInt(strings.TrimPrefix(v, prefix), 10, 64)
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(0, n), true
	}
}

func extractTimeRange(body []byte) (time.Time, time.Time, bool) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	for {
		tok, err := dec.Token()
		if err != nil {
			return time.Time{}, time.Time{}, false
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Space != nsCal || se.Name.Local != "time-range" {
			continue
		}
		var start, end time.Time
		for _, a := range se.Attr {
			switch a.Name.Local {
			case "start":
				start, _ = time.Parse("20060102T150405Z", strings.TrimSpace(a.Value))
			case "end":
				end, _ = time.Parse("20060102T150405Z", strings.TrimSpace(a.Value))
			}
		}
		if !start.IsZero() || !end.IsZero() {
			return start, end, true
		}
	}
}

func extractCalendarPatch(body []byte) (color, display string) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	for {
		tok, err := dec.Token()
		if err != nil {
			return color, display
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Space == nsApple && se.Name.Local == "calendar-color" {
			_ = dec.DecodeElement(&color, &se)
			color = strings.TrimSpace(color)
		} else if se.Name.Space == nsDAV && se.Name.Local == "displayname" {
			_ = dec.DecodeElement(&display, &se)
			display = strings.TrimSpace(display)
		}
	}
}
