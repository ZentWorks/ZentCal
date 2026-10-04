package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/zentworks/zentcal/internal/auth"
	"github.com/zentworks/zentcal/internal/db"
	"github.com/zentworks/zentcal/internal/httpx"
	"github.com/zentworks/zentcal/internal/oidc"
	"github.com/zentworks/zentcal/internal/security"
)

func (h *Handler) saveOIDCSettings(ctx context.Context, r *http.Request) error {
	enabled := r.FormValue("oidc_enabled") == "true"
	localLogin := r.FormValue("oidc_local_login") == "true"
	issuer := strings.TrimSpace(r.FormValue("oidc_issuer"))
	clientID := strings.TrimSpace(r.FormValue("oidc_client_id"))
	secret := r.FormValue("oidc_client_secret")
	if secret == "" && r.FormValue("oidc_client_secret_clear") != "true" {
		var enc string
		if err := h.DB.QueryRow(ctx, `SELECT value FROM settings WHERE key='oidc_client_secret' AND secret`).Scan(&enc); err == nil && enc != "" {
			var err error
			secret, err = h.Secrets.Decrypt(enc)
			if err != nil {
				return errors.New("Gespeichertes OIDC Client Secret konnte nicht entschlüsselt werden.")
			}
		}
	}
	if !localLogin && !enabled {
		return errors.New("Lokaler Login kann nur deaktiviert werden, wenn OIDC aktiviert ist.")
	}
	authorizationOrigin := ""
	if enabled {
		if issuer == "" || clientID == "" || secret == "" {
			return errors.New("Issuer URL, Client ID und Client Secret sind für OIDC erforderlich.")
		}
		discovery, err := h.OIDC.Discover(ctx, issuer)
		if err != nil {
			return err
		}
		authorizationOrigin = httpsOrigin(discovery.AuthorizationEndpoint)
		if authorizationOrigin == "" {
			return errors.New("OIDC Authorization Endpoint ist ungültig.")
		}
	}
	if enabled && !localLogin {
		var last string
		_ = h.DB.QueryRow(ctx, `SELECT value FROM settings WHERE key='oidc_last_success_fingerprint' AND NOT secret`).Scan(&last)
		if last == "" || last != oidcFingerprint(issuer, clientID, secret) {
			return errors.New("Lokalen Login erst deaktivieren, nachdem mit dieser OIDC-Konfiguration mindestens eine erfolgreiche SSO-Anmeldung durchgeführt wurde.")
		}
	}
	authMethod := strings.TrimSpace(r.FormValue("oidc_auth_method"))
	if authMethod != "client_secret_basic" {
		authMethod = "client_secret_post"
	}
	vals := map[string]string{
		"oidc_enabled":              boolString(enabled),
		"oidc_issuer":               issuer,
		"oidc_client_id":            clientID,
		"oidc_scopes":               strings.TrimSpace(r.FormValue("oidc_scopes")),
		"oidc_groups_claim":         strings.TrimSpace(r.FormValue("oidc_groups_claim")),
		"oidc_group_mapping":        strings.TrimSpace(r.FormValue("oidc_group_mapping")),
		"oidc_auth_method":          authMethod,
		"oidc_auto_provision":       boolString(r.FormValue("oidc_auto_provision") == "true"),
		"oidc_sync_name":            boolString(r.FormValue("oidc_sync_name") == "true"),
		"oidc_sync_email":           boolString(r.FormValue("oidc_sync_email") == "true"),
		"oidc_sync_groups":          boolString(r.FormValue("oidc_sync_groups") == "true"),
		"oidc_local_login":          boolString(localLogin),
		"oidc_authorization_origin": authorizationOrigin,
	}
	if vals["oidc_scopes"] == "" {
		vals["oidc_scopes"] = "openid profile email"
	}
	if vals["oidc_groups_claim"] == "" {
		vals["oidc_groups_claim"] = "groups"
	}
	if err := h.storeSettings(ctx, vals, false); err != nil {
		return err
	}
	if r.FormValue("oidc_client_secret_clear") == "true" {
		_, err := h.DB.Exec(ctx, `DELETE FROM settings WHERE key='oidc_client_secret'`)
		return err
	}
	if r.FormValue("oidc_client_secret") != "" {
		enc, err := h.Secrets.Encrypt(r.FormValue("oidc_client_secret"))
		if err != nil {
			return err
		}
		return h.storeSettings(ctx, map[string]string{"oidc_client_secret": enc}, true)
	}
	return nil
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func (h *Handler) testOIDC(w http.ResponseWriter, r *http.Request) {
	_, ok := h.adminAction(w, r)
	if !ok {
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	issuer := strings.TrimSpace(r.FormValue("oidc_issuer"))
	d, err := h.OIDC.Discover(r.Context(), issuer)
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "message": "OIDC Provider erreichbar. Issuer und Discovery sind gültig.", "issuer": d.Issuer})
}

func (h *Handler) oidcStart(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.OIDC.Load(r.Context())
	if err != nil || !cfg.Enabled {
		http.Error(w, "OIDC ist nicht aktiviert.", http.StatusNotFound)
		return
	}
	redirectURI := h.externalBaseURL() + "/auth/oidc/callback"
	returnTo := r.URL.Query().Get("next")
	if !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") {
		returnTo = "/"
	}

	// The public direct SSO link is intentionally the only flow that may reach
	// auto-provisioning. A sensitive in-session reauthentication is instead
	// bound to the already authenticated ZentCal account.
	var location string
	if target, parseErr := url.Parse(returnTo); parseErr == nil && target.Query().Get("reauth_password_reset") == "1" {
		ss, sessionErr := h.Auth.SessionFromRequest(r)
		if sessionErr != nil || ss.User.AuthType != "oidc" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		location, err = h.OIDC.BeginFlow(r.Context(), cfg, redirectURI, returnTo, "reauth", ss.User.ID)
	} else {
		location, err = h.OIDC.Begin(r.Context(), cfg, redirectURI, returnTo)
	}
	if err != nil {
		h.renderPublic(w, r, "login", pageData{Title: "Anmelden", Version: h.Version, Error: err.Error(), Data: map[string]any{"Step": "email"}})
		return
	}
	http.Redirect(w, r, location, http.StatusFound)
}

func (h *Handler) oidcLinkStart(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.action(w, r, true)
	if !ok {
		return
	}
	if ss.User.AuthType == "oidc" {
		httpx.Error(w, 400, "Dieses Konto ist bereits mit Single Sign-On verbunden.")
		return
	}
	if err := parseRequestForm(r); err != nil {
		httpx.Error(w, 400, "Ungültige Formulardaten.")
		return
	}
	var passwordHash string
	if err := h.DB.QueryRow(r.Context(), `SELECT password_hash FROM users WHERE id=$1 AND auth_type='local' AND status='active'`, ss.User.ID).Scan(&passwordHash); err != nil || !security.PasswordCheck(passwordHash, r.FormValue("current_password")) {
		httpx.Error(w, 403, "Aktuelles Passwort ist falsch.")
		return
	}
	cfg, err := h.OIDC.Load(r.Context())
	if err != nil || !cfg.Enabled {
		httpx.Error(w, 400, "Single Sign-On ist für diese ZentCal-Instanz nicht aktiviert.")
		return
	}
	location, err := h.OIDC.BeginFlow(r.Context(), cfg, h.externalBaseURL()+"/auth/oidc/callback", "/account", "link", ss.User.ID)
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "redirect": location})
}

func (h *Handler) oidcUnlinkStart(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.action(w, r, true)
	if !ok {
		return
	}
	if ss.User.AuthType != "oidc" {
		httpx.Error(w, 400, "Dieses Konto ist nicht mit Single Sign-On verbunden.")
		return
	}
	cfg, err := h.OIDC.Load(r.Context())
	if err != nil || !cfg.Enabled {
		httpx.Error(w, 400, "Single Sign-On ist für diese ZentCal-Instanz nicht aktiviert.")
		return
	}
	if !cfg.LocalLogin {
		httpx.Error(w, 400, "SSO kann erst getrennt werden, wenn der lokale Login in den OIDC-Einstellungen aktiviert ist.")
		return
	}
	_, smtpEnabled, smtpErr := h.loadSMTPConfig(r.Context())
	if smtpErr != nil {
		httpx.Error(w, 500, "SMTP-Konfiguration ist ungültig: "+smtpErr.Error())
		return
	}
	if !smtpEnabled {
		httpx.Error(w, 400, "SSO kann nur getrennt werden, wenn SMTP aktiviert ist. Das neue temporäre Passwort wird per E-Mail zugestellt.")
		return
	}
	location, err := h.OIDC.BeginFlow(r.Context(), cfg, h.externalBaseURL()+"/auth/oidc/callback", "/account", "unlink", ss.User.ID)
	if err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	httpx.JSON(w, 200, map[string]any{"ok": true, "redirect": location})
}

func (h *Handler) oidcCallback(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.OIDC.Load(r.Context())
	if err != nil || !cfg.Enabled {
		http.Error(w, "OIDC ist nicht aktiviert.", http.StatusNotFound)
		return
	}
	if r.URL.Query().Get("error") != "" {
		if _, sessionErr := h.Auth.SessionFromRequest(r); sessionErr == nil {
			http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("SSO-Anmeldung wurde abgebrochen oder vom Provider abgelehnt."), http.StatusSeeOther)
			return
		}
		h.renderPublic(w, r, "login", pageData{Title: "Anmelden", Version: h.Version, Error: "SSO-Anmeldung wurde abgebrochen oder vom Provider abgelehnt.", Data: map[string]any{"Step": "email"}})
		return
	}
	claims, err := h.OIDC.Callback(r.Context(), cfg, r.URL.Query().Get("state"), r.URL.Query().Get("code"))
	if err != nil {
		if _, sessionErr := h.Auth.SessionFromRequest(r); sessionErr == nil {
			http.Redirect(w, r, "/account?sso_error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
			return
		}
		h.renderPublic(w, r, "login", pageData{Title: "Anmelden", Version: h.Version, Error: err.Error(), Data: map[string]any{"Step": "email"}})
		return
	}

	switch claims.Purpose {
	case "link":
		h.finishOIDCLink(w, r, cfg, claims)
		return
	case "unlink":
		h.finishOIDCUnlink(w, r, cfg, claims)
		return
	case "existing":
		h.finishOIDCExistingLogin(w, r, cfg, claims)
		return
	case "reauth":
		h.finishOIDCReauth(w, r, cfg, claims)
		return
	case "direct", "login": // login is retained for in-flight states created before the upgrade.
		// Direct SSO is the only login path that may auto-provision a new user,
		// and oidcUser enforces cfg.AutoProvision before doing so.
	default:
		h.renderPublic(w, r, "login", pageData{Title: "Anmelden", Version: h.Version, Error: "Ungültiger SSO-Anmeldevorgang.", Data: map[string]any{"Step": "email"}})
		return
	}

	u, err := h.oidcUser(r.Context(), cfg, claims)
	if err != nil {
		h.renderPublic(w, r, "login", pageData{Title: "Anmelden", Version: h.Version, Error: err.Error(), Data: map[string]any{"Step": "email"}})
		return
	}
	token, _, err := h.Auth.CreateSession(r.Context(), u, r)
	if err != nil {
		http.Error(w, "Session error", 500)
		return
	}
	h.setSession(w, r, token)
	h.Audit.Write(r.Context(), r, u.ID, "auth.oidc_login", "auth", u.ID, map[string]any{"issuer": cfg.Issuer})
	_ = h.storeSettings(r.Context(), map[string]string{"oidc_last_success_fingerprint": oidcFingerprint(cfg.Issuer, cfg.ClientID, cfg.ClientSecret)}, false)
	target := claims.ReturnTo
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (h *Handler) boundOIDCUser(ctx context.Context, cfg oidc.Config, c oidc.Claims) (auth.User, error) {
	if strings.TrimSpace(c.UserID) == "" {
		return auth.User{}, errors.New("SSO-Anmeldung konnte nicht zugeordnet werden.")
	}
	issuer := strings.TrimSuffix(cfg.Issuer, "/")
	var u auth.User
	var linkedIssuer, linkedSubject string
	err := h.DB.QueryRow(ctx, `SELECT id::text,name,first_name,last_name,email,role,status,auth_type,language,timezone,must_change_password,created_at,last_login,last_sync,coalesce(oidc_issuer,''),coalesce(oidc_subject,'') FROM users WHERE id=$1`, c.UserID).Scan(
		&u.ID, &u.Name, &u.FirstName, &u.LastName, &u.Email, &u.Role, &u.Status, &u.AuthType, &u.Language, &u.Timezone, &u.MustChangePassword, &u.CreatedAt, &u.LastLogin, &u.LastSync, &linkedIssuer, &linkedSubject,
	)
	if err != nil || u.Status != "active" || u.AuthType != "oidc" {
		return auth.User{}, errors.New("SSO-Anmeldung konnte diesem ZentCal-Konto nicht zugeordnet werden.")
	}
	if linkedIssuer == "" && linkedSubject == "" {
		// Administratively prepared SSO accounts are intentionally created without
		// a provider subject. Bind them exactly once on their first email-first SSO
		// login, but only when the provider email matches the existing ZentCal email.
		if strings.TrimSpace(c.Email) == "" || !strings.EqualFold(strings.TrimSpace(c.Email), strings.TrimSpace(u.Email)) {
			return auth.User{}, errors.New("Die SSO-Identität passt nicht zu diesem ZentCal-Konto.")
		}
		var otherID string
		err = h.DB.QueryRow(ctx, `SELECT id::text FROM users WHERE oidc_issuer=$1 AND oidc_subject=$2 AND id<>$3`, issuer, c.Subject, u.ID).Scan(&otherID)
		if err == nil {
			return auth.User{}, errors.New("Diese SSO-Identität ist bereits mit einem anderen ZentCal-Konto verbunden.")
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return auth.User{}, err
		}
		cmd, bindErr := h.DB.Exec(ctx, `UPDATE users SET oidc_issuer=$1,oidc_subject=$2,must_change_password=false,updated_at=now() WHERE id=$3 AND auth_type='oidc' AND oidc_issuer IS NULL AND oidc_subject IS NULL`, issuer, c.Subject, u.ID)
		if bindErr != nil || cmd.RowsAffected() != 1 {
			return auth.User{}, errors.New("SSO-Identität konnte nicht mit diesem ZentCal-Konto verbunden werden.")
		}
		linkedIssuer, linkedSubject = issuer, c.Subject
	} else if strings.TrimSuffix(linkedIssuer, "/") != issuer || linkedSubject != c.Subject {
		return auth.User{}, errors.New("SSO-Anmeldung konnte diesem ZentCal-Konto nicht zugeordnet werden.")
	}

	name, firstName, lastName, email, role := u.Name, u.FirstName, u.LastName, u.Email, u.Role
	if cfg.SyncEmail && c.Email != "" {
		email = c.Email
	}
	if cfg.SyncGroups && u.Role != "owner" {
		role = oidc.RoleForGroups(cfg.GroupMapping, c.Groups)
	}
	cmd, err := h.DB.Exec(ctx, `UPDATE users SET name=$1,first_name=$2,last_name=$3,email=$4,role=$5,last_login=now(),updated_at=now() WHERE id=$6 AND auth_type='oidc' AND oidc_issuer=$7 AND oidc_subject=$8`, name, firstName, lastName, email, role, u.ID, linkedIssuer, linkedSubject)
	if err != nil || cmd.RowsAffected() != 1 {
		return auth.User{}, errors.New("SSO-Benutzer konnte nicht synchronisiert werden. Prüfe insbesondere, ob die E-Mail-Adresse bereits verwendet wird.")
	}
	if _, err := db.EnsurePersonalCalendar(ctx, h.DB, u.ID, name); err != nil {
		return auth.User{}, errors.New("Persönlicher Kalender konnte nicht aktualisiert werden.")
	}
	u.Name, u.FirstName, u.LastName, u.Email, u.Role = name, firstName, lastName, email, role
	return u, nil
}

func (h *Handler) finishOIDCExistingLogin(w http.ResponseWriter, r *http.Request, cfg oidc.Config, c oidc.Claims) {
	u, err := h.boundOIDCUser(r.Context(), cfg, c)
	if err != nil {
		h.Audit.Write(r.Context(), r, c.UserID, "auth.oidc_login_rejected", "auth", c.UserID, map[string]any{"issuer": strings.TrimSuffix(cfg.Issuer, "/")})
		h.renderPublic(w, r, "login", pageData{Title: "Anmelden", Version: h.Version, Error: err.Error(), Data: map[string]any{"Step": "email"}})
		return
	}
	token, _, err := h.Auth.CreateSession(r.Context(), u, r)
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	h.setSession(w, r, token)
	h.Audit.Write(r.Context(), r, u.ID, "auth.oidc_login", "auth", u.ID, map[string]any{"issuer": strings.TrimSuffix(cfg.Issuer, "/"), "flow": "existing"})
	_ = h.storeSettings(r.Context(), map[string]string{"oidc_last_success_fingerprint": oidcFingerprint(cfg.Issuer, cfg.ClientID, cfg.ClientSecret)}, false)
	target := c.ReturnTo
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (h *Handler) finishOIDCReauth(w http.ResponseWriter, r *http.Request, cfg oidc.Config, c oidc.Claims) {
	ss, err := h.Auth.SessionFromRequest(r)
	if err != nil || ss.User.ID != c.UserID || ss.User.AuthType != "oidc" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	u, err := h.boundOIDCUser(r.Context(), cfg, c)
	if err != nil || u.ID != ss.User.ID {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("Erneute SSO-Bestätigung ist fehlgeschlagen."), http.StatusSeeOther)
		return
	}
	reauthPurpose, reauthTarget := "", ""
	if targetURL, parseErr := url.Parse(c.ReturnTo); parseErr == nil {
		switch targetURL.Query().Get("reauth_action") {
		case "restore":
			reauthPurpose, reauthTarget = "backup_restore", targetURL.Query().Get("backup_id")
		case "delete":
			reauthPurpose, reauthTarget = "backup_delete", targetURL.Query().Get("backup_id")
		case "upload_restore":
			reauthPurpose, reauthTarget = "backup_upload_restore", "upload"
		}
	}
	if _, err := h.DB.Exec(r.Context(), `UPDATE sessions SET reauthenticated_at=now(),reauth_purpose=$3,reauth_target=$4 WHERE id=$1 AND user_id=$2`, ss.ID, ss.User.ID, reauthPurpose, reauthTarget); err != nil {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("Erneute SSO-Bestätigung konnte nicht gespeichert werden."), http.StatusSeeOther)
		return
	}
	h.Audit.Write(r.Context(), r, u.ID, "auth.oidc_reauthenticated", "auth", u.ID, map[string]any{"issuer": strings.TrimSuffix(cfg.Issuer, "/")})
	_ = h.storeSettings(r.Context(), map[string]string{"oidc_last_success_fingerprint": oidcFingerprint(cfg.Issuer, cfg.ClientID, cfg.ClientSecret)}, false)
	target := c.ReturnTo
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (h *Handler) finishOIDCLink(w http.ResponseWriter, r *http.Request, cfg oidc.Config, c oidc.Claims) {
	ss, err := h.Auth.SessionFromRequest(r)
	if err != nil || ss.User.ID != c.UserID {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if ss.User.AuthType == "oidc" {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("Dieses Konto ist bereits mit Single Sign-On verbunden."), http.StatusSeeOther)
		return
	}
	issuer := strings.TrimSuffix(cfg.Issuer, "/")
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("SSO-Verknüpfung konnte nicht gestartet werden."), http.StatusSeeOther)
		return
	}
	defer tx.Rollback(r.Context())

	var existingID string
	err = tx.QueryRow(r.Context(), `SELECT id::text FROM users WHERE oidc_issuer=$1 AND oidc_subject=$2`, issuer, c.Subject).Scan(&existingID)
	if err == nil && existingID != ss.User.ID {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("Diese SSO-Identität ist bereits mit einem anderen ZentCal-Konto verbunden."), http.StatusSeeOther)
		return
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("SSO-Verknüpfung konnte nicht geprüft werden."), http.StatusSeeOther)
		return
	}

	name, firstName, lastName, email, role := ss.User.Name, ss.User.FirstName, ss.User.LastName, ss.User.Email, ss.User.Role
	if cfg.SyncEmail && c.Email != "" {
		email = c.Email
	}
	if cfg.SyncGroups && ss.User.Role != "owner" {
		role = oidc.RoleForGroups(cfg.GroupMapping, c.Groups)
	}
	cmd, err := tx.Exec(r.Context(), `UPDATE users SET name=$1,first_name=$2,last_name=$3,email=$4,role=$5,auth_type='oidc',oidc_issuer=$6,oidc_subject=$7,must_change_password=false,updated_at=now() WHERE id=$8 AND auth_type='local'`, name, firstName, lastName, email, role, issuer, c.Subject, ss.User.ID)
	if err != nil || cmd.RowsAffected() != 1 {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("SSO konnte nicht verknüpft werden. Prüfe, ob die vom Provider gelieferte E-Mail bereits von einem anderen Konto verwendet wird."), http.StatusSeeOther)
		return
	}
	if _, err := db.EnsurePersonalCalendar(r.Context(), tx, ss.User.ID, name); err != nil {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("SSO konnte nicht verknüpft werden, weil der persönliche Kalender nicht aktualisiert werden konnte."), http.StatusSeeOther)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("SSO-Verknüpfung konnte nicht gespeichert werden."), http.StatusSeeOther)
		return
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "auth.oidc_linked", "user", ss.User.ID, map[string]any{"issuer": issuer})
	_ = h.storeSettings(r.Context(), map[string]string{"oidc_last_success_fingerprint": oidcFingerprint(cfg.Issuer, cfg.ClientID, cfg.ClientSecret)}, false)
	http.Redirect(w, r, "/account?sso_linked=1", http.StatusSeeOther)
}

func (h *Handler) finishOIDCUnlink(w http.ResponseWriter, r *http.Request, cfg oidc.Config, c oidc.Claims) {
	ss, err := h.Auth.SessionFromRequest(r)
	if err != nil || ss.User.ID != c.UserID {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !cfg.LocalLogin {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("SSO kann erst getrennt werden, wenn der lokale Login aktiviert ist."), http.StatusSeeOther)
		return
	}
	var name, email, language, linkedIssuer, linkedSubject, authType, status string
	if err := h.DB.QueryRow(r.Context(), `SELECT name,email,language,coalesce(oidc_issuer,''),coalesce(oidc_subject,''),auth_type,status FROM users WHERE id=$1`, ss.User.ID).Scan(&name, &email, &language, &linkedIssuer, &linkedSubject, &authType, &status); err != nil || authType != "oidc" || status != "active" {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("SSO-Verbindung konnte nicht geladen werden."), http.StatusSeeOther)
		return
	}
	if strings.TrimSuffix(linkedIssuer, "/") != strings.TrimSuffix(cfg.Issuer, "/") || linkedSubject != c.Subject {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("Zur Bestätigung muss dieselbe SSO-Identität verwendet werden, die mit diesem ZentCal-Konto verbunden ist."), http.StatusSeeOther)
		return
	}
	cfgSMTP, enabled, smtpErr := h.loadSMTPConfig(r.Context())
	if smtpErr != nil || !enabled {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("SSO kann nicht getrennt werden, solange SMTP nicht funktionsfähig aktiviert ist."), http.StatusSeeOther)
		return
	}
	temporary, err := security.RandomToken(12)
	if err != nil {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("Temporäres Passwort konnte nicht erzeugt werden."), http.StatusSeeOther)
		return
	}
	hash, err := security.PasswordHash(temporary)
	if err != nil {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("Temporäres Passwort konnte nicht erzeugt werden."), http.StatusSeeOther)
		return
	}
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("SSO-Verbindung konnte nicht getrennt werden."), http.StatusSeeOther)
		return
	}
	defer tx.Rollback(r.Context())
	cmd, err := tx.Exec(r.Context(), `UPDATE users SET password_hash=$1,must_change_password=true,auth_type='local',oidc_issuer=NULL,oidc_subject=NULL,updated_at=now() WHERE id=$2 AND auth_type='oidc' AND oidc_issuer=$3 AND oidc_subject=$4`, hash, ss.User.ID, linkedIssuer, linkedSubject)
	if err != nil || cmd.RowsAffected() != 1 {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("SSO-Verbindung konnte nicht getrennt werden."), http.StatusSeeOther)
		return
	}
	if _, err := tx.Exec(r.Context(), `DELETE FROM sessions WHERE user_id=$1`, ss.User.ID); err != nil {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("SSO-Verbindung konnte nicht vollständig getrennt werden."), http.StatusSeeOther)
		return
	}
	vars := map[string]string{"user_name": name, "email": email, "temporary_password": temporary}
	if err := h.sendTemplatedMail(r.Context(), r, cfgSMTP, email, language, "sso_unlinked", vars, "", ""); err != nil {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("SSO wurde nicht getrennt, weil das temporäre Passwort nicht per E-Mail zugestellt werden konnte: "+err.Error()), http.StatusSeeOther)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		http.Redirect(w, r, "/account?sso_error="+url.QueryEscape("SSO-Verbindung konnte nicht vollständig getrennt werden."), http.StatusSeeOther)
		return
	}
	h.Audit.Write(r.Context(), r, ss.User.ID, "auth.oidc_unlinked", "user", ss.User.ID, map[string]any{"issuer": linkedIssuer, "delivery": "smtp"})
	clearSession(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) oidcUser(ctx context.Context, cfg oidc.Config, c oidc.Claims) (auth.User, error) {
	var u auth.User
	var linkedIssuer, linkedSubject string
	scan := func(query string, args ...any) error {
		return h.DB.QueryRow(ctx, query, args...).Scan(&u.ID, &u.Name, &u.FirstName, &u.LastName, &u.Email, &u.Role, &u.Status, &u.CreatedAt, &u.LastLogin, &u.LastSync, &linkedIssuer, &linkedSubject)
	}
	issuer := strings.TrimSuffix(cfg.Issuer, "/")
	query := `SELECT id::text,name,first_name,last_name,email,role,status,created_at,last_login,last_sync,coalesce(oidc_issuer,''),coalesce(oidc_subject,'') FROM users WHERE oidc_issuer=$1 AND oidc_subject=$2`
	err := scan(query, issuer, c.Subject)
	if errors.Is(err, pgx.ErrNoRows) {
		var existingID, existingAuth, existingIssuer, existingSubject string
		emailErr := h.DB.QueryRow(ctx, `SELECT id::text,auth_type,coalesce(oidc_issuer,''),coalesce(oidc_subject,'') FROM users WHERE lower(email)=lower($1)`, c.Email).Scan(&existingID, &existingAuth, &existingIssuer, &existingSubject)
		if emailErr == nil {
			if existingAuth == "oidc" && existingIssuer == "" && existingSubject == "" {
				var otherID string
				dupErr := h.DB.QueryRow(ctx, `SELECT id::text FROM users WHERE oidc_issuer=$1 AND oidc_subject=$2 AND id<>$3`, issuer, c.Subject, existingID).Scan(&otherID)
				if dupErr == nil {
					return u, errors.New("Diese SSO-Identität ist bereits mit einem anderen ZentCal-Konto verbunden.")
				}
				if dupErr != nil && !errors.Is(dupErr, pgx.ErrNoRows) {
					return u, dupErr
				}
				cmd, bindErr := h.DB.Exec(ctx, `UPDATE users SET oidc_issuer=$1,oidc_subject=$2,must_change_password=false,updated_at=now() WHERE id=$3 AND auth_type='oidc' AND oidc_issuer IS NULL AND oidc_subject IS NULL`, issuer, c.Subject, existingID)
				if bindErr != nil || cmd.RowsAffected() != 1 {
					return u, errors.New("SSO-Identität konnte nicht mit diesem ZentCal-Konto verbunden werden.")
				}
				err = scan(`SELECT id::text,name,first_name,last_name,email,role,status,created_at,last_login,last_sync,coalesce(oidc_issuer,''),coalesce(oidc_subject,'') FROM users WHERE id=$1`, existingID)
				if err != nil {
					return u, err
				}
			} else {
				return u, errors.New("Für diese E-Mail-Adresse existiert bereits ein ZentCal-Konto. Melde dich zunächst lokal an und verbinde Single Sign-On in den Kontoeinstellungen.")
			}
		}
		if emailErr != nil && !errors.Is(emailErr, pgx.ErrNoRows) {
			return u, emailErr
		}
		if emailErr == nil {
			// Existing prepared OIDC account was bound above; skip auto-provisioning.
		} else if !cfg.AutoProvision {
			return u, errors.New("Für dieses SSO-Konto existiert noch kein ZentCal-Benutzer.")
		} else {
			random, randomErr := security.RandomToken(48)
			if randomErr != nil {
				return u, randomErr
			}
			hash, hashErr := security.PasswordHash(random)
			if hashErr != nil {
				return u, hashErr
			}
			fallbackName := strings.TrimSpace(c.Email)
			if at := strings.Index(fallbackName, "@"); at > 0 {
				fallbackName = fallbackName[:at]
			}
			if fallbackName == "" {
				fallbackName = "SSO Benutzer"
			}
			name, firstName, lastName := fallbackName, fallbackName, ""
			if cfg.SyncName && strings.TrimSpace(c.Name) != "" {
				name, firstName, lastName = c.Name, c.FirstName, c.LastName
			}
			u = auth.User{ID: security.UUID(), Name: name, FirstName: firstName, LastName: lastName, Email: c.Email, Role: "user", Status: "active"}
			if cfg.SyncGroups {
				u.Role = oidc.RoleForGroups(cfg.GroupMapping, c.Groups)
			}
			_, err = h.DB.Exec(ctx, `INSERT INTO users(id,name,first_name,last_name,email,password_hash,role,status,auth_type,oidc_issuer,oidc_subject) VALUES($1,$2,$3,$4,$5,$6,$7,'active','oidc',$8,$9)`, u.ID, u.Name, u.FirstName, u.LastName, u.Email, hash, u.Role, issuer, c.Subject)
			if err != nil {
				return u, err
			}
		}
	} else if err != nil {
		return u, err
	}
	if u.Status != "active" {
		return u, errors.New("Dieses ZentCal-Konto ist deaktiviert oder gesperrt.")
	}
	name, firstName, lastName, email, role := u.Name, u.FirstName, u.LastName, u.Email, u.Role
	// Existing ZentCal accounts keep the names maintained in ZentCal.
	if cfg.SyncEmail && c.Email != "" {
		email = c.Email
	}
	if cfg.SyncGroups && u.Role != "owner" {
		role = oidc.RoleForGroups(cfg.GroupMapping, c.Groups)
	}
	_, err = h.DB.Exec(ctx, `UPDATE users SET name=$1,first_name=$2,last_name=$3,email=$4,role=$5,auth_type='oidc',oidc_issuer=$6,oidc_subject=$7,must_change_password=false,last_login=now(),updated_at=now() WHERE id=$8`, name, firstName, lastName, email, role, issuer, c.Subject, u.ID)
	if err != nil {
		return u, errors.New("SSO-Benutzer konnte nicht synchronisiert werden. Prüfe insbesondere, ob die E-Mail-Adresse bereits verwendet wird.")
	}
	if _, err := db.EnsurePersonalCalendar(ctx, h.DB, u.ID, name); err != nil {
		return u, err
	}
	u.Name, u.FirstName, u.LastName, u.Email, u.Role, u.AuthType, u.MustChangePassword = name, firstName, lastName, email, role, "oidc", false
	return u, nil
}

func oidcFingerprint(issuer, clientID, secret string) string {
	sum := sha256.Sum256([]byte(strings.TrimSuffix(strings.TrimSpace(issuer), "/") + "\x00" + strings.TrimSpace(clientID) + "\x00" + secret))
	return hex.EncodeToString(sum[:])
}
