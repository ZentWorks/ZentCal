package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zentworks/zentcal/internal/security"
)

type Client struct {
	DB      *pgxpool.Pool
	Secrets *security.SecretBox
	HTTP    *http.Client
}
type Config struct {
	Enabled                                                                       bool
	Issuer, ClientID, ClientSecret, Scopes, GroupsClaim, GroupMapping, AuthMethod string
	AutoProvision, SyncName, SyncEmail, SyncGroups, LocalLogin                    bool
}
type Discovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	Issuer                string `json:"issuer"`
}
type Claims struct {
	Subject, Name, FirstName, LastName, Email, ReturnTo string
	Purpose, UserID                                     string
	EmailVerified                                       *bool
	Groups                                              []string
}
type jwtClaims struct {
	Iss               string `json:"iss"`
	Sub               string `json:"sub"`
	Aud               any    `json:"aud"`
	Azp               string `json:"azp"`
	Exp               int64  `json:"exp"`
	Iat               int64  `json:"iat"`
	Nbf               int64  `json:"nbf"`
	Nonce             string `json:"nonce"`
	Name              string `json:"name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	EmailVerified     *bool  `json:"email_verified"`
}

func New(db *pgxpool.Pool, secrets *security.SecretBox) *Client {
	return &Client{DB: db, Secrets: secrets, HTTP: &http.Client{Timeout: 10 * time.Second}}
}
func (c *Client) Load(ctx context.Context) (Config, error) {
	vals := map[string]string{}
	rows, err := c.DB.Query(ctx, `SELECT key,value,secret FROM settings WHERE key LIKE 'oidc_%'`)
	if err != nil {
		return Config{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		var sec bool
		if rows.Scan(&k, &v, &sec) != nil {
			continue
		}
		if sec && v != "" {
			v, err = c.Secrets.Decrypt(v)
			if err != nil {
				return Config{}, err
			}
		}
		vals[k] = v
	}
	b := func(k string, def bool) bool {
		v, ok := vals[k]
		if !ok {
			return def
		}
		return v == "true"
	}
	return Config{Enabled: b("oidc_enabled", false), Issuer: vals["oidc_issuer"], ClientID: vals["oidc_client_id"], ClientSecret: vals["oidc_client_secret"], Scopes: def(vals["oidc_scopes"], "openid profile email"), GroupsClaim: def(vals["oidc_groups_claim"], "groups"), GroupMapping: vals["oidc_group_mapping"], AuthMethod: def(vals["oidc_auth_method"], "client_secret_post"), AutoProvision: b("oidc_auto_provision", true), SyncName: b("oidc_sync_name", true), SyncEmail: b("oidc_sync_email", true), SyncGroups: b("oidc_sync_groups", false), LocalLogin: b("oidc_local_login", true)}, rows.Err()
}
func def(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}
func (c *Client) Discover(ctx context.Context, issuer string) (Discovery, error) {
	issuer = strings.TrimSuffix(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return Discovery{}, errors.New("Issuer URL ist erforderlich.")
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return Discovery{}, errors.New("Issuer muss eine vollständige HTTPS-URL sein.")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Discovery{}, fmt.Errorf("OIDC Discovery fehlgeschlagen: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Discovery{}, fmt.Errorf("OIDC Discovery antwortete mit HTTP %d", resp.StatusCode)
	}
	var d Discovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return d, err
	}
	if strings.TrimSuffix(d.Issuer, "/") != issuer || d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return d, errors.New("OIDC Discovery ist unvollständig oder Issuer stimmt nicht überein.")
	}
	for _, endpoint := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI} {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return d, errors.New("OIDC Discovery enthält einen unsicheren oder ungültigen Endpoint.")
		}
	}
	return d, nil
}
func (c *Client) Begin(ctx context.Context, cfg Config, redirectURI, returnTo string) (string, error) {
	return c.BeginFlow(ctx, cfg, redirectURI, returnTo, "direct", "")
}

func (c *Client) BeginFlow(ctx context.Context, cfg Config, redirectURI, returnTo, purpose, userID string) (string, error) {
	_, _ = c.DB.Exec(ctx, `DELETE FROM oidc_states WHERE expires_at<=now()`)
	d, err := c.Discover(ctx, cfg.Issuer)
	if err != nil {
		return "", err
	}
	switch purpose {
	case "direct", "login": // "login" remains accepted for short-lived pre-upgrade states.
		userID = ""
	case "existing", "reauth", "link", "unlink":
		if strings.TrimSpace(userID) == "" {
			return "", errors.New("Für diesen OIDC-Vorgang fehlt der ZentCal-Benutzer.")
		}
	default:
		return "", errors.New("Ungültiger OIDC-Vorgang.")
	}
	state, err := security.RandomToken(32)
	if err != nil {
		return "", err
	}
	nonce, err := security.RandomToken(24)
	if err != nil {
		return "", err
	}
	verifier, err := security.RandomToken(48)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	_, err = c.DB.Exec(ctx, `INSERT INTO oidc_states(state_hash,nonce,verifier,redirect_uri,return_to,purpose,user_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,NULLIF($7,'')::uuid,now()+interval '10 minutes')`, security.TokenHash(state), nonce, verifier, redirectURI, returnTo, purpose, userID)
	if err != nil {
		return "", err
	}
	q := url.Values{"client_id": {cfg.ClientID}, "response_type": {"code"}, "redirect_uri": {redirectURI}, "scope": {cfg.Scopes}, "state": {state}, "nonce": {nonce}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	return d.AuthorizationEndpoint + "?" + q.Encode(), nil
}
func (c *Client) Callback(ctx context.Context, cfg Config, state, code string) (Claims, error) {
	var nonce, verifier, redirectURI, returnTo, purpose, userID string
	err := c.DB.QueryRow(ctx, `DELETE FROM oidc_states WHERE state_hash=$1 AND expires_at>now() RETURNING nonce,verifier,redirect_uri,return_to,purpose,coalesce(user_id::text,'')`, security.TokenHash(state)).Scan(&nonce, &verifier, &redirectURI, &returnTo, &purpose, &userID)
	if err != nil {
		return Claims{}, errors.New("OIDC state ist ungültig oder abgelaufen.")
	}
	d, err := c.Discover(ctx, cfg.Issuer)
	if err != nil {
		return Claims{}, err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "client_id": {cfg.ClientID}, "code_verifier": {verifier}}
	if cfg.AuthMethod != "client_secret_basic" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cfg.AuthMethod == "client_secret_basic" {
		req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Claims{}, fmt.Errorf("OIDC Token-Austausch fehlgeschlagen: %w", err)
	}
	defer resp.Body.Close()
	var tr struct {
		IDToken     string `json:"id_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return Claims{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || tr.IDToken == "" {
		return Claims{}, fmt.Errorf("OIDC Token-Austausch fehlgeschlagen: %s %s", tr.Error, tr.Description)
	}
	raw, claimsMap, jc, err := c.verifyJWT(ctx, tr.IDToken, d.JWKSURI, cfg.ClientID, strings.TrimSuffix(cfg.Issuer, "/"), nonce)
	if err != nil {
		return Claims{}, err
	}
	_ = raw
	groups := extractGroups(claimsMap, cfg.GroupsClaim)
	name := jc.Name
	if name == "" {
		name = jc.PreferredUsername
	}
	if name == "" {
		name = jc.Email
	}
	firstName, lastName := strings.TrimSpace(jc.GivenName), strings.TrimSpace(jc.FamilyName)
	if firstName == "" {
		parts := strings.Fields(name)
		if len(parts) > 0 {
			firstName = parts[0]
			if len(parts) > 1 {
				lastName = strings.Join(parts[1:], " ")
			}
		}
	}
	return Claims{Subject: jc.Sub, Name: name, FirstName: firstName, LastName: lastName, Email: strings.ToLower(jc.Email), EmailVerified: jc.EmailVerified, Groups: groups, ReturnTo: returnTo, Purpose: purpose, UserID: userID}, nil
}
func extractGroups(m map[string]any, claim string) []string {
	var v any = m
	for _, part := range strings.Split(claim, ".") {
		obj, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = obj[part]
	}
	switch x := v.(type) {
	case []any:
		out := []string{}
		for _, item := range x {
			if value, ok := item.(string); ok {
				out = append(out, value)
			}
		}
		return out
	case string:
		if strings.TrimSpace(x) == "" {
			return nil
		}
		return []string{x}
	default:
		return nil
	}
}

func RoleForGroups(mapping string, groups []string) string {
	m := map[string]string{}
	for _, line := range strings.Split(mapping, "\n") {
		p := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(p) == 2 {
			group, role := strings.TrimSpace(p[0]), strings.TrimSpace(p[1])
			if group != "" && (role == "administrator" || role == "user") {
				m[group] = role
			}
		}
	}
	for _, g := range groups {
		if m[g] == "administrator" {
			return "administrator"
		}
	}
	return "user"
}
func (c *Client) verifyJWT(ctx context.Context, token, jwksURI, clientID, issuer, nonce string) ([]byte, map[string]any, jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, jwtClaims{}, errors.New("Ungültiges OIDC ID-Token.")
	}
	dec := func(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
	hb, err := dec(parts[0])
	if err != nil {
		return nil, nil, jwtClaims{}, err
	}
	pb, err := dec(parts[1])
	if err != nil {
		return nil, nil, jwtClaims{}, err
	}
	sig, err := dec(parts[2])
	if err != nil {
		return nil, nil, jwtClaims{}, err
	}
	var h struct{ Alg, Kid string }
	if json.Unmarshal(hb, &h) != nil {
		return nil, nil, jwtClaims{}, errors.New("Ungültiger JWT Header.")
	}
	var jm map[string]any
	var jc jwtClaims
	if json.Unmarshal(pb, &jm) != nil || json.Unmarshal(pb, &jc) != nil {
		return nil, nil, jwtClaims{}, errors.New("Ungültige JWT Claims.")
	}
	key, err := c.fetchKey(ctx, jwksURI, h.Kid, h.Alg)
	if err != nil {
		return nil, nil, jwtClaims{}, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch k := key.(type) {
	case *rsa.PublicKey:
		if h.Alg != "RS256" || rsa.VerifyPKCS1v15(k, crypto.SHA256, sum[:], sig) != nil {
			return nil, nil, jwtClaims{}, errors.New("OIDC ID-Token Signatur ist ungültig.")
		}
	case *ecdsa.PublicKey:
		if h.Alg != "ES256" || len(sig) != 64 || !ecdsa.Verify(k, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return nil, nil, jwtClaims{}, errors.New("OIDC ID-Token Signatur ist ungültig.")
		}
	default:
		return nil, nil, jwtClaims{}, errors.New("Nicht unterstützter OIDC Signaturschlüssel.")
	}
	now := time.Now().Unix()
	if strings.TrimSuffix(jc.Iss, "/") != issuer || jc.Sub == "" || jc.Exp < now-60 || jc.Nonce != nonce || !audHas(jc.Aud, clientID) || jc.Iat > now+60 || (jc.Nbf != 0 && jc.Nbf > now+60) {
		return nil, nil, jwtClaims{}, errors.New("OIDC ID-Token Claims sind ungültig.")
	}
	if audCount(jc.Aud) > 1 && jc.Azp != clientID {
		return nil, nil, jwtClaims{}, errors.New("OIDC ID-Token azp Claim ist ungültig.")
	}
	if jc.Email == "" {
		return nil, nil, jwtClaims{}, errors.New("OIDC Provider lieferte keine E-Mail-Adresse.")
	}
	return pb, jm, jc, nil
}
func audHas(v any, want string) bool {
	switch x := v.(type) {
	case string:
		return x == want
	case []any:
		for _, a := range x {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
func audCount(v any) int {
	switch x := v.(type) {
	case string:
		if x == "" {
			return 0
		}
		return 1
	case []any:
		return len(x)
	default:
		return 0
	}
}
func (c *Client) fetchKey(ctx context.Context, uri, kid, alg string) (any, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS antwortete mit HTTP %d", resp.StatusCode)
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set) != nil {
		return nil, errors.New("JWKS konnte nicht gelesen werden.")
	}
	for _, k := range set.Keys {
		if ks, _ := k["kid"].(string); kid != "" && ks != kid {
			continue
		}
		kty, _ := k["kty"].(string)
		if kty == "RSA" && alg == "RS256" {
			nS, _ := k["n"].(string)
			eS, _ := k["e"].(string)
			nb, _ := base64.RawURLEncoding.DecodeString(nS)
			eb, _ := base64.RawURLEncoding.DecodeString(eS)
			e := 0
			for _, b := range eb {
				e = e*256 + int(b)
			}
			return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
		}
		if kty == "EC" && alg == "ES256" {
			crv, _ := k["crv"].(string)
			if crv != "P-256" {
				continue
			}
			xs, _ := k["x"].(string)
			ys, _ := k["y"].(string)
			xb, _ := base64.RawURLEncoding.DecodeString(xs)
			yb, _ := base64.RawURLEncoding.DecodeString(ys)
			return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}, nil
		}
	}
	return nil, errors.New("Passender OIDC Signaturschlüssel wurde nicht gefunden.")
}
func IsNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
