package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testVerifyRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	e := big.NewInt(int64(key.PublicKey.E)).Bytes()
	jwks, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "k1", "alg": "RS256", "n": enc(key.PublicKey.N.Bytes()), "e": enc(e)}}})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	defer server.Close()
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{"iss": "https://issuer.example", "sub": "user-1", "aud": "zentcal", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": "nonce-1", "email": "user@example.com", "email_verified": true})
	input := enc(header) + "." + enc(claims)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	token := input + "." + enc(sig)
	client := &Client{HTTP: &http.Client{Timeout: time.Second}}
	_, _, got, err := client.verifyJWT(context.Background(), token, server.URL, "zentcal", "https://issuer.example", "nonce-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Email != "user@example.com" || got.Sub != "user-1" {
		t.Fatalf("unexpected claims: %#v", got)
	}
	if _, _, _, err := client.verifyJWT(context.Background(), token, server.URL, "zentcal", "https://issuer.example", "wrong"); err == nil {
		t.Fatal("wrong nonce must fail")
	}
}
