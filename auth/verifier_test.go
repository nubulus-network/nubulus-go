package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	issuer  = "https://idp.test"
	project = "385111705782321341"
)

func setup(t *testing.T) (*rsa.PrivateKey, *Verifier) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": "k1", "kty": "RSA", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(srv.Close)
	return key, New(issuer, project, srv.URL, nil)
}

func claims(mod func(jwt.MapClaims)) jwt.MapClaims {
	c := jwt.MapClaims{
		"iss": issuer, "sub": "user-1", "aud": []string{"panel", project}, "client_id": "mcp",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		"urn:zitadel:iam:user:resourceowner:id":             "org-1",
		"urn:zitadel:iam:user:resourceowner:name":           "ejemplo",
		"urn:zitadel:iam:org:project:roles":                 map[string]any{"account.owner": map[string]any{"org-1": "x"}},
		"urn:zitadel:iam:org:project:" + project + ":roles": map[string]any{"account.owner": map[string]any{"org-1": "x"}},
		"urn:zitadel:iam:org:project:999:roles":             map[string]any{"account.admin": map[string]any{}},
	}
	if mod != nil {
		mod(c)
	}
	return c
}

func sign(t *testing.T, key *rsa.PrivateKey, c jwt.MapClaims) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestValidToken(t *testing.T) {
	key, v := setup(t)
	c, err := v.Verify(context.Background(), sign(t, key, claims(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "user-1" || c.OrgID != "org-1" || c.OrgName != "ejemplo" || c.ClientID != "mcp" {
		t.Fatalf("claims: %+v", c)
	}
	if len(c.Roles) != 1 || c.Roles[0] != "account.owner" {
		t.Fatalf("roles must come from this project only: %v", c.Roles)
	}
}

func TestRejected(t *testing.T) {
	key, v := setup(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := map[string]string{
		"wrong audience": sign(t, key, claims(func(c jwt.MapClaims) { c["aud"] = []string{"panel"} })),
		"wrong issuer":   sign(t, key, claims(func(c jwt.MapClaims) { c["iss"] = "https://evil.test" })),
		"expired":        sign(t, key, claims(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() })),
		"no exp":         sign(t, key, claims(func(c jwt.MapClaims) { delete(c, "exp") })),
		"no subject":     sign(t, key, claims(func(c jwt.MapClaims) { delete(c, "sub") })),
		"other key":      sign(t, other, claims(nil)),
	}
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, claims(nil))
	hs.Header["kid"] = "k1"
	cases["HS256"], _ = hs.SignedString([]byte("secret"))
	none := jwt.NewWithClaims(jwt.SigningMethodNone, claims(nil))
	cases["alg none"], _ = none.SignedString(jwt.UnsafeAllowNoneSignatureType)

	for name, tok := range cases {
		if _, err := v.Verify(context.Background(), tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
