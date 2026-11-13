// Package auth validates platform JWTs issued by Zitadel, the same way
// the six services do (dns-api/internal/adapters/secondary/auth/zitadel.go):
// RS256 signature against the instance JWKS, exact issuer, and the platform
// project id among the audiences.
//
// It is stricter than the services in two places, both on purpose: only RS256
// is accepted (the services accept any RSA variant), and `exp` is required
// (the services accept a token without one).
//
// This is a candidate for the shared nubulus-go/auth package of RFC 0011 §10.
package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims is what the server needs from a platform token.
type Claims struct {
	Subject    string
	ClientID   string
	OrgID      string // urn:zitadel:iam:user:resourceowner:id
	OrgName    string // urn:zitadel:iam:user:resourceowner:name
	Roles      []string
	Expiration time.Time
}

// Verifier validates platform tokens.
type Verifier struct {
	issuer    string
	projectID string
	jwksURL   string
	http      *http.Client

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	lastFetch time.Time
}

// New builds a verifier. jwksURL is normally issuer + "/oauth/v2/keys".
func New(issuer, projectID, jwksURL string, client *http.Client) *Verifier {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Verifier{issuer: issuer, projectID: projectID, jwksURL: jwksURL, http: client, keys: map[string]*rsa.PublicKey{}}
}

// LooksLikeJWT reports whether s has the three-segment shape of a JWS.
func LooksLikeJWT(s string) bool { return strings.Count(s, ".") == 2 }

// Verify validates a token and extracts its claims.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	tok, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("kid header not found")
		}
		return v.key(ctx, kid)
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	mc, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("auth: unexpected claims type")
	}
	aud, _ := mc.GetAudience()
	if !contains(aud, v.projectID) {
		return nil, errors.New("auth: project audience missing")
	}
	c := &Claims{}
	c.Subject, _ = mc["sub"].(string)
	c.ClientID, _ = mc["client_id"].(string)
	c.OrgID, _ = mc["urn:zitadel:iam:user:resourceowner:id"].(string)
	c.OrgName, _ = mc["urn:zitadel:iam:user:resourceowner:name"].(string)
	if exp, err := mc.GetExpirationTime(); err == nil && exp != nil {
		c.Expiration = exp.Time
	}
	c.Roles = projectRoles(mc, v.projectID)
	if c.Subject == "" {
		return nil, errors.New("auth: token has no subject")
	}
	return c, nil
}

// projectRoles reads the role names from both variants of the role claim, like
// accounts-api's Claims.ProjectRoles. Only this project's scoped claim is read,
// never a project-grant variant.
func projectRoles(mc jwt.MapClaims, projectID string) []string {
	seen := map[string]bool{}
	for _, key := range []string{"urn:zitadel:iam:org:project:roles", "urn:zitadel:iam:org:project:" + projectID + ":roles"} {
		m, ok := mc[key].(map[string]any)
		if !ok {
			continue
		}
		for role := range m {
			if role != "" {
				seen[role] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// key returns the public key for kid, refetching the JWKS when the kid is
// unknown (key rotation), at most once a minute.
func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	k, ok := v.keys[kid]
	stale := time.Since(v.lastFetch) > time.Minute
	v.mu.RUnlock()
	if ok {
		return k, nil
	}
	if !stale {
		return nil, fmt.Errorf("unknown kid %q", kid)
	}
	if err := v.fetch(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown kid %q", kid)
}

func (v *Verifier) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: status %d", resp.StatusCode)
	}
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	v.mu.Lock()
	v.keys, v.lastFetch = keys, time.Now()
	v.mu.Unlock()
	return nil
}

func contains(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}
