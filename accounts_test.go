package nubulus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
)

func TestAccountsMeWithTokenSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/accounts/me" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer user-token" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"INVALID_TOKEN","message":"no"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":[{"account":{"id":"acct_1","name":"Ejemplo","slug":"ejemplo","type":"personal","status":"active"},"role":"owner"}]}`))
	}))
	defer srv.Close()

	c, err := New(context.Background(), Config{
		AccountsEndpoint: srv.URL,
		TokenSource:      oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "user-token"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ms, err := c.Accounts.Me(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].Role != "owner" || ms[0].Account.Slug != "ejemplo" {
		t.Fatalf("unexpected: %+v", ms)
	}

	bad, _ := New(context.Background(), Config{
		AccountsEndpoint: srv.URL,
		TokenSource:      oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "other"}),
	})
	_, err = bad.Accounts.Me(context.Background())
	if StatusOf(err) != http.StatusUnauthorized || CodeOf(err) != "INVALID_TOKEN" {
		t.Fatalf("expected a typed 401, got %v", err)
	}
}
