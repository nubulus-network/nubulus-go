package nubulus

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func wafServer(t *testing.T, routes map[string]func(w http.ResponseWriter, r *http.Request)) *WAFClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"INVALID_TOKEN","message":"no"}`))
			return
		}
		h, ok := routes[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"NOT_FOUND","message":"no such route"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	c, err := New(context.Background(), Config{WAFEndpoint: srv.URL, TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "tok"})})
	if err != nil {
		t.Fatal(err)
	}
	return c.WAF
}

func TestWAFSitesAndCurrentConfig(t *testing.T) {
	waf := wafServer(t, map[string]func(http.ResponseWriter, *http.Request){
		"/api/v1/tenants": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"data":[{"id":"t1","name":"Tienda","domains":["tienda.example"],"waf_enabled":true}],"total":1}`))
		},
		"/api/v1/tenants/t1/config/versions": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("limit") != "1" {
				t.Errorf("CurrentConfig must ask for one version, got %q", r.URL.RawQuery)
			}
			w.Write([]byte(`{"data":[{"revision":7,"source":"user","change_summary":[{"section":"engine","op":"update","field":"paranoia_level","from":1,"to":2}]}],"total":7}`))
		},
		"/api/v1/tenants/t1/config/versions/7": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"revision":7,"snapshot":{"schema":1,"engine":{"paranoia_level":2},"future_section":{"x":1}}}`))
		},
	})
	sites, err := waf.ListSites(context.Background())
	if err != nil || len(sites) != 1 || sites[0].Domains[0] != "tienda.example" {
		t.Fatalf("ListSites: %+v %v", sites, err)
	}
	v, err := waf.CurrentConfig(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	if err := json.Unmarshal(v.Snapshot, &snap); err != nil || snap["future_section"] == nil {
		t.Fatalf("the snapshot must pass through untouched, including unknown sections: %s", v.Snapshot)
	}
}

func TestWAFQueryLogsSendsFilters(t *testing.T) {
	from := time.Date(2026, 11, 1, 0, 0, 0, 0, time.FixedZone("CET", 3600))
	waf := wafServer(t, map[string]func(http.ResponseWriter, *http.Request){
		"/api/v1/tenants/t1/logs": func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			want := map[string]string{"action": "blocked", "attack_type": "sqli,xss", "status": "!2xx", "from": "2026-10-31T23:00:00Z", "limit": "50", "min_score": "5"}
			for k, v := range want {
				if q.Get(k) != v {
					t.Errorf("%s = %q, want %q", k, q.Get(k), v)
				}
			}
			if q.Has("ip") || q.Has("offset") {
				t.Errorf("zero values must not be sent: %s", r.URL.RawQuery)
			}
			w.Write([]byte(`{"data":[{"id":"l1","path":"/login","matched_rules":[{"rule_id":"942100","score":5}],"attack_types":["sqli"]}],"total":1,"limit":50,"offset":0}`))
		},
	})
	page, err := waf.QueryLogs(context.Background(), "t1", LogQuery{Action: "blocked", AttackType: "sqli,xss", Status: "!2xx", From: from, Limit: 50, MinScore: 5})
	if err != nil || page.Total != 1 || page.Data[0].MatchedRules[0].RuleID != "942100" {
		t.Fatalf("QueryLogs: %+v %v", page, err)
	}
}

func TestWAFTopAndErrors(t *testing.T) {
	waf := wafServer(t, map[string]func(http.ResponseWriter, *http.Request){
		"/api/v1/tenants/t1/analytics/top": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("dimension") != "ip" || r.URL.Query().Get("range") != "24h" {
				t.Errorf("query: %s", r.URL.RawQuery)
			}
			w.Write([]byte(`{"dimension":"ip","total":10,"items":[{"value":"203.0.113.9","total":8,"blocked":8}]}`))
		},
	})
	raw, err := waf.AnalyticsTop(context.Background(), "t1", "ip", 5, AnalyticsQuery{Range: "24h"})
	if err != nil || !strings.Contains(string(raw), "203.0.113.9") {
		t.Fatalf("AnalyticsTop: %s %v", raw, err)
	}
	if _, err := waf.GetSite(context.Background(), "otro"); !IsNotFound(err) {
		t.Fatalf("a missing site must be a typed 404, got %v", err)
	}
}
