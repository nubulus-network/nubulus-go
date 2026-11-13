package nubulus

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// WAFClient is waf-api. A "site" here is what the API calls a tenant: one
// protected web site with its domains, origin and security configuration.
//
// The read surface only, for now: sites, configuration (current snapshot,
// version history, what the edge actually loads), request logs and analytics.
type WAFClient struct {
	service
}

// Site is a WAF site (a tenant in the API).
type Site struct {
	ID                 string          `json:"id"`
	AccountID          string          `json:"account_id"`
	Name               string          `json:"name"`
	Slug               string          `json:"slug"`
	Domains            []string        `json:"domains"`
	OriginURL          string          `json:"origin_url"`
	WAFEnabled         bool            `json:"waf_enabled"`
	EngineSettings     json.RawMessage `json:"engine_settings,omitempty"`
	AnomalyThreshold   int             `json:"anomaly_threshold"`
	RateLimitRPS       int             `json:"rate_limit_rps"`
	RateLimitWindow    string          `json:"rate_limit_window"`
	AllowedIPs         []string        `json:"allowed_ips"`
	SharedIntelOptIn   bool            `json:"shared_intel_opt"`
	BlockAICrawlers    bool            `json:"block_ai_crawlers"`
	UpstreamHostMode   string          `json:"upstream_host_mode"`
	UpstreamHostCustom string          `json:"upstream_host_custom,omitempty"`
	TierID             string          `json:"tier_id"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

// ListSites returns the sites of the caller's account.
func (c *WAFClient) ListSites(ctx context.Context) ([]Site, error) {
	var out struct {
		Data []Site `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/tenants?limit=100", nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// GetSite returns one site.
func (c *WAFClient) GetSite(ctx context.Context, siteID string) (*Site, error) {
	var out Site
	if err := c.do(ctx, http.MethodGet, "/api/v1/tenants/"+url.PathEscape(siteID), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ConfigVersion is one version of a site's security configuration (waf-api
// RFC 0008). Snapshot is only present when fetching a single version, and is
// kept as raw JSON: its schema is versioned by waf-api (the "schema" field)
// and passing it through untouched is what keeps this client from breaking
// when a section is added.
type ConfigVersion struct {
	Revision       int             `json:"revision"`
	ParentRevision *int            `json:"parent_revision"`
	ContentHash    string          `json:"content_hash"`
	BundleRevision string          `json:"bundle_revision"`
	Source         string          `json:"source"`
	ChangeSummary  []ConfigChange  `json:"change_summary"`
	RestoredFrom   *int            `json:"restored_from"`
	Actor          ConfigActor     `json:"actor"`
	Label          string          `json:"label"`
	Pinned         bool            `json:"pinned"`
	CreatedAt      time.Time       `json:"created_at"`
	Snapshot       json.RawMessage `json:"snapshot,omitempty"`
}

// ConfigChange is one entry of a version's change summary.
type ConfigChange struct {
	Section string `json:"section"`
	Op      string `json:"op"`
	Field   string `json:"field,omitempty"`
	ID      string `json:"id,omitempty"`
	Label   string `json:"label,omitempty"`
	From    any    `json:"from,omitempty"`
	To      any    `json:"to,omitempty"`
}

// ConfigActor is who made a change.
type ConfigActor struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

// ListConfigVersions returns the most recent versions first, without
// snapshots. before, if non-zero, pages back from that revision.
func (c *WAFClient) ListConfigVersions(ctx context.Context, siteID string, limit, before int) ([]ConfigVersion, int, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if before > 0 {
		q.Set("before", strconv.Itoa(before))
	}
	var out struct {
		Data  []ConfigVersion `json:"data"`
		Total int             `json:"total"`
	}
	path := "/api/v1/tenants/" + url.PathEscape(siteID) + "/config/versions"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, 0, err
	}
	return out.Data, out.Total, nil
}

// GetConfigVersion returns one version with its snapshot.
func (c *WAFClient) GetConfigVersion(ctx context.Context, siteID string, revision int) (*ConfigVersion, error) {
	var out ConfigVersion
	path := fmt.Sprintf("/api/v1/tenants/%s/config/versions/%d", url.PathEscape(siteID), revision)
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CurrentConfig returns the latest version with its snapshot: the security
// configuration the site has now.
func (c *WAFClient) CurrentConfig(ctx context.Context, siteID string) (*ConfigVersion, error) {
	list, _, err := c.ListConfigVersions(ctx, siteID, 1, 0)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, &APIError{Status: http.StatusNotFound, Code: CodeNotFound, Message: "site has no configuration versions"}
	}
	return c.GetConfigVersion(ctx, siteID, list[0].Revision)
}

// EngineStatus is what the edge actually loads for a site. Fallback means
// the full configuration does not compile and the site is protected by OWASP
// CRS alone until it is fixed.
type EngineStatus struct {
	BundleRevision string            `json:"bundle_revision"`
	Fallback       bool              `json:"fallback"`
	FallbackError  string            `json:"fallback_error,omitempty"`
	ActiveRules    int               `json:"active_rules"`
	SkippedRules   []json.RawMessage `json:"skipped_rules"`
}

// EngineStatus returns what the edge loads for a site.
func (c *WAFClient) EngineStatus(ctx context.Context, siteID string) (*EngineStatus, error) {
	var out EngineStatus
	if err := c.do(ctx, http.MethodGet, "/api/v1/tenants/"+url.PathEscape(siteID)+"/engine-status", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RuleMatch is one rule that matched a request.
type RuleMatch struct {
	RuleID      string `json:"rule_id"`
	Phase       int    `json:"phase"`
	Score       int    `json:"score"`
	Action      string `json:"action"`
	Target      string `json:"target"`
	Description string `json:"description"`
}

// RequestLog is one request processed by the WAF. waf-api redacts the values
// of Authorization, Proxy-Authorization, X-Api-Key, Set-Cookie and of every
// cookie at ingestion; everything else in the headers, the path and the query
// string is whatever the client sent, attacker-controlled by definition.
type RequestLog struct {
	ID              string            `json:"id"`
	TenantID        string            `json:"tenant_id"`
	Timestamp       time.Time         `json:"timestamp"`
	Method          string            `json:"method"`
	Path            string            `json:"path"`
	QueryString     string            `json:"query_string"`
	Host            string            `json:"host"`
	RequestHeaders  map[string]string `json:"request_headers"`
	RequestBodyHash string            `json:"request_body_hash"`
	ContentType     string            `json:"content_type"`
	ClientIP        string            `json:"client_ip"`
	ClientASN       int               `json:"client_asn"`
	ClientASNOrg    string            `json:"client_asn_org"`
	ClientCountry   string            `json:"client_country"`
	StatusCode      int               `json:"status_code"`
	ResponseHeaders map[string]string `json:"response_headers"`
	Action          string            `json:"action"`
	TotalScore      int               `json:"total_score"`
	MatchedRules    []RuleMatch       `json:"matched_rules"`
	BlockReason     string            `json:"block_reason"`
	ProcessingTime  int64             `json:"processing_time"` // nanoseconds
	BotCategory     string            `json:"bot_category"`
	BotName         string            `json:"bot_name"`
	BotVerified     string            `json:"bot_verified"`
	BlockSource     string            `json:"block_source"`
	AttackTypes     []string          `json:"attack_types"`
	BytesOut        int64             `json:"bytes_out"`
	BytesIn         int64             `json:"bytes_in"`
}

// LogQuery filters GET /logs. Zero values are omitted. Status, BlockSource and
// AttackType take comma-separated lists, with "!" in front to negate.
type LogQuery struct {
	Action      string // allowed | blocked | logged
	IP          string
	Country     string
	ASN         int
	RuleID      string
	Host        string
	Path        string // prefix
	Method      string
	UserAgent   string // substring
	Status      string // e.g. "5xx", "403,429", "!2xx"
	BlockSource string // e.g. "waf_anomaly,would_block"
	AttackType  string // e.g. "sqli,xss"
	BotCategory string
	BotName     string
	BotVerified string
	MinScore    int
	MaxScore    int
	From, To    time.Time
	OrderBy     string // timestamp | score
	OrderDir    string // asc | desc
	Limit       int    // the API caps it at 200
	Offset      int
}

func (q LogQuery) values() url.Values {
	v := url.Values{}
	set := func(k, s string) {
		if s != "" {
			v.Set(k, s)
		}
	}
	setInt := func(k string, n int) {
		if n != 0 {
			v.Set(k, strconv.Itoa(n))
		}
	}
	set("action", q.Action)
	set("ip", q.IP)
	set("country", q.Country)
	setInt("asn", q.ASN)
	set("rule_id", q.RuleID)
	set("host", q.Host)
	set("path", q.Path)
	set("method", q.Method)
	set("user_agent", q.UserAgent)
	set("status", q.Status)
	set("block_source", q.BlockSource)
	set("attack_type", q.AttackType)
	set("bot_category", q.BotCategory)
	set("bot_name", q.BotName)
	set("bot_verified", q.BotVerified)
	setInt("min_score", q.MinScore)
	setInt("max_score", q.MaxScore)
	if !q.From.IsZero() {
		v.Set("from", q.From.UTC().Format(time.RFC3339))
	}
	if !q.To.IsZero() {
		v.Set("to", q.To.UTC().Format(time.RFC3339))
	}
	set("order_by", q.OrderBy)
	set("order_dir", q.OrderDir)
	setInt("limit", q.Limit)
	setInt("offset", q.Offset)
	return v
}

// LogPage is one page of request logs.
type LogPage struct {
	Data   []RequestLog `json:"data"`
	Total  int          `json:"total"`
	Limit  int          `json:"limit"`
	Offset int          `json:"offset"`
}

// QueryLogs lists request logs, newest first unless ordered otherwise.
func (c *WAFClient) QueryLogs(ctx context.Context, siteID string, q LogQuery) (*LogPage, error) {
	var out LogPage
	path := "/api/v1/tenants/" + url.PathEscape(siteID) + "/logs"
	if v := q.values(); len(v) > 0 {
		path += "?" + v.Encode()
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetLog returns one request log in full.
func (c *WAFClient) GetLog(ctx context.Context, siteID, logID string) (*RequestLog, error) {
	var out RequestLog
	path := "/api/v1/tenants/" + url.PathEscape(siteID) + "/logs/" + url.PathEscape(logID)
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AnalyticsQuery is the period and filters of the analytics endpoints. Range
// ("24h", "7d", "30d") wins over From/To.
type AnalyticsQuery struct {
	Range       string
	From, To    time.Time
	Host        string
	Action      string
	BlockSource string
}

func (q AnalyticsQuery) values() url.Values {
	v := url.Values{}
	if q.Range != "" {
		v.Set("range", q.Range)
	}
	if !q.From.IsZero() {
		v.Set("from", q.From.UTC().Format(time.RFC3339))
	}
	if !q.To.IsZero() {
		v.Set("to", q.To.UTC().Format(time.RFC3339))
	}
	if q.Host != "" {
		v.Set("host", q.Host)
	}
	if q.Action != "" {
		v.Set("action", q.Action)
	}
	if q.BlockSource != "" {
		v.Set("block_source", q.BlockSource)
	}
	return v
}

// AnalyticsSummary returns the totals of the period and of the previous period
// of the same length. The shape is waf-api's AnalyticsSummary, passed through
// as raw JSON.
func (c *WAFClient) AnalyticsSummary(ctx context.Context, siteID string, q AnalyticsQuery) (json.RawMessage, error) {
	var out json.RawMessage
	path := "/api/v1/tenants/" + url.PathEscape(siteID) + "/analytics/summary"
	if v := q.values(); len(v) > 0 {
		path += "?" + v.Encode()
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// TopDimensions are the dimensions of AnalyticsTop.
var TopDimensions = []string{"ip", "country", "asn", "path", "host", "status", "method", "rule", "attack_type", "user_agent", "block_source"}

// AnalyticsTop returns the top N values of a dimension, each with its total,
// how many were blocked, and the GET /logs filter that lists them. Raw JSON,
// waf-api's AnalyticsTop.
func (c *WAFClient) AnalyticsTop(ctx context.Context, siteID, dimension string, limit int, q AnalyticsQuery) (json.RawMessage, error) {
	v := q.values()
	v.Set("dimension", dimension)
	if limit > 0 {
		v.Set("limit", strconv.Itoa(limit))
	}
	var out json.RawMessage
	path := "/api/v1/tenants/" + url.PathEscape(siteID) + "/analytics/top?" + v.Encode()
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}
