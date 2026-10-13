// Package loki implements allow-listed, bounded Loki range searches and
// adapter-local forward pages. The forward page contract deliberately does not
// claim an exact event identity for a Loki timestamp/line pair.
package loki

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adapters/source"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	defaultMaxBytes = 8 << 20
	defaultMaxLines = 5000
	maxWindow       = 24 * time.Hour
)

var nodePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Auth struct{ BearerToken, Username, Password string }
type Config struct {
	BaseURL            string
	Timeout            time.Duration
	MaxBytes           int64
	MaxLines           int
	Templates          map[string]string
	PageLabelAllowlist []string
	Auth               Auth
}
type Client struct {
	baseURL            *url.URL
	http               *http.Client
	maxBytes           int64
	maxLines           int
	templates          map[string]string
	pageLabelAllowlist map[string]bool
	auth               Auth
}
type SearchRequest struct {
	TemplateID, Node string
	Start, End       time.Time
	Limit            int
}
type Entry struct {
	Labels    []domain.Label
	Timestamp time.Time
	Line      string
}
type SearchResult struct {
	Entries         []Entry
	BytesRead       int64
	StreamsReturned int
}

type response struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Stream map[string]string `json:"stream"`
			Values [][]string        `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

func NewClient(cfg Config) (*Client, error) {
	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("invalid Loki base URL")
	}
	if parsed.Scheme == "http" && !isLoopback(parsed.Hostname()) {
		return nil, fmt.Errorf("non-loopback Loki base URL must use HTTPS")
	}
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("loki timeout must be positive")
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = defaultMaxBytes
	}
	if cfg.MaxLines == 0 {
		cfg.MaxLines = defaultMaxLines
	}
	if cfg.MaxBytes < 1 || cfg.MaxBytes > defaultMaxBytes || cfg.MaxLines < 1 || cfg.MaxLines > defaultMaxLines {
		return nil, fmt.Errorf("loki response limits are invalid")
	}
	if cfg.Auth.BearerToken != "" && (cfg.Auth.Username != "" || cfg.Auth.Password != "") || (cfg.Auth.Username == "") != (cfg.Auth.Password == "") {
		return nil, fmt.Errorf("invalid Loki authentication")
	}
	if len(cfg.Templates) == 0 || len(cfg.Templates) > 128 {
		return nil, fmt.Errorf("loki query templates are required and bounded")
	}
	templates := make(map[string]string, len(cfg.Templates))
	for id, query := range cfg.Templates {
		if !nodePattern.MatchString(id) || query == "" || len(query) > 4096 || strings.Count(query, "{{node}}") > 1 {
			return nil, fmt.Errorf("invalid Loki query template")
		}
		templates[id] = query
	}
	pageLabelAllowlist := make(map[string]bool, len(cfg.PageLabelAllowlist))
	if len(cfg.PageLabelAllowlist) > maxNormalizedLabels {
		return nil, fmt.Errorf("loki page label allowlist is invalid")
	}
	for _, name := range cfg.PageLabelAllowlist {
		if !pageLabelPattern.MatchString(name) || pageSensitiveName.MatchString(name) || pageLabelAllowlist[name] {
			return nil, fmt.Errorf("loki page label allowlist is invalid")
		}
		pageLabelAllowlist[name] = true
	}
	return &Client{baseURL: parsed, http: &http.Client{Timeout: cfg.Timeout, CheckRedirect: rejectRedirect}, maxBytes: cfg.MaxBytes, maxLines: cfg.MaxLines, templates: templates, pageLabelAllowlist: pageLabelAllowlist, auth: cfg.Auth}, nil
}

func isLoopback(host string) bool {
	return strings.EqualFold(host, "localhost") || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

func rejectRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func (c *Client) DiscoverCapabilities(context.Context) ([]source.Capability, error) {
	return []source.Capability{{ID: "loki.log_search.v1", Version: "1"}}, nil
}
func (c *Client) Health(ctx context.Context) (source.Health, error) {
	endpoint := c.baseURL.ResolveReference(&url.URL{Path: "/ready"})
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	c.authorize(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return source.Health{}, classifyTransport(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return source.Health{}, classifyStatus(resp.StatusCode)
	}
	caps, _ := c.DiscoverCapabilities(ctx)
	return source.Health{Reachable: true, Capabilities: caps}, nil
}
func (c *Client) Search(ctx context.Context, input SearchRequest) (SearchResult, error) {
	query, ok := c.templates[input.TemplateID]
	if !ok {
		return SearchResult{}, source.InvalidArgument("Loki query template is not allow-listed")
	}
	if input.Node != "" {
		if !nodePattern.MatchString(input.Node) || !strings.Contains(query, "{{node}}") {
			return SearchResult{}, source.InvalidArgument("invalid Loki node scope")
		}
		query = strings.ReplaceAll(query, "{{node}}", input.Node)
	} else if strings.Contains(query, "{{node}}") {
		return SearchResult{}, source.InvalidArgument("Loki node scope is required")
	}
	if input.Start.IsZero() || input.End.IsZero() || !input.End.After(input.Start) || input.End.Sub(input.Start) > maxWindow || input.Limit < 1 || input.Limit > c.maxLines {
		return SearchResult{}, source.InvalidArgument("invalid Loki search bounds")
	}
	return c.queryRange(ctx, query, input.Start, input.End, input.Limit, "BACKWARD")
}

// queryRange is shared by backward diagnostic search and the forward page
// contract. Entries are normalized into chronological order locally because a
// stream-shaped response is grouped by stream, while page semantics are based
// only on the documented timestamp ordering direction.
func (c *Client) queryRange(ctx context.Context, query string, start, end time.Time, limit int, direction string) (SearchResult, error) {
	endpoint := c.baseURL.ResolveReference(&url.URL{Path: "/loki/api/v1/query_range"})
	values := endpoint.Query()
	values.Set("query", query)
	values.Set("start", strconv.FormatInt(start.UTC().UnixNano(), 10))
	values.Set("end", strconv.FormatInt(end.UTC().UnixNano(), 10))
	values.Set("limit", strconv.Itoa(limit))
	values.Set("direction", direction)
	endpoint.RawQuery = values.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return SearchResult{}, source.NewError(domain.FailureInternal, false, "build Loki request", err)
	}
	c.authorize(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return SearchResult{}, classifyTransport(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return SearchResult{}, classifyStatus(resp.StatusCode)
	}
	if resp.ContentLength > c.maxBytes {
		return SearchResult{}, source.NewError(domain.FailureResultLimit, false, "Loki response exceeds byte limit", nil)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
	if err != nil {
		return SearchResult{}, source.NewError(domain.FailureSourceUnavailable, true, "read Loki response", err)
	}
	if int64(len(body)) > c.maxBytes {
		return SearchResult{}, source.NewError(domain.FailureResultLimit, false, "Loki response exceeds byte limit", nil)
	}
	var raw response
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if err := decoder.Decode(&raw); err != nil {
		return SearchResult{}, malformed(err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return SearchResult{}, malformed(fmt.Errorf("trailing JSON"))
	}
	if raw.Status != "success" || raw.Data.ResultType != "streams" {
		return SearchResult{}, malformed(fmt.Errorf("unexpected response shape"))
	}
	result := SearchResult{BytesRead: int64(len(body)), StreamsReturned: len(raw.Data.Result)}
	for _, stream := range raw.Data.Result {
		for _, pair := range stream.Values {
			if len(pair) != 2 {
				return SearchResult{}, malformed(fmt.Errorf("invalid log entry"))
			}
			nanos, err := strconv.ParseInt(pair[0], 10, 64)
			if err != nil {
				return SearchResult{}, malformed(err)
			}
			result.Entries = append(result.Entries, Entry{Labels: domain.SortedLabels(stream.Stream), Timestamp: time.Unix(0, nanos).UTC(), Line: pair[1]})
			if len(result.Entries) > limit || len(result.Entries) > c.maxLines {
				return SearchResult{}, source.NewError(domain.FailureResultLimit, false, "Loki line limit exceeded", nil)
			}
		}
	}
	sort.SliceStable(result.Entries, func(i, j int) bool { return result.Entries[i].Timestamp.Before(result.Entries[j].Timestamp) })
	return result, nil
}
func (c *Client) authorize(req *http.Request) {
	if c.auth.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.auth.BearerToken)
	} else if c.auth.Username != "" {
		req.SetBasicAuth(c.auth.Username, c.auth.Password)
	}
}
func classifyTransport(ctx context.Context, err error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return source.NewError(domain.FailureDeadlineExceeded, true, "Loki query timed out", err)
	}
	return source.NewError(domain.FailureSourceUnavailable, true, "Loki source unavailable", err)
}
func classifyStatus(status int) error {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return source.NewError(domain.FailureUnauthorized, false, "Loki authentication failed", nil)
	case status == http.StatusTooManyRequests || status >= 500:
		return source.NewError(domain.FailureSourceUnavailable, true, "Loki returned a transient error", nil)
	default:
		return source.NewError(domain.FailureSourceUnavailable, false, "Loki rejected the query", nil)
	}
}
func malformed(err error) error {
	return source.NewError(domain.FailureMalformedResponse, false, "Loki returned a malformed response", err)
}
