package prometheus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	defaultMaxBytes  = 10 << 20
	defaultMaxSeries = 10_000
)

var nodePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type queryTemplate struct {
	metrics  []string
	identity bool
}

// dcgmTemplates is the complete PromQL allow-list. User input can only become
// an exact Hostname matcher; callers cannot supply metric names or PromQL.
var dcgmTemplates = map[domain.QueryKind]queryTemplate{
	domain.QueryGPUIdentity: {
		metrics:  []string{"DCGM_FI_DEV_GPU_UTIL"},
		identity: true,
	},
	domain.QueryGPUUtilization: {metrics: []string{"DCGM_FI_DEV_GPU_UTIL"}},
	domain.QueryGPUTemperature: {metrics: []string{"DCGM_FI_DEV_GPU_TEMP", "DCGM_FI_DEV_MEMORY_TEMP"}},
	domain.QueryGPUPower:       {metrics: []string{"DCGM_FI_DEV_POWER_USAGE", "DCGM_FI_DEV_POWER_MGMT_LIMIT"}},
	domain.QueryGPUMemory:      {metrics: []string{"DCGM_FI_DEV_FB_USED", "DCGM_FI_DEV_FB_FREE", "DCGM_FI_DEV_FB_RESERVED"}},
	domain.QueryGPUECC: {metrics: []string{
		"DCGM_FI_DEV_ECC_SBE_VOL_TOTAL", "DCGM_FI_DEV_ECC_DBE_VOL_TOTAL",
		"DCGM_FI_DEV_ECC_SBE_AGG_TOTAL", "DCGM_FI_DEV_ECC_DBE_AGG_TOTAL",
		"DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS", "DCGM_FI_DEV_UNCORRECTABLE_REMAPPED_ROWS",
		"DCGM_FI_DEV_ROW_REMAP_FAILURE",
	}},
	domain.QueryGPUXID: {metrics: []string{"DCGM_FI_DEV_XID_ERRORS"}},
}

type Auth struct {
	BearerToken string
	Username    string
	Password    string
}

type Config struct {
	BaseURL   string
	Timeout   time.Duration
	MaxBytes  int64
	MaxSeries int
	Auth      Auth
}

type Client struct {
	baseURL   *url.URL
	http      *http.Client
	maxBytes  int64
	maxSeries int
	auth      Auth
}

type Sample struct {
	Metric     map[string]string
	Value      float64
	ObservedAt time.Time
}

type QueryResult struct {
	Samples        []Sample
	SeriesReturned int
	BytesRead      int64
	WarningCount   int
}

type Error struct {
	Code      domain.FailureCode
	Retryable bool
	Message   string
	Cause     error
}

func (e *Error) Error() string { return e.Message }
func (e *Error) Unwrap() error { return e.Cause }

func NewClient(cfg Config) (*Client, error) {
	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid prometheus base URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("prometheus URL scheme must be http or https")
	}
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("prometheus timeout must be positive")
	}
	if cfg.Auth.BearerToken != "" && (cfg.Auth.Username != "" || cfg.Auth.Password != "") {
		return nil, fmt.Errorf("prometheus bearer and basic authentication are mutually exclusive")
	}
	if (cfg.Auth.Username == "") != (cfg.Auth.Password == "") {
		return nil, fmt.Errorf("prometheus basic authentication requires username and password")
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = defaultMaxBytes
	}
	if cfg.MaxSeries == 0 {
		cfg.MaxSeries = defaultMaxSeries
	}
	if cfg.MaxBytes < 1 || cfg.MaxBytes > defaultMaxBytes {
		return nil, fmt.Errorf("prometheus maximum response bytes must be between 1 and %d", defaultMaxBytes)
	}
	if cfg.MaxSeries < 1 || cfg.MaxSeries > defaultMaxSeries {
		return nil, fmt.Errorf("prometheus maximum series must be between 1 and %d", defaultMaxSeries)
	}
	return &Client{
		baseURL:   parsed,
		http:      &http.Client{Timeout: cfg.Timeout},
		maxBytes:  cfg.MaxBytes,
		maxSeries: cfg.MaxSeries,
		auth:      cfg.Auth,
	}, nil
}

// WithTaskBounds returns an independent client view. Task limits can only
// tighten this client's local byte/series ceilings. A nonzero deadline opts
// into that request's timeout instead of the local HTTP timeout; only the
// scheduled in-process worker opts in. Remote collectors retain their local cap.
func (c *Client) WithTaskBounds(maxSeries int, maxBytes int64, deadline time.Time) (*Client, error) {
	if maxSeries < 1 || maxSeries > defaultMaxSeries || maxBytes < 1 || maxBytes > defaultMaxBytes {
		return nil, &Error{Code: domain.FailureInvalidArgument, Message: "invalid task response limits"}
	}
	bounded := *c
	bounded.maxSeries = min(c.maxSeries, maxSeries)
	bounded.maxBytes = min(c.maxBytes, maxBytes)
	if !deadline.IsZero() {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, &Error{Code: domain.FailureDeadlineExceeded, Message: "collection deadline exceeded"}
		}
		httpClient := *c.http
		httpClient.Timeout = remaining
		bounded.http = &httpClient
	}
	return &bounded, nil
}

func RenderQuery(kind domain.QueryKind, node string) (string, error) {
	return renderQuery(kind, node, true)
}

func renderQuery(kind domain.QueryKind, node string, instantSupport bool) (string, error) {
	if kind == domain.QuerySourceHealth {
		if node != "" {
			return "", fmt.Errorf("source health query does not accept a node")
		}
		return "up", nil
	}
	template, ok := dcgmTemplates[kind]
	if !ok {
		return "", fmt.Errorf("query kind is not allow-listed")
	}
	if node != "" && !nodePattern.MatchString(node) {
		return "", fmt.Errorf("node has invalid characters or length")
	}
	selectors := make([]string, 0, len(template.metrics))
	leaf := func(selector string) string {
		if !instantSupport || len(domain.DCGMFields(kind)) == 0 {
			return selector
		}
		// timestamp() must see a leaf vector selector, never an evaluated
		// expression/union whose timestamps have become evaluation time.
		return "(" + selector + " and (timestamp(" + selector + ") >= time() - 120) and (timestamp(" + selector + ") <= time()))"
	}
	for _, metric := range template.metrics {
		if node == "" {
			selectors = append(selectors, leaf(metric))
		} else {
			// DCGM exporter releases and deployments use both Hostname and
			// hostname. Both selectors remain static and node is validated above.
			selectors = append(selectors, `(`+leaf(metric+`{Hostname="`+node+`"}`)+` or `+leaf(metric+`{hostname="`+node+`"}`)+`)`)
		}
	}
	join := " or "
	if instantSupport && len(domain.DCGMFields(kind)) > 0 {
		join = " or on(__name__) "
	}
	expression := strings.Join(selectors, join)
	if len(selectors) > 1 {
		expression = "(" + expression + ")"
	}
	if template.identity {
		return "count by (Hostname, hostname, UUID, uuid, device, gpu, modelName, pci_bus_id) (" + expression + ")", nil
	}
	return expression, nil
}

func (c *Client) Instant(ctx context.Context, kind domain.QueryKind, node string, at time.Time) (QueryResult, error) {
	query, err := RenderQuery(kind, node)
	if err != nil {
		return QueryResult{}, &Error{Code: domain.FailureInvalidArgument, Message: "invalid query parameters", Cause: err}
	}
	endpoint := c.baseURL.ResolveReference(&url.URL{Path: "/api/v1/query"})
	values := endpoint.Query()
	values.Set("query", query)
	// Prometheus evaluates at millisecond precision. Never round an instant
	// query behind its requested causal boundary.
	evaluationAt := at.Truncate(time.Millisecond)
	if evaluationAt.Before(at) {
		evaluationAt = evaluationAt.Add(time.Millisecond)
	}
	values.Set("time", formatTimestamp(evaluationAt))
	endpoint.RawQuery = values.Encode()
	body, bytesRead, err := c.get(ctx, endpoint)
	if err != nil {
		return QueryResult{}, err
	}
	result, err := parseVectorResponse(body, c.maxSeries)
	if err != nil {
		return QueryResult{}, err
	}
	result.BytesRead = bytesRead
	return result, nil
}

func (c *Client) Range(ctx context.Context, kind domain.QueryKind, node string, queryRange domain.CollectionRange) (QueryResult, error) {
	query, err := renderQuery(kind, node, false)
	if err != nil {
		return QueryResult{}, &Error{Code: domain.FailureInvalidArgument, Message: "invalid query parameters", Cause: err}
	}
	if err := validateRange(queryRange); err != nil {
		return QueryResult{}, &Error{Code: domain.FailureInvalidArgument, Message: "invalid query range", Cause: err}
	}
	endpoint := c.baseURL.ResolveReference(&url.URL{Path: "/api/v1/query_range"})
	values := endpoint.Query()
	values.Set("query", query)
	values.Set("start", formatTimestamp(queryRange.Start))
	values.Set("end", formatTimestamp(queryRange.End))
	values.Set("step", strconv.FormatFloat(queryRange.Step.Seconds(), 'f', 3, 64))
	endpoint.RawQuery = values.Encode()
	body, bytesRead, err := c.get(ctx, endpoint)
	if err != nil {
		return QueryResult{}, err
	}
	result, err := parseMatrixResponse(body, c.maxSeries)
	if err != nil {
		return QueryResult{}, err
	}
	result.BytesRead = bytesRead
	return result, nil
}

func validateRange(queryRange domain.CollectionRange) error {
	if queryRange.Start.IsZero() || queryRange.End.IsZero() || !queryRange.End.After(queryRange.Start) {
		return fmt.Errorf("range end must be after its start")
	}
	if queryRange.End.Sub(queryRange.Start) > 24*time.Hour {
		return fmt.Errorf("range cannot exceed 24 hours")
	}
	if queryRange.Step < time.Second || queryRange.Step > time.Hour {
		return fmt.Errorf("range step must be between one second and one hour")
	}
	return nil
}

func formatTimestamp(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func (c *Client) get(ctx context.Context, endpoint *url.URL) ([]byte, int64, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, 0, &Error{Code: domain.FailureInternal, Message: "build Prometheus request", Cause: err}
	}
	c.authorize(req)
	response, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, 0, &Error{Code: domain.FailureDeadlineExceeded, Retryable: true, Message: "Prometheus query timed out", Cause: err}
		}
		return nil, 0, &Error{Code: domain.FailureSourceUnavailable, Retryable: true, Message: "Prometheus source unavailable", Cause: err}
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, 0, &Error{Code: domain.FailureUnauthorized, Message: "Prometheus authentication failed"}
	}
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
		return nil, 0, &Error{Code: domain.FailureSourceUnavailable, Retryable: true, Message: "Prometheus returned a transient error"}
	}
	if response.StatusCode != http.StatusOK {
		return nil, 0, &Error{Code: domain.FailureSourceUnavailable, Message: "Prometheus rejected the query"}
	}
	if response.ContentLength > c.maxBytes {
		return nil, 0, &Error{Code: domain.FailureResultLimit, Message: "Prometheus response exceeds byte limit"}
	}

	limited := io.LimitReader(response.Body, c.maxBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, 0, &Error{Code: domain.FailureSourceUnavailable, Retryable: true, Message: "read Prometheus response", Cause: err}
	}
	if int64(len(body)) > c.maxBytes {
		return nil, 0, &Error{Code: domain.FailureResultLimit, Message: "Prometheus response exceeds byte limit"}
	}
	return body, int64(len(body)), nil
}

func (c *Client) authorize(req *http.Request) {
	if c.auth.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.auth.BearerToken)
	} else if c.auth.Username != "" {
		req.SetBasicAuth(c.auth.Username, c.auth.Password)
	}
}

type apiResponse struct {
	Status    string   `json:"status"`
	ErrorType string   `json:"errorType"`
	Warnings  []string `json:"warnings"`
	Data      struct {
		ResultType string          `json:"resultType"`
		Result     json.RawMessage `json:"result"`
	} `json:"data"`
}

type apiVectorSeries struct {
	Metric map[string]string `json:"metric"`
	Value  []json.RawMessage `json:"value"`
}

type apiMatrixSeries struct {
	Metric map[string]string   `json:"metric"`
	Values [][]json.RawMessage `json:"values"`
}

func decodeResponse(body []byte, expectedType string) (apiResponse, error) {
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	var response apiResponse
	if err := decoder.Decode(&response); err != nil {
		return apiResponse{}, &Error{Code: domain.FailureMalformedResponse, Message: "Prometheus returned malformed JSON", Cause: err}
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return apiResponse{}, &Error{Code: domain.FailureMalformedResponse, Message: "Prometheus returned trailing JSON data", Cause: err}
	}
	if response.Status != "success" || response.Data.ResultType != expectedType || response.Data.Result == nil {
		return apiResponse{}, &Error{Code: domain.FailureMalformedResponse, Message: "Prometheus returned an unexpected response shape"}
	}
	return response, nil
}

func parseVectorResponse(body []byte, maxSeries int) (QueryResult, error) {
	response, err := decodeResponse(body, "vector")
	if err != nil {
		return QueryResult{}, err
	}
	var seriesValues []apiVectorSeries
	if err := json.Unmarshal(response.Data.Result, &seriesValues); err != nil {
		return QueryResult{}, &Error{Code: domain.FailureMalformedResponse, Message: "Prometheus vector result is malformed", Cause: err}
	}
	if len(seriesValues) > maxSeries {
		return QueryResult{}, &Error{Code: domain.FailureResultLimit, Message: "Prometheus response exceeds series limit"}
	}
	result := QueryResult{Samples: make([]Sample, 0, len(seriesValues)), SeriesReturned: len(seriesValues), WarningCount: len(response.Warnings)}
	for _, series := range seriesValues {
		sample, err := parseSample(series.Metric, series.Value)
		if err != nil {
			return QueryResult{}, err
		}
		result.Samples = append(result.Samples, sample)
	}
	return result, nil
}

func parseMatrixResponse(body []byte, maxSeries int) (QueryResult, error) {
	response, err := decodeResponse(body, "matrix")
	if err != nil {
		return QueryResult{}, err
	}
	var seriesValues []apiMatrixSeries
	if err := json.Unmarshal(response.Data.Result, &seriesValues); err != nil {
		return QueryResult{}, &Error{Code: domain.FailureMalformedResponse, Message: "Prometheus matrix result is malformed", Cause: err}
	}
	if len(seriesValues) > maxSeries {
		return QueryResult{}, &Error{Code: domain.FailureResultLimit, Message: "Prometheus response exceeds series limit"}
	}
	result := QueryResult{SeriesReturned: len(seriesValues), WarningCount: len(response.Warnings)}
	for _, series := range seriesValues {
		for _, value := range series.Values {
			sample, err := parseSample(series.Metric, value)
			if err != nil {
				return QueryResult{}, err
			}
			result.Samples = append(result.Samples, sample)
		}
	}
	return result, nil
}

func parseSample(metric map[string]string, tuple []json.RawMessage) (Sample, error) {
	if len(tuple) != 2 {
		return Sample{}, &Error{Code: domain.FailureMalformedResponse, Message: "Prometheus sample has an invalid value tuple"}
	}
	// json.Number also accepts quoted numbers; the API requires a JSON number.
	if strings.HasPrefix(strings.TrimSpace(string(tuple[0])), "\"") {
		return Sample{}, &Error{Code: domain.FailureMalformedResponse, Message: "Prometheus sample timestamp is invalid"}
	}
	var timestamp json.Number
	var rawValue string
	if err := json.Unmarshal(tuple[0], &timestamp); err != nil {
		return Sample{}, &Error{Code: domain.FailureMalformedResponse, Message: "Prometheus sample timestamp is invalid", Cause: err}
	}
	if err := json.Unmarshal(tuple[1], &rawValue); err != nil {
		return Sample{}, &Error{Code: domain.FailureMalformedResponse, Message: "Prometheus sample value is invalid", Cause: err}
	}
	value, err := strconv.ParseFloat(rawValue, 64)
	if err != nil {
		return Sample{}, &Error{Code: domain.FailureMalformedResponse, Message: "Prometheus sample value is not numeric", Cause: err}
	}
	observedAt, err := parseTimestamp(timestamp.String())
	if err != nil {
		return Sample{}, &Error{Code: domain.FailureMalformedResponse, Message: "Prometheus sample timestamp is invalid", Cause: err}
	}
	return Sample{Metric: metric, Value: value, ObservedAt: observedAt}, nil
}

// parseTimestamp preserves decimal seconds exactly rather than introducing
// float64 error at modern Unix epochs. Bounds also prevent oversized exponents
// from allocating unbounded integers. Sub-nanosecond values fail closed.
func parseTimestamp(raw string) (time.Time, error) {
	invalid := fmt.Errorf("timestamp outside supported nanosecond precision or range")
	if len(raw) == 0 || len(raw) > 64 {
		return time.Time{}, invalid
	}
	if i := strings.IndexAny(raw, "eE"); i >= 0 {
		exponent, err := strconv.Atoi(raw[i+1:])
		if err != nil || exponent < -32 || exponent > 32 {
			return time.Time{}, invalid
		}
	}
	seconds, ok := new(big.Rat).SetString(raw)
	if !ok {
		return time.Time{}, invalid
	}
	nanos := seconds.Mul(seconds, big.NewRat(int64(time.Second), 1))
	if !nanos.IsInt() || !nanos.Num().IsInt64() {
		return time.Time{}, invalid
	}
	return time.Unix(0, nanos.Num().Int64()).UTC(), nil
}
