// Package redfish provides bounded read-only Redfish collection. It never
// follows arbitrary links returned by a BMC; every requested path is built
// from validated identifiers and fixed collection routes.
package redfish

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adapters/source"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const defaultMaxBytes = 4 << 20

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Config struct {
	BaseURL, Username, Password string
	Timeout                     time.Duration
	MaxBytes                    int64
	MaxRecords                  int
	TLSConfig                   *tls.Config
}
type Client struct {
	baseURL            *url.URL
	http               *http.Client
	username, password string
	maxBytes           int64
	maxRecords         int
}
type Inventory struct{ ID, Name, Manufacturer, Model, SerialNumber, PowerState, Health string }
type Sensor struct{ ID, Name, Reading, Unit, Health string }
type Event struct {
	ID, Severity, Message string
	CreatedAt             time.Time
}
type Result[T any] struct {
	Records   []T
	BytesRead int64
	Failures  []source.Failure
}
type collection struct {
	Members []struct {
		ODataID string `json:"@odata.id"`
	} `json:"Members"`
	Count         *int   `json:"Members@odata.count"`
	ODataCount    *int   `json:"@odata.count"`
	NextLink      string `json:"Members@odata.nextLink"`
	ODataNextLink string `json:"@odata.nextLink"`
}
type systemPayload struct {
	ID, Name, Manufacturer, Model, SerialNumber, PowerState string
	Status                                                  struct{ Health string }
}
type sensorPayload struct {
	ID, Name     string
	Reading      any
	ReadingUnits string
	Status       struct{ Health string }
}
type eventPayload struct{ ID, Severity, Message, Created string }

func NewClient(cfg Config) (*Client, error) {
	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" {
		return nil, fmt.Errorf("redfish base URL must be an HTTPS origin")
	}
	if cfg.Timeout <= 0 || cfg.Username == "" || cfg.Password == "" {
		return nil, fmt.Errorf("redfish timeout and credentials are required")
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = defaultMaxBytes
	}
	if cfg.MaxRecords == 0 {
		cfg.MaxRecords = 1024
	}
	if cfg.MaxBytes < 1 || cfg.MaxBytes > defaultMaxBytes || cfg.MaxRecords < 1 || cfg.MaxRecords > 4096 {
		return nil, fmt.Errorf("redfish response limits are invalid")
	}
	if cfg.TLSConfig != nil && cfg.TLSConfig.InsecureSkipVerify {
		return nil, fmt.Errorf("redfish TLS verification cannot be disabled")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.TLSConfig != nil {
		transport.TLSClientConfig = cfg.TLSConfig.Clone()
	}
	return &Client{baseURL: parsed, http: &http.Client{Timeout: cfg.Timeout, Transport: transport, CheckRedirect: rejectRedirect}, username: cfg.Username, password: cfg.Password, maxBytes: cfg.MaxBytes, maxRecords: cfg.MaxRecords}, nil
}

func rejectRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
func (c *Client) DiscoverCapabilities(ctx context.Context) ([]source.Capability, error) {
	var root struct{ RedfishVersion string }
	_, err := c.get(ctx, "/redfish/v1", &root)
	if err != nil {
		return nil, err
	}
	return []source.Capability{{ID: "redfish.inventory.v1", Version: root.RedfishVersion}, {ID: "redfish.sensors.v1", Version: root.RedfishVersion}, {ID: "redfish.event_log.v1", Version: root.RedfishVersion}}, nil
}
func (c *Client) Health(ctx context.Context) (source.Health, error) {
	caps, err := c.DiscoverCapabilities(ctx)
	if err != nil {
		return source.Health{}, err
	}
	return source.Health{Reachable: true, Capabilities: caps}, nil
}

func (c *Client) Inventory(ctx context.Context, systemIDs []string) (Result[Inventory], error) {
	ids, bytesRead, err := c.resolveIDs(ctx, "/redfish/v1/Systems", systemIDs)
	if err != nil {
		return Result[Inventory]{}, err
	}
	result := Result[Inventory]{BytesRead: bytesRead}
	for _, id := range ids {
		var raw systemPayload
		read, err := c.get(ctx, "/redfish/v1/Systems/"+url.PathEscape(id), &raw)
		result.BytesRead += read
		if result.BytesRead > c.maxBytes {
			return Result[Inventory]{}, limitError()
		}
		if err != nil {
			result.Failures = append(result.Failures, failure(id, err))
			continue
		}
		if raw.ID == "" {
			raw.ID = id
		}
		result.Records = append(result.Records, Inventory{ID: raw.ID, Name: raw.Name, Manufacturer: raw.Manufacturer, Model: raw.Model, SerialNumber: raw.SerialNumber, PowerState: raw.PowerState, Health: raw.Status.Health})
	}
	return result, nil
}
func (c *Client) Sensors(ctx context.Context, chassisIDs []string) (Result[Sensor], error) {
	ids, bytesRead, err := c.resolveIDs(ctx, "/redfish/v1/Chassis", chassisIDs)
	if err != nil {
		return Result[Sensor]{}, err
	}
	result := Result[Sensor]{BytesRead: bytesRead}
	for _, chassis := range ids {
		var list collection
		read, err := c.get(ctx, "/redfish/v1/Chassis/"+url.PathEscape(chassis)+"/Sensors", &list)
		result.BytesRead += read
		if result.BytesRead > c.maxBytes {
			return Result[Sensor]{}, limitError()
		}
		if err != nil {
			result.Failures = append(result.Failures, failure(chassis, err))
			continue
		}
		if err := completeCollection(list); err != nil {
			return Result[Sensor]{}, err
		}
		if len(list.Members) > c.maxRecords {
			return Result[Sensor]{}, limitError()
		}
		for _, member := range list.Members {
			if len(result.Records)+len(result.Failures) >= c.maxRecords {
				return Result[Sensor]{}, limitError()
			}
			id, ok := memberID(member.ODataID, "/redfish/v1/Chassis/"+chassis+"/Sensors/")
			if !ok {
				result.Failures = append(result.Failures, source.Failure{Code: domain.FailureMalformedResponse, Target: chassis, Message: "Redfish returned an invalid sensor reference"})
				continue
			}
			var raw sensorPayload
			read, err = c.get(ctx, "/redfish/v1/Chassis/"+url.PathEscape(chassis)+"/Sensors/"+url.PathEscape(id), &raw)
			result.BytesRead += read
			if result.BytesRead > c.maxBytes {
				return Result[Sensor]{}, limitError()
			}
			if err != nil {
				result.Failures = append(result.Failures, failure(chassis+"/"+id, err))
				continue
			}
			reading, ok := scalar(raw.Reading)
			if !ok {
				result.Failures = append(result.Failures, source.Failure{Code: domain.FailureMalformedResponse, Target: chassis + "/" + id, Message: "Redfish sensor reading is malformed"})
				continue
			}
			if raw.ID == "" {
				raw.ID = id
			}
			result.Records = append(result.Records, Sensor{ID: chassis + "/" + raw.ID, Name: raw.Name, Reading: reading, Unit: raw.ReadingUnits, Health: raw.Status.Health})
		}
	}
	return result, nil
}
func (c *Client) EventLog(ctx context.Context, systemID, serviceID string, limit int) (Result[Event], error) {
	if !idPattern.MatchString(systemID) || !idPattern.MatchString(serviceID) || limit < 1 || limit > c.maxRecords {
		return Result[Event]{}, source.InvalidArgument("invalid Redfish event-log scope")
	}
	path := "/redfish/v1/Systems/" + url.PathEscape(systemID) + "/LogServices/" + url.PathEscape(serviceID) + "/Entries?$top=" + strconv.Itoa(limit)
	var list collection
	bytesRead, err := c.get(ctx, path, &list)
	if err != nil {
		return Result[Event]{}, err
	}
	if err := completeCollection(list); err != nil {
		return Result[Event]{}, err
	}
	if len(list.Members) > limit {
		return Result[Event]{}, limitError()
	}
	result := Result[Event]{BytesRead: bytesRead}
	for _, member := range list.Members {
		prefix := "/redfish/v1/Systems/" + systemID + "/LogServices/" + serviceID + "/Entries/"
		id, ok := memberID(member.ODataID, prefix)
		if !ok {
			result.Failures = append(result.Failures, source.Failure{Code: domain.FailureMalformedResponse, Target: systemID, Message: "Redfish returned an invalid event reference"})
			continue
		}
		var raw eventPayload
		read, err := c.get(ctx, strings.TrimSuffix(path, "?$top="+strconv.Itoa(limit))+"/"+url.PathEscape(id), &raw)
		result.BytesRead += read
		if result.BytesRead > c.maxBytes {
			return Result[Event]{}, limitError()
		}
		if err != nil {
			result.Failures = append(result.Failures, failure(id, err))
			continue
		}
		created, err := time.Parse(time.RFC3339, raw.Created)
		if err != nil {
			result.Failures = append(result.Failures, source.Failure{Code: domain.FailureMalformedResponse, Target: id, Message: "Redfish event timestamp is malformed"})
			continue
		}
		if raw.ID == "" {
			raw.ID = id
		}
		result.Records = append(result.Records, Event{ID: raw.ID, Severity: raw.Severity, Message: raw.Message, CreatedAt: created.UTC()})
	}
	return result, nil
}

func (c *Client) resolveIDs(ctx context.Context, path string, requested []string) ([]string, int64, error) {
	if len(requested) > c.maxRecords {
		return nil, 0, limitError()
	}
	if len(requested) > 0 {
		seen := map[string]bool{}
		for _, id := range requested {
			if !idPattern.MatchString(id) || seen[id] {
				return nil, 0, source.InvalidArgument("invalid Redfish target scope")
			}
			seen[id] = true
		}
		return append([]string(nil), requested...), 0, nil
	}
	var list collection
	read, err := c.get(ctx, path, &list)
	if err != nil {
		return nil, read, err
	}
	if err := completeCollection(list); err != nil {
		return nil, read, err
	}
	if len(list.Members) > c.maxRecords {
		return nil, read, limitError()
	}
	ids := make([]string, 0, len(list.Members))
	for _, member := range list.Members {
		id, ok := memberID(member.ODataID, path+"/")
		if !ok {
			return nil, read, source.NewError(domain.FailureMalformedResponse, false, "Redfish returned an invalid member reference", nil)
		}
		ids = append(ids, id)
	}
	return ids, read, nil
}

// completeCollection fails closed instead of reporting a first page as a
// complete result. Pagination is deliberately not followed: a BMC-provided
// link must not broaden the adapter's fixed, caller-authorized route set.
func completeCollection(list collection) error {
	if list.NextLink != "" || list.ODataNextLink != "" {
		return limitError()
	}
	if list.Count != nil && list.ODataCount != nil && *list.Count != *list.ODataCount {
		return source.NewError(domain.FailureMalformedResponse, false, "Redfish returned inconsistent collection metadata", nil)
	}
	count := list.Count
	if count == nil {
		count = list.ODataCount
	}
	if count == nil {
		return nil
	}
	if *count < 0 || *count < len(list.Members) {
		return source.NewError(domain.FailureMalformedResponse, false, "Redfish returned inconsistent collection metadata", nil)
	}
	if *count > len(list.Members) {
		return limitError()
	}
	return nil
}
func memberID(reference, prefix string) (string, bool) {
	if !strings.HasPrefix(reference, prefix) {
		return "", false
	}
	id := strings.TrimPrefix(reference, prefix)
	return id, idPattern.MatchString(id)
}
func (c *Client) get(ctx context.Context, path string, destination any) (int64, error) {
	endpoint := c.baseURL.ResolveReference(&url.URL{Path: strings.Split(path, "?")[0], RawQuery: func() string {
		pieces := strings.SplitN(path, "?", 2)
		if len(pieces) == 2 {
			return pieces[1]
		}
		return ""
	}()})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return 0, source.NewError(domain.FailureInternal, false, "build Redfish request", err)
	}
	req.SetBasicAuth(c.username, c.password)
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return 0, source.NewError(domain.FailureDeadlineExceeded, true, "Redfish query timed out", err)
		}
		return 0, source.NewError(domain.FailureSourceUnavailable, true, "Redfish source unavailable", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return 0, source.NewError(domain.FailureUnauthorized, false, "Redfish authentication failed", nil)
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return 0, source.NewError(domain.FailureSourceUnavailable, true, "Redfish returned a transient error", nil)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, source.NewError(domain.FailureSourceUnavailable, false, "Redfish rejected the query", nil)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
	if err != nil {
		return 0, source.NewError(domain.FailureSourceUnavailable, true, "read Redfish response", err)
	}
	if int64(len(body)) > c.maxBytes {
		return 0, limitError()
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if err := decoder.Decode(destination); err != nil {
		return int64(len(body)), source.NewError(domain.FailureMalformedResponse, false, "Redfish returned a malformed response", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return int64(len(body)), source.NewError(domain.FailureMalformedResponse, false, "Redfish returned trailing JSON", err)
	}
	return int64(len(body)), nil
}
func failure(target string, err error) source.Failure {
	var typed *source.Error
	if errors.As(err, &typed) {
		return source.Failure{Code: typed.Code, Retryable: typed.Retryable, Target: target, Message: typed.Message}
	}
	return source.Failure{Code: domain.FailureInternal, Target: target, Message: "Redfish target query failed"}
}
func limitError() error {
	return source.NewError(domain.FailureResultLimit, false, "Redfish result limit exceeded", nil)
}
func scalar(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, v != ""
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case json.Number:
		return v.String(), true
	default:
		return "", false
	}
}
