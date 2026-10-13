package collectorruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	protocolHeader    = "X-Sherlock-Protocol-Version"
	correlationHeader = "X-Correlation-ID"
	maximumBodyBytes  = int64(11 << 20)
)

type HTTPClient struct {
	baseURL  *url.URL
	client   *http.Client
	renewFor time.Duration
}

func NewHTTPClient(rawBaseURL string, client *http.Client, renewFor time.Duration) (*HTTPClient, error) {
	baseURL, err := url.Parse(rawBaseURL)
	if err != nil || (baseURL.Scheme != "http" && baseURL.Scheme != "https") || baseURL.Host == "" {
		return nil, fmt.Errorf("collector control URL must be absolute HTTP(S)")
	}
	if client == nil || renewFor < time.Second || renewFor > 5*time.Minute {
		return nil, fmt.Errorf("HTTP client and a renewal duration up to five minutes are required")
	}
	return &HTTPClient{baseURL: baseURL, client: client, renewFor: renewFor}, nil
}

type capabilityWire struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type sourceHealthWire struct {
	SourceID     string    `json:"source_id"`
	Availability string    `json:"availability"`
	SafeMessage  string    `json:"safe_message"`
	CheckedAt    time.Time `json:"checked_at"`
}
type commandPackWire struct {
	PackID       string `json:"pack_id"`
	Version      string `json:"version"`
	DigestSHA256 string `json:"digest_sha256"`
}
type heartbeatWire struct {
	ProtocolMin  int                `json:"protocol_min,omitempty"`
	ProtocolMax  int                `json:"protocol_max,omitempty"`
	Version      string             `json:"version"`
	BuildCommit  string             `json:"build_commit"`
	Capabilities []capabilityWire   `json:"capabilities"`
	CommandPacks []commandPackWire  `json:"command_packs"`
	SourceHealth []sourceHealthWire `json:"source_health"`
}

func (c *HTTPClient) Heartbeat(ctx context.Context, heartbeat Heartbeat) error {
	body := heartbeatWire{Version: heartbeat.Version, BuildCommit: heartbeat.BuildCommit, ProtocolMin: heartbeat.ProtocolMin, ProtocolMax: heartbeat.ProtocolMax, CommandPacks: make([]commandPackWire, 0, len(heartbeat.CommandPacks))}
	for _, capability := range heartbeat.Capabilities {
		body.Capabilities = append(body.Capabilities, capabilityWire(capability))
	}
	for _, pack := range heartbeat.CommandPacks {
		body.CommandPacks = append(body.CommandPacks, commandPackWire(pack))
	}
	for _, source := range heartbeat.SourceHealth {
		body.SourceHealth = append(body.SourceHealth, sourceHealthWire{SourceID: string(source.SourceID), Availability: source.Availability, SafeMessage: source.SafeMessage, CheckedAt: source.CheckedAt.UTC()})
	}
	_, err := c.do(ctx, http.MethodPost, "/collector/v1/heartbeat", body, nil, http.StatusOK)
	return err
}

type rangeWire struct {
	Start       time.Time `json:"start"`
	End         time.Time `json:"end"`
	StepSeconds float64   `json:"step_seconds"`
}
type taskWire struct {
	RunID          string     `json:"run_id"`
	ClusterID      string     `json:"cluster_id"`
	SourceID       string     `json:"source_id"`
	QueryKind      string     `json:"query_kind"`
	NodeFilter     string     `json:"node_filter"`
	Range          *rangeWire `json:"range,omitempty"`
	ScheduledFor   time.Time  `json:"scheduled_for"`
	Deadline       time.Time  `json:"deadline"`
	MaxSeries      int        `json:"max_series"`
	MaxBytes       int64      `json:"max_bytes"`
	IdempotencyKey string     `json:"idempotency_key"`
}
type claimWire struct {
	WorkID        string    `json:"work_id"`
	Attempt       int       `json:"attempt"`
	LeaseToken    string    `json:"lease_token"`
	LeaseExpires  time.Time `json:"lease_expires_at"`
	WorkExpiresAt time.Time `json:"work_expires_at"`
	Task          taskWire  `json:"task"`
}

func (c *HTTPClient) Claim(ctx context.Context, claim ClaimRequest) (*domain.WorkLease, error) {
	path := "/collector/v1/work/claim?wait_seconds=" + strconv.Itoa(int(claim.Wait/time.Second))
	var wire claimWire
	status, err := c.do(ctx, http.MethodGet, path, nil, &wire, http.StatusOK, http.StatusNoContent)
	if err != nil || status == http.StatusNoContent {
		return nil, err
	}
	task := domain.CollectionTask{
		RunID: domain.RunID(wire.Task.RunID), ClusterID: domain.ClusterID(wire.Task.ClusterID), SourceID: domain.SourceID(wire.Task.SourceID), Query: domain.QueryKind(wire.Task.QueryKind),
		Node: wire.Task.NodeFilter, ScheduledFor: wire.Task.ScheduledFor.UTC(), Deadline: wire.Task.Deadline.UTC(), MaxSeries: wire.Task.MaxSeries,
		MaxBytes: wire.Task.MaxBytes, IdempotencyKey: wire.Task.IdempotencyKey,
	}
	if wire.Task.Range != nil {
		task.Range = &domain.CollectionRange{Start: wire.Task.Range.Start.UTC(), End: wire.Task.Range.End.UTC(), Step: time.Duration(wire.Task.Range.StepSeconds * float64(time.Second))}
	}
	return &domain.WorkLease{
		CollectorID: claim.CollectorID, Attempt: wire.Attempt, LeaseToken: wire.LeaseToken, LeaseExpires: wire.LeaseExpires.UTC(),
		Work: domain.CollectorWork{WorkID: domain.WorkID(wire.WorkID), Task: task, Status: domain.WorkLeased, AvailableAt: wire.Task.ScheduledFor.UTC(), WorkExpiresAt: wire.WorkExpiresAt.UTC()},
	}, nil
}

type leaseWire struct {
	LeaseToken      string `json:"lease_token"`
	DurationSeconds int    `json:"duration_seconds,omitempty"`
}

func (c *HTTPClient) Start(ctx context.Context, ref LeaseRef) error {
	_, err := c.do(ctx, http.MethodPost, leasePath(ref, "/start"), leaseWire{LeaseToken: ref.LeaseToken}, nil, http.StatusNoContent)
	return err
}

func (c *HTTPClient) Renew(ctx context.Context, ref LeaseRef) (time.Time, error) {
	_, err := c.do(ctx, http.MethodPost, leasePath(ref, "/renew"), leaseWire{LeaseToken: ref.LeaseToken, DurationSeconds: int(c.renewFor.Seconds())}, nil, http.StatusNoContent)
	return time.Now().UTC().Add(c.renewFor), err
}

type chunkWire struct {
	LeaseToken string `json:"lease_token"`
	Payload    string `json:"payload_base64"`
	SHA256     string `json:"sha256"`
}

func (c *HTTPClient) UploadChunk(ctx context.Context, chunk ResultChunk) error {
	body := chunkWire{LeaseToken: chunk.LeaseToken, Payload: base64.StdEncoding.EncodeToString(chunk.Payload), SHA256: chunk.SHA256}
	path := leasePath(chunk.LeaseRef, "/results/chunks/"+strconv.Itoa(chunk.Index))
	_, err := c.do(ctx, http.MethodPut, path, body, nil, http.StatusCreated, http.StatusOK, http.StatusNoContent)
	return err
}

type finalizationWire struct {
	LeaseToken string              `json:"lease_token"`
	RunID      domain.RunID        `json:"run_id"`
	Status     domain.ResultStatus `json:"status"`
	ChunkCount int                 `json:"chunk_count"`
	Bytes      int64               `json:"bytes"`
	SHA256     string              `json:"sha256"`
}

func (c *HTTPClient) Finalize(ctx context.Context, finalization Finalization) error {
	body := finalizationWire{LeaseToken: finalization.LeaseToken, RunID: finalization.RunID, Status: finalization.Status, ChunkCount: finalization.ChunkCount, Bytes: finalization.Bytes, SHA256: finalization.SHA256}
	_, err := c.do(ctx, http.MethodPost, leasePath(finalization.LeaseRef, "/results/finalize"), body, nil, http.StatusOK, http.StatusNoContent)
	return err
}

func leasePath(ref LeaseRef, suffix string) string {
	return "/collector/v1/work/" + url.PathEscape(string(ref.WorkID)) + "/attempts/" + strconv.Itoa(ref.Attempt) + suffix
}

func (c *HTTPClient) do(ctx context.Context, method, path string, body, output any, expected ...int) (int, error) {
	return c.doWithHeaders(ctx, method, path, body, output, nil, expected...)
}

func (c *HTTPClient) doWithHeaders(ctx context.Context, method, path string, body, output any, headers map[string]string, expected ...int) (int, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("encode collector control request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	pathPart, query := path, ""
	if index := strings.IndexByte(path, '?'); index >= 0 {
		pathPart, query = path[:index], path[index+1:]
	}
	reference, err := url.Parse(pathPart)
	if err != nil {
		return 0, fmt.Errorf("invalid collector control path")
	}
	reference.RawQuery = query
	target := c.baseURL.ResolveReference(reference)
	request, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return 0, fmt.Errorf("create collector control request: %w", err)
	}
	request.Header.Set(protocolHeader, strconv.Itoa(ProtocolVersion))
	request.Header.Set(correlationHeader, correlationID())
	request.Header.Set("Accept", "application/json, application/problem+json")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return 0, fmt.Errorf("send collector control request: %w", err)
	}
	defer response.Body.Close()
	for _, status := range expected {
		if response.StatusCode == status {
			if output != nil && status != http.StatusNoContent {
				decoder := json.NewDecoder(io.LimitReader(response.Body, maximumBodyBytes))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(output); err != nil {
					return status, fmt.Errorf("decode collector control response: %w", err)
				}
			}
			return status, nil
		}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumBodyBytes))
	failure := fmt.Errorf("collector control returned HTTP %d", response.StatusCode)
	if response.StatusCode == http.StatusConflict || response.StatusCode == http.StatusGone {
		return response.StatusCode, errors.Join(ErrLeaseLost, failure)
	}
	return response.StatusCode, failure
}

func correlationID() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
