// Code generated from api/openapi/sherlock-v1.yaml; DO NOT EDIT.
// Sherlock-OpenAPI-SHA256: 13decf32bd524545379fd08fbd86c5cf345d189b996712dce317dfe3f4eba4c3

package sherlock

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Freshness string
type CollectionStatus string
type SourceStatus string
type SourceSupport string
type HealthState string
type HealthSeverity string
type EvidenceStatus string
type EventType string

const (
	FreshnessFresh   Freshness = "FRESH"
	FreshnessStale   Freshness = "STALE"
	FreshnessUnknown Freshness = "UNKNOWN"

	CollectionStatusSucceeded CollectionStatus = "SUCCEEDED"
	CollectionStatusNoData    CollectionStatus = "NO_DATA"
	CollectionStatusPartial   CollectionStatus = "PARTIAL"
	CollectionStatusFailed    CollectionStatus = "FAILED"

	EventTypeCollectionRunUpdated EventType = "collection_run.updated"
	EventTypeSourceUpdated        EventType = "source.updated"
)

type Coverage struct {
	Requested      int   `json:"requested"`
	Successful     int   `json:"successful"`
	Failed         int   `json:"failed"`
	Complete       bool  `json:"complete"`
	SeriesExpected *int  `json:"series_expected,omitempty"`
	SeriesReturned int   `json:"series_returned,omitempty"`
	BytesRead      int64 `json:"bytes_read,omitempty"`
}

type CollectionError struct {
	Code      string `json:"code"`
	SourceID  string `json:"source_id,omitempty"`
	TargetID  string `json:"target_id,omitempty"`
	Retryable bool   `json:"retryable"`
	Message   string `json:"message,omitempty"`
}

type ResponseMeta struct {
	RequestID        string           `json:"request_id"`
	GeneratedAt      time.Time        `json:"generated_at"`
	CollectionStatus CollectionStatus `json:"collection_status"`
	Freshness        Freshness        `json:"freshness"`
	Coverage         Coverage         `json:"coverage"`
	Warnings         []string         `json:"warnings"`
	NextPageToken    string           `json:"next_page_token,omitempty"`
}

type StateMetadata struct {
	ObservedAt       time.Time        `json:"observed_at"`
	CollectedAt      time.Time        `json:"collected_at"`
	Freshness        Freshness        `json:"freshness"`
	Coverage         Coverage         `json:"coverage"`
	CollectionStatus CollectionStatus `json:"collection_status"`
}

type Cluster struct {
	ClusterID    string   `json:"cluster_id"`
	Name         string   `json:"name"`
	Capabilities []string `json:"capabilities"`
	StateMetadata
}

type Source struct {
	SourceID      string           `json:"source_id"`
	Kind          string           `json:"kind"`
	Status        SourceStatus     `json:"status"`
	LastSuccessAt *time.Time       `json:"last_success_at,omitempty"`
	LastError     *CollectionError `json:"last_error,omitempty"`
	StateMetadata
	CoverageByScope []SourceCoverage `json:"coverage_by_scope,omitempty"`
}

type SourceProvenance struct {
	SourceID        string    `json:"source_id"`
	SourceAt        time.Time `json:"source_at"`
	EffectiveAt     time.Time `json:"effective_at"`
	ObservedAt      time.Time `json:"observed_at"`
	SourceReference string    `json:"source_reference,omitempty"`
	EvidenceIDs     []string  `json:"evidence_ids,omitempty"`
}
type SourceCoverage struct {
	Scope      string           `json:"scope"`
	Support    SourceSupport    `json:"support"`
	State      string           `json:"state"`
	Expected   int              `json:"expected"`
	Observed   int              `json:"observed"`
	Provenance SourceProvenance `json:"provenance"`
}

type Label struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Observation struct {
	ObservationID   string   `json:"observation_id"`
	SchemaVersion   int      `json:"schema_version"`
	ClusterID       string   `json:"cluster_id"`
	SourceID        string   `json:"source_id"`
	Kind            string   `json:"kind"`
	EntityKey       string   `json:"entity_key"`
	Metric          string   `json:"metric"`
	Labels          []Label  `json:"labels"`
	Value           float64  `json:"value"`
	Unit            string   `json:"unit"`
	SourceReference string   `json:"source_reference"`
	EvidenceIDs     []string `json:"evidence_ids,omitempty"`
	StateMetadata
}

type HealthSignal struct {
	SchemaVersion   int            `json:"schema_version"`
	Type            HealthState    `json:"type"`
	Category        HealthState    `json:"category"`
	Severity        HealthSeverity `json:"severity"`
	SourceID        string         `json:"source_id"`
	EntityKey       string         `json:"entity_key"`
	Metric          string         `json:"metric,omitempty"`
	ObservedAt      time.Time      `json:"observed_at"`
	ProjectedAt     time.Time      `json:"projected_at"`
	Freshness       Freshness      `json:"freshness"`
	Coverage        Coverage       `json:"coverage"`
	Evidence        []string       `json:"evidence"`
	CounterEvidence []string       `json:"counter_evidence"`
	Reason          string         `json:"reason"`
}

type HealthSummary struct {
	ClusterID string             `json:"cluster_id"`
	State     HealthState        `json:"state"`
	Severity  HealthSeverity     `json:"severity"`
	Signals   []HealthSignal     `json:"signals"`
	Errors    []CollectionError  `json:"errors"`
	Shared    *ClusterHealthView `json:"shared,omitempty"`
	StateMetadata
}

type ClusterCapacityView struct {
	Condition          string `json:"condition"`
	ExpectedNodes      *int64 `json:"expected_nodes"`
	ExpectedGPUs       *int64 `json:"expected_gpus"`
	ObservedNodes      *int64 `json:"observed_nodes"`
	ObservedGPUs       *int64 `json:"observed_gpus"`
	ExpectedRevisionID string `json:"expected_revision_id,omitempty"`
	ObservedRevisionID string `json:"observed_revision_id,omitempty"`
}

type ClusterMonitoringView struct {
	CollectorCondition string `json:"collector_condition"`
	FreshnessCondition string `json:"freshness_condition"`
	CoverageCondition  string `json:"coverage_condition"`
	SupportCondition   string `json:"support_condition"`
	ExpectedCollectors int64  `json:"expected_collectors"`
	FreshCollectors    int64  `json:"fresh_collectors"`
	FreshSources       int64  `json:"fresh_sources"`
	StaleSources       int64  `json:"stale_sources"`
	SourcesWithoutData int64  `json:"sources_without_data"`
	CompleteStreams    int64  `json:"complete_streams"`
	PartialStreams     int64  `json:"partial_streams"`
	NoDataStreams      int64  `json:"no_data_streams"`
	UnavailableStreams int64  `json:"unavailable_streams"`
	HistoricalStreams  int64  `json:"historical_streams"`
	ExpectedOperations int64  `json:"expected_operations"`
	FreshOperations    int64  `json:"fresh_operations"`
	LateOperations     int64  `json:"late_operations"`
	FailedOperations   int64  `json:"failed_operations"`
}

type ClusterHealthView struct {
	SchemaVersion int                   `json:"schema_version"`
	ClusterID     string                `json:"cluster_id"`
	GeneratedAt   time.Time             `json:"generated_at"`
	WindowStart   time.Time             `json:"window_start"`
	WindowEnd     time.Time             `json:"window_end"`
	Capacity      ClusterCapacityView   `json:"capacity"`
	Monitoring    ClusterMonitoringView `json:"monitoring"`
	Workload      string                `json:"workload_condition"`
	Progress      string                `json:"progress_state"`
	Attention     []string              `json:"attention"`
}

type GPUMetric struct {
	Value      float64   `json:"value"`
	Unit       string    `json:"unit"`
	ObservedAt time.Time `json:"observed_at"`
}

type GPUSummary struct {
	GPUID    string               `json:"gpu_id"`
	NodeID   string               `json:"node_id"`
	UUID     string               `json:"uuid,omitempty"`
	Model    string               `json:"model,omitempty"`
	Health   HealthState          `json:"health"`
	Severity HealthSeverity       `json:"severity"`
	Signals  []HealthSignal       `json:"signals"`
	Metrics  map[string]GPUMetric `json:"metrics"`
	StateMetadata
}

type CollectionRun struct {
	RunID        string            `json:"run_id"`
	ClusterID    string            `json:"cluster_id"`
	SourceID     string            `json:"source_id"`
	Query        string            `json:"query"`
	Status       CollectionStatus  `json:"status"`
	ScheduledFor time.Time         `json:"scheduled_for"`
	StartedAt    time.Time         `json:"started_at"`
	CompletedAt  time.Time         `json:"completed_at"`
	Failures     []CollectionError `json:"failures"`
	StateMetadata
}

type EvidenceTarget struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type EvidenceCoverage struct {
	Expected []EvidenceTarget `json:"expected"`
	Covered  []EvidenceTarget `json:"covered"`
	Complete bool             `json:"complete"`
}

type EvidenceSourceReference struct {
	SourceID          string `json:"source_id"`
	RunID             string `json:"run_id"`
	Operation         string `json:"operation"`
	DefinitionVersion string `json:"definition_version"`
	Reference         string `json:"reference"`
}

type ArtifactReference struct {
	ArtifactID    string `json:"artifact_id"`
	SHA256        string `json:"sha256"`
	Bytes         int64  `json:"bytes"`
	MediaType     string `json:"media_type"`
	Compression   string `json:"compression"`
	ParserVersion string `json:"parser_version"`
	Redactions    struct {
		PolicyVersion string `json:"policy_version"`
		MatchCount    int    `json:"match_count"`
	} `json:"redactions"`
	RetentionClass string `json:"retention_class"`
	Availability   string `json:"availability"`
}

type Evidence struct {
	EvidenceID    string                  `json:"evidence_id"`
	SchemaVersion int                     `json:"schema_version"`
	ClusterID     string                  `json:"cluster_id"`
	Status        EvidenceStatus          `json:"status"`
	Source        EvidenceSourceReference `json:"source"`
	TimeRange     struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	} `json:"time_range"`
	CollectedAt time.Time          `json:"collected_at"`
	Coverage    EvidenceCoverage   `json:"coverage"`
	Artifact    *ArtifactReference `json:"artifact,omitempty"`
	Supersedes  *string            `json:"supersedes,omitempty"`
}

type DiagnosticDefinitionReference struct {
	PackID            string `json:"pack_id"`
	PackVersion       string `json:"pack_version"`
	DefinitionID      string `json:"definition_id"`
	DefinitionVersion string `json:"definition_version"`
	DefinitionSHA256  string `json:"definition_sha256"`
}
type DiagnosticArgument struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type DiagnosticRunRequest struct {
	Definition  DiagnosticDefinitionReference `json:"definition"`
	Targets     []string                      `json:"targets"`
	Arguments   []DiagnosticArgument          `json:"arguments"`
	Deadline    *time.Time                    `json:"deadline,omitempty"`
	MaxAttempts int                           `json:"max_attempts,omitempty"`
}
type DiagnosticAuthorizationPreview struct {
	Allowed          bool   `json:"allowed"`
	ApprovalRequired bool   `json:"approval_required"`
	ReasonCode       string `json:"reason_code"`
}
type DiagnosticApprovalRequest struct {
	ExpiresAt time.Time `json:"expires_at"`
}
type DiagnosticTargetResult struct {
	Target                    string `json:"target"`
	Status                    string `json:"status"`
	Retryable                 bool   `json:"retryable"`
	ExitCode                  *int   `json:"exit_code,omitempty"`
	Signal                    string `json:"signal,omitempty"`
	TimedOut                  bool   `json:"timed_out"`
	StdoutTruncated           bool   `json:"stdout_truncated"`
	StderrTruncated           bool   `json:"stderr_truncated"`
	StdoutBytes               int64  `json:"stdout_bytes"`
	StderrBytes               int64  `json:"stderr_bytes"`
	StdoutSHA256              string `json:"stdout_sha256"`
	StdoutTransformationState string `json:"stdout_transformation_state"`
	StderrSHA256              string `json:"stderr_sha256"`
	ErrorCode                 string `json:"error_code,omitempty"`
}
type DiagnosticAttempt struct {
	Attempt      int                      `json:"attempt"`
	RunnerID     string                   `json:"runner_id"`
	Status       string                   `json:"status"`
	LeaseExpires time.Time                `json:"lease_expires_at"`
	PlanSHA256   string                   `json:"plan_sha256,omitempty"`
	StartedAt    *time.Time               `json:"started_at,omitempty"`
	CompletedAt  *time.Time               `json:"completed_at,omitempty"`
	Targets      []DiagnosticTargetResult `json:"targets"`
}
type DiagnosticRun struct {
	RunID       string                        `json:"run_id"`
	ClusterID   string                        `json:"cluster_id"`
	Definition  DiagnosticDefinitionReference `json:"definition"`
	Privilege   string                        `json:"privilege"`
	Status      string                        `json:"status"`
	RequestedBy string                        `json:"requested_by"`
	RequestedAt time.Time                     `json:"requested_at"`
	Deadline    time.Time                     `json:"deadline"`
	CompletedAt *time.Time                    `json:"completed_at,omitempty"`
	Version     int                           `json:"version"`
	WorkID      string                        `json:"work_id,omitempty"`
	Attempts    []DiagnosticAttempt           `json:"attempts"`
}

type IncidentSeverity string
type IncidentStatus string
type InvestigationStatus string

type CreateIncidentRequest struct {
	Title       string           `json:"title"`
	Summary     string           `json:"summary"`
	Severity    IncidentSeverity `json:"severity"`
	TargetIDs   []string         `json:"target_ids"`
	EvidenceIDs []string         `json:"evidence_ids"`
}
type Incident struct {
	IncidentID       string           `json:"incident_id"`
	ClusterID        string           `json:"cluster_id"`
	Title            string           `json:"title"`
	Summary          string           `json:"summary"`
	Severity         IncidentSeverity `json:"severity"`
	Status           IncidentStatus   `json:"status"`
	TargetIDs        []string         `json:"target_ids"`
	EvidenceIDs      []string         `json:"evidence_ids"`
	CreatedBy        string           `json:"created_by"`
	CreatedAt        time.Time        `json:"created_at"`
	UpdatedAt        time.Time        `json:"updated_at"`
	Version          int              `json:"version"`
	InvestigationIDs []string         `json:"investigation_ids"`
}
type IncidentListResponse struct {
	Data          []Incident `json:"data"`
	NextPageToken string     `json:"next_page_token,omitempty"`
}
type IncidentListOptions struct {
	ListOptions
	Status   IncidentStatus
	Severity IncidentSeverity
}
type InvestigationBudget struct {
	MaxDecisions        int   `json:"max_decisions"`
	MaxToolCalls        int   `json:"max_tool_calls"`
	MaxDiagnosticCalls  int   `json:"max_diagnostic_calls,omitempty"`
	MaxPrivilegedCalls  int   `json:"max_privileged_calls"`
	MaxFanOut           int   `json:"max_fan_out"`
	MaxModelTokens      int64 `json:"max_model_tokens"`
	MaxCostMicros       int64 `json:"max_cost_micros"`
	DecisionsUsed       int   `json:"decisions_used"`
	ToolCallsUsed       int   `json:"tool_calls_used"`
	DiagnosticCallsUsed int   `json:"diagnostic_calls_used,omitempty"`
	PrivilegedCallsUsed int   `json:"privileged_calls_used"`
	FanOutUsed          int   `json:"fan_out_used"`
	ModelTokensUsed     int64 `json:"model_tokens_used"`
	CostMicrosUsed      int64 `json:"cost_micros_used"`
}
type InvestigationScope struct {
	EntityKind string    `json:"entity_kind"`
	EntityIDs  []string  `json:"entity_ids"`
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
}
type StartInvestigationRequest struct {
	ClusterID       string              `json:"cluster_id"`
	IncidentID      string              `json:"incident_id"`
	Question        string              `json:"question"`
	Scope           InvestigationScope  `json:"scope"`
	SuccessCriteria []string            `json:"success_criteria"`
	Budget          InvestigationBudget `json:"budget"`
	Deadline        time.Time           `json:"deadline"`
}
type InvestigationAction struct {
	ActionID     string `json:"action_id"`
	ToolID       string `json:"tool_id"`
	ActionSHA256 string `json:"action_sha256"`
	Privileged   bool   `json:"privileged"`
	FanOut       int    `json:"fan_out"`
}
type Investigation struct {
	InvestigationID string               `json:"investigation_id"`
	ClusterID       string               `json:"cluster_id"`
	IncidentID      string               `json:"incident_id"`
	Question        string               `json:"question"`
	Scope           InvestigationScope   `json:"scope"`
	SuccessCriteria []string             `json:"success_criteria"`
	Status          InvestigationStatus  `json:"status"`
	StopReason      string               `json:"stop_reason,omitempty"`
	Budget          InvestigationBudget  `json:"budget"`
	PendingAction   *InvestigationAction `json:"pending_action,omitempty"`
	FindingIDs      []string             `json:"finding_ids"`
	CreatedBy       string               `json:"created_by"`
	CreatedAt       time.Time            `json:"created_at"`
	Deadline        time.Time            `json:"deadline"`
	UpdatedAt       time.Time            `json:"updated_at"`
	CompletedAt     *time.Time           `json:"completed_at,omitempty"`
	Version         int                  `json:"version"`
}
type CancelInvestigationRequest struct {
	ExpectedVersion int    `json:"expected_version"`
	Reason          string `json:"reason"`
}
type ApproveInvestigationRequest struct {
	ApprovalID      string    `json:"approval_id"`
	ActionID        string    `json:"action_id"`
	ActionSHA256    string    `json:"action_sha256"`
	ExpectedVersion int       `json:"expected_version"`
	ExpiresAt       time.Time `json:"expires_at"`
}
type InvestigationEvent struct {
	EventID         string              `json:"event_id"`
	SchemaVersion   int                 `json:"schema_version"`
	InvestigationID string              `json:"investigation_id"`
	ClusterID       string              `json:"cluster_id"`
	Sequence        int64               `json:"sequence"`
	Type            string              `json:"type"`
	FromStatus      InvestigationStatus `json:"from_status,omitempty"`
	ToStatus        InvestigationStatus `json:"to_status,omitempty"`
	OccurredAt      time.Time           `json:"occurred_at"`
	Attributes      map[string]any      `json:"attributes,omitempty"`
}
type InvestigationEvidence struct {
	InvestigationID string    `json:"investigation_id"`
	EvidenceID      string    `json:"evidence_id"`
	ClusterID       string    `json:"cluster_id"`
	EntityIDs       []string  `json:"entity_ids"`
	RecordedAt      time.Time `json:"recorded_at"`
}
type Hypothesis struct {
	HypothesisID          string   `json:"hypothesis_id"`
	InvestigationID       string   `json:"investigation_id"`
	Statement             string   `json:"statement"`
	Status                string   `json:"status"`
	Confidence            float64  `json:"confidence"`
	SupportingEvidenceIDs []string `json:"supporting_evidence_ids"`
	CounterEvidenceIDs    []string `json:"counter_evidence_ids"`
	UnresolvedTests       []string `json:"unresolved_tests"`
	Version               int      `json:"version"`
}
type Finding struct {
	FindingID          string   `json:"finding_id"`
	InvestigationID    string   `json:"investigation_id"`
	Kind               string   `json:"kind"`
	Statement          string   `json:"statement"`
	EntityIDs          []string `json:"entity_ids"`
	Severity           string   `json:"severity"`
	Confidence         *float64 `json:"confidence,omitempty"`
	EvidenceIDs        []string `json:"evidence_ids"`
	CounterEvidenceIDs []string `json:"counter_evidence_ids"`
	Status             string   `json:"status"`
	ValidationStatus   string   `json:"validation_status"`
	ValidationErrors   []string `json:"validation_errors"`
}
type InvestigationEventListResponse struct {
	Data []InvestigationEvent `json:"data"`
}
type InvestigationEvidenceListResponse struct {
	Data []InvestigationEvidence `json:"data"`
}
type HypothesisListResponse struct {
	Data []Hypothesis `json:"data"`
}
type FindingListResponse struct {
	Data []Finding `json:"data"`
}

type listResponse[T any] struct {
	Data   []T               `json:"data"`
	Meta   ResponseMeta      `json:"meta"`
	Errors []CollectionError `json:"errors"`
}

type ClusterListResponse = listResponse[Cluster]
type SourceListResponse = listResponse[Source]
type ObservationListResponse = listResponse[Observation]
type GPUSummaryListResponse = listResponse[GPUSummary]
type CollectionRunListResponse = listResponse[CollectionRun]
type EvidenceListResponse = listResponse[Evidence]

type Problem struct {
	Type       string `json:"type"`
	Title      string `json:"title"`
	Status     int    `json:"status"`
	Code       string `json:"code"`
	Detail     string `json:"detail"`
	RequestID  string `json:"request_id"`
	Violations []struct {
		Field  string `json:"field"`
		Reason string `json:"reason"`
	} `json:"violations,omitempty"`
}

type APIError struct {
	Problem Problem
	Header  http.Header
}

func (e *APIError) Error() string {
	return fmt.Sprintf("sherlock API: %d %s: %s", e.Problem.Status, e.Problem.Code, e.Problem.Detail)
}

type ListOptions struct {
	PageSize  int
	PageToken string
}

type ObservationListOptions struct {
	ListOptions
	SourceID, EntityKey, Kind, Metric string
	ObservedAfter, ObservedBefore     *time.Time
}

type Client struct {
	baseURL    *url.URL
	apiKey     string
	httpClient *http.Client
}

func NewClient(baseURL, apiKey string, httpClient *http.Client) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid Sherlock base URL %q", baseURL)
	}
	if apiKey == "" {
		return nil, errors.New("sherlock API key is required")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{baseURL: u, apiKey: apiKey, httpClient: httpClient}, nil
}

func (c *Client) ListClusters(ctx context.Context, options ListOptions) (*ClusterListResponse, error) {
	return getList[Cluster](ctx, c, "/clusters", listValues(options))
}

func (c *Client) GetCluster(ctx context.Context, clusterID string) (*Cluster, error) {
	path, err := clusterPath(clusterID)
	if err != nil {
		return nil, err
	}
	return getOne[Cluster](ctx, c, path)
}

func (c *Client) GetHealth(ctx context.Context, clusterID string) (*HealthSummary, error) {
	path, err := clusterPath(clusterID)
	if err != nil {
		return nil, err
	}
	return getOne[HealthSummary](ctx, c, path+"/health")
}

func (c *Client) ListSources(ctx context.Context, clusterID string, options ListOptions, status SourceStatus) (*SourceListResponse, error) {
	path, err := clusterPath(clusterID)
	if err != nil {
		return nil, err
	}
	q := listValues(options)
	set(q, "status", string(status))
	return getList[Source](ctx, c, path+"/sources", q)
}

func (c *Client) ListObservations(ctx context.Context, clusterID string, options ObservationListOptions) (*ObservationListResponse, error) {
	path, err := clusterPath(clusterID)
	if err != nil {
		return nil, err
	}
	q := listValues(options.ListOptions)
	set(q, "source_id", options.SourceID)
	set(q, "entity_key", options.EntityKey)
	set(q, "kind", options.Kind)
	set(q, "metric", options.Metric)
	setTime(q, "observed_after", options.ObservedAfter)
	setTime(q, "observed_before", options.ObservedBefore)
	return getList[Observation](ctx, c, path+"/observations", q)
}

func (c *Client) ListGPUSummaries(ctx context.Context, clusterID string, options ListOptions, nodeID string, health HealthState) (*GPUSummaryListResponse, error) {
	path, err := clusterPath(clusterID)
	if err != nil {
		return nil, err
	}
	q := listValues(options)
	set(q, "node_id", nodeID)
	set(q, "health", string(health))
	return getList[GPUSummary](ctx, c, path+"/gpus", q)
}

func (c *Client) ListCollectionRuns(ctx context.Context, clusterID string, options ListOptions, sourceID string, status CollectionStatus) (*CollectionRunListResponse, error) {
	path, err := clusterPath(clusterID)
	if err != nil {
		return nil, err
	}
	q := listValues(options)
	set(q, "source_id", sourceID)
	set(q, "status", string(status))
	return getList[CollectionRun](ctx, c, path+"/collection-runs", q)
}

func (c *Client) ListEvidence(ctx context.Context, clusterID string, options ListOptions, status EvidenceStatus, targetID string) (*EvidenceListResponse, error) {
	path, err := clusterPath(clusterID)
	if err != nil {
		return nil, err
	}
	q := listValues(options)
	set(q, "status", string(status))
	set(q, "target_id", targetID)
	return getList[Evidence](ctx, c, path+"/evidence", q)
}

func (c *Client) GetEvidence(ctx context.Context, clusterID, evidenceID string) (*Evidence, error) {
	path, err := clusterPath(clusterID)
	if err != nil {
		return nil, err
	}
	if evidenceID == "" {
		return nil, errors.New("evidence_id is required")
	}
	return getOne[Evidence](ctx, c, path+"/evidence/"+url.PathEscape(evidenceID))
}

func (c *Client) PreviewDiagnosticRun(ctx context.Context, clusterID string, input DiagnosticRunRequest) (*DiagnosticAuthorizationPreview, error) {
	path, err := clusterPath(clusterID)
	if err != nil {
		return nil, err
	}
	return postOne[DiagnosticAuthorizationPreview](ctx, c, path+"/diagnostic-runs/preview", input, "")
}

func (c *Client) StartDiagnosticRun(ctx context.Context, clusterID, idempotencyKey string, input DiagnosticRunRequest) (*DiagnosticRun, error) {
	path, err := clusterPath(clusterID)
	if err != nil {
		return nil, err
	}
	if idempotencyKey == "" {
		return nil, errors.New("idempotency key is required")
	}
	return postOne[DiagnosticRun](ctx, c, path+"/diagnostic-runs", input, idempotencyKey)
}

func (c *Client) GetDiagnosticRun(ctx context.Context, clusterID, runID string) (*DiagnosticRun, error) {
	path, err := clusterPath(clusterID)
	if err != nil {
		return nil, err
	}
	if runID == "" {
		return nil, errors.New("run_id is required")
	}
	return getOne[DiagnosticRun](ctx, c, path+"/diagnostic-runs/"+url.PathEscape(runID))
}

func (c *Client) ApproveDiagnosticRun(ctx context.Context, clusterID, runID string, input DiagnosticApprovalRequest) (*DiagnosticRun, error) {
	path, err := clusterPath(clusterID)
	if err != nil {
		return nil, err
	}
	if runID == "" {
		return nil, errors.New("run_id is required")
	}
	return postOne[DiagnosticRun](ctx, c, path+"/diagnostic-runs/"+url.PathEscape(runID)+"/approval", input, "")
}

func (c *Client) CreateIncident(ctx context.Context, clusterID, idempotencyKey string, input CreateIncidentRequest) (*Incident, error) {
	path, err := clusterPath(clusterID)
	if err != nil {
		return nil, err
	}
	if idempotencyKey == "" {
		return nil, errors.New("idempotency key is required")
	}
	return postOne[Incident](ctx, c, path+"/incidents", input, idempotencyKey)
}
func (c *Client) ListIncidents(ctx context.Context, clusterID string, options IncidentListOptions) (*IncidentListResponse, error) {
	path, err := clusterPath(clusterID)
	if err != nil {
		return nil, err
	}
	q := listValues(options.ListOptions)
	set(q, "status", string(options.Status))
	set(q, "severity", string(options.Severity))
	return getOneWithQuery[IncidentListResponse](ctx, c, path+"/incidents", q)
}
func (c *Client) GetIncident(ctx context.Context, incidentID string) (*Incident, error) {
	if incidentID == "" {
		return nil, errors.New("incident_id is required")
	}
	return getOne[Incident](ctx, c, "/incidents/"+url.PathEscape(incidentID))
}
func (c *Client) StartInvestigation(ctx context.Context, idempotencyKey string, input StartInvestigationRequest) (*Investigation, error) {
	if idempotencyKey == "" {
		return nil, errors.New("idempotency key is required")
	}
	return postOne[Investigation](ctx, c, "/investigations", input, idempotencyKey)
}
func (c *Client) GetInvestigation(ctx context.Context, investigationID string) (*Investigation, error) {
	path, err := investigationPath(investigationID)
	if err != nil {
		return nil, err
	}
	return getOne[Investigation](ctx, c, path)
}
func (c *Client) CancelInvestigation(ctx context.Context, investigationID string, input CancelInvestigationRequest) (*Investigation, error) {
	path, err := investigationPath(investigationID)
	if err != nil {
		return nil, err
	}
	return postOne[Investigation](ctx, c, path+"/cancel", input, "")
}
func (c *Client) ApproveInvestigationAction(ctx context.Context, investigationID string, input ApproveInvestigationRequest) (*Investigation, error) {
	path, err := investigationPath(investigationID)
	if err != nil {
		return nil, err
	}
	return postOne[Investigation](ctx, c, path+"/approvals", input, "")
}
func (c *Client) ListInvestigationEvents(ctx context.Context, investigationID, lastEventID string, limit int) (*InvestigationEventListResponse, error) {
	path, err := investigationPath(investigationID)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	return getOneWithHeader[InvestigationEventListResponse](ctx, c, path+"/events", q, "Last-Event-ID", lastEventID)
}
func (c *Client) ListInvestigationEvidence(ctx context.Context, investigationID string) (*InvestigationEvidenceListResponse, error) {
	path, err := investigationPath(investigationID)
	if err != nil {
		return nil, err
	}
	return getOne[InvestigationEvidenceListResponse](ctx, c, path+"/evidence")
}
func (c *Client) ListInvestigationHypotheses(ctx context.Context, investigationID string) (*HypothesisListResponse, error) {
	path, err := investigationPath(investigationID)
	if err != nil {
		return nil, err
	}
	return getOne[HypothesisListResponse](ctx, c, path+"/hypotheses")
}
func (c *Client) ListInvestigationFindings(ctx context.Context, investigationID string) (*FindingListResponse, error) {
	path, err := investigationPath(investigationID)
	if err != nil {
		return nil, err
	}
	return getOne[FindingListResponse](ctx, c, path+"/findings")
}

type Event struct {
	ID   string
	Type EventType
	Data json.RawMessage
}

type StreamOptions struct {
	LastEventID string
	EventTypes  []EventType
}

// StreamEvents holds the response open until ctx is cancelled or the server
// closes it. The caller must consume both returned channels.
func (c *Client) StreamEvents(ctx context.Context, clusterID string, options StreamOptions) (<-chan Event, <-chan error, error) {
	path, err := clusterPath(clusterID)
	if err != nil {
		return nil, nil, err
	}
	q := url.Values{}
	for _, eventType := range options.EventTypes {
		q.Add("event_type", string(eventType))
	}
	req, err := c.newRequest(ctx, path+"/events", q)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	if options.LastEventID != "" {
		req.Header.Set("Last-Event-ID", options.LastEventID)
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	if response.StatusCode != http.StatusOK {
		defer response.Body.Close()
		return nil, nil, decodeAPIError(response)
	}
	events, errs := make(chan Event), make(chan error, 1)
	go func() {
		defer close(events)
		defer close(errs)
		defer response.Body.Close()
		if err := scanEvents(ctx, response.Body, events); err != nil && !errors.Is(err, context.Canceled) {
			errs <- err
		}
	}()
	return events, errs, nil
}

func (c *Client) newRequest(ctx context.Context, path string, query url.Values) (*http.Request, error) {
	u := *c.baseURL
	u.Path = strings.TrimRight(c.baseURL.Path, "/") + path
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	return req, nil
}

func getList[T any](ctx context.Context, c *Client, path string, query url.Values) (*listResponse[T], error) {
	return getOneWithQuery[listResponse[T]](ctx, c, path, query)
}

func getOne[T any](ctx context.Context, c *Client, path string) (*T, error) {
	return getOneWithQuery[T](ctx, c, path, nil)
}

func getOneWithQuery[T any](ctx context.Context, c *Client, path string, query url.Values) (*T, error) {
	req, err := c.newRequest(ctx, path, query)
	if err != nil {
		return nil, err
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, decodeAPIError(response)
	}
	var result T
	decoder := json.NewDecoder(io.LimitReader(response.Body, 32<<20))
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("decode Sherlock response: %w", err)
	}
	return &result, nil
}

func getOneWithHeader[T any](ctx context.Context, c *Client, path string, query url.Values, name, value string) (*T, error) {
	req, err := c.newRequest(ctx, path, query)
	if err != nil {
		return nil, err
	}
	if value != "" {
		req.Header.Set(name, value)
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, decodeAPIError(response)
	}
	var result T
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode Sherlock response: %w", err)
	}
	return &result, nil
}

func postOne[T any](ctx context.Context, c *Client, path string, input any, idempotencyKey string) (*T, error) {
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("encode Sherlock request: %w", err)
	}
	u := *c.baseURL
	u.Path = strings.TrimRight(c.baseURL.Path, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, decodeAPIError(response)
	}
	var result T
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode Sherlock response: %w", err)
	}
	return &result, nil
}

func decodeAPIError(response *http.Response) error {
	var problem Problem
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&problem); err != nil {
		problem = Problem{Status: response.StatusCode, Code: "HTTP_ERROR", Detail: response.Status}
	}
	if problem.Status == 0 {
		problem.Status = response.StatusCode
	}
	return &APIError{Problem: problem, Header: response.Header.Clone()}
}

func clusterPath(clusterID string) (string, error) {
	if clusterID == "" {
		return "", errors.New("cluster_id is required")
	}
	return "/clusters/" + url.PathEscape(clusterID), nil
}

func investigationPath(investigationID string) (string, error) {
	if investigationID == "" {
		return "", errors.New("investigation_id is required")
	}
	return "/investigations/" + url.PathEscape(investigationID), nil
}

func listValues(options ListOptions) url.Values {
	q := url.Values{}
	if options.PageSize > 0 {
		q.Set("page_size", strconv.Itoa(options.PageSize))
	}
	set(q, "page_token", options.PageToken)
	return q
}
func set(q url.Values, key, value string) {
	if value != "" {
		q.Set(key, value)
	}
}
func setTime(q url.Values, key string, value *time.Time) {
	if value != nil {
		q.Set(key, value.UTC().Format(time.RFC3339Nano))
	}
}

func scanEvents(ctx context.Context, body io.Reader, output chan<- Event) error {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	var event Event
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if len(event.Data) > 0 {
				select {
				case output <- event:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			event = Event{}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "id":
			event.ID = value
		case "event":
			event.Type = EventType(value)
		case "data":
			if len(event.Data) > 0 {
				event.Data = append(event.Data, '\n')
			}
			event.Data = append(event.Data, value...)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read Sherlock event stream: %w", err)
	}
	return nil
}
