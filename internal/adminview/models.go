// Package adminview provides redacted, cross-cluster operational projections
// for Sherlock administrators. Its models intentionally contain aggregates and
// safe identifiers only; raw evidence, diagnostic output, model content,
// credentials, and actor identities do not cross this boundary.
package adminview

import (
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/networkmonitor"
)

// State makes missing and degraded operational evidence explicit.
type State string

const (
	StateHealthy     State = "HEALTHY"
	StateDegraded    State = "DEGRADED"
	StateUnavailable State = "UNAVAILABLE"
	StateNoData      State = "NO_DATA"
)

type Query struct {
	At        time.Time
	Window    time.Duration
	FreshFor  time.Duration
	Limit     int
	Offset    int
	ClusterID string
}

type Dashboard struct {
	GeneratedAt time.Time        `json:"generated_at"`
	WindowStart time.Time        `json:"window_start"`
	WindowEnd   time.Time        `json:"window_end"`
	Clusters    []ClusterSummary `json:"clusters"`
	HasMore     bool             `json:"has_more"`
}

type ClusterSummary struct {
	ClusterID              string                        `json:"cluster_id"`
	DisplayName            string                        `json:"display_name"`
	ExpectedCollectorNames []string                      `json:"expected_collector_names"`
	Overall                State                         `json:"overall"`
	Connectivity           ConnectivitySummary           `json:"connectivity"`
	Freshness              FreshnessSummary              `json:"freshness"`
	Queue                  QueueSummary                  `json:"queue"`
	Investigations         InvestigationSummary          `json:"investigations"`
	ModelUsage             ModelUsageSummary             `json:"model_usage"`
	Evidence               EvidenceCoverageSummary       `json:"evidence"`
	Audit                  AuditSummary                  `json:"audit"`
	Resources              ResourceSummary               `json:"resources"`
	Health                 application.ClusterHealthView `json:"health"`
	Schedule               ScheduleSummary               `json:"schedule"`
	Network                networkmonitor.Summary        `json:"network"`
	SlurmOperations        []SlurmOperationStatus        `json:"slurm_operations,omitempty"`
}

// SlurmOperationStatus is the latest committed run for an enabled Slurm
// schedule. It is separate from evidence-envelope coverage: a timely PARTIAL
// snapshot must not disappear behind a Prometheus-only 5/8 summary.
type SlurmOperationStatus struct {
	SourceID        string     `json:"source_id"`
	Operation       string     `json:"operation"`
	Status          string     `json:"status"`
	Fresh           bool       `json:"fresh"`
	LastCompletedAt *time.Time `json:"last_completed_at,omitempty"`
}

type ScheduleSummary struct {
	Expected int64 `json:"expected"`
	Fresh    int64 `json:"fresh"`
	Late     int64 `json:"late"`
	Failed   int64 `json:"failed"`
}

// ResourceSummary is derived only from current normalized projections. Node
// and GPU counts therefore mean observed resources, not a complete inventory.
// CPU utilization remains absent until a reviewed CPU collection path exists.
type ResourceSummary struct {
	Truncated              bool       `json:"truncated,omitempty"`
	State                  State      `json:"state"`
	ObservedNodes          int64      `json:"observed_nodes"`
	ObservedGPUs           int64      `json:"observed_gpus"`
	GPUUtilizationPercent  *float64   `json:"gpu_utilization_percent,omitempty"`
	GPUUtilizationSamples  int64      `json:"gpu_utilization_samples"`
	CPUUtilizationPercent  *float64   `json:"cpu_utilization_percent,omitempty"`
	CPUUtilizationSamples  int64      `json:"cpu_utilization_samples"`
	LastObservedAt         *time.Time `json:"last_observed_at,omitempty"`
	ExpectedInventoryNodes *int64     `json:"expected_inventory_nodes,omitempty"`
	ExpectedInventoryGPUs  *int64     `json:"expected_inventory_gpus,omitempty"`
	ObservedInventoryNodes *int64     `json:"observed_inventory_nodes,omitempty"`
	ObservedInventoryGPUs  *int64     `json:"observed_inventory_gpus,omitempty"`
	ExpectedRevisionID     string     `json:"expected_revision_id,omitempty"`
	ObservedRevisionID     string     `json:"observed_revision_id,omitempty"`
}

type ConnectivitySummary struct {
	State                State `json:"state"`
	RegisteredCollectors int64 `json:"registered_collectors"`
	Collectors           int64 `json:"collectors"`
	ActiveCollectors     int64 `json:"active_collectors"`
	FreshCollectors      int64 `json:"fresh_collectors"`
	StaleCollectors      int64 `json:"stale_collectors"`
	// MissingCollectorNames contains configured expected collector names that have
	// no fresh active registration. Inactive historical registrations are reported
	// separately so they cannot inflate the expected collector denominator.
	MissingCollectorNames   []string   `json:"missing_collector_names"`
	MissingCollectorLabels  []string   `json:"missing_collector_labels"`
	ExcludedCollectorLabels []string   `json:"excluded_collector_labels"`
	SourceGapLabels         []string   `json:"source_gap_labels"`
	OnDemandSourceLabels    []string   `json:"on_demand_source_labels"`
	Sources                 int64      `json:"sources"`
	AvailableSources        int64      `json:"available_sources"`
	UnavailableSources      int64      `json:"unavailable_sources"`
	UnknownSources          int64      `json:"unknown_sources"`
	LastCollectorContact    *time.Time `json:"last_collector_contact,omitempty"`
}

type FreshnessSummary struct {
	State              State      `json:"state"`
	FreshSources       int64      `json:"fresh_sources"`
	StaleSources       int64      `json:"stale_sources"`
	SourcesWithoutData int64      `json:"sources_without_data"`
	LastSuccessAt      *time.Time `json:"last_success_at,omitempty"`
}

type QueueSummary struct {
	State                  State `json:"state"`
	CollectionAvailable    int64 `json:"collection_available"`
	CollectionLeased       int64 `json:"collection_leased"`
	DiagnosticAvailable    int64 `json:"diagnostic_available"`
	DiagnosticLeased       int64 `json:"diagnostic_leased"`
	DiagnosticBlocked      int64 `json:"diagnostic_blocked"`
	InvestigationAvailable int64 `json:"investigation_available"`
	InvestigationLeased    int64 `json:"investigation_leased"`
	Overdue                int64 `json:"overdue"`
}

type InvestigationSummary struct {
	State  State `json:"state"`
	Active int64 `json:"active"`
	// AwaitingEvidence counts runs parked because a remote execution they
	// dispatched has not completed. They are active but are deliberately
	// performing no transition, so an operator seeing a flat active count needs
	// this to tell "waiting on a cluster" from "stuck".
	AwaitingEvidence int64      `json:"awaiting_evidence"`
	Completed        int64      `json:"completed"`
	Partial          int64      `json:"partial"`
	Blocked          int64      `json:"blocked"`
	Cancelled        int64      `json:"cancelled"`
	LastUpdate       *time.Time `json:"last_update,omitempty"`
}

type ModelUsageSummary struct {
	State            State      `json:"state"`
	Calls            int64      `json:"calls"`
	Succeeded        int64      `json:"succeeded"`
	Rejected         int64      `json:"rejected"`
	Failed           int64      `json:"failed"`
	InputTokens      int64      `json:"input_tokens"`
	OutputTokens     int64      `json:"output_tokens"`
	CostMicrounits   int64      `json:"cost_microunits"`
	AverageLatencyMS int64      `json:"average_latency_ms"`
	LastCallAt       *time.Time `json:"last_call_at,omitempty"`
}

type EvidenceCoverageSummary struct {
	State State `json:"state"`
	// Current* fields describe only the newest envelope in each independent
	// (cluster, source, operation, scope) stream. The unprefixed counters remain
	// the trailing-window activity totals for historical context.
	CurrentTotal                int64                  `json:"current_total"`
	CurrentComplete             int64                  `json:"current_complete"`
	CurrentPartial              int64                  `json:"current_partial"`
	CurrentNoData               int64                  `json:"current_no_data"`
	CurrentUnavailable          int64                  `json:"current_unavailable"`
	CurrentExpectedTargets      int64                  `json:"current_expected_targets"`
	CurrentCoveredTargets       int64                  `json:"current_covered_targets"`
	CurrentArtifactsPending     int64                  `json:"current_artifacts_pending"`
	CurrentArtifactsUnavailable int64                  `json:"current_artifacts_unavailable"`
	CurrentArtifactsCorrupt     int64                  `json:"current_artifacts_corrupt"`
	CurrentStreams              []EvidenceStreamHealth `json:"current_streams"`
	HistoricalSuperseded        int64                  `json:"historical_superseded"`
	Total                       int64                  `json:"total"`
	Complete                    int64                  `json:"complete"`
	Partial                     int64                  `json:"partial"`
	NoData                      int64                  `json:"no_data"`
	Unavailable                 int64                  `json:"unavailable"`
	ExpectedTargets             int64                  `json:"expected_targets"`
	CoveredTargets              int64                  `json:"covered_targets"`
	ArtifactsPending            int64                  `json:"artifacts_pending"`
	ArtifactsUnavailable        int64                  `json:"artifacts_unavailable"`
	ArtifactsCorrupt            int64                  `json:"artifacts_corrupt"`
	LastCollectedAt             *time.Time             `json:"last_collected_at,omitempty"`
}

// EvidenceStreamHealth contains only bounded identifiers and failure metadata
// already classified safe at collection time. It never includes raw evidence,
// query text, endpoints, credentials, or artifact content.
type EvidenceStreamHealth struct {
	SourceID          string    `json:"source_id"`
	Operation         string    `json:"operation"`
	Scope             string    `json:"scope"`
	Status            string    `json:"status"`
	RunID             string    `json:"run_id,omitempty"`
	LatestAttempt     time.Time `json:"latest_attempt"`
	ExpectedTargets   []string  `json:"expected_targets"`
	CoveredTargets    []string  `json:"covered_targets"`
	MissingTargets    []string  `json:"missing_targets"`
	SeriesExpected    *int      `json:"series_expected,omitempty"`
	SeriesReturned    *int      `json:"series_returned,omitempty"`
	FailureCode       string    `json:"failure_code,omitempty"`
	SafeFailureReason string    `json:"safe_failure_reason,omitempty"`
	Condition         string    `json:"condition"`
	RecommendedAction string    `json:"recommended_action"`
}

type AuditSummary struct {
	State          State      `json:"state"`
	Events         int64      `json:"events"`
	Allowed        int64      `json:"allowed"`
	DeniedOrFailed int64      `json:"denied_or_failed"`
	LastEventAt    *time.Time `json:"last_event_at,omitempty"`
}
