package domain

import (
	"fmt"
	"sort"
	"time"
)

type ClusterID string
type SourceID string
type RunID string
type ObservationID string

type QueryKind string

const (
	QuerySourceHealth   QueryKind = "prometheus_source_health"
	QueryGPUIdentity    QueryKind = "dcgm_gpu_identity"
	QueryGPUUtilization QueryKind = "dcgm_gpu_utilization"
	QueryGPUTemperature QueryKind = "dcgm_gpu_temperature"
	QueryGPUPower       QueryKind = "dcgm_gpu_power"
	QueryGPUMemory      QueryKind = "dcgm_gpu_memory"
	QueryGPUECC         QueryKind = "dcgm_gpu_ecc"
	QueryGPUXID         QueryKind = "dcgm_gpu_xid"
)

func (q QueryKind) Validate() error {
	switch q {
	case QuerySourceHealth, QueryGPUIdentity, QueryGPUUtilization, QueryGPUTemperature,
		QueryGPUPower, QueryGPUMemory, QueryGPUECC, QueryGPUXID:
		return nil
	default:
		return fmt.Errorf("unknown query kind %q", q)
	}
}

// IsGPU reports whether the query produces observations about an individual
// GPU. It deliberately does not imply that any returned (or missing) value is
// healthy.
func (q QueryKind) IsGPU() bool {
	switch q {
	case QueryGPUIdentity, QueryGPUUtilization, QueryGPUTemperature, QueryGPUPower,
		QueryGPUMemory, QueryGPUECC, QueryGPUXID:
		return true
	default:
		return false
	}
}

type CollectionTask struct {
	RunID          RunID
	ClusterID      ClusterID
	SourceID       SourceID
	Query          QueryKind
	Node           string
	Range          *CollectionRange
	ScheduledFor   time.Time
	Deadline       time.Time
	MaxSeries      int
	MaxBytes       int64
	IdempotencyKey string
}

type CollectionRange struct {
	Start time.Time
	End   time.Time
	Step  time.Duration
}

type ResultStatus string

const (
	ResultSucceeded ResultStatus = "SUCCEEDED"
	ResultNoData    ResultStatus = "NO_DATA"
	ResultPartial   ResultStatus = "PARTIAL"
	ResultFailed    ResultStatus = "FAILED"
)

type FailureCode string

const (
	FailureSourceUnavailable    FailureCode = "SOURCE_UNAVAILABLE"
	FailureDeadlineExceeded     FailureCode = "DEADLINE_EXCEEDED"
	FailureMalformedResponse    FailureCode = "MALFORMED_RESPONSE"
	FailureResultLimit          FailureCode = "RESULT_LIMIT_EXCEEDED"
	FailureUnauthorized         FailureCode = "UNAUTHORIZED"
	FailureInvalidArgument      FailureCode = "INVALID_ARGUMENT"
	FailurePartialData          FailureCode = "PARTIAL_DATA"
	FailureCollectorUnavailable FailureCode = "COLLECTOR_UNAVAILABLE"
	FailureInternal             FailureCode = "INTERNAL"
)

type CollectionFailure struct {
	Code      FailureCode
	Retryable bool
	Target    string
	Message   string
}

type Coverage struct {
	MetricFields   []DCGMFieldEvidence `json:"-"`
	SeriesExpected *int
	SeriesReturned int
	BytesRead      int64
	Complete       bool
	// ExpectedTargets is an authoritative inventory snapshot when one is
	// available. An empty slice means target completeness was not proven; it
	// must never be inferred from the returned samples alone.
	ExpectedTargets []EvidenceTarget
}

type Label struct {
	Name  string
	Value string
}

func SortedLabels(values map[string]string) []Label {
	labels := make([]Label, 0, len(values))
	for name, value := range values {
		labels = append(labels, Label{Name: name, Value: value})
	}
	sort.Slice(labels, func(i, j int) bool { return labels[i].Name < labels[j].Name })
	return labels
}

type Observation struct {
	Semantics       *MetricSemantics `json:"-"`
	ID              ObservationID
	SchemaVersion   int
	ClusterID       ClusterID
	SourceID        SourceID
	Kind            string
	EntityKey       string
	Metric          string
	Labels          []Label
	Value           float64
	Unit            string
	ObservedAt      time.Time
	CollectedAt     time.Time
	SourceReference string
}

type CollectionResult struct {
	Task         CollectionTask
	Status       ResultStatus
	StartedAt    time.Time
	CompletedAt  time.Time
	Coverage     Coverage
	Observations []Observation
	Failures     []CollectionFailure
}

type Freshness string

const (
	FreshnessUnknown Freshness = "UNKNOWN"
	FreshnessFresh   Freshness = "FRESH"
	FreshnessStale   Freshness = "STALE"
)

func FreshnessAt(lastSuccess *time.Time, now time.Time, freshFor time.Duration) Freshness {
	if lastSuccess == nil {
		return FreshnessUnknown
	}
	if now.Sub(lastSuccess.UTC()) <= freshFor {
		return FreshnessFresh
	}
	return FreshnessStale
}

type CurrentProjection struct {
	ClusterID      ClusterID
	SourceID       SourceID
	EntityKey      string
	Metric         string
	ObservationID  ObservationID
	ObservedAt     time.Time
	LastSuccessAt  time.Time
	Freshness      Freshness
	ProjectionTime time.Time
}
