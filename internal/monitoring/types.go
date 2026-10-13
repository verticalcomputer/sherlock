package monitoring

import (
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const StateVersion = 1

type RuleID string
type Reason string
type TransitionKind string

const (
	TransitionOpen            TransitionKind = "OPEN"
	TransitionRecover         TransitionKind = "RECOVER"
	ReasonSourceDeadline      Reason         = "SOURCE_DEADLINE_MISSED"
	ReasonThermalThreshold    Reason         = "THERMAL_THRESHOLD_CONFIRMED"
	ReasonHistoricalCounter   Reason         = "HISTORICAL_COUNTER_POSITIVE"
	ReasonRemapFailure        Reason         = "ROW_REMAP_FAILURE_ASSERTED"
	ReasonFreshRecovery       Reason         = "DISTINCT_FRESH_RECOVERY_CONFIRMED"
	ReasonReviewedDisposition Reason         = "REVIEWED_RECOVERY_DISPOSITION"
	ReasonStartupGrace        Reason         = "STARTUP_GRACE"
	ReasonMissing             Reason         = "MISSING_EVIDENCE"
	ReasonUnsupported         Reason         = "UNSUPPORTED_FIELD"
	ReasonStale               Reason         = "STALE_EVIDENCE"
	ReasonFuture              Reason         = "FUTURE_EVIDENCE"
	ReasonInvalid             Reason         = "INVALID_EVIDENCE"
	ReasonConflict            Reason         = "CONFLICTING_EVIDENCE"
	ReasonAuthority           Reason         = "AUTHORITY_UNAVAILABLE"
	ReasonCounterReset        Reason         = "COUNTER_EPOCH_UNKNOWN"
	ReasonCollectionFailed    Reason         = "REQUIRED_COLLECTION_FAILED"
	ReasonCollectionNoData    Reason         = "REQUIRED_COLLECTION_NO_DATA"
)

// Binding is frozen enrollment authority. Store validation must prove this
// exact operation and scope against durable schedule and expected inventory.
type Binding struct {
	Operation           domain.CollectionOperationID `json:"operation"`
	Scope               domain.CollectionScope       `json:"scope"`
	ScheduleRevision    int64                        `json:"schedule_revision"`
	InventoryRevisionID string                       `json:"inventory_revision_id,omitempty"`
}

type Policy struct {
	ID                  string           `json:"id"`
	Revision            int64            `json:"revision"`
	ClusterID           domain.ClusterID `json:"cluster_id"`
	SourceID            domain.SourceID  `json:"source_id"`
	EntityKey           string           `json:"entity_key"`
	Rule                RuleID           `json:"rule"`
	RuleVersion         int              `json:"rule_version"`
	Metric              string           `json:"metric"`
	Unit                string           `json:"unit"`
	Binding             Binding          `json:"binding"`
	EnrolledAt          time.Time        `json:"enrolled_at"`
	StartupGraceSeconds int64            `json:"startup_grace_seconds"`
	// Evidence expires at age >= FreshForSeconds. Expired evidence never
	// recovers immediately before a silence deadline opens another occurrence.
	FreshForSeconds int64 `json:"fresh_for_seconds"`
	ConfirmCount    int   `json:"confirm_count"`
	// Windows are maximum source-time spans, minimum durations are holds,
	// and MaxSampleGapSeconds bounds every adjacent pair of actual samples.
	// A v1 enrollment explicitly declares zero-duration holds where intended.
	ConfirmWindowSeconds      int64                 `json:"confirm_window_seconds"`
	ConfirmMinDurationSeconds int64                 `json:"confirm_min_duration_seconds"`
	RecoverCount              int                   `json:"recover_count"`
	RecoverWindowSeconds      int64                 `json:"recover_window_seconds"`
	RecoverMinDurationSeconds int64                 `json:"recover_min_duration_seconds"`
	MaxSampleGapSeconds       int64                 `json:"max_sample_gap_seconds"`
	OpenThreshold             float64               `json:"open_threshold"`
	RecoverBelow              float64               `json:"recover_below"`
	Severity                  domain.HealthSeverity `json:"severity"`
	// v1 accepts false only. Complete-empty contact for another source contract
	// needs a reviewed version; it can never establish physical GPU health.
	AllowEmptySuccess bool `json:"allow_empty_success"`
}

// Sample retains immutable evidence. Unsupported/missing cells never become a
// synthetic zero observation. Collection status is independent of sensor value.
type Sample struct {
	Observation           domain.Observation
	RunID                 domain.RunID
	CollectionCompletedAt time.Time
	Status                domain.ResultStatus
	Supported             bool
	CoverageComplete      bool
}

// RunEvidence is distinct from a collector heartbeat and matches the enrolled
// schedule, operation and finite scope exactly. Empty/no-data is not success.
type RunEvidence struct {
	RunID            domain.RunID
	ClusterID        domain.ClusterID
	SourceID         domain.SourceID
	Binding          Binding
	CompletedAt      time.Time
	Status           domain.ResultStatus
	CoverageComplete bool
	Count            int
	// Exact policy sensor assessment from this run, not source-wide support.
	// Telemetry policies use complete required-operation coverage instead.
	FieldState string
	// Set only from verified legacy run provenance by persistence. Typed v2
	// uses strict timestamp ordering even when the observation name is shared.
	LegacySourceClockTolerance bool
}

type RecoveryDisposition struct {
	ID                 string    `json:"id"`
	PolicyID           string    `json:"policy_id"`
	EnrollmentRevision int64     `json:"enrollment_revision"`
	Occurrence         int64     `json:"occurrence"`
	ReviewedAt         time.Time `json:"reviewed_at"`
	Actor              string    `json:"actor"`
	EvidenceID         string    `json:"evidence_id"`
}

type Input struct {
	At                  time.Time // Authoritative PostgreSQL time from the locked evaluation.
	AuthorityValid      bool
	Samples             []Sample
	Runs                []RunEvidence
	RecoveryDisposition *RecoveryDisposition
}

type EvidenceRef struct {
	ObservationID domain.ObservationID `json:"observation_id,omitempty"`
	RunID         domain.RunID         `json:"run_id"`
	ObservedAt    time.Time            `json:"observed_at"`
	CollectedAt   time.Time            `json:"collected_at"`
	CompletedAt   time.Time            `json:"completed_at"`
}

// State is bounded durable JSON. Repeated evaluations preserve immutable
// cursors and cannot increment confirmation counts from clock ticks.
type State struct {
	Version                 int           `json:"version"`
	PolicyID                string        `json:"policy_id"`
	EnrollmentRevision      int64         `json:"enrollment_revision"`
	Occurrence              int64         `json:"occurrence"`
	Open                    bool          `json:"open"`
	OpenedAt                time.Time     `json:"opened_at"`
	FaultAt                 time.Time     `json:"fault_at"`
	FirstQualifying         *EvidenceRef  `json:"first_qualifying,omitempty"`
	LastQualifying          *EvidenceRef  `json:"last_qualifying,omitempty"`
	SourceCursor            *EvidenceRef  `json:"source_cursor,omitempty"`
	RunCursor               *EvidenceRef  `json:"run_cursor,omitempty"`
	Pending                 []EvidenceRef `json:"pending,omitempty"`
	RecoveryPending         []EvidenceRef `json:"recovery_pending,omitempty"`
	PendingCount            int64         `json:"pending_count"`
	RecoveryCount           int64         `json:"recovery_count"`
	PendingOmittedEvidence  int64         `json:"pending_omitted_evidence"`
	RecoveryOmittedEvidence int64         `json:"recovery_omitted_evidence"`
	LastHistoricalValue     *float64      `json:"last_historical_value,omitempty"`
	ReviewedCounterValue    *float64      `json:"reviewed_counter_value,omitempty"`
	ReviewedAt              time.Time     `json:"reviewed_at"`
	DispositionID           string        `json:"disposition_id,omitempty"`
	LastRelevantSuccessAt   time.Time     `json:"last_relevant_success_at"`
	LastEvaluatedAt         time.Time     `json:"last_evaluated_at"`
	LastGap                 Reason        `json:"last_gap,omitempty"`
}

type Transition struct {
	Kind                  TransitionKind        `json:"kind"`
	Occurrence            int64                 `json:"occurrence"`
	At                    time.Time             `json:"at"`
	Reason                Reason                `json:"reason"`
	Severity              domain.HealthSeverity `json:"severity"`
	Evidence              []EvidenceRef         `json:"evidence"`
	DispositionID         string                `json:"disposition_id,omitempty"`
	QualifyingSampleCount int64                 `json:"qualifying_sample_count"`
	OmittedEvidenceCount  int64                 `json:"omitted_evidence_count"`
}

type Decision struct {
	State      State
	Transition *Transition
}
