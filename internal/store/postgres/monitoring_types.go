package postgres

import (
	"encoding/json"
	"errors"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/monitoring"
	"time"
)

var (
	ErrMonitoringNotFound       = errors.New("monitoring enrollment or episode not found")
	ErrMonitoringRevision       = errors.New("monitoring operator revision conflict")
	ErrMonitoringAuthority      = errors.New("monitoring durable authority unavailable")
	ErrMonitoringPolicyConflict = errors.New("monitoring policy is immutable; disable and use an explicit new policy ID")
)

type MonitoringHistoryCoverage struct {
	MeasuredAt                    time.Time `json:"measured_at"`
	From                          time.Time `json:"from"`
	Through                       time.Time `json:"through"`
	OmittedAttemptsLowerBound     int64     `json:"omitted_attempts_lower_bound"`
	OmittedObservationsLowerBound int64     `json:"omitted_observations_lower_bound"`
}

type MonitoringEnrollment struct {
	HistoryCoverage *MonitoringHistoryCoverage `json:"history_coverage_gap,omitempty"`
	LastAttemptAt   *time.Time                 `json:"last_attempt_at,omitempty"`
	Policy          monitoring.Policy          `json:"policy"`
	Enabled         bool                       `json:"enabled"`
	Revision        int64                      `json:"revision"`
	State           monitoring.State           `json:"state"`
	NextDueAt       time.Time                  `json:"next_due_at"`
	LastFailureCode string                     `json:"last_failure_code,omitempty"`
}
type MonitoringEpisode struct {
	PolicyID           string                `json:"policy_id"`
	EnrollmentRevision int64                 `json:"enrollment_revision"`
	Occurrence         int64                 `json:"occurrence"`
	Version            int64                 `json:"version"`
	IncidentID         string                `json:"incident_id"`
	OpenedAt           time.Time             `json:"opened_at"`
	ClosedAt           *time.Time            `json:"closed_at,omitempty"`
	ClosedReason       monitoring.Reason     `json:"closed_reason,omitempty"`
	Owner              string                `json:"owner,omitempty"`
	AcknowledgedBy     string                `json:"acknowledged_by,omitempty"`
	AcknowledgedAt     *time.Time            `json:"acknowledged_at,omitempty"`
	MaintenanceUntil   *time.Time            `json:"maintenance_until,omitempty"`
	MaintenanceBy      string                `json:"maintenance_by,omitempty"`
	DispositionID      string                `json:"disposition_id,omitempty"`
	Reason             monitoring.Reason     `json:"reason"`
	Severity           domain.HealthSeverity `json:"severity"`
	Evidence           []MonitoringEvidence  `json:"evidence"`
}

// Raw IDs are logical references, not a retention guarantee. Immutable values
// and run assessments survive raw retention. Availability is computed at read.
type MonitoringEvidence struct {
	QualifyingSampleCount int64                        `json:"qualifying_sample_count"`
	OmittedEvidenceCount  int64                        `json:"omitted_evidence_count"`
	EvidenceID            string                       `json:"evidence_id"`
	Transition            monitoring.TransitionKind    `json:"transition"`
	At                    time.Time                    `json:"at"`
	Snapshot              []MonitoringEvidenceSnapshot `json:"snapshot"`
	RawEvidenceAvailable  bool                         `json:"raw_evidence_available"`
}
type MonitoringEvidenceSnapshot struct {
	QualifyingObservationsLowerBound int                     `json:"qualifying_observations_lower_bound,omitempty"`
	LegacySourceClockTolerance       bool                    `json:"legacy_source_clock_tolerance,omitempty"`
	SourceClockContract              string                  `json:"source_clock_contract,omitempty"`
	Reference                        monitoring.EvidenceRef  `json:"reference"`
	Metric                           string                  `json:"metric,omitempty"`
	Value                            *float64                `json:"value,omitempty"`
	Unit                             string                  `json:"unit,omitempty"`
	Semantics                        *domain.MetricSemantics `json:"semantics,omitempty"`
	Status                           domain.ResultStatus     `json:"collection_status"`
	Supported                        bool                    `json:"supported"`
	CoverageComplete                 bool                    `json:"coverage_complete"`
}
type MonitoringAudit struct {
	Revision   int64           `json:"revision"`
	Occurrence int64           `json:"occurrence,omitempty"`
	Action     string          `json:"action"`
	Actor      string          `json:"actor"`
	ActorKind  string          `json:"actor_kind"`
	At         time.Time       `json:"at"`
	Details    json.RawMessage `json:"details"`
}
type MonitoringStatus struct {
	Enrollment        MonitoringEnrollment `json:"enrollment"`
	Episodes          []MonitoringEpisode  `json:"episodes"`
	EpisodesTruncated bool                 `json:"episodes_truncated"`
	Audit             []MonitoringAudit    `json:"audit"`
	AuditTruncated    bool                 `json:"audit_truncated"`
}
