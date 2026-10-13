package domain

import "time"

// HealthSignalType describes the fact established by a deterministic
// projection. Collection-state types are deliberately distinct from metric
// incident types so callers never have to interpret missing data as normal.
type HealthSignalType string

const (
	HealthSignalNormal      HealthSignalType = "NORMAL"
	HealthSignalPartial     HealthSignalType = "PARTIAL"
	HealthSignalStale       HealthSignalType = "STALE"
	HealthSignalUnavailable HealthSignalType = "UNAVAILABLE"
	HealthSignalNoData      HealthSignalType = "NO_DATA"
	HealthSignalXID         HealthSignalType = "XID"
	HealthSignalECC         HealthSignalType = "ECC"
	HealthSignalThermal     HealthSignalType = "THERMAL"
	HealthSignalMemory      HealthSignalType = "MEMORY"
	HealthSignalPower       HealthSignalType = "POWER"
	HealthSignalUtilization HealthSignalType = "UTILIZATION"
)

type HealthSeverity string

const (
	HealthSeverityUnknown  HealthSeverity = "UNKNOWN"
	HealthSeverityInfo     HealthSeverity = "INFO"
	HealthSeverityWarning  HealthSeverity = "WARNING"
	HealthSeverityCritical HealthSeverity = "CRITICAL"
)

// HealthThreshold records the exact rule used to produce a signal. A nil
// threshold means that the signal describes collection state rather than a
// numeric comparison.
type HealthThreshold struct {
	Operator string
	Value    float64
	Unit     string
}

// HealthSignal is a versioned, deterministic projection over observations.
// Evidence contains observations that satisfy the rule; CounterEvidence
// contains observations in the same category that do not satisfy it.
type HealthSignal struct {
	SchemaVersion   int
	Type            HealthSignalType
	Category        HealthSignalType
	Severity        HealthSeverity
	ClusterID       ClusterID
	SourceID        SourceID
	EntityKey       string
	Metric          string
	ObservedAt      time.Time
	ProjectedAt     time.Time
	Freshness       Freshness
	Threshold       *HealthThreshold
	Evidence        []ObservationID
	CounterEvidence []ObservationID
	Coverage        Coverage
	Reason          string
}
