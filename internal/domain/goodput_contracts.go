package domain

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// InventoryContractSchemaVersion versions the domain facts introduced for
// inventory, allocation, source coverage, and workload progress. Adapters and
// persistence map their own versions to this contract explicitly.
const InventoryContractSchemaVersion = 1

// These identifiers are deliberately distinct so a node name, a physical GPU
// UUID, and a scheduler job cannot be accidentally joined by string value.
type InventoryRevisionID string
type StableNodeID string
type PhysicalGPUUUID string
type MIGIdentity string
type SchedulerNamespace string
type SchedulerJobID string
type ProgressCohort string
type ProgressUnit string
type ProgressResetEpoch string

type EntityKind string

const (
	EntityNode EntityKind = "NODE"
	EntityGPU  EntityKind = "GPU"
	EntityMIG  EntityKind = "MIG"
)

func (kind EntityKind) Validate() error {
	switch kind {
	case EntityNode, EntityGPU, EntityMIG:
		return nil
	default:
		return fmt.Errorf("unknown entity kind %q", kind)
	}
}

// EntityIdentity is a stable identity, not a display name. Its key is safe to
// use for joins across revisions because it is scoped to one cluster and does
// not depend on the latest hostname or scheduler alias.
type EntityIdentity struct {
	ClusterID       ClusterID
	Kind            EntityKind
	NodeID          StableNodeID
	PhysicalGPUUUID PhysicalGPUUUID
	MIGIdentity     MIGIdentity
}

func CreateEntityIdentity(identity EntityIdentity) (EntityIdentity, error) {
	if identity.ClusterID == "" {
		return EntityIdentity{}, fmt.Errorf("entity cluster identifier is required")
	}
	if err := identity.Kind.Validate(); err != nil {
		return EntityIdentity{}, err
	}
	if !validGoodputIdentifier(string(identity.NodeID)) {
		return EntityIdentity{}, fmt.Errorf("stable node identifier is required")
	}
	switch identity.Kind {
	case EntityNode:
		if identity.PhysicalGPUUUID != "" || identity.MIGIdentity != "" {
			return EntityIdentity{}, fmt.Errorf("node identity cannot include GPU or MIG identity")
		}
	case EntityGPU:
		if !validGoodputIdentifier(string(identity.PhysicalGPUUUID)) || identity.MIGIdentity != "" {
			return EntityIdentity{}, fmt.Errorf("GPU identity requires a physical GPU UUID and cannot include MIG identity")
		}
	case EntityMIG:
		if !validGoodputIdentifier(string(identity.PhysicalGPUUUID)) || !validGoodputIdentifier(string(identity.MIGIdentity)) {
			return EntityIdentity{}, fmt.Errorf("MIG identity requires physical GPU UUID and MIG identity")
		}
	}
	return identity, nil
}

// Key is a deterministic stable identity key. It intentionally excludes any
// mutable display name supplied by a source adapter.
func (identity EntityIdentity) Key() string {
	return strings.Join([]string{
		string(identity.ClusterID), string(identity.Kind), string(identity.NodeID),
		string(identity.PhysicalGPUUUID), string(identity.MIGIdentity),
	}, "/")
}

// JobIdentity identifies one scheduler attempt. SubmitAt is part of the key so
// a scheduler job ID reused after accounting retention cannot join old work.
type JobIdentity struct {
	SchedulerNamespace SchedulerNamespace
	JobID              SchedulerJobID
	SubmitAt           time.Time
	Attempt            int
}

func CreateJobIdentity(identity JobIdentity) (JobIdentity, error) {
	if !validGoodputIdentifier(string(identity.SchedulerNamespace)) || !validGoodputIdentifier(string(identity.JobID)) {
		return JobIdentity{}, fmt.Errorf("scheduler namespace and job identifier are required")
	}
	if identity.SubmitAt.IsZero() {
		return JobIdentity{}, fmt.Errorf("job submit time is required")
	}
	if identity.Attempt < 0 {
		return JobIdentity{}, fmt.Errorf("job attempt cannot be negative")
	}
	identity.SubmitAt = identity.SubmitAt.UTC()
	return identity, nil
}

// InventoryRevision is an immutable, source-scoped set of stable entities.
// SourceAt records the source's observation time, EffectiveAt records when the
// facts apply, and ObservedAt records when Sherlock received them.
type InventoryRevision struct {
	SchemaVersion int
	ID            InventoryRevisionID
	ClusterID     ClusterID
	SourceID      SourceID
	SourceAt      time.Time
	EffectiveAt   time.Time
	ObservedAt    time.Time
	Entities      []EntityIdentity
}

func CreateInventoryRevision(revision InventoryRevision) (InventoryRevision, error) {
	if revision.SchemaVersion != InventoryContractSchemaVersion {
		return InventoryRevision{}, fmt.Errorf("unsupported inventory revision schema version %d", revision.SchemaVersion)
	}
	if !validGoodputIdentifier(string(revision.ID)) || revision.ClusterID == "" || revision.SourceID == "" {
		return InventoryRevision{}, fmt.Errorf("inventory revision, cluster, and source identifiers are required")
	}
	if err := validateFactTimes(revision.SourceAt, revision.EffectiveAt, revision.ObservedAt); err != nil {
		return InventoryRevision{}, fmt.Errorf("inventory revision: %w", err)
	}
	if len(revision.Entities) == 0 {
		return InventoryRevision{}, fmt.Errorf("inventory revision must contain at least one entity")
	}
	entities := make([]EntityIdentity, len(revision.Entities))
	seen := make(map[string]struct{}, len(revision.Entities))
	for index, entity := range revision.Entities {
		validated, err := CreateEntityIdentity(entity)
		if err != nil {
			return InventoryRevision{}, fmt.Errorf("inventory entity %d: %w", index, err)
		}
		if validated.ClusterID != revision.ClusterID {
			return InventoryRevision{}, fmt.Errorf("inventory entity %d belongs to another cluster", index)
		}
		if _, duplicate := seen[validated.Key()]; duplicate {
			return InventoryRevision{}, fmt.Errorf("inventory revision contains duplicate entity %q", validated.Key())
		}
		seen[validated.Key()] = struct{}{}
		entities[index] = validated
	}
	revision.SourceAt, revision.EffectiveAt, revision.ObservedAt = revision.SourceAt.UTC(), revision.EffectiveAt.UTC(), revision.ObservedAt.UTC()
	revision.Entities = entities
	return revision, nil
}

type AllocationState string

const (
	AllocationUnknown     AllocationState = "UNKNOWN"
	AllocationPending     AllocationState = "PENDING"
	AllocationRunning     AllocationState = "RUNNING"
	AllocationSuspended   AllocationState = "SUSPENDED"
	AllocationCompleting  AllocationState = "COMPLETING"
	AllocationCompleted   AllocationState = "COMPLETED"
	AllocationCancelled   AllocationState = "CANCELLED"
	AllocationFailed      AllocationState = "FAILED"
	AllocationUnsupported AllocationState = "UNSUPPORTED"
)

func (state AllocationState) Validate() error {
	switch state {
	case AllocationUnknown, AllocationPending, AllocationRunning, AllocationSuspended, AllocationCompleting,
		AllocationCompleted, AllocationCancelled, AllocationFailed, AllocationUnsupported:
		return nil
	default:
		return fmt.Errorf("unknown allocation state %q", state)
	}
}

// AllocationSnapshot records the scheduler's allocation at an effective time.
// Consumers must join an entity to this snapshot by EffectiveAt, never by the
// entity's most recently observed name or allocation.
type AllocationSnapshot struct {
	SchemaVersion int
	ClusterID     ClusterID
	SourceID      SourceID
	Job           JobIdentity
	State         AllocationState
	SourceAt      time.Time
	EffectiveAt   time.Time
	ObservedAt    time.Time
	Entities      []EntityIdentity
}

func CreateAllocationSnapshot(snapshot AllocationSnapshot) (AllocationSnapshot, error) {
	if snapshot.SchemaVersion != InventoryContractSchemaVersion {
		return AllocationSnapshot{}, fmt.Errorf("unsupported allocation snapshot schema version %d", snapshot.SchemaVersion)
	}
	if snapshot.ClusterID == "" || snapshot.SourceID == "" {
		return AllocationSnapshot{}, fmt.Errorf("allocation cluster and source identifiers are required")
	}
	job, err := CreateJobIdentity(snapshot.Job)
	if err != nil {
		return AllocationSnapshot{}, err
	}
	if err := snapshot.State.Validate(); err != nil {
		return AllocationSnapshot{}, err
	}
	if err := validateFactTimes(snapshot.SourceAt, snapshot.EffectiveAt, snapshot.ObservedAt); err != nil {
		return AllocationSnapshot{}, fmt.Errorf("allocation snapshot: %w", err)
	}
	entities, err := validateAllocationEntities(snapshot.ClusterID, snapshot.State, snapshot.Entities)
	if err != nil {
		return AllocationSnapshot{}, err
	}
	snapshot.Job = job
	snapshot.SourceAt, snapshot.EffectiveAt, snapshot.ObservedAt = snapshot.SourceAt.UTC(), snapshot.EffectiveAt.UTC(), snapshot.ObservedAt.UTC()
	snapshot.Entities = entities
	return snapshot, nil
}

type CoverageScope string

const (
	CoverageInventory   CoverageScope = "INVENTORY"
	CoverageAllocations CoverageScope = "ALLOCATIONS"
	CoverageProgress    CoverageScope = "PROGRESS"
	CoverageMetrics     CoverageScope = "METRICS"
	CoverageEvents      CoverageScope = "EVENTS"
)

func (scope CoverageScope) Validate() error {
	switch scope {
	case CoverageInventory, CoverageAllocations, CoverageProgress, CoverageMetrics, CoverageEvents:
		return nil
	default:
		return fmt.Errorf("unknown source coverage scope %q", scope)
	}
}

type SourceCoverageState string

const (
	SourceCoverageUnknown     SourceCoverageState = "UNKNOWN"
	SourceCoverageComplete    SourceCoverageState = "COMPLETE"
	SourceCoveragePartial     SourceCoverageState = "PARTIAL"
	SourceCoverageUnavailable SourceCoverageState = "UNAVAILABLE"
	SourceCoverageUnsupported SourceCoverageState = "UNSUPPORTED"
)

func (state SourceCoverageState) Validate() error {
	switch state {
	case SourceCoverageUnknown, SourceCoverageComplete, SourceCoveragePartial, SourceCoverageUnavailable, SourceCoverageUnsupported:
		return nil
	default:
		return fmt.Errorf("unknown source coverage state %q", state)
	}
}

// SourceCoverage states what one declared source established for one scope.
// It deliberately does not map a successful fetch to an all-clear health
// result; UNKNOWN and UNSUPPORTED remain distinct durable facts.
type SourceCoverage struct {
	SchemaVersion int
	ClusterID     ClusterID
	SourceID      SourceID
	Scope         CoverageScope
	State         SourceCoverageState
	Expected      int
	Observed      int
	SourceAt      time.Time
	EffectiveAt   time.Time
	ObservedAt    time.Time
}

func CreateSourceCoverage(coverage SourceCoverage) (SourceCoverage, error) {
	if coverage.SchemaVersion != InventoryContractSchemaVersion {
		return SourceCoverage{}, fmt.Errorf("unsupported source coverage schema version %d", coverage.SchemaVersion)
	}
	if coverage.ClusterID == "" || coverage.SourceID == "" {
		return SourceCoverage{}, fmt.Errorf("source coverage cluster and source identifiers are required")
	}
	if err := coverage.Scope.Validate(); err != nil {
		return SourceCoverage{}, err
	}
	if err := coverage.State.Validate(); err != nil {
		return SourceCoverage{}, err
	}
	if err := validateFactTimes(coverage.SourceAt, coverage.EffectiveAt, coverage.ObservedAt); err != nil {
		return SourceCoverage{}, fmt.Errorf("source coverage: %w", err)
	}
	if err := validateCoverageCounts(coverage.State, coverage.Expected, coverage.Observed); err != nil {
		return SourceCoverage{}, err
	}
	coverage.SourceAt, coverage.EffectiveAt, coverage.ObservedAt = coverage.SourceAt.UTC(), coverage.EffectiveAt.UTC(), coverage.ObservedAt.UTC()
	return coverage, nil
}

type ProgressState string

const (
	ProgressUnknown     ProgressState = "UNKNOWN"
	ProgressMeasured    ProgressState = "MEASURED"
	ProgressUnmeasured  ProgressState = "UNMEASURED"
	ProgressUnsupported ProgressState = "UNSUPPORTED"
)

func (state ProgressState) Validate() error {
	switch state {
	case ProgressUnknown, ProgressMeasured, ProgressUnmeasured, ProgressUnsupported:
		return nil
	default:
		return fmt.Errorf("unknown progress state %q", state)
	}
}

// ProgressObservation records an opt-in, monotonic committed-output counter
// for one workload attempt and compatible cohort. It does not infer progress
// from utilization, process liveness, or scheduler state.
type ProgressObservation struct {
	SchemaVersion int
	ClusterID     ClusterID
	SourceID      SourceID
	Job           JobIdentity
	Cohort        ProgressCohort
	State         ProgressState
	Unit          ProgressUnit
	Committed     *float64
	ResetEpoch    ProgressResetEpoch
	SourceAt      time.Time
	EffectiveAt   time.Time
	ObservedAt    time.Time
}

func CreateProgressObservation(observation ProgressObservation) (ProgressObservation, error) {
	if observation.SchemaVersion != InventoryContractSchemaVersion {
		return ProgressObservation{}, fmt.Errorf("unsupported progress observation schema version %d", observation.SchemaVersion)
	}
	if observation.ClusterID == "" || observation.SourceID == "" || !validGoodputIdentifier(string(observation.Cohort)) {
		return ProgressObservation{}, fmt.Errorf("progress cluster, source, and cohort are required")
	}
	job, err := CreateJobIdentity(observation.Job)
	if err != nil {
		return ProgressObservation{}, err
	}
	if err := observation.State.Validate(); err != nil {
		return ProgressObservation{}, err
	}
	if err := validateFactTimes(observation.SourceAt, observation.EffectiveAt, observation.ObservedAt); err != nil {
		return ProgressObservation{}, fmt.Errorf("progress observation: %w", err)
	}
	if err := validateProgressValue(observation); err != nil {
		return ProgressObservation{}, err
	}
	observation.Job = job
	observation.SourceAt, observation.EffectiveAt, observation.ObservedAt = observation.SourceAt.UTC(), observation.EffectiveAt.UTC(), observation.ObservedAt.UTC()
	if observation.Committed != nil {
		value := *observation.Committed
		observation.Committed = &value
	}
	return observation, nil
}

func validateFactTimes(sourceAt, effectiveAt, observedAt time.Time) error {
	if sourceAt.IsZero() || effectiveAt.IsZero() || observedAt.IsZero() {
		return fmt.Errorf("source, effective, and observed timestamps are required")
	}
	return nil
}

func validateAllocationEntities(clusterID ClusterID, state AllocationState, values []EntityIdentity) ([]EntityIdentity, error) {
	if (state == AllocationUnknown || state == AllocationUnsupported) && len(values) > 0 {
		return nil, fmt.Errorf("%s allocation cannot claim entities", state)
	}
	if state != AllocationUnknown && state != AllocationUnsupported && len(values) == 0 {
		return nil, fmt.Errorf("%s allocation must identify at least one entity", state)
	}
	entities := make([]EntityIdentity, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, entity := range values {
		validated, err := CreateEntityIdentity(entity)
		if err != nil {
			return nil, fmt.Errorf("allocation entity %d: %w", index, err)
		}
		if validated.ClusterID != clusterID {
			return nil, fmt.Errorf("allocation entity %d belongs to another cluster", index)
		}
		if _, duplicate := seen[validated.Key()]; duplicate {
			return nil, fmt.Errorf("allocation contains duplicate entity %q", validated.Key())
		}
		seen[validated.Key()] = struct{}{}
		entities[index] = validated
	}
	return entities, nil
}

func validateCoverageCounts(state SourceCoverageState, expected, observed int) error {
	if expected < 0 || observed < 0 || observed > expected {
		return fmt.Errorf("source coverage counts are invalid")
	}
	switch state {
	case SourceCoverageComplete:
		if expected == 0 || observed != expected {
			return fmt.Errorf("complete source coverage requires all expected targets")
		}
	case SourceCoveragePartial:
		if expected == 0 || observed == 0 || observed == expected {
			return fmt.Errorf("partial source coverage requires some but not all expected targets")
		}
	case SourceCoverageUnavailable:
		if observed != 0 {
			return fmt.Errorf("unavailable source coverage cannot observe targets")
		}
	case SourceCoverageUnsupported:
		if expected != 0 || observed != 0 {
			return fmt.Errorf("unsupported source coverage cannot report target counts")
		}
	case SourceCoverageUnknown:
		if observed != 0 {
			return fmt.Errorf("unknown source coverage cannot report observed targets")
		}
	}
	return nil
}

func validateProgressValue(observation ProgressObservation) error {
	switch observation.State {
	case ProgressMeasured:
		if !validGoodputIdentifier(string(observation.Unit)) || !validGoodputIdentifier(string(observation.ResetEpoch)) || observation.Committed == nil || math.IsNaN(*observation.Committed) || math.IsInf(*observation.Committed, 0) || *observation.Committed < 0 {
			return fmt.Errorf("measured progress requires unit, reset epoch, and finite non-negative committed output")
		}
	case ProgressUnknown, ProgressUnmeasured, ProgressUnsupported:
		if observation.Unit != "" || observation.ResetEpoch != "" || observation.Committed != nil {
			return fmt.Errorf("%s progress cannot include a committed-output measurement", observation.State)
		}
	}
	return nil
}

func validGoodputIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	return !strings.ContainsAny(value, "\x00\r\n\t")
}
