package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

const CollectionProtocolVersion = 2

// ValidateCollectionClaimSources bounds the configured source instances a
// collector can request in one claim; it does not grant cluster authority.
func ValidateCollectionClaimSources(sources []SourceID) error {
	if len(sources) < 1 || len(sources) > 100 {
		return fmt.Errorf("typed claim requires between one and 100 configured sources")
	}
	seen := make(map[SourceID]bool, len(sources))
	for _, source := range sources {
		if !validControlID(string(source)) || seen[source] {
			return fmt.Errorf("typed claim source is invalid or duplicated")
		}
		seen[source] = true
	}
	return nil
}

type CollectionPayloadKind string
type CollectionPayloadSchema string

const (
	CollectionPayloadMetrics       CollectionPayloadKind   = "metrics"
	CollectionPayloadInventory     CollectionPayloadKind   = "inventory"
	CollectionPayloadAllocation    CollectionPayloadKind   = "allocation"
	CollectionPayloadEvents        CollectionPayloadKind   = "events"
	CollectionPayloadSlurmSnapshot CollectionPayloadKind   = "slurm_snapshot"
	CollectionPayloadGPUProcess    CollectionPayloadKind   = "gpu_process"
	CollectionMetricsSchema        CollectionPayloadSchema = "sherlock.collection.metrics.v1"
	CollectionInventorySchema      CollectionPayloadSchema = "sherlock.collection.inventory.v1"
	CollectionAllocationSchema     CollectionPayloadSchema = "sherlock.collection.allocation.v1"
	CollectionEventsSchema         CollectionPayloadSchema = "sherlock.collection.events.v1"
	CollectionSlurmSnapshotSchema  CollectionPayloadSchema = "sherlock.collection.slurm_snapshot.v1"
)

// CollectionPlan is a reviewed request, never an executable or source URL.
// SourceID selects a locally configured instance of SourceKind. Scope is a
// finite set of stable nodes; adapters may not expand it from result contents.
type CollectionPlan struct {
	SchemaVersion     int                     `json:"schema_version"`
	RunID             RunID                   `json:"run_id"`
	ClusterID         ClusterID               `json:"cluster_id"`
	SourceID          SourceID                `json:"source_id"`
	SourceKind        CollectionSourceKind    `json:"source_kind"`
	Operation         CollectionOperationID   `json:"operation"`
	PayloadSchema     CollectionPayloadSchema `json:"payload_schema"`
	Scope             CollectionScope         `json:"scope"`
	Interval          *CollectionInterval     `json:"interval,omitempty"`
	Cursor            string                  `json:"cursor,omitempty"`
	ScheduledFor      time.Time               `json:"scheduled_for"`
	Deadline          time.Time               `json:"deadline"`
	Limits            CollectionLimits        `json:"limits"`
	InventoryRevision InventoryRevisionID     `json:"inventory_revision,omitempty"`
	IdempotencyKey    string                  `json:"idempotency_key"`
}

type CollectionScope struct {
	Nodes []StableNodeID `json:"nodes"`
}
type CollectionInterval struct {
	Start       time.Time `json:"start"`
	End         time.Time `json:"end"`
	StepSeconds int       `json:"step_seconds,omitempty"`
}
type CollectionLimits struct {
	MaxRecords int   `json:"max_records"`
	MaxBytes   int64 `json:"max_bytes"`
}

func ValidateCollectionPlan(plan CollectionPlan) error {
	if plan.SchemaVersion != CollectionProtocolVersion {
		return fmt.Errorf("unsupported collection plan version")
	}
	op, ok := ReviewedCollectionOperation(plan.Operation)
	if !ok || op.Source != plan.SourceKind || op.Schema != plan.PayloadSchema {
		return fmt.Errorf("unreviewed collection operation, source kind, or schema")
	}
	if !validControlID(string(plan.RunID)) || !validControlID(string(plan.ClusterID)) || !validControlID(string(plan.SourceID)) || !validGoodputIdentifier(plan.IdempotencyKey) {
		return fmt.Errorf("collection plan identifiers are invalid")
	}
	if plan.ScheduledFor.IsZero() || !plan.Deadline.After(plan.ScheduledFor) || plan.Deadline.Sub(plan.ScheduledFor) > 24*time.Hour {
		return fmt.Errorf("collection plan execution interval is invalid")
	}
	if plan.Limits.MaxRecords < 1 || plan.Limits.MaxRecords > 10000 || plan.Limits.MaxBytes < 1 || plan.Limits.MaxBytes > 10<<20 {
		return fmt.Errorf("collection plan limits are invalid")
	}
	if plan.Operation == OperationGPUProcessObservations && validateGPUProcessLimits(plan.Limits.MaxRecords, plan.Limits.MaxBytes) != nil {
		return fmt.Errorf("GPU process collection plan limits are invalid")
	}
	if len(plan.Scope.Nodes) < 1 || len(plan.Scope.Nodes) > 10000 {
		return fmt.Errorf("collection plan requires bounded node scope")
	}
	seen := make(map[StableNodeID]bool, len(plan.Scope.Nodes))
	for _, node := range plan.Scope.Nodes {
		if !validControlID(string(node)) || seen[node] {
			return fmt.Errorf("collection plan node scope is invalid or duplicated")
		}
		seen[node] = true
	}
	if (plan.Interval == nil) == (plan.Cursor == "") {
		return fmt.Errorf("collection plan requires exactly one interval or cursor")
	}
	if plan.Cursor != "" && (!validGoodputIdentifier(plan.Cursor) || len(plan.Cursor) > 256) {
		return fmt.Errorf("collection cursor is invalid")
	}
	if plan.Interval != nil {
		i := plan.Interval
		if i.Start.IsZero() || !i.End.After(i.Start) || i.End.Sub(i.Start) > 24*time.Hour || i.StepSeconds < 0 || i.StepSeconds > 3600 {
			return fmt.Errorf("collection interval is invalid")
		}
	}
	if plan.InventoryRevision != "" && !validGoodputIdentifier(string(plan.InventoryRevision)) {
		return fmt.Errorf("inventory revision is invalid")
	}
	return nil
}

// TypedWorkLease augments the existing durable work and attempt authority.
// It is not an independent lease or queue. A store must load Plan together
// with WorkLease in the same claim transaction.
type TypedWorkLease struct {
	Lease WorkLease
	Plan  CollectionPlan
}

func ValidateTypedWorkLease(lease TypedWorkLease) error {
	if err := ValidateCollectionPlan(lease.Plan); err != nil {
		return err
	}
	l, p := lease.Lease, lease.Plan
	if !ValidCollectorWorkID(string(l.Work.WorkID)) || l.Attempt < 1 || !validControlID(string(l.CollectorID)) || len(l.LeaseToken) < 32 || len(l.LeaseToken) > 256 || l.LeaseExpires.IsZero() || l.Work.WorkExpiresAt.IsZero() {
		return fmt.Errorf("typed work lease authority is invalid")
	}
	if l.Work.Task.RunID != p.RunID || l.Work.Task.ClusterID != p.ClusterID || l.Work.Task.SourceID != p.SourceID || l.Work.Task.IdempotencyKey != p.IdempotencyKey {
		return fmt.Errorf("typed plan does not match durable work identity")
	}
	return nil
}

// CollectionPayload is a closed tagged union. Exactly one pointer must be set,
// including for empty results. Domain facts retain their GP-02 JSON field names.
type CollectionPayload struct {
	Kind          CollectionPayloadKind        `json:"kind"`
	Metrics       *CollectionMetricsPayload    `json:"metrics,omitempty"`
	Inventory     *CollectionInventoryPayload  `json:"inventory,omitempty"`
	Allocation    *CollectionAllocationPayload `json:"allocation,omitempty"`
	Events        *CollectionEventsPayload     `json:"events,omitempty"`
	SlurmSnapshot *SlurmSnapshotPayload        `json:"slurm_snapshot,omitempty"`
	GPUProcess    *GPUProcessSnapshotPayload   `json:"gpu_process,omitempty"`
}
type CollectionMetricsPayload struct {
	Observations []CollectionMetric `json:"observations"`
}

// CollectionMetric binds an existing metric observation to the stable node
// scope without trusting a mutable hostname or interpreting arbitrary labels.
type CollectionMetric struct {
	NodeID      StableNodeID `json:"node_id"`
	Observation Observation  `json:"observation"`
}
type CollectionInventoryPayload struct {
	Revisions []InventoryRevision `json:"revisions"`
}
type CollectionAllocationPayload struct {
	Snapshots []AllocationSnapshot `json:"snapshots"`
}
type CollectionEventsPayload struct {
	Events []CollectionEvent `json:"events"`
}

// CollectionEvent describes scheduler state transitions, not command output.
type CollectionEvent struct {
	ID         string          `json:"id"`
	NodeID     StableNodeID    `json:"node_id"`
	Job        JobIdentity     `json:"job"`
	State      AllocationState `json:"state"`
	OccurredAt time.Time       `json:"occurred_at"`
}

type TypedCollectorResult struct {
	SchemaVersion int                 `json:"schema_version"`
	WorkID        WorkID              `json:"work_id"`
	Attempt       int                 `json:"attempt"`
	Plan          CollectionPlan      `json:"plan"`
	Status        ResultStatus        `json:"status"`
	StartedAt     time.Time           `json:"started_at"`
	CompletedAt   time.Time           `json:"completed_at"`
	Coverage      SourceCoverage      `json:"coverage"`
	Payload       CollectionPayload   `json:"payload"`
	Failures      []CollectionFailure `json:"failures"`
	NextCursor    string              `json:"next_cursor,omitempty"`
}

func ValidateTypedCollectorResult(result TypedCollectorResult) error {
	if result.SchemaVersion != CollectionProtocolVersion || !ValidCollectorWorkID(string(result.WorkID)) || result.Attempt < 1 {
		return fmt.Errorf("typed result envelope is invalid")
	}
	p := result.Plan
	if err := ValidateCollectionPlan(p); err != nil {
		return err
	}
	if !validResultStatus(result.Status) || result.StartedAt.IsZero() || result.CompletedAt.Before(result.StartedAt) {
		return fmt.Errorf("typed result status or timestamps are invalid")
	}
	if err := validateFailures(result.Failures); err != nil {
		return err
	}
	if result.NextCursor != "" && (p.Cursor == "" || !validGoodputIdentifier(result.NextCursor)) {
		return fmt.Errorf("typed result cursor is invalid")
	}
	c := result.Coverage
	if _, err := CreateSourceCoverage(c); err != nil {
		return err
	}
	if c.ClusterID != p.ClusterID || c.SourceID != p.SourceID || c.Expected > p.Limits.MaxRecords {
		return fmt.Errorf("typed result coverage identity or limits are invalid")
	}
	op, _ := ReviewedCollectionOperation(p.Operation)
	payload := result.Payload
	count := 0
	for _, present := range []bool{payload.Metrics != nil, payload.Inventory != nil, payload.Allocation != nil, payload.Events != nil, payload.SlurmSnapshot != nil, payload.GPUProcess != nil} {
		if present {
			count++
		}
	}
	if count != 1 || payload.Kind != op.Payload {
		return fmt.Errorf("typed result requires exactly one reviewed payload variant")
	}
	records := 0
	checkEntities := func(entities []EntityIdentity) error {
		if len(entities) > p.Limits.MaxRecords {
			return fmt.Errorf("typed result entity limit exceeded")
		}
		for _, e := range entities {
			if e.ClusterID != p.ClusterID || !slices.Contains(p.Scope.Nodes, e.NodeID) {
				return fmt.Errorf("typed result entity is outside plan scope")
			}
		}
		return nil
	}
	switch payload.Kind {
	case CollectionPayloadMetrics:
		if payload.Metrics == nil || c.Scope != CoverageMetrics {
			return fmt.Errorf("metrics payload or coverage scope mismatch")
		}
		records = len(payload.Metrics.Observations)
		observations := make([]Observation, 0, records)
		for _, metric := range payload.Metrics.Observations {
			if !slices.Contains(p.Scope.Nodes, metric.NodeID) {
				return fmt.Errorf("metric result is outside plan scope")
			}
			observations = append(observations, metric.Observation)
		}
		if err := validateObservations(CollectionResult{Task: CollectionTask{ClusterID: p.ClusterID, SourceID: p.SourceID}, CompletedAt: result.CompletedAt, Observations: observations}); err != nil {
			return err
		}
	case CollectionPayloadInventory:
		if payload.Inventory == nil || c.Scope != CoverageInventory {
			return fmt.Errorf("inventory payload or coverage scope mismatch")
		}
		for _, revision := range payload.Inventory.Revisions {
			if _, err := CreateInventoryRevision(revision); err != nil {
				return err
			}
			if revision.ClusterID != p.ClusterID || revision.SourceID != p.SourceID {
				return fmt.Errorf("inventory result identity mismatch")
			}
			if err := checkEntities(revision.Entities); err != nil {
				return err
			}
			records += len(revision.Entities)
		}
	case CollectionPayloadAllocation:
		if payload.Allocation == nil || c.Scope != CoverageAllocations {
			return fmt.Errorf("allocation payload or coverage scope mismatch")
		}
		records = len(payload.Allocation.Snapshots)
		for _, snapshot := range payload.Allocation.Snapshots {
			if _, err := CreateAllocationSnapshot(snapshot); err != nil {
				return err
			}
			if snapshot.ClusterID != p.ClusterID || snapshot.SourceID != p.SourceID {
				return fmt.Errorf("allocation result identity mismatch")
			}
			if err := checkEntities(snapshot.Entities); err != nil {
				return err
			}
		}
	case CollectionPayloadEvents:
		if payload.Events == nil || c.Scope != CoverageEvents {
			return fmt.Errorf("events payload or coverage scope mismatch")
		}
		records = len(payload.Events.Events)
		seen := make(map[string]bool, records)
		for _, event := range payload.Events.Events {
			if !validControlID(event.ID) || seen[event.ID] || !slices.Contains(p.Scope.Nodes, event.NodeID) || event.OccurredAt.IsZero() {
				return fmt.Errorf("event identity, scope, or timestamp is invalid")
			}
			seen[event.ID] = true
			if _, err := CreateJobIdentity(event.Job); err != nil {
				return err
			}
			if err := event.State.Validate(); err != nil {
				return err
			}
		}
	case CollectionPayloadSlurmSnapshot:
		if payload.SlurmSnapshot == nil || c.Scope != CoverageAllocations {
			return fmt.Errorf("slurm snapshot payload or coverage scope mismatch")
		}
		if len(result.Failures) > 32 {
			return fmt.Errorf("slurm snapshot failure limit exceeded")
		}
		var err error
		records, err = ValidateSlurmSnapshotPayload(*payload.SlurmSnapshot, p, c, result.Status, result.StartedAt, result.CompletedAt)
		if err != nil {
			return err
		}
	case CollectionPayloadGPUProcess:
		if payload.GPUProcess == nil || c.Scope != CoverageMetrics {
			return fmt.Errorf("GPU process payload or coverage scope mismatch")
		}
		var err error
		records, err = ValidateGPUProcessSnapshotPayload(*payload.GPUProcess, p, c)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown typed result variant")
	}
	if records > p.Limits.MaxRecords {
		return fmt.Errorf("typed result record limit exceeded")
	}
	switch result.Status {
	case ResultSucceeded:
		if records == 0 || len(result.Failures) != 0 || c.State != SourceCoverageComplete {
			return fmt.Errorf("succeeded typed result is inconsistent")
		}
	case ResultNoData:
		if records != 0 || len(result.Failures) != 0 {
			return fmt.Errorf("no-data typed result is inconsistent")
		}
	case ResultPartial:
		if len(result.Failures) == 0 || c.State == SourceCoverageComplete {
			return fmt.Errorf("partial typed result is inconsistent")
		}
	case ResultFailed:
		if records != 0 || len(result.Failures) == 0 || c.State == SourceCoverageComplete || result.NextCursor != "" {
			return fmt.Errorf("failed typed result is inconsistent")
		}
	}
	return nil
}

// ValidateTypedResultForLease is the mandatory pre-commit binding check for
// durable ingestion. Authentication supplies the lease; the submitted plan is
// never authoritative. GP-03c must call this inside its finalization transaction.
func ValidateTypedResultForLease(result TypedCollectorResult, lease TypedWorkLease) error {
	if err := ValidateTypedWorkLease(lease); err != nil {
		return err
	}
	actual, err := json.Marshal(result.Plan)
	if err != nil {
		return err
	}
	expected, err := json.Marshal(lease.Plan)
	if err != nil {
		return err
	}
	if result.WorkID != lease.Lease.Work.WorkID || result.Attempt != lease.Lease.Attempt || !bytes.Equal(actual, expected) {
		return fmt.Errorf("typed result does not match its leased plan")
	}
	_, err = EncodeTypedCollectorResult(result)
	return err
}

func EncodeTypedCollectorResult(result TypedCollectorResult) ([]byte, error) {
	if err := ValidateTypedCollectorResult(result); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	if int64(len(encoded)) > result.Plan.Limits.MaxBytes {
		return nil, fmt.Errorf("typed result byte limit exceeded")
	}
	return encoded, nil
}

func DecodeTypedCollectorResult(encoded []byte) (TypedCollectorResult, error) {
	var result TypedCollectorResult
	d := json.NewDecoder(bytes.NewReader(encoded))
	d.DisallowUnknownFields()
	if err := d.Decode(&result); err != nil {
		return result, err
	}
	if err := ensureJSONEOF(d); err != nil {
		return result, err
	}
	canonical, err := EncodeTypedCollectorResult(result)
	if err != nil {
		return result, err
	}
	if !bytes.Equal(encoded, canonical) {
		return result, fmt.Errorf("typed result is not canonically encoded")
	}
	return result, nil
}
