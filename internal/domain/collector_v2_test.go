package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func typedPlan() CollectionPlan {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	return CollectionPlan{SchemaVersion: 2, RunID: "run-1", ClusterID: "cluster-1", SourceID: "slurm-1", SourceKind: CollectionSourceSlurm,
		Operation: OperationSlurmInventory, PayloadSchema: CollectionInventorySchema, Scope: CollectionScope{Nodes: []StableNodeID{"node-1"}},
		Interval: &CollectionInterval{Start: now.Add(-time.Minute), End: now}, ScheduledFor: now, Deadline: now.Add(time.Minute),
		Limits: CollectionLimits{MaxRecords: 10, MaxBytes: 100000}, IdempotencyKey: "key-1"}
}

func typedResult() TypedCollectorResult {
	p := typedPlan()
	return TypedCollectorResult{SchemaVersion: 2, WorkID: "work-1", Attempt: 1, Plan: p, Status: ResultSucceeded, StartedAt: p.ScheduledFor, CompletedAt: p.Deadline,
		Coverage: SourceCoverage{SchemaVersion: 1, ClusterID: p.ClusterID, SourceID: p.SourceID, Scope: CoverageInventory, State: SourceCoverageComplete, Expected: 1, Observed: 1, SourceAt: p.ScheduledFor, EffectiveAt: p.ScheduledFor, ObservedAt: p.Deadline},
		Payload:  CollectionPayload{Kind: CollectionPayloadInventory, Inventory: &CollectionInventoryPayload{Revisions: []InventoryRevision{{SchemaVersion: 1, ID: "revision-1", ClusterID: p.ClusterID, SourceID: p.SourceID, SourceAt: p.ScheduledFor, EffectiveAt: p.ScheduledFor, ObservedAt: p.Deadline, Entities: []EntityIdentity{{ClusterID: p.ClusterID, Kind: EntityNode, NodeID: "node-1"}}}}}}}
}

func typedSnapshotResult() TypedCollectorResult {
	r := typedResult()
	p := &r.Plan
	p.Operation, p.PayloadSchema = OperationSlurmSnapshot, CollectionSlurmSnapshotSchema
	r.Coverage.Scope = CoverageAllocations
	inventoryCoverage := r.Coverage
	inventoryCoverage.Scope = CoverageInventory
	revision := r.Payload.Inventory.Revisions[0]
	sources := make([]SlurmSourceObservation, 0, 4)
	for _, sourceKind := range []string{"nodes", "partitions", "jobs", "accounting"} {
		source := SlurmSourceObservation{Kind: sourceKind, DataParserVersion: SlurmSnapshotDataParserVersion, SlurmVersion: "23.11.10", SchemaSupport: SlurmSchemaSupported, BytesRead: 1, SourceAt: r.CompletedAt}
		if sourceKind == "accounting" {
			source.WindowStart, source.WindowEnd = p.Interval.Start, p.Interval.End
		}
		sources = append(sources, source)
	}
	r.Payload = CollectionPayload{Kind: CollectionPayloadSlurmSnapshot, SlurmSnapshot: &SlurmSnapshotPayload{Inventory: &revision, InventoryCoverage: inventoryCoverage, AllocationCoverage: r.Coverage, Sources: sources, ValidEmptyJobs: true, ValidEmptyAccounting: true}}
	return r
}

func TestTypedCollectionPlanRejectsUnboundedAndUnreviewedWork(t *testing.T) {
	for name, mutate := range map[string]func(*CollectionPlan){
		"version": func(p *CollectionPlan) { p.SchemaVersion = 99 }, "operation": func(p *CollectionPlan) { p.Operation = "shell.exec.v1" },
		"source": func(p *CollectionPlan) { p.SourceKind = CollectionSourcePrometheus }, "schema": func(p *CollectionPlan) { p.PayloadSchema = CollectionMetricsSchema },
		"empty scope": func(p *CollectionPlan) { p.Scope.Nodes = nil }, "duplicate scope": func(p *CollectionPlan) { p.Scope.Nodes = append(p.Scope.Nodes, "node-1") },
		"interval and cursor": func(p *CollectionPlan) { p.Cursor = "cursor-1" }, "neither interval nor cursor": func(p *CollectionPlan) { p.Interval = nil },
		"large interval": func(p *CollectionPlan) { p.Interval.Start = p.Interval.End.Add(-25 * time.Hour) }, "limits": func(p *CollectionPlan) { p.Limits.MaxRecords = 10001 },
	} {
		t.Run(name, func(t *testing.T) {
			p := typedPlan()
			mutate(&p)
			if ValidateCollectionPlan(p) == nil {
				t.Fatal("invalid plan accepted")
			}
		})
	}
	if _, err := LegacyCollectionCapabilities([]CollectionOperationID{OperationSlurmInventory}); err == nil {
		t.Fatal("typed-only operation exposed as v1 capability")
	}
}

func TestTypedResultClosedVariantsAndCanonicalRoundTrip(t *testing.T) {
	for _, kind := range []CollectionPayloadKind{CollectionPayloadInventory, CollectionPayloadMetrics, CollectionPayloadAllocation, CollectionPayloadEvents, CollectionPayloadSlurmSnapshot} {
		t.Run(string(kind), func(t *testing.T) {
			r := typedResult()
			p := &r.Plan
			switch kind {
			case CollectionPayloadMetrics:
				p.SourceKind, p.Operation, p.PayloadSchema = CollectionSourcePrometheus, OperationPrometheusGPUUtilization, CollectionMetricsSchema
				r.Coverage.Scope = CoverageMetrics
				r.Payload = CollectionPayload{Kind: kind, Metrics: &CollectionMetricsPayload{Observations: []CollectionMetric{{NodeID: "node-1", Observation: Observation{ID: "o1", SchemaVersion: 1, ClusterID: p.ClusterID, SourceID: p.SourceID, Kind: "gpu", EntityKey: "node-1", Metric: "utilization", Unit: "percent", Value: 1, ObservedAt: r.StartedAt, CollectedAt: r.CompletedAt, SourceReference: "sample-1"}}}}}
			case CollectionPayloadAllocation:
				p.Operation, p.PayloadSchema = OperationSlurmAllocation, CollectionAllocationSchema
				r.Coverage.Scope = CoverageAllocations
				r.Payload = CollectionPayload{Kind: kind, Allocation: &CollectionAllocationPayload{Snapshots: []AllocationSnapshot{{SchemaVersion: 1, ClusterID: p.ClusterID, SourceID: p.SourceID, Job: JobIdentity{SchedulerNamespace: "slurm", JobID: "42", SubmitAt: r.StartedAt}, State: AllocationRunning, SourceAt: r.StartedAt, EffectiveAt: r.StartedAt, ObservedAt: r.CompletedAt, Entities: []EntityIdentity{{ClusterID: p.ClusterID, Kind: EntityNode, NodeID: "node-1"}}}}}}
			case CollectionPayloadEvents:
				p.Operation, p.PayloadSchema = OperationSlurmEvents, CollectionEventsSchema
				r.Coverage.Scope = CoverageEvents
				r.Payload = CollectionPayload{Kind: kind, Events: &CollectionEventsPayload{Events: []CollectionEvent{{ID: "event-1", NodeID: "node-1", Job: JobIdentity{SchedulerNamespace: "slurm", JobID: "42", SubmitAt: r.StartedAt}, State: AllocationRunning, OccurredAt: r.StartedAt}}}}
			case CollectionPayloadSlurmSnapshot:
				r = typedSnapshotResult()
			}
			encoded, err := EncodeTypedCollectorResult(r)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeTypedCollectorResult(encoded)
			if err != nil || decoded.Payload.Kind != kind {
				t.Fatalf("round trip: %v", err)
			}
			if _, err := DecodeTypedCollectorResult(append(encoded, '\n')); err == nil {
				t.Fatal("noncanonical result accepted")
			}
			unknown := strings.Replace(string(encoded), `"payload":{`, `"payload":{"shell":"id",`, 1)
			if _, err := DecodeTypedCollectorResult([]byte(unknown)); err == nil {
				t.Fatal("unknown field accepted")
			}
		})
	}
}

func TestTypedSnapshotAcceptsReviewedV39Provenance(t *testing.T) {
	r := typedSnapshotResult()
	for i := range r.Payload.SlurmSnapshot.Sources {
		r.Payload.SlurmSnapshot.Sources[i].DataParserVersion = SlurmSnapshotDataParserVersion2302
		r.Payload.SlurmSnapshot.Sources[i].SlurmVersion = "23.2.8"
	}
	encoded, err := EncodeTypedCollectorResult(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeTypedCollectorResult(encoded); err != nil {
		t.Fatal(err)
	}
}

func TestSlurmSnapshotRejectsForgedCompleteEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*TypedCollectorResult){
		"complete allocation without inventory proof": func(r *TypedCollectorResult) {
			r.Payload.SlurmSnapshot.Inventory = nil
			r.Payload.SlurmSnapshot.InventoryCoverage.State = SourceCoverageUnknown
			r.Payload.SlurmSnapshot.InventoryCoverage.Expected = 0
			r.Payload.SlurmSnapshot.InventoryCoverage.Observed = 0
		},
		"inventory denominator outside plan": func(r *TypedCollectorResult) {
			r.Payload.SlurmSnapshot.InventoryCoverage.Expected = 2
			r.Payload.SlurmSnapshot.InventoryCoverage.Observed = 2
		},
		"allocation denominator outside plan": func(r *TypedCollectorResult) {
			r.Coverage.Expected = 2
			r.Coverage.Observed = 2
			r.Payload.SlurmSnapshot.AllocationCoverage = r.Coverage
		},
		"unreviewed parser advertised supported": func(r *TypedCollectorResult) {
			r.Payload.SlurmSnapshot.Sources[0].DataParserVersion = "data_parser/v0.0.41"
		},
		"allocation claims GPU authority": func(r *TypedCollectorResult) {
			snapshot := AllocationSnapshot{SchemaVersion: 1, ClusterID: r.Plan.ClusterID, SourceID: r.Plan.SourceID, Job: JobIdentity{SchedulerNamespace: "slurm", JobID: "42", SubmitAt: r.StartedAt, Attempt: 1}, State: AllocationRunning, SourceAt: r.StartedAt, EffectiveAt: r.StartedAt, ObservedAt: r.CompletedAt, Entities: []EntityIdentity{{ClusterID: r.Plan.ClusterID, Kind: EntityGPU, NodeID: "node-1", PhysicalGPUUUID: "gpu-1"}}}
			r.Payload.SlurmSnapshot.Allocations = []SlurmAllocationFact{{RecordIdentity: CanonicalSlurmAllocationRecordID(snapshot), Snapshot: snapshot}}
		},
		"failure count exceeds snapshot cap": func(r *TypedCollectorResult) {
			r.Status = ResultPartial
			r.Coverage.State = SourceCoverageUnknown
			r.Coverage.Expected, r.Coverage.Observed = 0, 0
			r.Payload.SlurmSnapshot.AllocationCoverage = r.Coverage
			r.Failures = make([]CollectionFailure, 33)
			for index := range r.Failures {
				r.Failures[index] = CollectionFailure{Code: FailurePartialData, Message: "bounded snapshot failure"}
			}
		},
		"result completes after deadline": func(r *TypedCollectorResult) {
			r.CompletedAt = r.Plan.Deadline.Add(time.Nanosecond)
		},
		"result starts before scheduled time": func(r *TypedCollectorResult) {
			r.StartedAt = r.Plan.ScheduledFor.Add(-time.Nanosecond)
		},
		"inventory timestamps exceed envelope": func(r *TypedCollectorResult) {
			revision := r.Payload.SlurmSnapshot.Inventory
			revision.SourceAt = r.CompletedAt.Add(time.Nanosecond)
			revision.EffectiveAt = revision.SourceAt
			revision.ObservedAt = revision.SourceAt
		},
		"accounting window is unrelated to plan": func(r *TypedCollectorResult) {
			r.Payload.SlurmSnapshot.Sources[3].WindowEnd = r.Plan.Interval.End.Add(-time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := typedSnapshotResult()
			mutate(&r)
			if _, err := EncodeTypedCollectorResult(r); err == nil {
				t.Fatal("forged Slurm snapshot accepted")
			}
		})
	}

	provenance := typedSnapshotResult()
	provenance.Status = ResultPartial
	provenance.Coverage.State = SourceCoverageUnknown
	provenance.Coverage.Expected, provenance.Coverage.Observed = 0, 0
	provenance.Payload.SlurmSnapshot.AllocationCoverage = provenance.Coverage
	provenance.Failures = []CollectionFailure{{Code: FailurePartialData, Message: "accounting attempt is unresolved"}}
	record := SlurmUnresolvedAccounting{ClusterID: provenance.Plan.ClusterID, SourceID: provenance.Plan.SourceID, SchedulerNamespace: "slurm", JobID: "40", SubmitAt: provenance.StartedAt.Add(-time.Hour), SubmitQuality: SlurmFieldPresent, SchedulerCluster: "cluster-a", RawState: "COMPLETED", StartQuality: SlurmFieldMissing, EndQuality: SlurmFieldMissing, MembershipQuality: SlurmFieldUnsupported, MembershipDigest: strings.Repeat("0", 64), AttemptQuality: SlurmFieldUnsupported, Provenance: []SlurmAccountingProvenance{{WindowStart: provenance.Plan.Interval.Start, WindowEnd: provenance.Plan.Interval.End, SourceAt: provenance.StartedAt, ObservedAt: provenance.CompletedAt}}}
	record.RecordIdentity = CanonicalSlurmUnresolvedRecordID(record)
	provenance.Payload.SlurmSnapshot.UnresolvedAccounting = []SlurmUnresolvedAccounting{record}
	if _, err := EncodeTypedCollectorResult(provenance); err != nil {
		t.Fatalf("valid unresolved provenance rejected: %v", err)
	}
	provenance.Payload.SlurmSnapshot.UnresolvedAccounting[0].Provenance[0].WindowStart = provenance.Plan.Interval.Start.Add(-time.Minute)
	if _, err := EncodeTypedCollectorResult(provenance); err == nil {
		t.Fatal("unresolved provenance outside source window accepted")
	}

	failed := typedSnapshotResult()
	failed.Status = ResultFailed
	failed.StartedAt = failed.Plan.Deadline.Add(time.Second)
	failed.CompletedAt = failed.StartedAt
	failed.Coverage.State = SourceCoverageUnknown
	failed.Coverage.Expected, failed.Coverage.Observed = 0, 0
	failed.Coverage.SourceAt, failed.Coverage.EffectiveAt, failed.Coverage.ObservedAt = failed.StartedAt, failed.StartedAt, failed.StartedAt
	failed.Payload.SlurmSnapshot = &SlurmSnapshotPayload{
		InventoryCoverage:  SourceCoverage{SchemaVersion: 1, ClusterID: failed.Plan.ClusterID, SourceID: failed.Plan.SourceID, Scope: CoverageInventory, State: SourceCoverageUnknown, SourceAt: failed.StartedAt, EffectiveAt: failed.StartedAt, ObservedAt: failed.StartedAt},
		AllocationCoverage: failed.Coverage,
	}
	failed.Failures = []CollectionFailure{{Code: FailureDeadlineExceeded, Message: "snapshot deadline expired"}}
	if _, err := EncodeTypedCollectorResult(failed); err != nil {
		t.Fatalf("failed deadline result rejected: %v", err)
	}
}

func TestTypedResultRejectsForgedScopeUnionAndLease(t *testing.T) {
	for name, mutate := range map[string]func(*TypedCollectorResult){
		"multiple variants": func(r *TypedCollectorResult) { r.Payload.Events = &CollectionEventsPayload{} },
		"wrong variant":     func(r *TypedCollectorResult) { r.Payload.Kind = CollectionPayloadEvents },
		"forged source":     func(r *TypedCollectorResult) { r.Payload.Inventory.Revisions[0].SourceID = "other" },
		"forged cluster":    func(r *TypedCollectorResult) { r.Coverage.ClusterID = "other" },
		"out of scope":      func(r *TypedCollectorResult) { r.Payload.Inventory.Revisions[0].Entities[0].NodeID = "node-2" },
		"bytes":             func(r *TypedCollectorResult) { r.Plan.Limits.MaxBytes = 1 },
		"failed with facts": func(r *TypedCollectorResult) { r.Status = ResultFailed },
	} {
		t.Run(name, func(t *testing.T) {
			r := typedResult()
			mutate(&r)
			if _, err := EncodeTypedCollectorResult(r); err == nil {
				t.Fatal("invalid result accepted")
			}
		})
	}
	r := typedResult()
	p := r.Plan
	l := TypedWorkLease{Plan: p, Lease: WorkLease{CollectorID: "collector-1", Attempt: 1, LeaseToken: strings.Repeat("a", 32), LeaseExpires: p.Deadline, Work: CollectorWork{WorkID: r.WorkID, WorkExpiresAt: p.Deadline, Task: CollectionTask{RunID: p.RunID, ClusterID: p.ClusterID, SourceID: p.SourceID, IdempotencyKey: p.IdempotencyKey}}}}
	if err := ValidateTypedResultForLease(r, l); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(r)
	_ = json.Unmarshal(encoded, &r)
	r.Plan.SourceID = "forged-source"
	if ValidateTypedResultForLease(r, l) == nil {
		t.Fatal("submitted plan became authority")
	}
}
