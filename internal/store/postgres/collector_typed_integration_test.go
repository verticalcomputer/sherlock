//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

type typedFixture struct {
	pool      *pgxpool.Pool
	store     *storepg.CollectorControlStore
	collector domain.CollectorID
	result    domain.TypedCollectorResult
	ref       collectorcontrol.LeaseRef
}

func TestTypedCollectionHeartbeatVersionSkewAndCapabilityReplacement(t *testing.T) {
	f := newTypedFixture(t, domain.CollectionPayloadInventory)
	ctx := context.Background()
	if _, err := f.store.EnqueueTypedCollectionWork(ctx, f.result.WorkID, f.result.Plan, f.result.Plan.ScheduledFor, f.result.Plan.Deadline); err != nil {
		t.Fatal(err)
	}
	report := collectorcontrol.Heartbeat{CollectorID: f.collector, Version: "old", ReportedAt: time.Now().UTC(), Capabilities: []collectorcontrol.CapabilityReport{{Name: string(domain.OperationSlurmInventory), Version: "1"}}}
	claim := func() (bool, error) {
		_, found, err := f.store.ClaimTypedWork(ctx, f.result.Plan.ClusterID, f.collector, strings.Repeat("a", 32), time.Minute, []domain.SourceID{f.result.Plan.SourceID})
		return found, err
	}
	if err := f.store.RecordHeartbeat(ctx, report); err != nil {
		t.Fatal(err)
	}
	if found, err := claim(); found || !errors.Is(err, collectorcontrol.ErrWorkLeaseInvalid) {
		t.Fatalf("old collector with typed-looking capability: found=%t err=%v", found, err)
	}
	report.ProtocolMin, report.ProtocolMax = 1, 2
	report.Capabilities = []collectorcontrol.CapabilityReport{{Name: string(domain.OperationSlurmEvents), Version: "1"}}
	if err := f.store.RecordHeartbeat(ctx, report); err != nil {
		t.Fatal(err)
	}
	if found, err := claim(); found || err != nil {
		t.Fatalf("unconfigured operation claimed: %t %v", found, err)
	}
	report.Capabilities = []collectorcontrol.CapabilityReport{{Name: string(domain.OperationSlurmInventory), Version: "99"}}
	if err := f.store.RecordHeartbeat(ctx, report); err != nil {
		t.Fatal(err)
	}
	if found, err := claim(); found || err != nil {
		t.Fatalf("incompatible operation version claimed: %t %v", found, err)
	}
	report.ProtocolMax = 99
	if err := f.store.RecordHeartbeat(ctx, report); err == nil {
		t.Fatal("unknown protocol range was persisted")
	}
	report.ProtocolMax = 2
	report.Capabilities[0].Version = "1"
	if err := f.store.RecordHeartbeat(ctx, report); err != nil {
		t.Fatal(err)
	}
	// v1 remains a separate claim family even when its identity has upgraded.
	if _, found, err := f.store.ClaimWork(ctx, f.collector, strings.Repeat("b", 32), time.Minute); found || err != nil {
		t.Fatalf("v1 claimed typed work: %t %v", found, err)
	}
	if found, err := claim(); !found || err != nil {
		t.Fatalf("upgraded compatible collector could not claim: %t %v", found, err)
	}
}

func newTypedFixture(t *testing.T, kind domain.CollectionPayloadKind) *typedFixture {
	t.Helper()
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated migrated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	suffix := fmt.Sprint(time.Now().UnixNano())
	cluster, source := domain.ClusterID("typed-c-"+suffix), domain.SourceID("typed-s-"+suffix)
	collections, _ := storepg.NewCollectionStore(pool)
	if err := collections.EnsureSource(ctx, cluster, "Typed fixture", source, "Typed source"); err != nil {
		t.Fatal(err)
	}
	store, _ := storepg.NewCollectorControlStore(pool)
	collector := domain.CollectorID("typed-collector-" + suffix)
	if err := store.RegisterCollector(ctx, storepg.CollectorRegistration{CollectorID: collector, ClusterID: cluster,
		DisplayName: "Typed fixture", Version: "fixture", ProtocolMin: 1, ProtocolMax: 2, OperatingSystem: "linux", Architecture: "amd64"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceCapabilities(ctx, collector, map[string]string{
		string(domain.OperationPrometheusGPUUtilization): "1", string(domain.OperationSlurmInventory): "1",
		string(domain.OperationSlurmAllocation): "1", string(domain.OperationSlurmEvents): "1", string(domain.QueryGPUUtilization): "1",
		string(domain.OperationSlurmSnapshot): "1",
	}); err != nil {
		t.Fatal(err)
	}
	now := fixtureDatabaseTime(t, ctx, pool)
	p := domain.CollectionPlan{SchemaVersion: 2, RunID: domain.RunID("typed-run-" + suffix), ClusterID: cluster, SourceID: source,
		SourceKind: domain.CollectionSourceSlurm, Operation: domain.OperationSlurmInventory, PayloadSchema: domain.CollectionInventorySchema,
		Scope:        domain.CollectionScope{Nodes: []domain.StableNodeID{"node-1"}},
		Interval:     &domain.CollectionInterval{Start: now.Add(-time.Minute), End: now},
		ScheduledFor: now, Deadline: now.Add(5 * time.Minute), Limits: domain.CollectionLimits{MaxRecords: 10, MaxBytes: 100000}, IdempotencyKey: "typed-key-" + suffix}
	r := domain.TypedCollectorResult{SchemaVersion: 2, WorkID: domain.WorkID("typed-work-" + suffix), Attempt: 1, Plan: p,
		Status: domain.ResultSucceeded, StartedAt: now, CompletedAt: now.Add(time.Second),
		Coverage: domain.SourceCoverage{SchemaVersion: 1, ClusterID: cluster, SourceID: source, Scope: domain.CoverageInventory,
			State: domain.SourceCoverageComplete, Expected: 1, Observed: 1, SourceAt: now, EffectiveAt: now, ObservedAt: now.Add(time.Second)}}
	entities := []domain.EntityIdentity{{ClusterID: cluster, Kind: domain.EntityNode, NodeID: "node-1"}}
	job := domain.JobIdentity{SchedulerNamespace: "slurm", JobID: "42", SubmitAt: now.Add(-time.Hour), Attempt: 1}
	switch kind {
	case domain.CollectionPayloadMetrics:
		r.Plan.SourceKind, r.Plan.Operation, r.Plan.PayloadSchema = domain.CollectionSourcePrometheus, domain.OperationPrometheusGPUUtilization, domain.CollectionMetricsSchema
		r.Coverage.Scope = domain.CoverageMetrics
		r.Payload = domain.CollectionPayload{Kind: kind, Metrics: &domain.CollectionMetricsPayload{Observations: []domain.CollectionMetric{{NodeID: "node-1", Observation: domain.Observation{
			ID: domain.ObservationID("typed-o-" + suffix), SchemaVersion: 1, ClusterID: cluster, SourceID: source, Kind: "gpu", EntityKey: "node-1", Metric: "utilization",
			Unit: "percent", Value: 42, ObservedAt: now, CollectedAt: now.Add(time.Second), SourceReference: "sample-1"}}}}}
	case domain.CollectionPayloadInventory:
		r.Payload = domain.CollectionPayload{Kind: kind, Inventory: &domain.CollectionInventoryPayload{Revisions: []domain.InventoryRevision{
			goodputInventoryRevision("typed-revision-"+suffix, cluster, source, now, entities)}}}
	case domain.CollectionPayloadAllocation:
		r.Plan.Operation, r.Plan.PayloadSchema, r.Coverage.Scope = domain.OperationSlurmAllocation, domain.CollectionAllocationSchema, domain.CoverageAllocations
		r.Payload = domain.CollectionPayload{Kind: kind, Allocation: &domain.CollectionAllocationPayload{Snapshots: []domain.AllocationSnapshot{
			goodputAllocationSnapshot(cluster, source, job, domain.AllocationRunning, now, entities)}}}
	case domain.CollectionPayloadEvents:
		r.Plan.Operation, r.Plan.PayloadSchema, r.Coverage.Scope = domain.OperationSlurmEvents, domain.CollectionEventsSchema, domain.CoverageEvents
		r.Plan.Interval, r.Plan.Cursor, r.NextCursor = nil, "cursor-0", "cursor-1"
		r.Payload = domain.CollectionPayload{Kind: kind, Events: &domain.CollectionEventsPayload{Events: []domain.CollectionEvent{
			{ID: "event-1", NodeID: "node-1", Job: job, State: domain.AllocationRunning, OccurredAt: now}}}}
	case domain.CollectionPayloadSlurmSnapshot:
		r.Plan.Operation, r.Plan.PayloadSchema, r.Coverage.Scope = domain.OperationSlurmSnapshot, domain.CollectionSlurmSnapshotSchema, domain.CoverageAllocations
		inventoryCoverage := r.Coverage
		inventoryCoverage.Scope = domain.CoverageInventory
		snapshot := goodputAllocationSnapshot(cluster, source, job, domain.AllocationRunning, now, entities)
		fact := domain.SlurmAllocationFact{Snapshot: snapshot}
		fact.RecordIdentity = domain.CanonicalSlurmAllocationRecordID(snapshot)
		sources := make([]domain.SlurmSourceObservation, 0, 4)
		for _, sourceKind := range []string{"nodes", "partitions", "jobs", "accounting"} {
			item := domain.SlurmSourceObservation{Kind: sourceKind, DataParserVersion: "data_parser/v0.0.40", SlurmVersion: "23.11.10", SchemaSupport: domain.SlurmSchemaSupported, BytesRead: 1, SourceAt: now}
			if sourceKind == "accounting" {
				item.WindowStart, item.WindowEnd = r.Plan.Interval.Start, r.Plan.Interval.End
			}
			sources = append(sources, item)
		}
		inventory := goodputInventoryRevision("typed-snapshot-revision-"+suffix, cluster, source, now, entities)
		r.Payload = domain.CollectionPayload{Kind: kind, SlurmSnapshot: &domain.SlurmSnapshotPayload{Inventory: &inventory, Allocations: []domain.SlurmAllocationFact{fact}, InventoryCoverage: inventoryCoverage, AllocationCoverage: r.Coverage, Sources: sources, ValidEmptyAccounting: true}}
	}
	if _, err := pool.Exec(ctx, `UPDATE sources SET kind=$2 WHERE source_id=$1`, source, r.Plan.SourceKind); err != nil {
		t.Fatal(err)
	}
	return &typedFixture{pool: pool, store: store, collector: collector, result: r}
}

func (f *typedFixture) claim(t *testing.T) {
	t.Helper()
	r := f.result
	inserted, err := f.store.EnqueueTypedCollectionWork(context.Background(), r.WorkID, r.Plan, r.Plan.ScheduledFor, r.Plan.Deadline)
	if err != nil || !inserted {
		t.Fatalf("enqueue inserted=%t err=%v", inserted, err)
	}
	lease, found, err := f.store.ClaimTypedWork(context.Background(), r.Plan.ClusterID, f.collector, strings.Repeat("a", 32), time.Minute, []domain.SourceID{r.Plan.SourceID})
	if err != nil || !found || lease.Lease.Work.WorkID != r.WorkID {
		t.Fatalf("claim=%+v found=%t err=%v", lease, found, err)
	}
	if err := domain.ValidateTypedResultForLease(r, lease); err != nil {
		t.Fatalf("stored plan binding: %v", err)
	}
	f.ref = collectorcontrol.LeaseRef{WorkID: r.WorkID, Attempt: lease.Lease.Attempt, LeaseToken: lease.Lease.LeaseToken}
}

func typedChecksum(r domain.TypedCollectorResult) string {
	encoded, _ := json.Marshal(r)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (f *typedFixture) submit(r domain.TypedCollectorResult) (collectorcontrol.FinalizeOutcome, error) {
	return f.store.SubmitTypedResult(context.Background(), f.result.Plan.ClusterID, f.collector, f.ref, r, typedChecksum(r))
}

func (f *typedFixture) count(t *testing.T, table string, want int) {
	t.Helper()
	var count int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM `+table+` WHERE run_id=$1`, f.result.Plan.RunID).Scan(&count); err != nil || count != want {
		t.Fatalf("%s count=%d want=%d err=%v", table, count, want, err)
	}
}

func TestTypedCollectionIngestsEveryPayloadAndReplays(t *testing.T) {
	for _, kind := range []domain.CollectionPayloadKind{domain.CollectionPayloadMetrics, domain.CollectionPayloadInventory, domain.CollectionPayloadAllocation, domain.CollectionPayloadEvents} {
		t.Run(string(kind), func(t *testing.T) {
			f := newTypedFixture(t, kind)
			f.claim(t)
			f.count(t, "collector_source_cursors", 0)
			outcome, err := f.submit(f.result)
			if err != nil || outcome.PreviouslyFinalized || outcome.SHA256 != typedChecksum(f.result) {
				t.Fatalf("finalize=%+v err=%v", outcome, err)
			}
			for _, table := range []string{"collection_runs", "collector_typed_result_ingestions", "goodput_source_coverage"} {
				f.count(t, table, 1)
			}
			stored, found, err := f.store.LoadFinalizedTypedResult(context.Background(), f.result.Plan.ClusterID, f.result.WorkID)
			if err != nil || !found || typedChecksum(stored) != typedChecksum(f.result) {
				t.Fatalf("stored result found=%t err=%v", found, err)
			}
			if _, found, err := f.store.LoadFinalizedTypedResult(context.Background(), "foreign-cluster", f.result.WorkID); err != nil || found {
				t.Fatalf("foreign result found=%t err=%v", found, err)
			}
			// Finalized replay remains valid after the original lease expires.
			if _, err := f.pool.Exec(context.Background(), `UPDATE collector_work_attempts SET claimed_at=clock_timestamp()-interval '2 minutes',lease_expires_at=clock_timestamp()-interval '1 minute' WHERE work_id=$1`, f.result.WorkID); err != nil {
				t.Fatal(err)
			}
			outcome, err = f.submit(f.result)
			if err != nil || !outcome.PreviouslyFinalized {
				t.Fatalf("replay=%+v err=%v", outcome, err)
			}
			changed := f.result
			changed.Coverage.ObservedAt = changed.Coverage.ObservedAt.Add(time.Second)
			if _, err := f.submit(changed); !errors.Is(err, collectorcontrol.ErrResultConflict) {
				t.Fatalf("conflicting finalization err=%v", err)
			}
			goodput, _ := storepg.NewGoodputStore(f.pool)
			switch kind {
			case domain.CollectionPayloadMetrics:
				f.count(t, "observations", 1)
				f.count(t, "goodput_metric_nodes", 1)
				var reference, node string
				if err := f.pool.QueryRow(context.Background(), `SELECT o.source_reference,n.stable_node_id FROM observations o JOIN goodput_metric_nodes n USING (observation_id) WHERE o.run_id=$1`, f.result.Plan.RunID).Scan(&reference, &node); err != nil || reference != "sample-1" || node != "node-1" {
					t.Fatalf("metric reference=%q node=%q err=%v", reference, node, err)
				}
			case domain.CollectionPayloadInventory:
				projection, found, err := goodput.GetCurrentInventoryRevision(context.Background(), f.result.Plan.ClusterID, f.result.Plan.SourceID, application.InventoryObserved)
				if err != nil || !found || projection.Revision.ID != f.result.Payload.Inventory.Revisions[0].ID {
					t.Fatalf("inventory=%+v found=%t err=%v", projection, found, err)
				}
			case domain.CollectionPayloadAllocation:
				snapshots, more, err := goodput.ListCurrentAllocationSnapshots(context.Background(), f.result.Plan.ClusterID, 10)
				if err != nil || more || len(snapshots) != 1 || snapshots[0].State != domain.AllocationRunning {
					t.Fatalf("allocations=%+v more=%t err=%v", snapshots, more, err)
				}
			case domain.CollectionPayloadEvents:
				f.count(t, "goodput_collection_events", 1)
				f.count(t, "collector_source_cursors", 1)
			}
		})
	}
}

func TestTypedCollectionRejectsForgedAuthorityAndPlan(t *testing.T) {
	f := newTypedFixture(t, domain.CollectionPayloadMetrics)
	f.claim(t)
	for name, mutate := range map[string]func(*domain.TypedCollectorResult){
		"cluster":             func(r *domain.TypedCollectorResult) { r.Plan.ClusterID = "forged-cluster" },
		"source":              func(r *domain.TypedCollectorResult) { r.Plan.SourceID = "forged-source" },
		"operation":           func(r *domain.TypedCollectorResult) { r.Plan.Operation = domain.OperationPrometheusGPUTemperature },
		"schema":              func(r *domain.TypedCollectorResult) { r.Plan.PayloadSchema = domain.CollectionEventsSchema },
		"source kind":         func(r *domain.TypedCollectorResult) { r.Plan.SourceKind = domain.CollectionSourceSlurm },
		"scope":               func(r *domain.TypedCollectorResult) { r.Plan.Scope.Nodes[0] = "node-2" },
		"inventory reference": func(r *domain.TypedCollectorResult) { r.Plan.InventoryRevision = "forged-revision" },
		"metric cluster": func(r *domain.TypedCollectorResult) {
			r.Payload.Metrics.Observations[0].Observation.ClusterID = "forged-cluster"
		},
		"metric source": func(r *domain.TypedCollectorResult) {
			r.Payload.Metrics.Observations[0].Observation.SourceID = "forged-source"
		},
		"work":    func(r *domain.TypedCollectorResult) { r.WorkID = "forged-work" },
		"attempt": func(r *domain.TypedCollectorResult) { r.Attempt++ },
	} {
		t.Run(name, func(t *testing.T) {
			encoded, _ := json.Marshal(f.result)
			var forged domain.TypedCollectorResult
			_ = json.Unmarshal(encoded, &forged)
			mutate(&forged)
			if _, err := f.submit(forged); !errors.Is(err, collectorcontrol.ErrResultConflict) {
				t.Fatalf("forged result err=%v", err)
			}
		})
	}
	for _, request := range []struct {
		cluster   domain.ClusterID
		collector domain.CollectorID
		ref       collectorcontrol.LeaseRef
	}{
		{"forged-cluster", f.collector, f.ref},
		{f.result.Plan.ClusterID, "forged-collector", f.ref},
		{f.result.Plan.ClusterID, f.collector, collectorcontrol.LeaseRef{WorkID: f.ref.WorkID, Attempt: f.ref.Attempt, LeaseToken: strings.Repeat("b", 32)}},
	} {
		if _, err := f.store.SubmitTypedResult(context.Background(), request.cluster, request.collector, request.ref, f.result, typedChecksum(f.result)); !errors.Is(err, collectorcontrol.ErrWorkLeaseInvalid) {
			t.Fatalf("forged authenticated authority err=%v", err)
		}
	}
	if _, err := f.store.SubmitTypedResult(context.Background(), f.result.Plan.ClusterID, f.collector, f.ref, f.result, strings.Repeat("0", 64)); !errors.Is(err, collectorcontrol.ErrResultConflict) {
		t.Fatalf("forged checksum err=%v", err)
	}
	f.count(t, "collection_runs", 0)
	f.count(t, "observations", 0)
	f.count(t, "goodput_source_coverage", 0)
	if _, err := f.submit(f.result); err != nil {
		t.Fatalf("valid finalization after forged attempts: %v", err)
	}
}

func TestTypedCollectionConcurrentFinalizeAndLeaseRecovery(t *testing.T) {
	f := newTypedFixture(t, domain.CollectionPayloadMetrics)
	f.claim(t)
	oldRef := f.ref
	if _, err := f.pool.Exec(context.Background(), `UPDATE collector_work_attempts SET claimed_at=clock_timestamp()-interval '2 minutes',lease_expires_at=clock_timestamp()-interval '1 minute' WHERE work_id=$1`, f.result.WorkID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.submit(f.result); !errors.Is(err, collectorcontrol.ErrWorkLeaseInvalid) {
		t.Fatalf("expired submission err=%v", err)
	}
	lease, found, err := f.store.ClaimTypedWork(context.Background(), f.result.Plan.ClusterID, f.collector, strings.Repeat("b", 32), time.Minute, []domain.SourceID{f.result.Plan.SourceID})
	if err != nil || !found || lease.Lease.Attempt != 2 {
		t.Fatalf("recovered lease=%+v found=%t err=%v", lease, found, err)
	}
	if _, err := f.store.SubmitTypedResult(context.Background(), f.result.Plan.ClusterID, f.collector, oldRef, f.result, typedChecksum(f.result)); !errors.Is(err, collectorcontrol.ErrWorkLeaseInvalid) {
		t.Fatalf("stale attempt err=%v", err)
	}
	f.result.Attempt = 2
	f.ref = collectorcontrol.LeaseRef{WorkID: f.result.WorkID, Attempt: 2, LeaseToken: lease.Lease.LeaseToken}
	var wg sync.WaitGroup
	outcomes := make(chan collectorcontrol.FinalizeOutcome, 2)
	errs := make(chan error, 2)
	for range 2 {
		wg.Go(func() { outcome, err := f.submit(f.result); outcomes <- outcome; errs <- err })
	}
	wg.Wait()
	close(outcomes)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	replays := 0
	for outcome := range outcomes {
		if outcome.PreviouslyFinalized {
			replays++
		}
	}
	if replays != 1 {
		t.Fatalf("concurrent replays=%d want=1", replays)
	}
	f.count(t, "observations", 1)
	f.count(t, "collector_typed_result_ingestions", 1)
}

func TestTypedCollectionCursorRollbackAndSourceIsolation(t *testing.T) {
	f := newTypedFixture(t, domain.CollectionPayloadEvents)
	f.claim(t)
	if _, err := f.submit(f.result); err != nil {
		t.Fatal(err)
	}
	first := f.result
	// A second result inserts one new event, then conflicts with an immutable event.
	f.result.Plan.RunID += "-next"
	f.result.Plan.IdempotencyKey += "-next"
	f.result.WorkID += "-next"
	f.result.Plan.Cursor, f.result.NextCursor = "cursor-1", "cursor-2"
	existing := first.Payload.Events.Events[0]
	newEvent := existing
	newEvent.ID = "event-2"
	existing.State = domain.AllocationCompleted
	f.result.Payload.Events = &domain.CollectionEventsPayload{Events: []domain.CollectionEvent{newEvent, existing}}
	f.result.Coverage.Expected, f.result.Coverage.Observed = 2, 2
	f.claim(t)
	if _, err := f.submit(f.result); !errors.Is(err, collectorcontrol.ErrResultConflict) {
		t.Fatalf("conflicting event err=%v", err)
	}
	for _, table := range []string{"collection_runs", "collector_typed_result_ingestions", "goodput_source_coverage", "goodput_collection_events", "collector_source_cursors"} {
		f.count(t, table, 0)
	}
	var cursor string
	if err := f.pool.QueryRow(context.Background(), `SELECT cursor FROM collector_source_cursors WHERE cluster_id=$1 AND source_id=$2`, first.Plan.ClusterID, first.Plan.SourceID).Scan(&cursor); err != nil || cursor != "cursor-1" {
		t.Fatalf("cursor after rollback=%q err=%v", cursor, err)
	}
	malformed := f.result
	malformed.Payload.Events = &domain.CollectionEventsPayload{Events: []domain.CollectionEvent{newEvent}}
	malformed.Payload.Events.Events[0].State = "malformed"
	if _, err := f.submit(malformed); !errors.Is(err, collectorcontrol.ErrResultConflict) {
		t.Fatalf("malformed event err=%v", err)
	}
	// A valid failed result persists unavailable coverage without changing the cursor.
	failed := f.result
	failed.Status, failed.NextCursor = domain.ResultFailed, ""
	failed.Payload.Events = &domain.CollectionEventsPayload{}
	failed.Coverage.State, failed.Coverage.Observed = domain.SourceCoverageUnavailable, 0
	failed.Failures = []domain.CollectionFailure{{Code: domain.FailureInternal, Message: "fixture source failed"}}
	if _, err := f.submit(failed); err != nil {
		t.Fatalf("record failed source: %v", err)
	}
	if err := f.pool.QueryRow(context.Background(), `SELECT cursor FROM collector_source_cursors WHERE cluster_id=$1 AND source_id=$2`, first.Plan.ClusterID, first.Plan.SourceID).Scan(&cursor); err != nil || cursor != "cursor-1" {
		t.Fatalf("cursor after failure=%q err=%v", cursor, err)
	}
	// Hold this source's cursor lock while another source in the same cluster commits.
	tx, err := f.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `SELECT 1 FROM collector_source_cursors WHERE cluster_id=$1 AND source_id=$2 FOR UPDATE`, first.Plan.ClusterID, first.Plan.SourceID); err != nil {
		t.Fatal(err)
	}
	f.result = first
	f.result.Plan.RunID += "-other"
	f.result.Plan.IdempotencyKey += "-other"
	f.result.WorkID += "-other"
	f.result.Plan.SourceID += "-other"
	f.result.Coverage.SourceID = f.result.Plan.SourceID
	if _, err := f.pool.Exec(context.Background(), `INSERT INTO sources(source_id,cluster_id,kind,display_name) VALUES($1,$2,'slurm','Other typed source')`, f.result.Plan.SourceID, f.result.Plan.ClusterID); err != nil {
		t.Fatal(err)
	}
	f.claim(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := f.store.SubmitTypedResult(ctx, f.result.Plan.ClusterID, f.collector, f.ref, f.result, typedChecksum(f.result)); err != nil {
		t.Fatalf("unrelated source blocked by failed source: %v", err)
	}
	f.count(t, "goodput_collection_events", 1)
	f.count(t, "collector_source_cursors", 1)
}

func TestTypedCollectionPlanIdempotencyAndV1Isolation(t *testing.T) {
	f := newTypedFixture(t, domain.CollectionPayloadMetrics)
	r := f.result
	if inserted, err := f.store.EnqueueTypedCollectionWork(context.Background(), r.WorkID, r.Plan, r.Plan.ScheduledFor, r.Plan.Deadline); err != nil || !inserted {
		t.Fatalf("enqueue=%t err=%v", inserted, err)
	}
	if inserted, err := f.store.EnqueueTypedCollectionWork(context.Background(), r.WorkID, r.Plan, r.Plan.ScheduledFor, r.Plan.Deadline); err != nil || inserted {
		t.Fatalf("duplicate enqueue=%t err=%v", inserted, err)
	}
	changed := r.Plan
	changed.Operation = domain.OperationPrometheusGPUTemperature
	if _, err := f.store.EnqueueTypedCollectionWork(context.Background(), r.WorkID, changed, r.Plan.ScheduledFor, r.Plan.Deadline); !errors.Is(err, collectorcontrol.ErrResultConflict) {
		t.Fatalf("changed enqueue err=%v", err)
	}
	if _, found, err := f.store.ClaimWork(context.Background(), f.collector, strings.Repeat("a", 32), time.Minute); err != nil || found {
		t.Fatalf("v1 claimed typed work found=%t err=%v", found, err)
	}
	if _, found, err := f.store.ClaimTypedWork(context.Background(), "foreign-cluster", f.collector, strings.Repeat("a", 32), time.Minute, []domain.SourceID{r.Plan.SourceID}); !errors.Is(err, collectorcontrol.ErrWorkLeaseInvalid) || found {
		t.Fatalf("foreign claim found=%t err=%v", found, err)
	}
	if _, err := f.pool.Exec(context.Background(), `UPDATE collectors SET protocol_max=1 WHERE collector_id=$1`, f.collector); err != nil {
		t.Fatal(err)
	}
	if _, found, err := f.store.ClaimTypedWork(context.Background(), r.Plan.ClusterID, f.collector, strings.Repeat("a", 32), time.Minute, []domain.SourceID{r.Plan.SourceID}); !errors.Is(err, collectorcontrol.ErrWorkLeaseInvalid) || found {
		t.Fatalf("v1-only collector found=%t err=%v", found, err)
	}
	if _, err := f.pool.Exec(context.Background(), `UPDATE collectors SET protocol_max=2 WHERE collector_id=$1`, f.collector); err != nil {
		t.Fatal(err)
	}
	if _, found, err := f.store.ClaimTypedWork(context.Background(), r.Plan.ClusterID, f.collector, strings.Repeat("a", 32), time.Minute, []domain.SourceID{"not-locally-configured"}); err != nil || found {
		t.Fatalf("unconfigured source claimed: %t %v", found, err)
	}
	lease, found, err := f.store.ClaimTypedWork(context.Background(), r.Plan.ClusterID, f.collector, strings.Repeat("a", 32), time.Minute, []domain.SourceID{r.Plan.SourceID})
	if err != nil || !found {
		t.Fatalf("typed claim found=%t err=%v", found, err)
	}
	encoded, _ := domain.EncodeTypedCollectorResult(r)
	digest := sha256.Sum256(encoded)
	ref := collectorcontrol.LeaseRef{WorkID: r.WorkID, Attempt: 1, LeaseToken: lease.Lease.LeaseToken}
	if _, err := f.store.UploadResultChunk(context.Background(), f.collector, collectorcontrol.ResultChunk{LeaseRef: ref, Index: 0, Payload: encoded, SHA256: hex.EncodeToString(digest[:])}); !errors.Is(err, collectorcontrol.ErrResultConflict) {
		t.Fatalf("v1 upload accepted typed work: %v", err)
	}
	if _, err := f.store.FinalizeResult(context.Background(), f.collector, collectorcontrol.ResultFinalization{LeaseRef: ref, RunID: r.Plan.RunID, Status: r.Status, ChunkCount: 1, Bytes: int64(len(encoded)), SHA256: hex.EncodeToString(digest[:])}); !errors.Is(err, collectorcontrol.ErrResultConflict) {
		t.Fatalf("v1 finalized typed work: %v", err)
	}
	var stored []byte
	if err := f.pool.QueryRow(context.Background(), `SELECT typed_plan FROM collector_work_items WHERE work_id=$1`, r.WorkID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	var plan domain.CollectionPlan
	_ = json.Unmarshal(stored, &plan)
	want, _ := json.Marshal(r.Plan)
	got, _ := json.Marshal(plan)
	if !bytes.Equal(want, got) {
		t.Fatal("persisted plan changed")
	}
}

func TestTypedCollectionStaleCursorRollsBackFactsAndCoverage(t *testing.T) {
	f := newTypedFixture(t, domain.CollectionPayloadEvents)
	f.claim(t)
	if _, err := f.submit(f.result); err != nil {
		t.Fatal(err)
	}
	f.result.Plan.RunID += "-stale"
	f.result.Plan.IdempotencyKey += "-stale"
	f.result.WorkID += "-stale"
	f.result.NextCursor = "cursor-2"
	f.result.Payload.Events.Events[0].ID = "event-2"
	f.claim(t)
	if _, err := f.submit(f.result); !errors.Is(err, collectorcontrol.ErrResultConflict) {
		t.Fatalf("stale cursor err=%v", err)
	}
	for _, table := range []string{"collection_runs", "collector_typed_result_ingestions", "goodput_source_coverage", "goodput_collection_events", "collector_source_cursors"} {
		f.count(t, table, 0)
	}
	var cursor, workStatus, attemptStatus string
	if err := f.pool.QueryRow(context.Background(), `SELECT cursor FROM collector_source_cursors WHERE cluster_id=$1 AND source_id=$2`, f.result.Plan.ClusterID, f.result.Plan.SourceID).Scan(&cursor); err != nil || cursor != "cursor-1" {
		t.Fatalf("stale commit changed cursor=%q err=%v", cursor, err)
	}
	if err := f.pool.QueryRow(context.Background(), `SELECT w.status,a.status FROM collector_work_items w JOIN collector_work_attempts a USING(work_id) WHERE w.work_id=$1 AND a.attempt=1`, f.result.WorkID).Scan(&workStatus, &attemptStatus); err != nil || workStatus != "LEASED" || attemptStatus != "CLAIMED" {
		t.Fatalf("rollback changed work=%q attempt=%q err=%v", workStatus, attemptStatus, err)
	}
}
