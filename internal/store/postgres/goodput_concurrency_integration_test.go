//go:build integration

package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestTypedCollectionConcurrentFactWritersSerializeValidity(t *testing.T) {
	for _, kind := range []domain.CollectionPayloadKind{domain.CollectionPayloadInventory, domain.CollectionPayloadAllocation} {
		t.Run(string(kind), func(t *testing.T) {
			f := newTypedFixture(t, kind)
			f.claim(t)
			first, firstRef := f.result, f.ref
			encoded, _ := json.Marshal(first)
			var second domain.TypedCollectorResult
			_ = json.Unmarshal(encoded, &second)
			second.WorkID += "-later"
			second.Plan.RunID += "-later"
			second.Plan.IdempotencyKey += "-later"
			second.StartedAt, second.CompletedAt = first.StartedAt.Add(time.Minute), first.CompletedAt.Add(time.Minute)
			second.Coverage.SourceAt = second.Coverage.SourceAt.Add(time.Minute)
			second.Coverage.EffectiveAt = second.Coverage.EffectiveAt.Add(time.Minute)
			second.Coverage.ObservedAt = second.Coverage.ObservedAt.Add(time.Minute)
			table := "goodput_current_inventory"
			firstEffective := first.Coverage.EffectiveAt
			if kind == domain.CollectionPayloadInventory {
				r := &second.Payload.Inventory.Revisions[0]
				r.ID += "-later"
				r.SourceAt, r.EffectiveAt, r.ObservedAt = r.SourceAt.Add(time.Minute), r.EffectiveAt.Add(time.Minute), r.ObservedAt.Add(time.Minute)
			} else {
				table = "goodput_current_allocations"
				s := &second.Payload.Allocation.Snapshots[0]
				s.State = domain.AllocationCompleted
				s.SourceAt, s.EffectiveAt, s.ObservedAt = s.SourceAt.Add(time.Minute), s.EffectiveAt.Add(time.Minute), s.ObservedAt.Add(time.Minute)
			}
			f.result = second
			f.claim(t)
			secondRef := f.ref
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			gate := time.Now().UnixNano()
			name := fmt.Sprintf("gp03c_projection_gate_%d", gate)
			identifier := pgx.Identifier{name}.Sanitize()
			// Pause the first transaction after its validity rebuild, but before
			// its current projection insert. A second uncoordinated rebuild would
			// miss the first uncommitted fact and leave two open-ended intervals.
			if _, err := f.pool.Exec(ctx, `CREATE FUNCTION `+identifier+`() RETURNS trigger LANGUAGE plpgsql AS $gate$
				BEGIN
				  IF NEW.source_id=TG_ARGV[0] AND NEW.effective_at=TG_ARGV[1]::timestamptz THEN
				    PERFORM pg_advisory_xact_lock(TG_ARGV[2]::bigint);
				  END IF;
				  RETURN NEW;
				END $gate$`); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_, _ = f.pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+identifier+` ON `+table)
				_, _ = f.pool.Exec(context.Background(), `DROP FUNCTION `+identifier+`()`)
			})
			var triggerSQL string
			if err := f.pool.QueryRow(ctx, `SELECT format('CREATE TRIGGER %I BEFORE INSERT ON %I FOR EACH ROW EXECUTE FUNCTION %I(%L,%L,%L)',
				$1::text,$2::text,$1::text,$3::text,$4::text,$5::text)`, name, table, string(first.Plan.SourceID), firstEffective.Format(time.RFC3339Nano), fmt.Sprint(gate)).Scan(&triggerSQL); err != nil {
				t.Fatal(err)
			}
			if _, err := f.pool.Exec(ctx, triggerSQL); err != nil {
				t.Fatal(err)
			}
			gateConn, err := f.pool.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer gateConn.Release()
			if _, err := gateConn.Exec(ctx, `SELECT pg_advisory_lock($1)`, gate); err != nil {
				t.Fatal(err)
			}
			defer func() { _, _ = gateConn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, gate) }()
			firstDone, secondDone := make(chan error, 1), make(chan error, 1)
			write := func(ref collectorcontrol.LeaseRef, result domain.TypedCollectorResult, done chan<- error) {
				_, err := f.store.SubmitTypedResult(ctx, result.Plan.ClusterID, f.collector, ref, result, typedChecksum(result))
				done <- err
			}
			go write(firstRef, first, firstDone)
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				var waiting bool
				if err := f.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory'
					AND NOT granted AND classid=$1::oid AND objid=$2::oid AND objsubid=1)`, gate>>32, gate&0xffffffff).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				select {
				case err := <-firstDone:
					t.Fatalf("first writer bypassed projection gate: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-ticker.C:
				}
			}
			go write(secondRef, second, secondDone)
			select {
			case err := <-secondDone:
				t.Fatalf("second writer passed an uncommitted predecessor: %v", err)
			case <-time.After(150 * time.Millisecond):
			}
			if _, err := gateConn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, gate); err != nil {
				t.Fatal(err)
			}
			for _, done := range []chan error{firstDone, secondDone} {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			store, _ := storepg.NewGoodputStore(f.pool)
			var validTo time.Time
			if kind == domain.CollectionPayloadInventory {
				if err := f.pool.QueryRow(ctx, `SELECT valid_to FROM goodput_inventory_revision_validity WHERE cluster_id=$1 AND revision_id=$2`, first.Plan.ClusterID, first.Payload.Inventory.Revisions[0].ID).Scan(&validTo); err != nil {
					t.Fatal(err)
				}
				current, found, err := store.GetCurrentInventoryRevision(ctx, first.Plan.ClusterID, first.Plan.SourceID, application.InventoryObserved)
				if err != nil || !found || current.Revision.ID != second.Payload.Inventory.Revisions[0].ID {
					t.Fatalf("current inventory=%+v found=%t err=%v", current, found, err)
				}
			} else {
				if err := f.pool.QueryRow(ctx, `SELECT v.valid_to FROM goodput_allocation_snapshot_validity v
					JOIN goodput_allocation_snapshots s USING(cluster_id,snapshot_key)
					WHERE s.cluster_id=$1 AND s.source_id=$2 AND s.effective_at=$3`, first.Plan.ClusterID, first.Plan.SourceID, firstEffective).Scan(&validTo); err != nil {
					t.Fatal(err)
				}
				current, more, err := store.ListCurrentAllocationSnapshots(ctx, first.Plan.ClusterID, 10)
				if err != nil || more || len(current) != 1 || current[0].State != domain.AllocationCompleted {
					t.Fatalf("current allocation=%+v more=%t err=%v", current, more, err)
				}
			}
			if !validTo.Equal(firstEffective.Add(time.Minute)) {
				t.Fatalf("predecessor validity end=%s want=%s", validTo, firstEffective.Add(time.Minute))
			}
			f.count(t, "collector_typed_result_ingestions", 1)
			f.count(t, "goodput_source_coverage", 1)
		})
	}
}

func TestSlurmSnapshotConcurrentOverlapDedupPreservesAttemptsAndProvenance(t *testing.T) {
	f := newTypedFixture(t, domain.CollectionPayloadSlurmSnapshot)
	f.result.Plan.Limits.MaxRecords = 32
	secondNode := domain.EntityIdentity{ClusterID: f.result.Plan.ClusterID, Kind: domain.EntityNode, NodeID: "node-2"}
	f.result.Plan.Scope.Nodes = append(f.result.Plan.Scope.Nodes, "node-2")
	f.result.Coverage.Expected, f.result.Coverage.Observed = 2, 2
	payload := f.result.Payload.SlurmSnapshot
	payload.InventoryCoverage.Expected, payload.InventoryCoverage.Observed = 2, 2
	payload.Inventory.Entities = append(payload.Inventory.Entities, secondNode)
	payload.Allocations[0].Snapshot.Entities = append(payload.Allocations[0].Snapshot.Entities, secondNode)
	payload.Allocations[0].RecordIdentity = domain.CanonicalSlurmAllocationRecordID(payload.Allocations[0].Snapshot)
	f.result.Status = domain.ResultPartial
	f.result.Coverage.State, f.result.Coverage.Expected, f.result.Coverage.Observed = domain.SourceCoverageUnknown, 0, 0
	payload.AllocationCoverage = f.result.Coverage
	payload.ValidEmptyAccounting = false
	f.result.Failures = []domain.CollectionFailure{{Code: domain.FailurePartialData, Target: "accounting", Message: "Slurm accounting attempt identity is unavailable"}}
	membership := sha256.Sum256([]byte("node-1"))
	unresolved := domain.SlurmUnresolvedAccounting{ClusterID: f.result.Plan.ClusterID, SourceID: f.result.Plan.SourceID, SchedulerNamespace: "slurm", JobID: "40", SubmitAt: f.result.StartedAt.Add(-2 * time.Hour), SubmitQuality: domain.SlurmFieldPresent, SchedulerCluster: "cluster-a", RawState: "COMPLETED", StartAt: f.result.StartedAt.Add(-90 * time.Minute), StartQuality: domain.SlurmFieldPresent, EndAt: f.result.StartedAt.Add(-time.Hour), EndQuality: domain.SlurmFieldPresent, NodeIDs: []domain.StableNodeID{"node-1"}, MembershipQuality: domain.SlurmFieldPresent, MembershipDigest: hex.EncodeToString(membership[:]), AttemptQuality: domain.SlurmFieldUnsupported, Provenance: []domain.SlurmAccountingProvenance{{WindowStart: f.result.Plan.Interval.Start, WindowEnd: f.result.Plan.Interval.End, SourceAt: f.result.StartedAt, ObservedAt: f.result.CompletedAt}}}
	unresolved.RecordIdentity = domain.CanonicalSlurmUnresolvedRecordID(unresolved)
	payload.UnresolvedAccounting = []domain.SlurmUnresolvedAccounting{unresolved}
	f.claim(t)
	first, firstRef := f.result, f.ref
	encoded, _ := json.Marshal(first)
	var second domain.TypedCollectorResult
	_ = json.Unmarshal(encoded, &second)
	second.WorkID += "-overlap"
	second.Plan.RunID += "-overlap"
	second.Plan.IdempotencyKey += "-overlap"
	second.CompletedAt = second.CompletedAt.Add(2 * time.Minute)
	snapshot := &second.Payload.SlurmSnapshot.Allocations[0].Snapshot
	snapshot.Entities[0], snapshot.Entities[1] = snapshot.Entities[1], snapshot.Entities[0]
	snapshot.SourceAt, snapshot.ObservedAt = snapshot.SourceAt.Add(time.Minute), snapshot.ObservedAt.Add(time.Minute)
	second.Payload.SlurmSnapshot.Allocations[0].RecordIdentity = domain.CanonicalSlurmAllocationRecordID(*snapshot)
	f.result = second
	f.claim(t)
	secondRef := f.ref
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	results := make(chan error, 2)
	for _, item := range []struct {
		ref    collectorcontrol.LeaseRef
		result domain.TypedCollectorResult
	}{{firstRef, first}, {secondRef, second}} {
		go func(item struct {
			ref    collectorcontrol.LeaseRef
			result domain.TypedCollectorResult
		}) {
			_, err := f.store.SubmitTypedResult(ctx, item.result.Plan.ClusterID, f.collector, item.ref, item.result, typedChecksum(item.result))
			results <- err
		}(item)
	}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	var facts, snapshots, observations, unresolvedFacts, provenanceRows int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM goodput_slurm_allocation_facts WHERE cluster_id=$1 AND source_id=$2`, first.Plan.ClusterID, first.Plan.SourceID).Scan(&facts); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM goodput_allocation_snapshots WHERE cluster_id=$1 AND source_id=$2`, first.Plan.ClusterID, first.Plan.SourceID).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM goodput_slurm_allocation_observations WHERE cluster_id=$1 AND source_id=$2`, first.Plan.ClusterID, first.Plan.SourceID).Scan(&observations); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM goodput_slurm_unresolved_accounting WHERE cluster_id=$1 AND source_id=$2`, first.Plan.ClusterID, first.Plan.SourceID).Scan(&unresolvedFacts); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM goodput_slurm_accounting_provenance WHERE cluster_id=$1 AND source_id=$2`, first.Plan.ClusterID, first.Plan.SourceID).Scan(&provenanceRows); err != nil {
		t.Fatal(err)
	}
	if facts != 1 || snapshots != 1 || observations != 2 || unresolvedFacts != 1 || provenanceRows != 2 {
		t.Fatalf("dedup facts=%d snapshots=%d observations=%d unresolved=%d provenance=%d", facts, snapshots, observations, unresolvedFacts, provenanceRows)
	}

	var retry domain.TypedCollectorResult
	_ = json.Unmarshal(encoded, &retry)
	retry.WorkID += "-attempt2"
	retry.Plan.RunID += "-attempt2"
	retry.Plan.IdempotencyKey += "-attempt2"
	retry.Payload.SlurmSnapshot.Allocations[0].Snapshot.Job.Attempt = 2
	retry.Payload.SlurmSnapshot.Allocations[0].RecordIdentity = domain.CanonicalSlurmAllocationRecordID(retry.Payload.SlurmSnapshot.Allocations[0].Snapshot)
	f.result = retry
	f.claim(t)
	if _, err := f.submit(retry); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM goodput_slurm_allocation_facts WHERE cluster_id=$1 AND source_id=$2`, first.Plan.ClusterID, first.Plan.SourceID).Scan(&facts); err != nil || facts != 2 {
		t.Fatalf("attempt facts=%d err=%v", facts, err)
	}

	forged := retry
	forged.WorkID += "-forged"
	forged.Plan.RunID += "-forged"
	forged.Plan.IdempotencyKey += "-forged"
	f.result = forged
	f.claim(t)
	forged.Payload.SlurmSnapshot.Allocations[0].Snapshot.State = domain.AllocationFailed
	if _, err := f.submit(forged); !errors.Is(err, collectorcontrol.ErrResultConflict) {
		t.Fatalf("forged core err=%v", err)
	}
	var ingested int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM collector_typed_result_ingestions WHERE run_id=$1`, forged.Plan.RunID).Scan(&ingested); err != nil || ingested != 0 {
		t.Fatalf("forged transaction persisted=%d err=%v", ingested, err)
	}
}

func TestSlurmSnapshotPartialMembershipPreservesExpectedAndObservedInventory(t *testing.T) {
	f := newTypedFixture(t, domain.CollectionPayloadSlurmSnapshot)
	ctx := context.Background()
	goodput, _ := storepg.NewGoodputStore(f.pool)
	expected := *f.result.Payload.SlurmSnapshot.Inventory
	expected.ID = "expected-" + expected.ID
	observed := expected
	observed.ID = "observed-" + observed.ID
	if inserted, err := goodput.RecordExpectedInventoryRevision(ctx, expected); err != nil || !inserted {
		t.Fatalf("seed expected inventory inserted=%t err=%v", inserted, err)
	}
	if inserted, err := goodput.RecordObservedInventoryRevision(ctx, observed); err != nil || !inserted {
		t.Fatalf("seed observed inventory inserted=%t err=%v", inserted, err)
	}

	result := f.result
	result.Status = domain.ResultPartial
	result.Coverage.State = domain.SourceCoverageUnknown
	result.Coverage.Expected, result.Coverage.Observed = 0, 0
	result.Payload.SlurmSnapshot.AllocationCoverage = result.Coverage
	result.Payload.SlurmSnapshot.Inventory = nil
	result.Payload.SlurmSnapshot.InventoryCoverage.State = domain.SourceCoverageUnknown
	result.Payload.SlurmSnapshot.InventoryCoverage.Expected, result.Payload.SlurmSnapshot.InventoryCoverage.Observed = 0, 0
	result.Payload.SlurmSnapshot.Sources[0].ReportedWarnings = 1
	result.Failures = []domain.CollectionFailure{{Code: domain.FailurePartialData, Target: "nodes", Message: "Slurm membership is incomplete"}}
	f.result = result
	f.claim(t)
	if _, err := f.submit(result); err != nil {
		t.Fatal(err)
	}
	for class, want := range map[application.InventoryClass]domain.InventoryRevisionID{
		application.InventoryExpected: expected.ID,
		application.InventoryObserved: observed.ID,
	} {
		current, found, err := goodput.GetCurrentInventoryRevision(ctx, result.Plan.ClusterID, result.Plan.SourceID, class)
		if err != nil || !found || current.Revision.ID != want {
			t.Fatalf("inventory class=%s current=%+v found=%t err=%v", class, current, found, err)
		}
	}
}

func TestSlurmSnapshotLateImmutableConflictRollsBackWholeFinalization(t *testing.T) {
	f := newTypedFixture(t, domain.CollectionPayloadSlurmSnapshot)
	f.claim(t)
	first := f.result
	if _, err := f.submit(first); err != nil {
		t.Fatal(err)
	}
	recordID := first.Payload.SlurmSnapshot.Allocations[0].RecordIdentity
	if _, err := f.pool.Exec(context.Background(), `UPDATE goodput_slurm_allocation_facts SET core_sha256=decode(repeat('00',32),'hex') WHERE cluster_id=$1 AND source_id=$2 AND record_identity=$3`, first.Plan.ClusterID, first.Plan.SourceID, recordID); err != nil {
		t.Fatal(err)
	}

	encoded, _ := json.Marshal(first)
	var conflict domain.TypedCollectorResult
	_ = json.Unmarshal(encoded, &conflict)
	conflict.WorkID += "-late-conflict"
	conflict.Plan.RunID += "-late-conflict"
	conflict.Plan.IdempotencyKey += "-late-conflict"
	conflict.CompletedAt = conflict.CompletedAt.Add(time.Minute)
	revision := conflict.Payload.SlurmSnapshot.Inventory
	revision.ID += "-late-conflict"
	revision.SourceAt = revision.SourceAt.Add(30 * time.Second)
	revision.EffectiveAt = revision.EffectiveAt.Add(30 * time.Second)
	revision.ObservedAt = revision.ObservedAt.Add(30 * time.Second)
	f.result = conflict
	f.claim(t)
	if _, err := f.submit(conflict); !errors.Is(err, collectorcontrol.ErrResultConflict) {
		t.Fatalf("late immutable conflict err=%v", err)
	}

	ctx := context.Background()
	for _, table := range []string{"collection_runs", "collector_typed_result_ingestions", "goodput_source_coverage", "goodput_slurm_snapshot_sources", "goodput_slurm_allocation_observations"} {
		var count int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE run_id=$1`, conflict.Plan.RunID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("rollback table=%s count=%d err=%v", table, count, err)
		}
	}
	var revisionCount int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM goodput_inventory_revisions WHERE cluster_id=$1 AND revision_id=$2`, conflict.Plan.ClusterID, revision.ID).Scan(&revisionCount); err != nil || revisionCount != 0 {
		t.Fatalf("rolled back inventory revision count=%d err=%v", revisionCount, err)
	}
	goodput, _ := storepg.NewGoodputStore(f.pool)
	current, found, err := goodput.GetCurrentInventoryRevision(ctx, first.Plan.ClusterID, first.Plan.SourceID, application.InventoryObserved)
	if err != nil || !found || current.Revision.ID != first.Payload.SlurmSnapshot.Inventory.ID {
		t.Fatalf("observed projection changed current=%+v found=%t err=%v", current, found, err)
	}
	var workStatus, attemptStatus string
	var workCompleted, attemptCompleted *time.Time
	if err := f.pool.QueryRow(ctx, `SELECT w.status,w.completed_at,a.status,a.completed_at FROM collector_work_items w JOIN collector_work_attempts a USING(work_id) WHERE w.work_id=$1 AND a.attempt=$2`, conflict.WorkID, conflict.Attempt).Scan(&workStatus, &workCompleted, &attemptStatus, &attemptCompleted); err != nil {
		t.Fatal(err)
	}
	if workStatus != string(domain.WorkLeased) || attemptStatus != string(domain.AttemptClaimed) || workCompleted != nil || attemptCompleted != nil {
		t.Fatalf("conflicting work finalized work=%s/%v attempt=%s/%v", workStatus, workCompleted, attemptStatus, attemptCompleted)
	}
}
