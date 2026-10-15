package testbed

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// Slurm fixtures enter through authenticated-identity, leased typed result
// finalization, not direct lifecycle-table insertion. No Slurm host is contacted.
func slurmFixtureSource(ctx context.Context, pool *pgxpool.Pool, prefix string) error {
	collections, _ := storepg.NewCollectionStore(pool)
	if err := collections.EnsureSource(ctx, domain.ClusterID(prefix), "Synthetic Slurm", domain.SourceID(prefix+"-source"), "Synthetic accounting"); err != nil {
		return err
	}
	if _, err := pool.Exec(ctx, `UPDATE sources SET kind='slurm' WHERE cluster_id=$1 AND source_id=$2`, prefix, prefix+"-source"); err != nil {
		return err
	}
	control, _ := storepg.NewCollectorControlStore(pool)
	collector := domain.CollectorID(prefix + "-collector")
	if err := control.RegisterCollector(ctx, storepg.CollectorRegistration{CollectorID: collector, ClusterID: domain.ClusterID(prefix), DisplayName: "Test bed Slurm", Version: "fixture", ProtocolMin: 1, ProtocolMax: 2, OperatingSystem: "linux", Architecture: "amd64"}); err != nil {
		return err
	}
	return control.ReplaceCapabilities(ctx, collector, map[string]string{string(domain.OperationSlurmSnapshot): "1"})
}
func slurmLifecycle(prefix, job string, attempt int, state string, at time.Time) domain.SlurmJobLifecycle {
	l := domain.SlurmJobLifecycle{ClusterID: domain.ClusterID(prefix), SourceID: domain.SourceID(prefix + "-source"), Job: domain.JobIdentity{SchedulerNamespace: "slurm", JobID: domain.SchedulerJobID(job), SubmitAt: at.Add(-time.Hour), Attempt: attempt}, RawState: state, SubmitQuality: domain.SlurmFieldPresent, StartAt: at.Add(-30 * time.Minute), StartQuality: domain.SlurmFieldPresent, EndAt: at.Add(-time.Minute), EndQuality: domain.SlurmFieldPresent, NodeIDs: []domain.StableNodeID{"node-1"}, Origin: "ACCOUNTING"}
	l.RecordIdentity = domain.CanonicalSlurmLifecycleRecordID(l)
	return l
}
func submitSlurmFixture(ctx context.Context, pool *pgxpool.Pool, prefix, run string, lifecycles []domain.SlurmJobLifecycle) error {
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	now = now.UTC()
	cluster, source := domain.ClusterID(prefix), domain.SourceID(prefix+"-source")
	plan := domain.CollectionPlan{SchemaVersion: 2, RunID: domain.RunID(run), ClusterID: cluster, SourceID: source, SourceKind: domain.CollectionSourceSlurm, Operation: domain.OperationSlurmSnapshot, PayloadSchema: domain.CollectionSlurmSnapshotSchema, Scope: domain.CollectionScope{Nodes: []domain.StableNodeID{"node-1"}}, Interval: &domain.CollectionInterval{Start: now.Add(-time.Hour), End: now}, ScheduledFor: now, Deadline: now.Add(5 * time.Minute), Limits: domain.CollectionLimits{MaxRecords: 1000, MaxBytes: 1 << 20}, IdempotencyKey: run}
	coverage := domain.SourceCoverage{SchemaVersion: 1, ClusterID: cluster, SourceID: source, Scope: domain.CoverageAllocations, State: domain.SourceCoverageComplete, Expected: 1, Observed: 1, SourceAt: now, EffectiveAt: now, ObservedAt: now}
	inventoryCoverage := coverage
	inventoryCoverage.Scope = domain.CoverageInventory
	inventory := domain.InventoryRevision{SchemaVersion: 1, ID: domain.InventoryRevisionID(run + "-inventory"), ClusterID: cluster, SourceID: source, SourceAt: now, EffectiveAt: now, ObservedAt: now, Entities: []domain.EntityIdentity{{ClusterID: cluster, Kind: domain.EntityNode, NodeID: "node-1"}}}
	sources := []domain.SlurmSourceObservation{}
	for _, kind := range []string{"nodes", "partitions", "jobs", "accounting"} {
		s := domain.SlurmSourceObservation{Kind: kind, DataParserVersion: domain.SlurmSnapshotDataParserVersion, SlurmVersion: "23.11.10", SchemaSupport: domain.SlurmSchemaSupported, BytesRead: 64, SourceAt: now}
		if kind == "accounting" {
			s.WindowStart, s.WindowEnd = plan.Interval.Start, plan.Interval.End
		}
		sources = append(sources, s)
	}
	result := domain.TypedCollectorResult{SchemaVersion: 2, WorkID: domain.WorkID(run + "-work"), Attempt: 1, Plan: plan, Status: domain.ResultSucceeded, StartedAt: now, CompletedAt: now.Add(time.Millisecond), Coverage: coverage, Payload: domain.CollectionPayload{Kind: domain.CollectionPayloadSlurmSnapshot, SlurmSnapshot: &domain.SlurmSnapshotPayload{Inventory: &inventory, Lifecycles: lifecycles, InventoryCoverage: inventoryCoverage, AllocationCoverage: coverage, Sources: sources, ValidEmptyJobs: true, ValidEmptyAccounting: len(lifecycles) == 0}}}
	control, _ := storepg.NewCollectorControlStore(pool)
	if _, err := control.EnqueueTypedCollectionWork(ctx, result.WorkID, plan, now, plan.Deadline); err != nil {
		return err
	}
	collector := domain.CollectorID(prefix + "-collector")
	lease, found, err := control.ClaimTypedWork(ctx, cluster, collector, strings.Repeat("a", 32), time.Minute, []domain.SourceID{source})
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("synthetic Slurm work was not claimed")
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	ref := collectorcontrol.LeaseRef{WorkID: result.WorkID, Attempt: lease.Lease.Attempt, LeaseToken: lease.Lease.LeaseToken}
	checksum := domain.ChecksumSHA256(raw).String()
	if _, err = control.SubmitTypedResult(ctx, cluster, collector, ref, result, checksum); err != nil {
		return err
	}
	// Lost finalization responses replay the exact typed payload and lease.
	_, err = control.SubmitTypedResult(ctx, cluster, collector, ref, result, checksum)
	return err
}
