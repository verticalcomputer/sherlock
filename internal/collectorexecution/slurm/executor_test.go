package slurm

import (
	"context"
	"strings"
	"testing"
	"time"

	adapter "github.com/verticalcomputer/sherlock/internal/adapters/slurm"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type snapshotFixture struct {
	nodes, partitions, jobs, accounting adapter.Result
	accountingErr                       error
	waitForAccountingExpiry             bool
	calls                               []string
	windowStart, windowEnd              time.Time
}

func (f *snapshotFixture) Nodes(context.Context, []string) (adapter.Result, error) {
	f.calls = append(f.calls, "nodes")
	return f.nodes, nil
}
func (f *snapshotFixture) Partitions(context.Context, []string) (adapter.Result, error) {
	f.calls = append(f.calls, "partitions")
	return f.partitions, nil
}
func (f *snapshotFixture) Jobs(context.Context, []string) (adapter.Result, error) {
	f.calls = append(f.calls, "jobs")
	return f.jobs, nil
}
func (f *snapshotFixture) AccountingAllocations(ctx context.Context, start, end time.Time, _ string, _ []string) (adapter.Result, error) {
	f.calls = append(f.calls, "accounting")
	f.windowStart, f.windowEnd = start, end
	if f.waitForAccountingExpiry {
		<-ctx.Done()
		return f.accounting, nil
	}
	return f.accounting, f.accountingErr
}

func TestSnapshotExecutorRefusesNilErrorAfterDeadline(t *testing.T) {
	now := time.Now().UTC()
	fixture := completeFixture(now)
	fixture.waitForAccountingExpiry = true
	executor, _ := NewSnapshot(fixture, fixedClock{now}, SnapshotConfig{ClusterID: "cluster-1", SourceID: "slurm-1", SchedulerNamespace: "slurm/cluster-a", SchedulerCluster: "cluster-a", Nodes: map[domain.StableNodeID]string{"node-1": "comp007"}, TrustedCurrentJobVisibility: true, TrustedAccountingVisibility: true, AccountingOverlap: time.Minute})
	lease := snapshotLease(now)
	lease.Plan.Deadline = time.Now().UTC().Add(20 * time.Millisecond)
	lease.Lease.LeaseExpires, lease.Lease.Work.WorkExpiresAt = lease.Plan.Deadline, lease.Plan.Deadline
	result := executor.ExecuteTyped(context.Background(), lease)
	if result.Status != domain.ResultFailed || result.Failures[0].Code != domain.FailureDeadlineExceeded {
		t.Fatalf("post-deadline result=%+v", result)
	}
}

func supported(records ...adapter.Record) adapter.Result {
	return adapter.Result{Records: records, BytesRead: 100, DataParserVersion: "data_parser/v0.0.40", SlurmVersion: "23.11.10", SchemaSupport: adapter.SchemaSupportSupported}
}

func snapshotLease(now time.Time) domain.TypedWorkLease {
	p := domain.CollectionPlan{SchemaVersion: 2, RunID: "run-1", ClusterID: "cluster-1", SourceID: "slurm-1", SourceKind: domain.CollectionSourceSlurm, Operation: domain.OperationSlurmSnapshot, PayloadSchema: domain.CollectionSlurmSnapshotSchema, Scope: domain.CollectionScope{Nodes: []domain.StableNodeID{"node-1"}}, Interval: &domain.CollectionInterval{Start: now.Add(-time.Hour), End: now.Add(-time.Minute)}, ScheduledFor: now, Deadline: now.Add(time.Minute), Limits: domain.CollectionLimits{MaxRecords: 50, MaxBytes: 100000}, IdempotencyKey: "snapshot-1"}
	return domain.TypedWorkLease{Plan: p, Lease: domain.WorkLease{CollectorID: "collector-1", Attempt: 1, LeaseToken: strings.Repeat("a", 32), LeaseExpires: p.Deadline, Work: domain.CollectorWork{WorkID: "work-1", WorkExpiresAt: p.Deadline, Task: domain.CollectionTask{RunID: p.RunID, ClusterID: p.ClusterID, SourceID: p.SourceID, IdempotencyKey: p.IdempotencyKey}}}}
}

func completeFixture(now time.Time) *snapshotFixture {
	return &snapshotFixture{
		nodes:      supported(adapter.Record{Kind: "node", ID: "comp007"}),
		partitions: supported(adapter.Record{Kind: "partition", ID: "gpu", Attributes: []domain.Label{{Name: "nodes/configured", Value: "comp007"}}, Fields: []adapter.FieldObservation{{Name: "nodes", Quality: adapter.FieldPresent}}}),
		jobs:       supported(adapter.Record{Kind: "job", ID: "42", State: "RUNNING", Attributes: []domain.Label{{Name: "cluster", Value: "cluster-a"}, {Name: "submit_time", Value: now.Add(-2 * time.Hour).Format(time.RFC3339)}, {Name: "restart_cnt", Value: "1"}, {Name: "nodes", Value: "comp007"}, {Name: "start_time", Value: now.Add(-90 * time.Minute).Format(time.RFC3339)}}, Fields: []adapter.FieldObservation{{Name: "submit_time", Quality: adapter.FieldPresent}, {Name: "restart_cnt", Quality: adapter.FieldPresent}, {Name: "nodes", Quality: adapter.FieldPresent}, {Name: "start_time", Quality: adapter.FieldPresent}, {Name: "end_time", Quality: adapter.FieldUnset}}}),
		accounting: supported(),
	}
}

func TestSnapshotExecutorUsesAuthorizedOverlappingWindowAndStableIdentity(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour)
	fixture := completeFixture(now)
	executor, err := NewSnapshot(fixture, fixedClock{now}, SnapshotConfig{ClusterID: "cluster-1", SourceID: "slurm-1", SchedulerNamespace: "slurm/cluster-a", SchedulerCluster: "cluster-a", Nodes: map[domain.StableNodeID]string{"node-1": "comp007"}, TrustedCurrentJobVisibility: true, TrustedAccountingVisibility: true, AccountingOverlap: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	lease := snapshotLease(now)
	result := executor.ExecuteTyped(context.Background(), lease)
	if err := domain.ValidateTypedResultForLease(result, lease); err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.ResultSucceeded || result.Payload.SlurmSnapshot.Inventory == nil || len(result.Payload.SlurmSnapshot.Allocations) != 1 {
		t.Fatalf("result=%+v", result)
	}
	if !fixture.windowStart.Equal(lease.Plan.Interval.Start.Add(-5*time.Minute)) || !fixture.windowEnd.Equal(lease.Plan.Interval.End) {
		t.Fatalf("accounting window=%s..%s", fixture.windowStart, fixture.windowEnd)
	}
	fact := result.Payload.SlurmSnapshot.Allocations[0]
	if fact.Snapshot.Job.Attempt != 1 || fact.RecordIdentity != domain.CanonicalSlurmAllocationRecordID(fact.Snapshot) {
		t.Fatalf("allocation=%+v", fact)
	}
}

func TestSnapshotExecutorPreservesMissingAccountingAndPartialMembership(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour)
	for name, mutate := range map[string]func(*snapshotFixture){
		"missing accounting": func(f *snapshotFixture) { f.accountingErr = context.DeadlineExceeded },
		"partial membership": func(f *snapshotFixture) { f.nodes = supported() },
		"unknown parser":     func(f *snapshotFixture) { f.nodes.SchemaSupport = adapter.SchemaSupportUnsupported },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := completeFixture(now)
			mutate(fixture)
			executor, _ := NewSnapshot(fixture, fixedClock{now}, SnapshotConfig{ClusterID: "cluster-1", SourceID: "slurm-1", SchedulerNamespace: "slurm/cluster-a", SchedulerCluster: "cluster-a", Nodes: map[domain.StableNodeID]string{"node-1": "comp007"}, TrustedCurrentJobVisibility: true, TrustedAccountingVisibility: true, AccountingOverlap: time.Minute})
			lease := snapshotLease(now)
			result := executor.ExecuteTyped(context.Background(), lease)
			if err := domain.ValidateTypedResultForLease(result, lease); err != nil {
				t.Fatal(err)
			}
			if result.Status != domain.ResultPartial || result.Coverage.State == domain.SourceCoverageComplete {
				t.Fatalf("result=%+v", result)
			}
			if name != "missing accounting" && result.Payload.SlurmSnapshot.Inventory != nil {
				t.Fatal("partial membership replaced observed inventory")
			}
		})
	}
}

func TestSnapshotExecutorRejectsBeforeOrAtAssignedBounds(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour)
	fixture := completeFixture(now)
	executor, _ := NewSnapshot(fixture, fixedClock{now}, SnapshotConfig{ClusterID: "cluster-1", SourceID: "slurm-1", SchedulerNamespace: "slurm/cluster-a", SchedulerCluster: "cluster-a", Nodes: map[domain.StableNodeID]string{"node-1": "comp007"}, TrustedCurrentJobVisibility: true, TrustedAccountingVisibility: true, AccountingOverlap: time.Minute})
	lease := snapshotLease(now)
	lease.Plan.ClusterID = "foreign"
	if result := executor.ExecuteTyped(context.Background(), lease); result.Status != domain.ResultFailed || len(fixture.calls) != 0 {
		t.Fatal("foreign identity reached source")
	}
	lease = snapshotLease(now)
	lease.Plan.Deadline = now
	if result := executor.ExecuteTyped(context.Background(), lease); result.Status != domain.ResultFailed || len(fixture.calls) != 0 {
		t.Fatal("expired work reached source")
	}
	lease = snapshotLease(now)
	lease.Plan.Limits.MaxBytes = 50
	if result := executor.ExecuteTyped(context.Background(), lease); result.Status != domain.ResultFailed || len(fixture.calls) != 1 || result.Failures[0].Code != domain.FailureResultLimit {
		t.Fatalf("limit result=%+v calls=%v", result, fixture.calls)
	}
}

func TestSnapshotExecutorKeepsForeignUnresolvedMembershipAsGap(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour)
	fixture := completeFixture(now)
	fixture.accounting = supported(adapter.Record{Kind: "accounting_job", ID: "41", State: "COMPLETED", Attributes: []domain.Label{{Name: "cluster", Value: "cluster-a"}, {Name: "submit_time", Value: now.Add(-3 * time.Hour).Format(time.RFC3339)}, {Name: "start_time", Value: now.Add(-2 * time.Hour).Format(time.RFC3339)}, {Name: "end_time", Value: now.Add(-time.Hour).Format(time.RFC3339)}, {Name: "nodes", Value: "foreign001"}}, Fields: []adapter.FieldObservation{{Name: "cluster", Quality: adapter.FieldPresent}, {Name: "submit_time", Quality: adapter.FieldPresent}, {Name: "restart_cnt", Quality: adapter.FieldUnsupported}, {Name: "start_time", Quality: adapter.FieldPresent}, {Name: "end_time", Quality: adapter.FieldPresent}, {Name: "nodes", Quality: adapter.FieldPresent}}})
	executor, _ := NewSnapshot(fixture, fixedClock{now}, SnapshotConfig{ClusterID: "cluster-1", SourceID: "slurm-1", SchedulerNamespace: "slurm/cluster-a", SchedulerCluster: "cluster-a", Nodes: map[domain.StableNodeID]string{"node-1": "comp007"}, TrustedCurrentJobVisibility: true, TrustedAccountingVisibility: true, AccountingOverlap: time.Minute})
	lease := snapshotLease(now)
	result := executor.ExecuteTyped(context.Background(), lease)
	if err := domain.ValidateTypedResultForLease(result, lease); err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.ResultPartial || len(result.Payload.SlurmSnapshot.UnresolvedAccounting) != 1 {
		t.Fatalf("result=%+v", result)
	}
	record := result.Payload.SlurmSnapshot.UnresolvedAccounting[0]
	if record.MembershipQuality != domain.SlurmFieldUnsupported || len(record.NodeIDs) != 0 || record.AttemptQuality != domain.SlurmFieldUnsupported {
		t.Fatalf("unresolved=%+v", record)
	}
}
