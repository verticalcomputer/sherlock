//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestProgressEvidenceReplayAndIsolation(t *testing.T) {
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated migrated database required")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	suffix := fmt.Sprint(time.Now().UnixNano())
	cluster, source := domain.ClusterID("progress-cluster-"+suffix), domain.SourceID("progress-source-"+suffix)
	otherSource := domain.SourceID("progress-other-" + suffix)
	collections, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []domain.SourceID{source, otherSource} {
		if err := collections.EnsureSource(ctx, cluster, "Progress fixture", id, string(id)); err != nil {
			t.Fatal(err)
		}
	}
	store, err := storepg.NewGoodputStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO goodput_progress_templates
		(cluster_id,source_id,template_id,template_revision,metric_name,scheduler_namespace,cohort,unit,
		 job_id_label,submit_at_label,attempt_label,reset_epoch_label,max_age_seconds,approved_by)
		VALUES ($1,$2,'trainer.tokens',1,'training_committed_tokens_total','slurm','model-a','tokens',
		'job_id','submit_at','attempt','reset_epoch',120,'test-reviewer')`, cluster, source); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	addRun := func(id, kind, status string, sourceID domain.SourceID) {
		t.Helper()
		_, err := pool.Exec(ctx, `INSERT INTO collection_runs
			(run_id,cluster_id,source_id,query_kind,idempotency_key,status,scheduled_for,started_at,completed_at,series_returned,bytes_read,coverage_complete)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$7,$7,1,0,true)`, id, cluster, sourceID, kind, id, status, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"progress-a-" + suffix, "progress-b-" + suffix, "progress-c-" + suffix} {
		addRun(id, application.ProgressOperation, "SUCCEEDED", source)
	}
	wrongRun := "dcgm-" + suffix
	addRun(wrongRun, "gpu.temperature", "SUCCEEDED", source)
	failedRun := "failed-" + suffix
	addRun(failedRun, application.ProgressOperation, "FAILED", source)
	noDataRun := "no-data-" + suffix
	addRun(noDataRun, application.ProgressOperation, "NO_DATA", source)
	foreignRun := "foreign-" + suffix
	addRun(foreignRun, application.ProgressOperation, "SUCCEEDED", otherSource)
	value := 12.0
	job := domain.JobIdentity{SchedulerNamespace: "slurm", JobID: "42", SubmitAt: now.Add(-time.Hour), Attempt: 1}
	evidence := application.ProgressEvidence{RunID: "progress-a-" + suffix, TemplateID: "trainer.tokens", TemplateRevision: 1,
		Observation: domain.ProgressObservation{SchemaVersion: 1, ClusterID: cluster, SourceID: source, Job: job,
			Cohort: "model-a", State: domain.ProgressMeasured, Unit: "tokens", Committed: &value,
			ResetEpoch: "checkpoint-1", SourceAt: now, EffectiveAt: now, ObservedAt: now}}
	if inserted, err := store.RecordProgressEvidence(ctx, evidence); err != nil || !inserted {
		t.Fatalf("first=%t %v", inserted, err)
	}
	if inserted, err := store.RecordProgressEvidence(ctx, evidence); err != nil || inserted {
		t.Fatalf("replay=%t %v", inserted, err)
	}
	second := evidence
	second.RunID = "progress-b-" + suffix
	second.Observation.ObservedAt = now.Add(time.Second)
	if inserted, err := store.RecordProgressEvidence(ctx, second); err != nil || inserted {
		t.Fatalf("second receipt=%t %v", inserted, err)
	}
	for label, mutate := range map[string]func(*application.ProgressEvidence){
		"conflicting value":   func(e *application.ProgressEvidence) { v := 13.0; e.Observation.Committed = &v },
		"conflicting receipt": func(e *application.ProgressEvidence) { e.Observation.ObservedAt = now.Add(time.Second) },
		"wrong operation":     func(e *application.ProgressEvidence) { e.RunID = wrongRun },
		"failed run":          func(e *application.ProgressEvidence) { e.RunID = failedRun },
		"no-data measured":    func(e *application.ProgressEvidence) { e.RunID = noDataRun },
		"foreign source":      func(e *application.ProgressEvidence) { e.RunID = foreignRun },
		"unapproved template": func(e *application.ProgressEvidence) { e.TemplateID = "unreviewed" },
		"wrong cohort":        func(e *application.ProgressEvidence) { e.Observation.Cohort = "other-model" },
		"wrong namespace":     func(e *application.ProgressEvidence) { e.Observation.Job.SchedulerNamespace = "other-scheduler" },
	} {
		t.Run(label, func(t *testing.T) {
			bad := evidence
			mutate(&bad)
			if _, err := store.RecordProgressEvidence(ctx, bad); err == nil {
				t.Fatal("rejected evidence accepted")
			}
		})
	}
	missing := evidence
	missing.RunID = noDataRun
	missing.Observation.State = domain.ProgressUnmeasured
	missing.Observation.Unit, missing.Observation.ResetEpoch, missing.Observation.Committed = "", "", nil
	missing.Observation.EffectiveAt = now.Add(time.Second)
	missing.Observation.ObservedAt = now.Add(2 * time.Second)
	if inserted, err := store.RecordProgressEvidence(ctx, missing); err != nil || !inserted {
		t.Fatalf("missing=%t %v", inserted, err)
	}
	reset := evidence
	reset.RunID = "progress-c-" + suffix
	reset.Observation.ResetEpoch = "checkpoint-2"
	if inserted, err := store.RecordProgressEvidence(ctx, reset); err != nil || !inserted {
		t.Fatalf("reset=%t %v", inserted, err)
	}
	reused := evidence
	reused.RunID = "progress-c-" + suffix
	reused.Observation.Job.SubmitAt = now.Add(-30 * time.Minute)
	if inserted, err := store.RecordProgressEvidence(ctx, reused); err != nil || !inserted {
		t.Fatalf("reused job=%t %v", inserted, err)
	}
	items, more, err := store.ListProgressSamples(ctx, cluster, source, job, 10)
	if err != nil || more || len(items) != 3 {
		t.Fatalf("list=%+v more=%t err=%v", items, more, err)
	}
	if items[0].Observation.State != domain.ProgressUnmeasured || len(items[0].Receipts) != 1 {
		t.Fatalf("missing evidence=%+v", items[0])
	}
	var twoReceipts bool
	for _, item := range items {
		if len(item.Receipts) == 2 {
			twoReceipts = item.Receipts[0].ObservedAt.Equal(now) && item.Receipts[1].ObservedAt.Equal(now.Add(time.Second))
		}
	}
	if !twoReceipts {
		t.Fatalf("distinct run provenance absent: %+v", items)
	}
	if page, more, err := store.ListProgressSamples(ctx, cluster, source, job, 1); err != nil || !more || len(page) != 1 {
		t.Fatalf("page=%+v more=%t err=%v", page, more, err)
	}
	if rows, more, err := store.ListProgressSamples(ctx, cluster, otherSource, job, 10); err != nil || more || len(rows) != 0 {
		t.Fatalf("source leak=%+v more=%t err=%v", rows, more, err)
	}
	if rows, more, err := store.ListProgressSamples(ctx, cluster, source, reused.Observation.Job, 10); err != nil || more || len(rows) != 1 {
		t.Fatalf("job reuse=%+v more=%t err=%v", rows, more, err)
	}
	windowRows, err := store.ListProgressWindowSamples(ctx, cluster, source, job, now, now.Add(time.Second))
	if err != nil || len(windowRows) != 3 {
		t.Fatalf("bounded progress window=%+v err=%v", windowRows, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE sources SET kind='slurm' WHERE source_id=$1`, otherSource); err != nil {
		t.Fatal(err)
	}
	entities := []domain.EntityIdentity{
		{ClusterID: cluster, Kind: domain.EntityGPU, NodeID: "node-a", PhysicalGPUUUID: "GPU-a"},
		{ClusterID: cluster, Kind: domain.EntityGPU, NodeID: "node-a", PhysicalGPUUUID: "GPU-b"},
	}
	firstAllocation := domain.AllocationSnapshot{SchemaVersion: 1, ClusterID: cluster, SourceID: otherSource, Job: job,
		State: domain.AllocationRunning, SourceAt: now, EffectiveAt: now, ObservedAt: now, Entities: entities}
	secondAllocation := firstAllocation
	secondAllocation.SourceAt, secondAllocation.EffectiveAt, secondAllocation.ObservedAt = now.Add(30*time.Second), now.Add(30*time.Second), now.Add(30*time.Second)
	secondAllocation.Entities = entities[:1]
	for _, snapshot := range []domain.AllocationSnapshot{firstAllocation, secondAllocation} {
		if inserted, err := store.RecordAllocationSnapshot(ctx, snapshot); err != nil || !inserted {
			t.Fatalf("allocation inserted=%t err=%v", inserted, err)
		}
	}
	intervals, err := store.ListProgressAllocationIntervals(ctx, cluster, otherSource, source, job, now, now.Add(time.Minute))
	if err != nil || len(intervals) != 2 || intervals[0].GPUCount != 2 || intervals[1].GPUCount != 1 ||
		!intervals[0].End.Equal(now.Add(30*time.Second)) || !intervals[1].End.Equal(now.Add(time.Minute)) {
		t.Fatalf("allocation intervals=%+v err=%v", intervals, err)
	}
	foreignIntervals, err := store.ListProgressAllocationIntervals(ctx, cluster, source, source, job, now, now.Add(time.Minute))
	if err != nil || len(foreignIntervals) != 0 {
		t.Fatalf("foreign allocation intervals=%+v err=%v", foreignIntervals, err)
	}
	firstExpected := goodputInventoryRevision("progress-expected-a-"+suffix, cluster, source, now,
		[]domain.EntityIdentity{{ClusterID: cluster, Kind: domain.EntityNode, NodeID: "node-a"}, entities[0], entities[1]})
	secondExpected := goodputInventoryRevision("progress-expected-b-"+suffix, cluster, source, now.Add(30*time.Second),
		[]domain.EntityIdentity{{ClusterID: cluster, Kind: domain.EntityNode, NodeID: "node-a"}, entities[0]})
	for _, revision := range []domain.InventoryRevision{firstExpected, secondExpected} {
		if inserted, err := store.RecordExpectedInventoryRevision(ctx, revision); err != nil || !inserted {
			t.Fatalf("expected inventory inserted=%t err=%v", inserted, err)
		}
	}
	nodeJob := job
	nodeJob.JobID = "node-only"
	nodeAllocation := domain.AllocationSnapshot{SchemaVersion: 1, ClusterID: cluster, SourceID: otherSource, Job: nodeJob,
		State: domain.AllocationRunning, SourceAt: now, EffectiveAt: now, ObservedAt: now,
		Entities: []domain.EntityIdentity{{ClusterID: cluster, Kind: domain.EntityNode, NodeID: "node-a"}}}
	if inserted, err := store.RecordAllocationSnapshot(ctx, nodeAllocation); err != nil || !inserted {
		t.Fatalf("node allocation inserted=%t err=%v", inserted, err)
	}
	nodeIntervals, err := store.ListProgressAllocationIntervals(ctx, cluster, otherSource, source, nodeJob, now, now.Add(time.Minute))
	if err != nil || len(nodeIntervals) != 2 || nodeIntervals[0].GPUCount != 0 || nodeIntervals[1].GPUCount != 0 ||
		nodeIntervals[0].InventoryRevisionID != firstExpected.ID || nodeIntervals[1].InventoryRevisionID != secondExpected.ID ||
		!nodeIntervals[0].End.Equal(now.Add(30*time.Second)) || !nodeIntervals[1].Start.Equal(now.Add(30*time.Second)) {
		t.Fatalf("node-only allocation claimed GPU denominator=%+v err=%v", nodeIntervals, err)
	}
	unknownMapping, err := store.ListProgressAllocationIntervals(ctx, cluster, otherSource, otherSource, nodeJob, now, now.Add(time.Minute))
	if err != nil || len(unknownMapping) != 1 || unknownMapping[0].GPUCount != 0 {
		t.Fatalf("unqualified inventory mapping=%+v err=%v", unknownMapping, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE goodput_progress_templates SET revoked_at=clock_timestamp()
		WHERE cluster_id=$1 AND source_id=$2 AND template_id='trainer.tokens' AND template_revision=1`, cluster, source); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordProgressEvidence(ctx, evidence); err == nil {
		t.Fatal("revoked template accepted a replay")
	}
}
