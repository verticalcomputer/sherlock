//go:build integration

package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestCollectorWorkLeaseExpiresAndRetriesWithoutDuplicateClaim(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	collectionStore, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	controlStore, err := storepg.NewCollectorControlStore(pool)
	if err != nil {
		t.Fatal(err)
	}

	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("collector-cluster-" + suffix)
	sourceID := domain.SourceID("collector-source-" + suffix)
	collectorID := domain.CollectorID("collector-" + suffix)
	if err := collectionStore.EnsureSource(ctx, clusterID, "Collector integration cluster", sourceID, "Collector Prometheus"); err != nil {
		t.Fatal(err)
	}
	if err := controlStore.RegisterCollector(ctx, storepg.CollectorRegistration{
		CollectorID: collectorID, ClusterID: clusterID, DisplayName: "Integration collector",
		Version: "0.2.0-test", BuildCommit: "test", ProtocolMin: 1, ProtocolMax: 1,
		OperatingSystem: "linux", Architecture: "amd64",
	}); err != nil {
		t.Fatal(err)
	}
	if err := controlStore.ReplaceCapabilities(ctx, collectorID, map[string]string{string(domain.QuerySourceHealth): "1"}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	work := domain.CollectorWork{
		WorkID: "work-" + domain.WorkID(suffix), Status: domain.WorkAvailable,
		AvailableAt: now.Add(-time.Second), WorkExpiresAt: now.Add(10 * time.Minute),
		Task: domain.CollectionTask{
			RunID: "run-" + domain.RunID(suffix), ClusterID: clusterID, SourceID: sourceID,
			Query: domain.QuerySourceHealth, ScheduledFor: now, Deadline: now.Add(5 * time.Minute),
			MaxSeries: 10_000, MaxBytes: 10 << 20, IdempotencyKey: "collector-integration/" + suffix,
		},
	}
	inserted, err := controlStore.EnqueueCollectionWork(ctx, work)
	if err != nil || !inserted {
		t.Fatalf("enqueue inserted=%v err=%v", inserted, err)
	}
	duplicate := work
	duplicate.WorkID = "duplicate-" + work.WorkID
	duplicate.Task.RunID = "duplicate-" + work.Task.RunID
	if inserted, err := controlStore.EnqueueCollectionWork(ctx, duplicate); err != nil || inserted {
		t.Fatalf("duplicate enqueue inserted=%v err=%v", inserted, err)
	}

	first, claimed, err := controlStore.ClaimWork(ctx, collectorID, "lease-token-one", time.Minute)
	if err != nil || !claimed {
		t.Fatalf("first claim claimed=%v err=%v", claimed, err)
	}
	if first.Work.WorkID != work.WorkID || first.Attempt != 1 || first.Work.Status != domain.WorkLeased {
		t.Fatalf("unexpected first lease: %+v", first)
	}
	if _, claimed, err := controlStore.ClaimWork(ctx, collectorID, "parallel-token", time.Minute); err != nil || claimed {
		t.Fatalf("parallel claim claimed=%v err=%v", claimed, err)
	}
	if err := controlStore.AcknowledgeWorkStart(ctx, collectorID, work.WorkID, 1, "wrong-token"); err == nil {
		t.Fatal("expected the wrong lease token to be rejected")
	}
	if err := controlStore.AcknowledgeWorkStart(ctx, collectorID, work.WorkID, 1, "lease-token-one"); err != nil {
		t.Fatal(err)
	}
	if err := controlStore.AcknowledgeWorkStart(ctx, collectorID, work.WorkID, 1, "lease-token-one"); err != nil {
		t.Fatalf("duplicate start acknowledgement was not idempotent: %v", err)
	}
	if err := controlStore.RenewWorkLease(ctx, collectorID, work.WorkID, 1, "lease-token-one", 90*time.Second); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, `
		UPDATE collector_work_attempts
		SET claimed_at=clock_timestamp() - interval '2 minutes',
		    started_at=clock_timestamp() - interval '119 seconds',
		    lease_expires_at=clock_timestamp() - interval '1 second'
		WHERE work_id=$1 AND attempt=1`, work.WorkID); err != nil {
		t.Fatal(err)
	}
	second, claimed, err := controlStore.ClaimWork(ctx, collectorID, "lease-token-two", time.Minute)
	if err != nil || !claimed {
		t.Fatalf("retry claim claimed=%v err=%v", claimed, err)
	}
	if second.Work.WorkID != work.WorkID || second.Attempt != 2 {
		t.Fatalf("unexpected retry lease: %+v", second)
	}
	if err := controlStore.RenewWorkLease(ctx, collectorID, work.WorkID, 1, "lease-token-one", time.Minute); err == nil {
		t.Fatal("expected the expired attempt to reject renewal")
	}
	var firstStatus domain.AttemptStatus
	if err := pool.QueryRow(ctx, `SELECT status FROM collector_work_attempts WHERE work_id=$1 AND attempt=1`, work.WorkID).Scan(&firstStatus); err != nil {
		t.Fatal(err)
	}
	if firstStatus != domain.AttemptExpired {
		t.Fatalf("first attempt status=%s", firstStatus)
	}
}
