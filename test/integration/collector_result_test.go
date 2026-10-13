//go:build integration

package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestCollectorResultChunksFinalizeIdempotently(t *testing.T) {
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
	collectionStore, _ := storepg.NewCollectionStore(pool)
	controlStore, _ := storepg.NewCollectorControlStore(pool)

	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("result-cluster-" + suffix)
	sourceID := domain.SourceID("result-source-" + suffix)
	collectorID := domain.CollectorID("result-collector-" + suffix)
	if err := collectionStore.EnsureSource(ctx, clusterID, "Result cluster", sourceID, "Result source"); err != nil {
		t.Fatal(err)
	}
	if err := controlStore.RegisterCollector(ctx, storepg.CollectorRegistration{CollectorID: collectorID, ClusterID: clusterID, DisplayName: "Result collector", Version: "0.2.0", BuildCommit: "test", ProtocolMin: 1, ProtocolMax: 1, OperatingSystem: "linux", Architecture: "amd64"}); err != nil {
		t.Fatal(err)
	}
	if err := controlStore.ReplaceCapabilities(ctx, collectorID, map[string]string{string(domain.QueryGPUUtilization): "1"}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	work := domain.CollectorWork{
		WorkID: domain.WorkID("result-work-" + suffix), Status: domain.WorkAvailable,
		AvailableAt: now.Add(-time.Second), WorkExpiresAt: now.Add(10 * time.Minute),
		Task: domain.CollectionTask{RunID: domain.RunID("result-run-" + suffix), ClusterID: clusterID, SourceID: sourceID, Query: domain.QueryGPUUtilization, ScheduledFor: now, Deadline: now.Add(5 * time.Minute), MaxSeries: 100, MaxBytes: 1 << 20, IdempotencyKey: "result/" + suffix},
	}
	if inserted, err := controlStore.EnqueueCollectionWork(ctx, work); err != nil || !inserted {
		t.Fatalf("enqueue inserted=%v err=%v", inserted, err)
	}
	lease, claimed, err := controlStore.ClaimWork(ctx, collectorID, "result-lease-token", time.Minute)
	if err != nil || !claimed {
		t.Fatalf("claim claimed=%v err=%v", claimed, err)
	}
	if err := controlStore.AcknowledgeWorkStart(ctx, collectorID, work.WorkID, lease.Attempt, lease.LeaseToken); err != nil {
		t.Fatal(err)
	}
	completed := now.Add(2 * time.Second)
	document := domain.NormalizeCollectorResultTimes(domain.CollectorResultDocument{
		SchemaVersion: domain.CollectorResultSchemaVersion, WorkID: work.WorkID, Attempt: lease.Attempt,
		Result: domain.CollectionResult{Task: work.Task, Status: domain.ResultSucceeded, StartedAt: now.Add(time.Second), CompletedAt: completed, Coverage: domain.Coverage{SeriesReturned: 1, BytesRead: 100, Complete: true}, Observations: []domain.Observation{{ID: domain.ObservationID("result-observation-" + suffix), SchemaVersion: 1, ClusterID: clusterID, SourceID: sourceID, Kind: "gpu_metric", EntityKey: "node/comp001/gpu/0", Metric: "DCGM_FI_DEV_GPU_UTIL", Labels: []domain.Label{{Name: "gpu", Value: "0"}}, Value: 42, Unit: "percent", ObservedAt: now, CollectedAt: completed, SourceReference: "prometheus:dcgm_gpu_utilization"}}},
	})
	payload, err := domain.EncodeCollectorResult(document)
	if err != nil {
		t.Fatal(err)
	}
	split := len(payload) / 2
	parts := [][]byte{payload[:split], payload[split:]}
	ref := collectorcontrol.LeaseRef{WorkID: work.WorkID, Attempt: lease.Attempt, LeaseToken: lease.LeaseToken}
	bad := collectorcontrol.ResultChunk{LeaseRef: ref, Index: 0, Payload: parts[0], SHA256: hex.EncodeToString(make([]byte, 32))}
	if _, err := controlStore.UploadResultChunk(ctx, collectorID, bad); !errors.Is(err, collectorcontrol.ErrResultConflict) {
		t.Fatalf("expected typed mismatched chunk checksum rejection, got %v", err)
	}
	for index, part := range parts {
		checksum := sha256.Sum256(part)
		chunk := collectorcontrol.ResultChunk{LeaseRef: ref, Index: index, Payload: part, SHA256: hex.EncodeToString(checksum[:])}
		outcome, err := controlStore.UploadResultChunk(ctx, collectorID, chunk)
		if err != nil || outcome.PreviouslyUploaded {
			t.Fatalf("upload %d outcome=%+v err=%v", index, outcome, err)
		}
		if index == 0 {
			outcome, err = controlStore.UploadResultChunk(ctx, collectorID, chunk)
			if err != nil || !outcome.PreviouslyUploaded {
				t.Fatalf("duplicate upload outcome=%+v err=%v", outcome, err)
			}
			conflictPayload := append([]byte(nil), part...)
			conflictPayload[0] ^= 1
			conflictHash := sha256.Sum256(conflictPayload)
			if _, err := controlStore.UploadResultChunk(ctx, collectorID, collectorcontrol.ResultChunk{LeaseRef: ref, Index: 0, Payload: conflictPayload, SHA256: hex.EncodeToString(conflictHash[:])}); err == nil {
				t.Fatal("expected conflicting duplicate chunk rejection")
			}
		}
	}
	finalChecksum := sha256.Sum256(payload)
	finalization := collectorcontrol.ResultFinalization{LeaseRef: ref, RunID: work.Task.RunID, Status: domain.ResultSucceeded, ChunkCount: len(parts), SHA256: hex.EncodeToString(finalChecksum[:]), Bytes: int64(len(payload))}
	wrong := finalization
	wrong.SHA256 = hex.EncodeToString(make([]byte, 32))
	if _, err := controlStore.FinalizeResult(ctx, collectorID, wrong); !errors.Is(err, collectorcontrol.ErrResultConflict) {
		t.Fatalf("expected typed final checksum mismatch rejection, got %v", err)
	}
	outcome, err := controlStore.FinalizeResult(ctx, collectorID, finalization)
	if err != nil || outcome.PreviouslyFinalized {
		t.Fatalf("finalize outcome=%+v err=%v", outcome, err)
	}
	outcome, err = controlStore.FinalizeResult(ctx, collectorID, finalization)
	if err != nil || !outcome.PreviouslyFinalized {
		t.Fatalf("duplicate finalize outcome=%+v err=%v", outcome, err)
	}
	loaded, found, err := controlStore.LoadFinalizedResult(ctx, work.WorkID)
	if err != nil || !found || loaded.Task.RunID != work.Task.RunID {
		t.Fatalf("load by work found=%v result=%+v err=%v", found, loaded, err)
	}
	loaded, found, err = controlStore.LoadFinalizedResultByRun(ctx, work.Task.RunID)
	if err != nil || !found || loaded.Status != domain.ResultSucceeded {
		t.Fatalf("load by run found=%v result=%+v err=%v", found, loaded, err)
	}
	var runs, observations, events, projections int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM collection_runs WHERE run_id=$1), (SELECT count(*) FROM observations WHERE run_id=$1), (SELECT count(*) FROM collection_events WHERE run_id=$1), (SELECT count(*) FROM current_projections WHERE observation_id=$2)`, work.Task.RunID, document.Result.Observations[0].ID).Scan(&runs, &observations, &events, &projections); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || observations != 1 || events != 1 || projections != 1 {
		t.Fatalf("duplicate projection persistence runs=%d observations=%d events=%d projections=%d", runs, observations, events, projections)
	}

	// A changed request after finalization fails closed.
	changed := finalization
	changed.Bytes++
	if _, err := controlStore.FinalizeResult(ctx, collectorID, changed); err == nil {
		t.Fatal("expected conflicting post-finalization request rejection")
	}
}

func TestCollectorResultRejectsStaleAttempt(t *testing.T) {
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
	collectionStore, _ := storepg.NewCollectionStore(pool)
	controlStore, _ := storepg.NewCollectorControlStore(pool)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID, sourceID, collectorID := domain.ClusterID("stale-cluster-"+suffix), domain.SourceID("stale-source-"+suffix), domain.CollectorID("stale-collector-"+suffix)
	if err := collectionStore.EnsureSource(ctx, clusterID, "Stale cluster", sourceID, "Stale source"); err != nil {
		t.Fatal(err)
	}
	if err := controlStore.RegisterCollector(ctx, storepg.CollectorRegistration{CollectorID: collectorID, ClusterID: clusterID, DisplayName: "Stale collector", Version: "0.2.0", BuildCommit: "test", ProtocolMin: 1, ProtocolMax: 1, OperatingSystem: "linux", Architecture: "amd64"}); err != nil {
		t.Fatal(err)
	}
	if err := controlStore.ReplaceCapabilities(ctx, collectorID, map[string]string{string(domain.QuerySourceHealth): "1"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	work := domain.CollectorWork{WorkID: domain.WorkID("stale-work-" + suffix), Status: domain.WorkAvailable, AvailableAt: now.Add(-time.Second), WorkExpiresAt: now.Add(time.Minute), Task: domain.CollectionTask{RunID: domain.RunID("stale-run-" + suffix), ClusterID: clusterID, SourceID: sourceID, Query: domain.QuerySourceHealth, ScheduledFor: now, Deadline: now.Add(time.Minute), MaxSeries: 10, MaxBytes: 1024, IdempotencyKey: "stale/" + suffix}}
	if inserted, err := controlStore.EnqueueCollectionWork(ctx, work); err != nil || !inserted {
		t.Fatalf("enqueue inserted=%v err=%v", inserted, err)
	}
	first, claimed, err := controlStore.ClaimWork(ctx, collectorID, "stale-token-one", time.Minute)
	if err != nil || !claimed {
		t.Fatalf("claim one claimed=%v err=%v", claimed, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE collector_work_attempts SET claimed_at=clock_timestamp()-interval '2 minutes', lease_expires_at=clock_timestamp()-interval '1 second' WHERE work_id=$1 AND attempt=1`, work.WorkID); err != nil {
		t.Fatal(err)
	}
	second, claimed, err := controlStore.ClaimWork(ctx, collectorID, "stale-token-two", time.Minute)
	if err != nil || !claimed || second.Attempt != 2 {
		t.Fatalf("claim two lease=%+v claimed=%v err=%v", second, claimed, err)
	}
	payload := []byte("x")
	checksum := sha256.Sum256(payload)
	if _, err := controlStore.UploadResultChunk(ctx, collectorID, collectorcontrol.ResultChunk{LeaseRef: collectorcontrol.LeaseRef{WorkID: work.WorkID, Attempt: first.Attempt, LeaseToken: first.LeaseToken}, Index: 0, Payload: payload, SHA256: hex.EncodeToString(checksum[:])}); !errors.Is(err, collectorcontrol.ErrWorkLeaseInvalid) {
		t.Fatalf("expected typed stale attempt upload rejection, got %v", err)
	}
}
