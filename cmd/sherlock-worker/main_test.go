package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	clientprom "github.com/prometheus/client_golang/prometheus"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

type scheduledJobStoreFake struct {
	bindErrors     map[string]error
	completeErrors map[string]error
	completed      []string
}

func (s *scheduledJobStoreFake) BindCollectionJob(_ context.Context, job storepg.ClaimedJob, _ string, _ domain.RunID) (domain.RunID, error) {
	return domain.RunID("canonical-" + job.JobID), s.bindErrors[job.JobID]
}
func (s *scheduledJobStoreFake) CompleteJob(_ context.Context, job storepg.ClaimedJob, _ string) error {
	s.completed = append(s.completed, job.JobID)
	return s.completeErrors[job.JobID]
}

func TestScheduledWorkerContinuesAfterSupersededClaims(t *testing.T) {
	for _, phase := range []string{"binding", "completion"} {
		t.Run(phase, func(t *testing.T) {
			store := &scheduledJobStoreFake{bindErrors: map[string]error{}, completeErrors: map[string]error{}}
			superseded := fmt.Errorf("revised configuration: %w", storepg.ErrCollectionClaimSuperseded)
			if phase == "binding" {
				store.bindErrors["old"] = superseded
			} else {
				store.completeErrors["old"] = superseded
			}
			var collected []domain.RunID
			for _, id := range []string{"old", "other"} {
				completed, err := processScheduledJob(context.Background(), store, storepg.ClaimedJob{JobID: id}, "owner", domain.CollectionTask{RunID: domain.RunID(id)}, func(_ context.Context, task domain.CollectionTask) error {
					collected = append(collected, task.RunID)
					return nil
				})
				if err != nil || completed != (id == "other") {
					t.Fatalf("%s processing stopped scheduler: completed=%v err=%v", id, completed, err)
				}
			}
			want := 1
			if phase == "completion" {
				want = 2
			}
			if len(collected) != want || collected[len(collected)-1] != "canonical-other" {
				t.Fatalf("subsequent work was not collected: %v", collected)
			}
			if store.completed[len(store.completed)-1] != "other" {
				t.Fatalf("subsequent work was not completed: %v", store.completed)
			}
		})
	}
}

func TestScheduledWorkerPreservesOperationalErrors(t *testing.T) {
	operational := errors.New("database unavailable")
	for _, phase := range []string{"binding", "completion"} {
		t.Run(phase, func(t *testing.T) {
			store := &scheduledJobStoreFake{bindErrors: map[string]error{}, completeErrors: map[string]error{}}
			if phase == "binding" {
				store.bindErrors["job"] = operational
			} else {
				store.completeErrors["job"] = operational
			}
			if _, err := processScheduledJob(context.Background(), store, storepg.ClaimedJob{JobID: "job"}, "owner", domain.CollectionTask{}, func(context.Context, domain.CollectionTask) error { return nil }); !errors.Is(err, operational) {
				t.Fatalf("operational error swallowed: %v", err)
			}
		})
	}
}

func TestPeriodicMaintenanceIsAsynchronousAndJoinsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	ready := make(chan struct{})
	var done <-chan struct{}
	go func() {
		done = startPeriodicMaintenance(ctx, defaultMaintenancePolicy(time.Hour), "retention", newMaintenanceMetrics(clientprom.NewRegistry()), slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)), func(ctx context.Context) error {
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		})
		close(ready)
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("slow maintenance blocked worker startup")
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("maintenance did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("maintenance did not join after cancellation")
	}
}

func TestScheduledCollectionTaskUsesPersistedBounds(t *testing.T) {
	now := time.Now().UTC()
	cfg := config.Worker{QueryTimeout: time.Second, MaxSeries: 100, MaxBytes: 1000}
	job := storepg.ClaimedJob{JobID: "job", ClusterID: "cluster", SourceID: "source", Query: domain.QueryGPUXID, ScheduledFor: now.Add(-time.Minute), ConfigurationRevision: 9, DesiredRevision: 3, Timeout: 5 * time.Second, MaxTargets: 7, MaxBytes: 256}
	task := scheduledCollectionTask(job, cfg, "run", now)
	if task.Deadline != now.Add(5*time.Second) || task.MaxSeries != 7 || task.MaxBytes != 256 || task.ClusterID != job.ClusterID || task.SourceID != job.SourceID || task.ScheduledFor != job.ScheduledFor || !strings.HasSuffix(task.IdempotencyKey, "/config/9") {
		t.Fatalf("persisted task: %+v", task)
	}
	job.DesiredRevision = 0
	task = scheduledCollectionTask(job, cfg, "run", now)
	if task.Deadline != now.Add(time.Second) || task.MaxSeries != 100 || task.MaxBytes != 1000 {
		t.Fatalf("legacy fallback: %+v", task)
	}
}

type artifactReconciliationRunnerFake struct {
	result application.ArtifactReconciliationResult
	err    error
}

type anomalyBridgeRunnerFake struct {
	progressed bool
	err        error
}

func (fake anomalyBridgeRunnerFake) RunOnce(context.Context) (bool, error) {
	return fake.progressed, fake.err
}

func TestScheduledQueriesIncludePrometheusXIDEvidence(t *testing.T) {
	queries := scheduledQueries()
	if len(queries) != 4 || queries[1] != domain.QueryGPUIdentity || queries[3] != domain.QueryGPUXID {
		t.Fatalf("scheduled queries=%v", queries)
	}
}

func TestScheduledJobIDsAreScopedBySource(t *testing.T) {
	first := scheduledJobID("prometheus-a", domain.QueryGPUUtilization)
	second := scheduledJobID("prometheus-b", domain.QueryGPUUtilization)
	if first == second || first != "m1/prometheus-a/dcgm_gpu_utilization" {
		t.Fatalf("scheduled job IDs are not source scoped: %q %q", first, second)
	}
}

func (fake artifactReconciliationRunnerFake) Run(context.Context, time.Time) (application.ArtifactReconciliationResult, error) {
	return fake.result, fake.err
}

func TestReconcileArtifactsContainsTransientFailure(t *testing.T) {
	metric := clientprom.NewCounterVec(clientprom.CounterOpts{Name: "test_artifact_reconciliation_total", Help: "test"}, []string{"condition"})
	registry := clientprom.NewRegistry()
	if err := registry.Register(metric); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	rt := runtime{
		logger:     slog.New(slog.NewJSONHandler(&logs, nil)),
		reconciled: metric,
		reconciler: artifactReconciliationRunnerFake{
			result: application.ArtifactReconciliationResult{Checked: 1, Available: 1, Failures: 1},
			err:    errors.New("secret/backend/path: temporary failure"),
		},
	}

	if err := rt.reconcileArtifacts(context.Background()); !errors.Is(err, errArtifactReconciliation) {
		t.Fatalf("transient reconciliation was not exposed to supervisor: %v", err)
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(families) != 1 {
		t.Fatalf("unexpected reconciliation metric families: %+v", families)
	}
	foundFailure := false
	for _, sample := range families[0].Metric {
		if len(sample.Label) == 1 && sample.Label[0].GetValue() == "FAILED" && sample.Counter.GetValue() == 1 {
			foundFailure = true
		}
	}
	if !foundFailure {
		t.Fatalf("FAILED metric was not incremented: %+v", families[0].Metric)
	}
	if strings.Contains(logs.String(), "secret/backend/path") || !strings.Contains(logs.String(), "artifact_reconciliation.failed") {
		t.Fatalf("unsafe or missing reconciliation failure log: %s", logs.String())
	}
}

func TestReconcileArtifactsSkipsDisabledReconciler(t *testing.T) {
	rt := runtime{}
	if err := rt.reconcileArtifacts(context.Background()); err != nil {
		t.Fatalf("disabled reconciliation returned error: %v", err)
	}
}

func TestReconcileArtifactsPropagatesSchedulerCancellation(t *testing.T) {
	metric := clientprom.NewCounterVec(clientprom.CounterOpts{Name: "test_artifact_reconciliation_canceled_total", Help: "test"}, []string{"condition"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt := runtime{
		logger:     slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)),
		reconciled: metric,
		reconciler: artifactReconciliationRunnerFake{result: application.ArtifactReconciliationResult{}, err: context.Canceled},
	}

	if err := rt.reconcileArtifacts(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
}

func TestAnomalyBridgeFailureDoesNotStopWorkerOrLeakError(t *testing.T) {
	var logs bytes.Buffer
	rt := runtime{logger: slog.New(slog.NewJSONHandler(&logs, nil)), anomalies: anomalyBridgeRunnerFake{progressed: true, err: errors.New("provider secret at /private/path")}}
	progressed, err := rt.reconcileAnomaliesOnce(context.Background())
	if err != nil || !progressed {
		t.Fatalf("progressed=%t err=%v", progressed, err)
	}
	if strings.Contains(logs.String(), "provider secret") || !strings.Contains(logs.String(), "ANOMALY_BRIDGE_FAILED") {
		t.Fatalf("unsafe anomaly log: %s", logs.String())
	}
}
