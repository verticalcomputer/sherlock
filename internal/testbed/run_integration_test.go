//go:build integration

package testbed

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func labPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated migrated PostgreSQL required")
	}
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}
func TestRealControllerContextBudgetAndRestart(t *testing.T) {
	pool := labPool(t)
	suite, digest := fixture(t)
	launch := func(ctx context.Context, id domain.InvestigationID, stop int) error {
		return Worker(ctx, pool, id, stop)
	}
	report, err := Run(t.Context(), pool, suite, digest, launch, false)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed || len(report.Cases) != 8 {
		raw, _ := json.MarshalIndent(report, "", "  ")
		t.Fatal(string(raw))
	}
	for _, c := range report.Cases {
		if c.WorkerProcesses != 1 || !c.RestartContextEqual || !c.FullStatementRetained || c.HiddenTestsRetained != 4 || c.RequiredEvidenceRecall != 1 || c.AuditedCalls != 4 {
			t.Fatalf("missing runtime path: %+v", c)
		}
	}
}
func TestGraderFailsWhenDistractingEvidenceWins(t *testing.T) {
	pool := labPool(t)
	suite, digest := fixture(t)
	suite.Scenarios = suite.Scenarios[:1]
	suite.Scenarios[0].World.Question = "Why did login activity change?"
	changed, _ := json.Marshal(suite)
	digest = domain.ChecksumSHA256(changed).String()
	report, err := Run(t.Context(), pool, suite, digest, func(ctx context.Context, id domain.InvestigationID, stop int) error {
		return Worker(ctx, pool, id, stop)
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed || report.Cases[0].RequiredEvidenceRecall >= 1 {
		t.Fatalf("grader accepted lost thermal evidence: %+v", report)
	}
}
func TestWorldRejectsForeignTargetsAndWithholdsLaterEvidence(t *testing.T) {
	pool := labPool(t)
	suite, _ := fixture(t)
	if err := Setup(t.Context(), pool); err != nil {
		t.Fatal(err)
	}
	prefix := "tb-scope-" + strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	id, err := prepare(t.Context(), pool, suite.Scenarios[0], prefix)
	if err != nil {
		t.Fatal(err)
	}
	adapter := worldAdapter{pool, id}
	w := suite.Scenarios[0].World
	action := domain.InvestigationAction{ToolID: "node.detail.v1", Targets: []string{"node-1"}, Start: w.Start, End: w.End}
	result, err := adapter.ExecuteInvestigationAction(t.Context(), "not-yet", action)
	if err != nil || len(result.Evidence) != 0 {
		t.Fatalf("future result leaked: %+v %v", result, err)
	}
	action.ToolID = "evidence.lookup.v1"
	action.Targets = []string{"other-node"}
	if _, err = adapter.ExecuteInvestigationAction(t.Context(), "foreign", action); err == nil {
		t.Fatal("foreign target admitted")
	}
	action.Targets = []string{"node-1"}
	action.Start = w.Start.Add(time.Minute)
	result, err = adapter.ExecuteInvestigationAction(t.Context(), "wrong-window", action)
	if err != nil || len(result.Evidence) != 0 {
		t.Fatalf("wrong window got helpful full-window evidence: %+v %v", result, err)
	}
	action.Targets = []string{"foreign-node"}
	if _, err := adapter.ExecuteInvestigationAction(t.Context(), "wrong-window", action); err == nil {
		t.Fatal("changed action reused an execution receipt")
	}
}

func TestTelemetryIncidentInvestigationCrashRecovery(t *testing.T) {
	pool := labPool(t)
	result, err := RunPipeline(t.Context(), pool, func(ctx context.Context, prefix, boundary string) error {
		err := PipelineWorker(ctx, pool, prefix, boundary, nil)
		if boundary != "" && errors.Is(err, ErrInjectedCrash) {
			return nil
		}
		return err
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Passed || len(result.Crashes) != 6 || result.Investigation.RequiredEvidenceRecall != 1 || !result.Investigation.RestartContextEqual {
		raw, _ := json.MarshalIndent(result, "", "  ")
		t.Fatal(string(raw))
	}
}

func TestIntakeControlsCannotCreateXIDIncident(t *testing.T) {
	pool := labPool(t)
	for _, mode := range []string{"healthy", "empty", "malformed", "ambiguous"} {
		t.Run(mode, func(t *testing.T) {
			suffix, _ := (platform.RandomIDGenerator{}).NewID()
			prefix := "tb-pipeline-" + suffix
			collections, _ := storepg.NewCollectionStore(pool)
			if err := collections.EnsureSource(t.Context(), domain.ClusterID(prefix), "Control", domain.SourceID(prefix+"-source"), "Control source"); err != nil {
				t.Fatal(err)
			}
			at := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
			result, err := collectPipeline(t.Context(), prefix, at, domain.QueryGPUXID, mode)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "healthy":
				if result.Status != domain.ResultSucceeded || len(result.Observations) != 1 || result.Observations[0].Value != 0 {
					t.Fatalf("invalid control: %+v", result)
				}
			case "empty":
				if result.Status != domain.ResultNoData || len(result.Observations) != 0 {
					t.Fatalf("empty became measured: %+v", result)
				}
			case "malformed":
				if result.Status != domain.ResultFailed || len(result.Observations) != 0 {
					t.Fatalf("malformed became measured: %+v", result)
				}
			case "ambiguous":
				if result.Status != domain.ResultPartial || len(result.Observations) != 0 {
					t.Fatalf("foreign identity survived: %+v", result)
				}
			}
			if _, err := collections.RecordResult(t.Context(), result); err != nil {
				t.Fatal(err)
			}
			bridgeStore, _ := storepg.NewAnomalyBridgeStore(pool)
			invStore, _ := storepg.NewInvestigationStore(pool)
			controller, _ := application.NewInvestigationController(invStore, application.ScriptedInvestigationPlanner{}, worldAdapter{pool: pool}, clock{time.Now().UTC().Add(time.Second)}, platform.RandomIDGenerator{})
			bridge, err := application.NewAnomalyBridge(bridgeStore, controller, clock{time.Now().UTC().Add(time.Second)}, "testbed-control-v1", domain.ClusterID(prefix), pipelinePolicy())
			if err != nil {
				t.Fatal(err)
			}
			for range 10 {
				progress, err := bridge.RunOnce(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if !progress {
					break
				}
			}
			var incidents, investigations int
			if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM incidents WHERE cluster_id=$1),(SELECT count(*) FROM investigations WHERE cluster_id=$1)`, prefix).Scan(&incidents, &investigations); err != nil || incidents != 0 || investigations != 0 {
				t.Fatalf("false incident admission: incidents=%d investigations=%d err=%v", incidents, investigations, err)
			}
		})
	}
}

func TestPipelineGraderRejectsCorruptedTelemetryAndLineage(t *testing.T) {
	pool := labPool(t)
	cases := []struct{ name, boundary, sql, violation, errorText string }{
		{name: "numeric value", boundary: "telemetry_committed", sql: `UPDATE observations SET value=88 WHERE cluster_id=$1 AND metric='DCGM_FI_DEV_GPU_TEMP'`, violation: "committed telemetry differs from independent numeric oracle"},
		{name: "entity identity", boundary: "telemetry_committed", sql: `UPDATE observations SET entity_key='foreign-identity' WHERE cluster_id=$1 AND metric='DCGM_FI_DEV_GPU_TEMP'`, errorText: "entity key disagrees with identity labels"},
		{name: "incident evidence link", boundary: "start_committed", sql: `DELETE FROM incident_evidence WHERE incident_id IN (SELECT incident_id FROM incidents WHERE cluster_id=$1)`, violation: "incident, source event, evidence and automatic start lineage missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result, err := RunPipeline(t.Context(), pool, func(ctx context.Context, prefix, boundary string) error {
				err := PipelineWorker(ctx, pool, prefix, boundary, nil)
				if boundary != "" && errors.Is(err, ErrInjectedCrash) {
					if boundary == c.boundary {
						_, err := pool.Exec(ctx, c.sql, prefix)
						return err
					}
					return nil
				}
				return err
			}, false)
			if c.errorText != "" {
				if err == nil || !strings.Contains(err.Error(), c.errorText) {
					t.Fatalf("corrupt identity accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			violations := append(result.Violations, result.Investigation.Violations...)
			if result.Passed || !slices.Contains(violations, c.violation) {
				t.Fatalf("grader trusted corrupted pipeline: %+v", result)
			}
		})
	}
}

func TestPipelineRequiresObservedCrashMarker(t *testing.T) {
	pool := labPool(t)
	_, err := RunPipeline(t.Context(), pool, func(context.Context, string, string) error { return nil }, false)
	if err == nil || !strings.Contains(err.Error(), "crash marker missing") {
		t.Fatalf("clean exit counted as crash: %v", err)
	}
}
