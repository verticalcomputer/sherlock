//go:build integration

package testbed

import (
	"context"
	"encoding/json"
	"os"
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
}
