//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestInvestigationPostgresResumeAndPrivilegedReplay(t *testing.T) {
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
	collections, _ := storepg.NewCollectionStore(pool)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("m6-cluster-" + suffix)
	if err := collections.EnsureSource(ctx, clusterID, "M6 cluster", domain.SourceID("m6-source-"+suffix), "M6 source"); err != nil {
		t.Fatal(err)
	}
	incidentID := domain.IncidentID("m6-incident-" + suffix)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO incidents (incident_id,cluster_id,title,severity,status,created_by,created_at,updated_at) VALUES ($1,$2,'Synthetic M6 incident','HIGH','OPEN','test',$3,$3)`, incidentID, clusterID, now); err != nil {
		t.Fatal(err)
	}
	store, err := storepg.NewInvestigationStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	action := domain.InvestigationAction{ID: domain.InvestigationActionID("m6-action-" + suffix), ToolID: "node.gpu_snapshot.v1", Digest: domain.ChecksumSHA256([]byte(suffix)), Privileged: true, FanOut: 1, Targets: []string{"node-1"}, Start: now.Add(-time.Hour), End: now, Arguments: []domain.InvestigationArgument{{Name: "detail", Kind: "STRING", String: "summary"}}}
	executor := &integrationIdempotentExecutor{results: map[string]application.InvestigationExecutionResult{}}
	clock := &integrationClock{now: now}
	request := domain.InvestigationRequest{ID: domain.InvestigationID("m6-investigation-" + suffix), IncidentID: incidentID, ClusterID: clusterID, Question: "Why is the synthetic node unhealthy?", RequestedBy: "test", IdempotencyKey: "m6-key-" + suffix, Scope: domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Hour), End: now}, SuccessCriteria: []string{"finish deterministically"}, Budget: domain.InvestigationBudget{MaxDecisions: 4, MaxToolCalls: 2, MaxPrivilegedCalls: 1, MaxFanOut: 2}, RequestedAt: now, Deadline: now.Add(time.Hour)}
	hypothesis := domain.Hypothesis{ID: "m9-hypothesis-" + domain.HypothesisID(suffix), InvestigationID: request.ID, Statement: "The synthetic cause remains unresolved.", Status: domain.HypothesisUnresolved, Confidence: 0.2, UnresolvedTests: []string{"Collect the bounded GPU snapshot."}, Version: 1}
	planner := &integrationSynthPlanner{ScriptedInvestigationPlanner: application.ScriptedInvestigationPlanner{Decisions: []application.InvestigationDecision{{Action: &action, Hypotheses: []domain.Hypothesis{hypothesis}}, {Stop: true, Outcome: domain.InvestigationCompleted, Reason: domain.StopSuccessCriteriaMet}}}}
	controller, _ := application.NewInvestigationController(store, planner, executor, clock, platform.RandomIDGenerator{})
	if _, created, err := controller.Start(ctx, application.StartInvestigationInput{Request: request}); err != nil || !created {
		t.Fatalf("start created=%t err=%v", created, err)
	}
	crashStore := &failAfterExecutionStore{InvestigationStore: store}
	for attempts := 0; attempts < 30; attempts++ {
		snapshot, found, err := store.LoadInvestigation(ctx, request.ID)
		if err != nil || !found {
			t.Fatalf("load found=%t err=%v", found, err)
		}
		if snapshot.Investigation.Status().Terminal() {
			if snapshot.Investigation.Status() != domain.InvestigationCompleted {
				t.Fatalf("status=%s", snapshot.Investigation.Status())
			}
			if executor.sideEffects != 1 || executor.calls != 2 {
				t.Fatalf("calls=%d side_effects=%d", executor.calls, executor.sideEffects)
			}
			if len(executor.observed.Targets) != 1 || executor.observed.Targets[0] != "node-1" || len(executor.observed.Arguments) != 1 {
				t.Fatalf("durable typed action=%+v", executor.observed)
			}
			if len(snapshot.Findings) != 1 || snapshot.Findings[0].Kind != domain.FindingRecommendation {
				t.Fatalf("durable synthesis findings=%+v", snapshot.Findings)
			}
			if hypotheses := snapshot.Hypotheses.Entries(); len(hypotheses) != 1 || hypotheses[0].ID != hypothesis.ID || hypotheses[0].Version != 1 {
				t.Fatalf("durable planner hypotheses=%+v", hypotheses)
			}
			var events int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM investigation_events WHERE investigation_id=$1`, request.ID).Scan(&events); err != nil {
				t.Fatal(err)
			}
			if events < 9 {
				t.Fatalf("events=%d", events)
			}
			audits, err := storepg.NewModelCallAuditStore(pool)
			if err != nil {
				t.Fatal(err)
			}
			audit := application.ModelCallAudit{
				CallID: "m7-call-" + suffix, CallKey: "investigation/" + string(request.ID) + "/plan/1",
				InvestigationID: request.ID, ClusterID: clusterID, Kind: application.ModelCallPlanning,
				Provider: "fixture", Model: "planner-v1", ModelConfigVersion: "config-v1",
				PromptSchemaVersion: "prompt-v1", ToolSchemaVersion: "tools-v1",
				InputTokens: 12, OutputTokens: 4, CostMicros: 3, Latency: 2 * time.Millisecond,
				Outcome: application.ModelCallSucceeded, OccurredAt: clock.Now(),
			}
			if err := audits.AppendModelCallAudit(ctx, audit); err != nil {
				t.Fatal(err)
			}
			if err := audits.AppendModelCallAudit(ctx, audit); err != nil {
				t.Fatal(err)
			}
			var modelCalls int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM investigation_model_calls WHERE investigation_id=$1`, request.ID).Scan(&modelCalls); err != nil || modelCalls != 1 {
				t.Fatalf("model call audit count=%d err=%v", modelCalls, err)
			}
			return
		}
		controllerStore := application.InvestigationStore(store)
		simulateCrash := snapshot.Investigation.Status() == domain.InvestigationExecuting && !crashStore.failed
		if simulateCrash {
			controllerStore = crashStore
		}
		controller, err = application.NewInvestigationController(controllerStore, planner, executor, clock, platform.RandomIDGenerator{})
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Investigation.Status() == domain.InvestigationAwaitingApproval {
			pending, _ := snapshot.Investigation.PendingAction()
			approval := domain.InvestigationApproval{ID: domain.InvestigationApprovalID("m6-approval-" + suffix), InvestigationID: request.ID, ActionID: pending.ID, ActionDigest: pending.Digest, InvestigationVersion: snapshot.Investigation.Version(), ApprovedBy: "operator", ApprovedAt: clock.Now(), ExpiresAt: clock.Now().Add(5 * time.Minute)}
			if _, err := controller.Approve(ctx, request.ID, approval); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if _, err := controller.Advance(ctx, request.ID); err != nil {
			if simulateCrash && crashStore.failed {
				continue
			}
			t.Fatal(err)
		}
	}
	t.Fatal("investigation did not complete")
}

func TestInvestigationPostgresRestartDowngradesIncompleteRequestedSuccess(t *testing.T) {
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
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	now := time.Now().UTC().Truncate(time.Microsecond)
	clusterID := domain.ClusterID("m95-cluster-" + suffix)
	collections, _ := storepg.NewCollectionStore(pool)
	if err := collections.EnsureSource(ctx, clusterID, "M9.5 cluster", domain.SourceID("m95-source-"+suffix), "M9.5 source"); err != nil {
		t.Fatal(err)
	}
	incidentID := domain.IncidentID("m95-incident-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO incidents (incident_id,cluster_id,title,severity,status,created_by,created_at,updated_at) VALUES ($1,$2,'Synthetic M9.5 incident','HIGH','OPEN','test',$3,$3)`, incidentID, clusterID, now); err != nil {
		t.Fatal(err)
	}
	store, err := storepg.NewInvestigationStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	request := domain.InvestigationRequest{ID: domain.InvestigationID("m95-investigation-" + suffix), IncidentID: incidentID, ClusterID: clusterID, Question: "Is the bounded report complete?", RequestedBy: "test", IdempotencyKey: "m95-key-" + suffix, Scope: domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Hour), End: now}, SuccessCriteria: []string{"produce a fully validated report"}, Budget: domain.InvestigationBudget{MaxDecisions: 2, MaxToolCalls: 1, MaxFanOut: 1}, RequestedAt: now, Deadline: now.Add(time.Hour)}
	planner := &integrationDispositionPlanner{ScriptedInvestigationPlanner: application.ScriptedInvestigationPlanner{Decisions: []application.InvestigationDecision{{Stop: true, Outcome: domain.InvestigationCompleted, Reason: domain.StopSuccessCriteriaMet}}}, disposition: application.SynthesisValidatedPartial}
	clock := &integrationClock{now: now}
	controller, err := application.NewInvestigationController(store, planner, &integrationIdempotentExecutor{results: map[string]application.InvestigationExecutionResult{}}, clock, platform.RandomIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := controller.Start(ctx, application.StartInvestigationInput{Request: request}); err != nil || !created {
		t.Fatalf("start created=%t err=%v", created, err)
	}
	for {
		snapshot, found, err := store.LoadInvestigation(ctx, request.ID)
		if err != nil || !found {
			t.Fatalf("load found=%t err=%v", found, err)
		}
		if snapshot.Investigation.Status() == domain.InvestigationSynthesizing {
			if snapshot.RequestedOutcome != domain.InvestigationCompleted || snapshot.RequestedStop != domain.StopSuccessCriteriaMet {
				t.Fatalf("requested terminal was not durable: %s/%s", snapshot.RequestedOutcome, snapshot.RequestedStop)
			}
			break
		}
		if _, err := controller.Advance(ctx, request.ID); err != nil {
			t.Fatal(err)
		}
	}
	// Reconstruct the controller at the durable synthesis boundary. The model's
	// incomplete report must not inherit the planner's requested success.
	controller, err = application.NewInvestigationController(store, planner, &integrationIdempotentExecutor{results: map[string]application.InvestigationExecutionResult{}}, clock, platform.RandomIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := controller.Advance(ctx, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Investigation.Status() != domain.InvestigationPartial || snapshot.Investigation.StopReason() != domain.StopNoUsefulAction {
		t.Fatalf("restart terminal=%s/%s", snapshot.Investigation.Status(), snapshot.Investigation.StopReason())
	}
}

type integrationSynthPlanner struct {
	application.ScriptedInvestigationPlanner
}

type integrationDispositionPlanner struct {
	application.ScriptedInvestigationPlanner
	disposition application.InvestigationSynthesisDisposition
}

func (planner *integrationDispositionPlanner) Synthesize(_ context.Context, snapshot application.InvestigationSnapshot) (application.InvestigationSynthesis, error) {
	return application.InvestigationSynthesis{Disposition: planner.disposition, Findings: []domain.Finding{{ID: domain.FindingID("m95-finding-" + string(snapshot.Investigation.Request().ID)), InvestigationID: snapshot.Investigation.Request().ID, Kind: domain.FindingRecommendation, Statement: "Collect additional bounded evidence before claiming completion.", EntityIDs: []string{"node-1"}, Severity: "INFO", Status: domain.FindingCurrent}}}, nil
}

func (*integrationSynthPlanner) Synthesize(_ context.Context, snapshot application.InvestigationSnapshot) (application.InvestigationSynthesis, error) {
	return application.InvestigationSynthesis{Disposition: application.SynthesisValidatedComplete, Findings: []domain.Finding{{ID: domain.FindingID("m7-finding-" + string(snapshot.Investigation.Request().ID)), InvestigationID: snapshot.Investigation.Request().ID, Kind: domain.FindingRecommendation, Statement: "Continue operator review.", EntityIDs: []string{"node-1"}, Severity: "INFO", Status: domain.FindingCurrent}}}, nil
}

type integrationClock struct{ now time.Time }

func (c *integrationClock) Now() time.Time { c.now = c.now.Add(time.Second); return c.now }

type integrationIdempotentExecutor struct {
	calls, sideEffects int
	results            map[string]application.InvestigationExecutionResult
	observed           domain.InvestigationAction
}

func (e *integrationIdempotentExecutor) ExecuteInvestigationAction(_ context.Context, key string, action domain.InvestigationAction) (application.InvestigationExecutionResult, error) {
	e.calls++
	e.observed = action
	if result, ok := e.results[key]; ok {
		return result, nil
	}
	e.sideEffects++
	result := application.InvestigationExecutionResult{Receipt: "receipt-" + key}
	e.results[key] = result
	return result, nil
}

type failAfterExecutionStore struct {
	*storepg.InvestigationStore
	failed bool
}

func (s *failAfterExecutionStore) SaveInvestigation(_ context.Context, _ int, _ application.InvestigationSnapshot, _ domain.InvestigationEvent) error {
	s.failed = true
	return context.Canceled
}

// The diagnostic grant is authority, so it must survive the round trip exactly
// and must default to refusing execution for any row written before M12.
func TestInvestigationDiagnosticBudgetRoundTripsAndDefaultsToZero(t *testing.T) {
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
	collections, _ := storepg.NewCollectionStore(pool)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("m12-cluster-" + suffix)
	if err := collections.EnsureSource(ctx, clusterID, "M12 cluster", domain.SourceID("m12-source-"+suffix), "M12 source"); err != nil {
		t.Fatal(err)
	}
	incidentID := domain.IncidentID("m12-incident-" + suffix)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO incidents (incident_id,cluster_id,title,severity,status,created_by,created_at,updated_at) VALUES ($1,$2,'Synthetic M12 incident','HIGH','OPEN','test',$3,$3)`, incidentID, clusterID, now); err != nil {
		t.Fatal(err)
	}
	store, err := storepg.NewInvestigationStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	newRequest := func(id, key string, budget domain.InvestigationBudget) domain.InvestigationRequest {
		return domain.InvestigationRequest{ID: domain.InvestigationID(id), IncidentID: incidentID, ClusterID: clusterID, Question: "Is the ECC fault contained or degrading?", RequestedBy: "test", IdempotencyKey: key, Scope: domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Hour), End: now}, SuccessCriteria: []string{"finish deterministically"}, Budget: budget, RequestedAt: now, Deadline: now.Add(time.Hour)}
	}
	executor := &integrationIdempotentExecutor{results: map[string]application.InvestigationExecutionResult{}}
	clock := &integrationClock{now: now}
	planner := &application.ScriptedInvestigationPlanner{Decisions: []application.InvestigationDecision{{Stop: true, Outcome: domain.InvestigationCompleted, Reason: domain.StopSuccessCriteriaMet}}}
	controller, _ := application.NewInvestigationController(store, planner, executor, clock, platform.RandomIDGenerator{})

	granted := newRequest("m12-granted-"+suffix, "m12-granted-key-"+suffix, domain.InvestigationBudget{MaxDecisions: 4, MaxToolCalls: 2, MaxDiagnosticCalls: 3, MaxFanOut: 2, MaxModelTokens: 1000, MaxCostMicros: 1000})
	if _, created, err := controller.Start(ctx, application.StartInvestigationInput{Request: granted}); err != nil || !created {
		t.Fatalf("start granted created=%t err=%v", created, err)
	}
	snapshot, found, err := store.LoadInvestigation(ctx, granted.ID)
	if err != nil || !found {
		t.Fatalf("load granted found=%t err=%v", found, err)
	}
	if got := snapshot.Investigation.Request().Budget.MaxDiagnosticCalls; got != 3 {
		t.Fatalf("MaxDiagnosticCalls did not survive persistence: got %d, want 3", got)
	}
	if got := snapshot.Investigation.Usage().DiagnosticCalls; got != 0 {
		t.Fatalf("a new investigation must start with no diagnostic usage: got %d", got)
	}

	// An investigation started without naming the dimension carries no
	// execution authority at all, which is what keeps every recorded baseline
	// behaving exactly as before.
	ungranted := newRequest("m12-ungranted-"+suffix, "m12-ungranted-key-"+suffix, domain.InvestigationBudget{MaxDecisions: 4, MaxToolCalls: 2, MaxFanOut: 2, MaxModelTokens: 1000, MaxCostMicros: 1000})
	if _, created, err := controller.Start(ctx, application.StartInvestigationInput{Request: ungranted}); err != nil || !created {
		t.Fatalf("start ungranted created=%t err=%v", created, err)
	}
	snapshot, found, err = store.LoadInvestigation(ctx, ungranted.ID)
	if err != nil || !found {
		t.Fatalf("load ungranted found=%t err=%v", found, err)
	}
	if got := snapshot.Investigation.Request().Budget.MaxDiagnosticCalls; got != 0 {
		t.Fatalf("an unnamed diagnostic budget must load as zero: got %d", got)
	}
	if snapshot.Investigation.Request().Budget.Allows(domain.InvestigationBudgetUsage{DiagnosticCalls: 1}) {
		t.Fatal("an investigation started without a diagnostic grant must refuse every diagnostic")
	}

	// Recorded usage must persist independently of the tool-call dimension.
	if _, err := pool.Exec(ctx, `UPDATE investigation_budgets SET used_diagnostic_calls=2 WHERE investigation_id=$1`, granted.ID); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err = store.LoadInvestigation(ctx, granted.ID)
	if err != nil {
		t.Fatal(err)
	}
	usage := snapshot.Investigation.Usage()
	if usage.DiagnosticCalls != 2 || usage.ToolCalls != 0 {
		t.Fatalf("usage did not round trip independently: diagnostic=%d tool=%d", usage.DiagnosticCalls, usage.ToolCalls)
	}
	// The database is the last line of the same invariant the domain enforces.
	if _, err := pool.Exec(ctx, `UPDATE investigation_budgets SET used_diagnostic_calls=4 WHERE investigation_id=$1`, granted.ID); err == nil {
		t.Fatal("the database must refuse diagnostic usage above the granted limit")
	}

	// The operation class must survive a restart: an action reconstituted as a
	// read would be charged to the wrong grant when it is later approved.
	awaiting := newRequest("m12-awaiting-"+suffix, "m12-awaiting-key-"+suffix, domain.InvestigationBudget{MaxDecisions: 4, MaxToolCalls: 2, MaxDiagnosticCalls: 1, MaxPrivilegedCalls: 1, MaxFanOut: 2, MaxModelTokens: 1000, MaxCostMicros: 1000})
	diagnostic := domain.InvestigationAction{ID: domain.InvestigationActionID("m12-action-" + suffix), ToolID: "gpu.ecc_counters.v1", Digest: domain.ChecksumSHA256([]byte("m12-" + suffix)), Diagnostic: true, Privileged: true, FanOut: 1, Targets: []string{"node-1"}, Start: now.Add(-time.Hour), End: now, Arguments: []domain.InvestigationArgument{{Name: "detail", Kind: "STRING", String: "ecc"}}}
	awaitingPlanner := &application.ScriptedInvestigationPlanner{Decisions: []application.InvestigationDecision{{Action: &diagnostic}, {Stop: true, Outcome: domain.InvestigationCompleted, Reason: domain.StopSuccessCriteriaMet}}}
	awaitingController, _ := application.NewInvestigationController(store, awaitingPlanner, executor, clock, platform.RandomIDGenerator{})
	if _, created, err := awaitingController.Start(ctx, application.StartInvestigationInput{Request: awaiting}); err != nil || !created {
		t.Fatalf("start awaiting created=%t err=%v", created, err)
	}
	for attempts := 0; attempts < 10; attempts++ {
		snapshot, found, err := store.LoadInvestigation(ctx, awaiting.ID)
		if err != nil || !found {
			t.Fatalf("load awaiting found=%t err=%v", found, err)
		}
		if snapshot.Investigation.Status() == domain.InvestigationAwaitingApproval || snapshot.Investigation.Status().Terminal() {
			break
		}
		if _, err := awaitingController.Advance(ctx, awaiting.ID); err != nil {
			t.Fatalf("advance awaiting: %v", err)
		}
	}
	snapshot, found, err = store.LoadInvestigation(ctx, awaiting.ID)
	if err != nil || !found {
		t.Fatalf("reload awaiting found=%t err=%v", found, err)
	}
	if snapshot.Investigation.Status() != domain.InvestigationAwaitingApproval {
		t.Fatalf("awaiting status = %s, want AWAITING_APPROVAL", snapshot.Investigation.Status())
	}
	pending, hasPending := snapshot.Investigation.PendingAction()
	if !hasPending || !pending.Diagnostic {
		t.Fatalf("the diagnostic operation class did not survive reconstitution: %+v", pending)
	}
	var stored string
	if err := pool.QueryRow(ctx, `SELECT operation FROM investigation_actions WHERE investigation_id=$1`, awaiting.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "DIAGNOSTIC" {
		t.Fatalf("stored operation = %q, want DIAGNOSTIC", stored)
	}
}

// The freshness rule is only as good as the query behind it, and that query
// reads targets out of a JSON column. Prove it against a real database rather
// than trusting the SQL: only successful diagnostics inside the window count,
// each target reports its own most recent probe, and an evidence lookup with
// the same targets is invisible to it.
func TestDiagnosticFreshnessQueryReportsOnlySuccessfulRecentDiagnostics(t *testing.T) {
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
	collections, _ := storepg.NewCollectionStore(pool)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("m12f-cluster-" + suffix)
	if err := collections.EnsureSource(ctx, clusterID, "M12 freshness cluster", domain.SourceID("m12f-source-"+suffix), "M12 source"); err != nil {
		t.Fatal(err)
	}
	incidentID := domain.IncidentID("m12f-incident-" + suffix)
	now := fixtureDatabaseTime(t, ctx, pool)
	if _, err := pool.Exec(ctx, `INSERT INTO incidents (incident_id,cluster_id,title,severity,status,created_by,created_at,updated_at) VALUES ($1,$2,'Synthetic M12 incident','HIGH','OPEN','test',$3,$3)`, incidentID, clusterID, now); err != nil {
		t.Fatal(err)
	}
	store, err := storepg.NewInvestigationStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	investigationID := domain.InvestigationID("m12f-investigation-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO investigations (investigation_id,cluster_id,incident_id,question,requested_by,scope,window_start,window_end,success_criteria,status,version,created_at) VALUES ($1,$2,$3,'freshness','test','{"entity_kind":"node","entity_ids":["n1"]}'::jsonb,$4,$5,'["x"]'::jsonb,'PLANNING',1,$5)`, investigationID, clusterID, incidentID, now.Add(-time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO investigation_budgets (investigation_id,cluster_id,deadline,max_decision_iterations,max_tool_calls,max_diagnostic_calls,max_privileged_calls,max_fan_out,max_model_tokens,max_cost_microunits) VALUES ($1,$2,$3,4,4,4,0,4,1000,1000)`, investigationID, clusterID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	stepID := "m12f-step-" + suffix
	if _, err := pool.Exec(ctx, `INSERT INTO investigation_steps (step_id,cluster_id,investigation_id,step_key,kind,status,investigation_version,available_at) VALUES ($1,$2,$3,$1,'EXECUTE','AVAILABLE',1,$4)`, stepID, clusterID, investigationID, now); err != nil {
		t.Fatal(err)
	}
	insertAction := func(id, toolID, operation, status string, targets []string, completedAt *time.Time) {
		t.Helper()
		arguments, err := json.Marshal(map[string]any{"fan_out": len(targets), "targets": targets})
		if err != nil {
			t.Fatal(err)
		}
		digest := domain.ChecksumSHA256([]byte(id))
		// The schema already guarantees a SUCCEEDED action carries a completion
		// time and a receipt, which is what makes it safe to read as a result.
		receipt := any(nil)
		if status == "SUCCEEDED" {
			receipt = "receipt-" + id
		}
		if _, err := pool.Exec(ctx, `INSERT INTO investigation_actions (action_id,cluster_id,investigation_id,step_id,action_key,tool_id,arguments,purpose,expected_information,action_digest,privilege,operation,status,execution_idempotency_key,execution_receipt,completed_at,completion_recorded_at) VALUES ($1,$2,$3,$4,$1,$5,$6,'p','e',$7,'UNPRIVILEGED',$8,$9,$1,$10,$11,CASE WHEN $9 IN ('SUCCEEDED','FAILED','REJECTED','CANCELLED') THEN clock_timestamp() END)`, id, clusterID, investigationID, stepID, toolID, arguments, digest[:], operation, status, receipt, completedAt); err != nil {
			t.Fatal(err)
		}
	}
	at := func(d time.Duration) *time.Time { value := now.Add(d); return &value }

	insertAction("m12f-a1-"+suffix, "gpu.ecc_counters.v1", "DIAGNOSTIC", "SUCCEEDED", []string{"n1", "n2"}, at(-30*time.Second))
	// A newer probe of n2 alone must win for n2 and leave n1 at its own time.
	insertAction("m12f-a2-"+suffix, "gpu.ecc_counters.v1", "DIAGNOSTIC", "SUCCEEDED", []string{"n2"}, at(-5*time.Second))
	// None of these may be reported: failed, still dispatched, a different
	// definition, or an evidence lookup over the same targets.
	insertAction("m12f-a3-"+suffix, "gpu.ecc_counters.v1", "DIAGNOSTIC", "FAILED", []string{"n3"}, at(-time.Second))
	insertAction("m12f-a4-"+suffix, "gpu.ecc_counters.v1", "DIAGNOSTIC", "DISPATCHED", []string{"n4"}, nil)
	insertAction("m12f-a5-"+suffix, "gpu.retired_pages.v1", "DIAGNOSTIC", "SUCCEEDED", []string{"n5"}, at(-time.Second))
	insertAction("m12f-a6-"+suffix, "gpu.ecc_counters.v1", "READ_ONLY", "SUCCEEDED", []string{"n6"}, at(-time.Second))

	targets := []string{"n1", "n2", "n3", "n4", "n5", "n6"}
	notBefore := now.Add(-time.Minute)
	for _, scope := range []struct {
		name  string
		query func() (map[string]time.Time, error)
	}{
		{"investigation", func() (map[string]time.Time, error) {
			return store.LatestInvestigationDiagnostics(ctx, investigationID, "gpu.ecc_counters.v1", targets, notBefore)
		}},
		{"cluster", func() (map[string]time.Time, error) {
			return store.LatestClusterDiagnostics(ctx, clusterID, "gpu.ecc_counters.v1", targets, notBefore)
		}},
	} {
		t.Run(scope.name, func(t *testing.T) {
			observed, err := scope.query()
			if err != nil {
				t.Fatal(err)
			}
			if len(observed) != 2 {
				t.Fatalf("only successful in-window diagnostics of this definition may be reported, got %v", observed)
			}
			if got := observed["n1"]; !got.Equal(now.Add(-30 * time.Second)) {
				t.Fatalf("n1 = %s, want the time of its own probe", got)
			}
			if got := observed["n2"]; !got.Equal(now.Add(-5 * time.Second)) {
				t.Fatalf("n2 = %s, want its most recent probe", got)
			}
		})
	}

	// A window that predates every probe reports nothing, which is what makes a
	// stale target admissible again rather than permanently suppressed.
	observed, err := store.LatestClusterDiagnostics(ctx, clusterID, "gpu.ecc_counters.v1", targets, now.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, current := observed["n1"]; current {
		t.Fatalf("a probe older than the interval was reported as current: %v", observed)
	}
	if _, err := store.LatestClusterDiagnostics(ctx, clusterID, "", targets, notBefore); err == nil {
		t.Fatal("a lookup without a definition must be refused")
	}
	if _, err := store.LatestClusterDiagnostics(ctx, clusterID, "gpu.ecc_counters.v1", nil, notBefore); err == nil {
		t.Fatal("a lookup without targets must be refused")
	}
}

// A parked investigation is doing work, not stuck: the lease claim must still
// pick it up so the next claim retries the dispatch, and the durable state must
// say why it is not advancing.
func TestParkedInvestigationRemainsClaimableAndVisible(t *testing.T) {
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
	collections, _ := storepg.NewCollectionStore(pool)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("m12p-cluster-" + suffix)
	if err := collections.EnsureSource(ctx, clusterID, "M12 parked cluster", domain.SourceID("m12p-source-"+suffix), "M12 source"); err != nil {
		t.Fatal(err)
	}
	incidentID := domain.IncidentID("m12p-incident-" + suffix)
	now := fixtureDatabaseTime(t, ctx, pool)
	if _, err := pool.Exec(ctx, `INSERT INTO incidents (incident_id,cluster_id,title,severity,status,created_by,created_at,updated_at) VALUES ($1,$2,'Synthetic M12 incident','HIGH','OPEN','test',$3,$3)`, incidentID, clusterID, now); err != nil {
		t.Fatal(err)
	}
	investigationID := domain.InvestigationID("m12p-investigation-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO investigations (investigation_id,cluster_id,incident_id,question,requested_by,scope,window_start,window_end,success_criteria,status,version,created_at) VALUES ($1,$2,$3,'parked','test','{"entity_kind":"node","entity_ids":["n1"]}'::jsonb,$4,$5,'["x"]'::jsonb,'AWAITING_EVIDENCE',1,$5)`, investigationID, clusterID, incidentID, now.Add(-time.Hour), now); err != nil {
		t.Fatalf("AWAITING_EVIDENCE must be a storable investigation state: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO investigation_budgets (investigation_id,cluster_id,deadline,max_decision_iterations,max_tool_calls,max_diagnostic_calls,max_privileged_calls,max_fan_out,max_model_tokens,max_cost_microunits) VALUES ($1,$2,$3,4,4,4,0,4,1000,1000)`, investigationID, clusterID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	leases, err := storepg.NewInvestigationLeaseStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	lease, claimed, err := leases.Claim(ctx, "m12p-worker-"+suffix, now, time.Minute, 8, 8)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if !claimed {
		t.Fatal("a parked investigation was not claimable, so it would never resume")
	}
	if lease.InvestigationID != investigationID {
		// Another investigation in the shared test database may be claimed first;
		// what matters is that this one is reachable, so look for it directly.
		var reachable bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM investigation_claims c JOIN investigations i USING (investigation_id) WHERE i.investigation_id=$1 AND i.status='AWAITING_EVIDENCE')`, investigationID).Scan(&reachable); err != nil {
			t.Fatal(err)
		}
		if !reachable {
			t.Fatal("a parked investigation has no claim row, so it would never resume")
		}
	}

	// The dashboard must be able to say why the run is not advancing rather
	// than showing an active count that never moves.
	var awaiting int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status='AWAITING_EVIDENCE') FROM investigations WHERE cluster_id=$1`, clusterID).Scan(&awaiting); err != nil {
		t.Fatal(err)
	}
	if awaiting != 1 {
		t.Fatalf("awaiting-evidence count = %d, want 1", awaiting)
	}
}
