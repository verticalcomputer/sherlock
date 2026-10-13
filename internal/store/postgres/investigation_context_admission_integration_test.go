//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationcontext"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

type diagnosticContextFixture struct {
	ctx              context.Context
	pool             *pgxpool.Pool
	store            *storepg.InvestigationStore
	request          domain.InvestigationRequest
	investigation    domain.Investigation
	entry            domain.InvestigationEvidence
	runID            domain.DiagnosticRunID
	workID           domain.DiagnosticWorkID
	actionID         domain.InvestigationActionID
	attempt          int
	ordinarySourceID domain.SourceID
}

func openContextAdmissionDatabase(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated migrated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return ctx, pool
}

func newDiagnosticContextFixture(t *testing.T, targets []string, failed map[string]bool) diagnosticContextFixture {
	t.Helper()
	ctx, pool := openContextAdmissionDatabase(t)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("m12-context-cluster-" + suffix)
	ordinarySourceID := domain.SourceID("m12-context-source-" + suffix)
	collections, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := collections.EnsureSource(ctx, clusterID, "M12 context cluster", ordinarySourceID, "M12 source"); err != nil {
		t.Fatal(err)
	}
	evidenceStore, err := storepg.NewEvidenceStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := evidenceStore.EnsureDiagnosticSource(ctx, clusterID, domain.DiagnosticEvidenceSourceID(clusterID)); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	requestedAt := now.Add(-5 * time.Minute)
	investigationID := domain.InvestigationID("m12-context-investigation-" + suffix)
	request := domain.InvestigationRequest{
		ID: investigationID, IncidentID: domain.IncidentID("m12-context-incident-" + suffix), ClusterID: clusterID,
		Question: "What did the bounded ECC diagnostic observe?", RequestedBy: "context-test", IdempotencyKey: "m12-context-" + suffix,
		Scope:           domain.InvestigationScope{EntityKind: "node", EntityIDs: append([]string(nil), targets...), Start: requestedAt.Add(-time.Hour), End: requestedAt},
		SuccessCriteria: []string{"cite the diagnostic result"},
		Budget:          domain.InvestigationBudget{MaxDecisions: 3, MaxToolCalls: 2, MaxDiagnosticCalls: 1, MaxFanOut: len(targets), MaxModelTokens: 1000, MaxCostMicros: 1000},
		RequestedAt:     requestedAt, Deadline: requestedAt.Add(time.Hour),
	}
	investigation, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	scopeJSON, _ := json.Marshal(map[string]any{"entity_kind": request.Scope.EntityKind, "entity_ids": request.Scope.EntityIDs})
	criteriaJSON, _ := json.Marshal(request.SuccessCriteria)
	if _, err := pool.Exec(ctx, `INSERT INTO investigations (investigation_id,cluster_id,question,requested_by,scope,window_start,window_end,success_criteria,status,version,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'PLANNING',1,$9,$9)`, request.ID, request.ClusterID, request.Question, request.RequestedBy, scopeJSON, request.Scope.Start, request.Scope.End, criteriaJSON, request.RequestedAt); err != nil {
		t.Fatal(err)
	}
	actionID := domain.InvestigationActionID("m12-context-action-" + suffix)
	stepID := "step-" + string(actionID)
	if _, err := pool.Exec(ctx, `INSERT INTO investigation_steps (step_id,cluster_id,investigation_id,step_key,kind,status,investigation_version,available_at) VALUES ($1,$2,$3,$1,'EXECUTE','AVAILABLE',1,$4)`, stepID, clusterID, request.ID, requestedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	actionArguments, _ := json.Marshal(map[string]any{"fan_out": len(targets), "targets": targets, "start": request.Scope.Start, "end": request.Scope.End})
	actionDigest := domain.ChecksumSHA256([]byte(actionID))
	if _, err := pool.Exec(ctx, `INSERT INTO investigation_actions (action_id,cluster_id,investigation_id,step_id,action_key,tool_id,arguments,purpose,expected_information,action_digest,privilege,operation,status,execution_idempotency_key,created_at) VALUES ($1,$2,$3,$4,$1,'gpu.ecc_counters.v1',$5,$6,$7,$8,'UNPRIVILEGED','DIAGNOSTIC','AVAILABLE',$9,$10)`, actionID, clusterID, request.ID, stepID, actionArguments, "never expose /usr/bin/ssh arbitrary-command-sentinel", "never expose https://credential.invalid/lease-token-sentinel", actionDigest[:], "investigation-credential-sentinel", requestedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	diagnosticStore, err := storepg.NewDiagnosticStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	runID := domain.DiagnosticRunID("m12-context-run-" + suffix)
	runTargets := make([]domain.DiagnosticTarget, len(targets))
	for index, target := range targets {
		runTargets[index] = domain.DiagnosticTarget(target)
	}
	definition := domain.DiagnosticDefinitionRef{PackID: "standard.readonly", PackVersion: "1.1.0", DefinitionID: "gpu.ecc_counters", DefinitionVersion: "1.0.0", DefinitionDigest: domain.ChecksumSHA256([]byte("m12-context-definition"))}
	runRequest := domain.DiagnosticRequest{
		RunID: runID, ClusterID: clusterID, Definition: definition, Privilege: domain.DiagnosticUnprivileged, Targets: runTargets,
		RequestedBy: "credential-sentinel", IdempotencyKey: "lease-token-sentinel-" + suffix,
		RequestedAt: requestedAt.Add(2 * time.Minute), Deadline: requestedAt.Add(45 * time.Minute), MaxAttempts: 1,
	}
	run, err := domain.NewDiagnosticRun(runRequest, false)
	if err != nil {
		t.Fatal(err)
	}
	workID := domain.DiagnosticWorkID("m12-context-work-" + suffix)
	if _, created, err := diagnosticStore.CreateDiagnosticRun(ctx, run, workID, contextDiagnosticAudit("m12-context-start-"+suffix, application.DiagnosticAuditStart, runRequest, "credential-sentinel", "ALLOWED", runRequest.RequestedAt)); err != nil || !created {
		t.Fatalf("create diagnostic: created=%t err=%v", created, err)
	}
	lease, found, err := diagnosticStore.ClaimDiagnosticWork(ctx, clusterID, "head-context", "raw-lease-token-sentinel", time.Minute, application.DiagnosticAuditEvent{EventID: "m12-context-claim-" + suffix, Kind: application.DiagnosticAuditClaim, ClusterID: clusterID, ActorID: "head-context", Outcome: "CLAIMED", OccurredAt: now.Add(-90 * time.Second)})
	if err != nil || !found {
		t.Fatalf("claim diagnostic: found=%t err=%v", found, err)
	}
	exitCode, failureExitCode := 0, 2
	result := domain.DiagnosticAttemptResult{
		WorkID: workID, RunID: runID, Attempt: lease.Attempt, RunnerID: "head-context", PlanDigest: domain.ChecksumSHA256([]byte("m12-context-plan")),
		StartedAt: now.Add(-time.Minute), CompletedAt: now.Add(-30 * time.Second),
	}
	for _, target := range runTargets {
		output := "volatile_ecc_uncorrected: 4\naggregate_ecc_uncorrected: 9"
		targetResult := domain.DiagnosticTargetResult{Target: target, Status: domain.DiagnosticTargetSucceeded, ExitCode: &exitCode, StdoutBytes: int64(len(output)), StdoutSHA256: domain.ChecksumSHA256([]byte(output)), StderrSHA256: domain.ChecksumSHA256(nil), StdoutExcerpt: output}
		if failed[string(target)] {
			output = "Field index is not valid for this query."
			targetResult = domain.DiagnosticTargetResult{Target: target, Status: domain.DiagnosticTargetFailed, ExitCode: &failureExitCode, ErrorCode: "EXIT_NONZERO", StdoutBytes: int64(len(output)), StdoutSHA256: domain.ChecksumSHA256([]byte(output)), StderrSHA256: domain.ChecksumSHA256(nil), StdoutExcerpt: output}
		}
		result.Targets = append(result.Targets, targetResult)
	}
	completed, recorded, err := diagnosticStore.RecordDiagnosticAttempt(ctx, clusterID, "head-context", lease, result, contextDiagnosticAudit("m12-context-result-"+suffix, application.DiagnosticAuditResult, runRequest, "head-context", "RECORDED", result.CompletedAt))
	if err != nil || !recorded {
		t.Fatalf("record diagnostic: recorded=%t err=%v", recorded, err)
	}
	if completed.Status() != domain.DiagnosticSucceeded && completed.Status() != domain.DiagnosticPartial && completed.Status() != domain.DiagnosticFailed {
		t.Fatalf("fixture diagnostic status=%s", completed.Status())
	}
	envelope, err := domain.DiagnosticEvidenceForAttempt(runRequest, result, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidenceStore.CreateEvidence(ctx, envelope); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE investigation_actions SET status='SUCCEEDED',diagnostic_run_id=$2,execution_receipt=$3,completed_at=$4,completion_recorded_at=clock_timestamp() WHERE action_id=$1`, actionID, runID, "diagnostic-receipt-"+suffix, result.CompletedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	entry := domain.InvestigationEvidence{EvidenceID: envelope.ID(), InvestigationID: request.ID, ClusterID: clusterID, EntityIDs: append([]string(nil), targets...), Status: envelope.Status(), ObservedStart: result.StartedAt, ObservedEnd: result.CompletedAt, RecordedAt: result.CompletedAt}
	exactScope, _ := json.Marshal(map[string]any{"entity_ids": entry.EntityIDs})
	if _, err := pool.Exec(ctx, `INSERT INTO investigation_evidence (ledger_entry_id,cluster_id,investigation_id,sequence,action_id,evidence_id,entry_kind,status,exact_scope,observed_start,observed_end,recorded_at) VALUES ($1,$2,$3,1,$4,$5,'OBSERVATION',$6,$7,$8,$9,$10)`, "ledger-"+string(entry.EvidenceID), clusterID, request.ID, actionID, entry.EvidenceID, entry.Status, exactScope, entry.ObservedStart, entry.ObservedEnd, entry.RecordedAt); err != nil {
		t.Fatal(err)
	}
	store, err := storepg.NewInvestigationStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	return diagnosticContextFixture{ctx: ctx, pool: pool, store: store, request: request, investigation: investigation, entry: entry, runID: runID, workID: workID, actionID: actionID, attempt: lease.Attempt, ordinarySourceID: ordinarySourceID}
}

func (fixture diagnosticContextFixture) snapshot(t *testing.T) application.InvestigationSnapshot {
	t.Helper()
	ledger, err := domain.NewEvidenceLedger([]domain.InvestigationEvidence{fixture.entry}, fixture.investigation)
	if err != nil {
		t.Fatal(err)
	}
	return application.InvestigationSnapshot{Investigation: fixture.investigation, Evidence: ledger}
}

func (fixture diagnosticContextFixture) load(t *testing.T) ([]investigationcontext.EvidenceInput, error) {
	t.Helper()
	return fixture.store.LoadInvestigationEvidenceContext(fixture.ctx, fixture.snapshot(t))
}

func contextDiagnosticAudit(id string, kind application.DiagnosticAuditKind, request domain.DiagnosticRequest, actor, outcome string, at time.Time) application.DiagnosticAuditEvent {
	return application.DiagnosticAuditEvent{EventID: id, Kind: kind, RunID: request.RunID, ClusterID: request.ClusterID, ActorID: actor, Outcome: outcome, DefinitionDigest: request.Definition.DefinitionDigest, TargetDigest: domain.DiagnosticTargetsDigest(request.Targets), OccurredAt: at}
}

func TestPostRequestDiagnosticEvidenceAdmissionLiveShape(t *testing.T) {
	fixture := newDiagnosticContextFixture(t, []string{"comp001"}, nil)
	inputs, err := fixture.load(t)
	if err != nil || len(inputs) != 1 {
		t.Fatalf("load context inputs=%+v err=%v", inputs, err)
	}
	if !inputs[0].AdmittedPostRequestDiagnostic {
		t.Fatal("durable store did not mark the reconstructed diagnostic admission")
	}
	checkpointStore, err := investigationcontext.NewPostgresStore(fixture.pool)
	if err != nil {
		t.Fatal(err)
	}
	engineConfig := investigationcontext.DefaultEngineConfig()
	engineConfig.EvidenceAllowanceTokens = 10_000
	engine, err := investigationcontext.NewEngine(engineConfig, checkpointStore)
	if err != nil {
		t.Fatal(err)
	}
	contextInput := investigationcontext.Input{InvestigationID: fixture.request.ID, ClusterID: fixture.request.ClusterID, Question: fixture.request.Question, Scope: fixture.request.Scope, SuccessCriteria: fixture.request.SuccessCriteria, Evidence: inputs}
	prepared, record, err := engine.Prepare(fixture.ctx, fixture.snapshot(t), contextInput)
	if err != nil {
		t.Fatalf("prepare M11 context: %v", err)
	}
	if len(prepared.Evidence) != 1 || prepared.Evidence[0].EvidenceID != fixture.entry.EvidenceID {
		t.Fatalf("retrieval dropped store-admitted diagnostic: selected=%+v exclusions=%+v", prepared.Evidence, record.Exclusions)
	}
	for _, exclusion := range record.Exclusions {
		if exclusion.EvidenceID == fixture.entry.EvidenceID {
			t.Fatalf("store-admitted diagnostic was excluded as %s", exclusion.Reason)
		}
	}
	builder, err := investigationcontext.NewBuilder(investigationcontext.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	built, err := builder.Build(prepared)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(built)
	contextJSON := string(encoded)
	for _, required := range []string{"volatile_ecc_uncorrected: 4", "aggregate_ecc_uncorrected: 9", `"trust":"UNTRUSTED_EVIDENCE_DATA"`, `"untrusted_excerpt"`} {
		if !strings.Contains(contextJSON, required) {
			t.Fatalf("context omitted %q: %s", required, contextJSON)
		}
	}
	for _, forbidden := range []string{"credential-sentinel", "lease-token-sentinel", "raw-lease-token-sentinel", "/usr/bin/ssh", "arbitrary-command-sentinel", "https://credential.invalid"} {
		if strings.Contains(contextJSON, forbidden) {
			t.Fatalf("context leaked %q: %s", forbidden, contextJSON)
		}
	}
}

func TestPostRequestDiagnosticEvidenceAdmissionAcceptsBoundedPartial(t *testing.T) {
	fixture := newDiagnosticContextFixture(t, []string{"comp001", "comp002"}, map[string]bool{"comp002": true})
	inputs, err := fixture.load(t)
	if err != nil || len(inputs) != 1 || inputs[0].Status != domain.EvidencePartial {
		t.Fatalf("bounded partial inputs=%+v err=%v", inputs, err)
	}
}

func TestPostRequestDiagnosticEvidenceAdmissionAcceptsCoherentFailureAsUnavailable(t *testing.T) {
	fixture := newDiagnosticContextFixture(t, []string{"comp001"}, map[string]bool{"comp001": true})
	inputs, err := fixture.load(t)
	if err != nil || len(inputs) != 1 {
		t.Fatalf("failed diagnostic inputs=%+v err=%v", inputs, err)
	}
	input := inputs[0]
	if input.Status != domain.EvidenceUnavailable || !input.AdmittedPostRequestDiagnostic {
		t.Fatalf("failed diagnostic input=%+v", input)
	}
	for _, required := range []string{"comp001=FAILED(exit=2", "Field index is not valid", "untrusted host text"} {
		if !strings.Contains(input.Summary+input.Excerpt, required) {
			t.Fatalf("failed diagnostic context omitted %q: summary=%q excerpt=%q", required, input.Summary, input.Excerpt)
		}
	}
}

func TestPostRequestDiagnosticEvidenceAdmissionRejectsForeignAttribution(t *testing.T) {
	t.Run("same evidence on another investigation", func(t *testing.T) {
		fixture := newDiagnosticContextFixture(t, []string{"comp001"}, nil)
		otherID := domain.InvestigationID("other-" + string(fixture.request.ID))
		otherRequest := fixture.request
		otherRequest.ID, otherRequest.IdempotencyKey = otherID, "other-"+fixture.request.IdempotencyKey
		other, err := domain.NewInvestigation(otherRequest)
		if err != nil {
			t.Fatal(err)
		}
		scopeJSON, _ := json.Marshal(map[string]any{"entity_kind": otherRequest.Scope.EntityKind, "entity_ids": otherRequest.Scope.EntityIDs})
		criteriaJSON, _ := json.Marshal(otherRequest.SuccessCriteria)
		if _, err := fixture.pool.Exec(fixture.ctx, `INSERT INTO investigations (investigation_id,cluster_id,question,requested_by,scope,window_start,window_end,success_criteria,status,version,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'PLANNING',1,$9,$9)`, otherID, otherRequest.ClusterID, otherRequest.Question, otherRequest.RequestedBy, scopeJSON, otherRequest.Scope.Start, otherRequest.Scope.End, criteriaJSON, otherRequest.RequestedAt); err != nil {
			t.Fatal(err)
		}
		stepID, actionID := "step-other-"+string(fixture.actionID), domain.InvestigationActionID("other-"+string(fixture.actionID))
		if _, err := fixture.pool.Exec(fixture.ctx, `INSERT INTO investigation_steps (step_id,cluster_id,investigation_id,step_key,kind,status,investigation_version,available_at) VALUES ($1,$2,$3,$1,'EXECUTE','AVAILABLE',1,$4)`, stepID, otherRequest.ClusterID, otherID, otherRequest.RequestedAt); err != nil {
			t.Fatal(err)
		}
		actionArguments, _ := json.Marshal(map[string]any{"fan_out": 1, "targets": []string{"comp001"}, "start": otherRequest.Scope.Start, "end": otherRequest.Scope.End})
		actionDigest := domain.ChecksumSHA256([]byte(actionID))
		if _, err := fixture.pool.Exec(fixture.ctx, `INSERT INTO investigation_actions (action_id,cluster_id,investigation_id,step_id,action_key,tool_id,arguments,purpose,expected_information,action_digest,privilege,operation,status,execution_idempotency_key,execution_receipt,completed_at,completion_recorded_at) VALUES ($1,$2,$3,$4,$1,'gpu.ecc_counters.v1',$5,'p','e',$6,'UNPRIVILEGED','DIAGNOSTIC','SUCCEEDED',$7,$8,$9,clock_timestamp())`, actionID, otherRequest.ClusterID, otherID, stepID, actionArguments, actionDigest[:], "other-action-"+string(actionID), "other-receipt-"+string(actionID), time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		exactScope, _ := json.Marshal(map[string]any{"entity_ids": fixture.entry.EntityIDs})
		if _, err := fixture.pool.Exec(fixture.ctx, `INSERT INTO investigation_evidence (ledger_entry_id,cluster_id,investigation_id,sequence,action_id,evidence_id,entry_kind,status,exact_scope,observed_start,observed_end,recorded_at) VALUES ($1,$2,$3,1,$4,$5,'OBSERVATION',$6,$7,$8,$9,$10)`, "ledger-"+string(fixture.entry.EvidenceID), otherRequest.ClusterID, otherID, actionID, fixture.entry.EvidenceID, fixture.entry.Status, exactScope, fixture.entry.ObservedStart, fixture.entry.ObservedEnd, fixture.entry.RecordedAt); err != nil {
			t.Fatal(err)
		}
		foreignEntry := fixture.entry
		foreignEntry.InvestigationID = otherID
		ledger, err := domain.NewEvidenceLedger([]domain.InvestigationEvidence{foreignEntry}, other)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.LoadInvestigationEvidenceContext(fixture.ctx, application.InvestigationSnapshot{Investigation: other, Evidence: ledger}); err == nil {
			t.Fatal("evidence from another investigation was admitted")
		}
	})

	t.Run("cross cluster", func(t *testing.T) {
		fixture := newDiagnosticContextFixture(t, []string{"comp001"}, nil)
		otherCluster := domain.ClusterID("other-" + string(fixture.request.ClusterID))
		collections, _ := storepg.NewCollectionStore(fixture.pool)
		if err := collections.EnsureSource(fixture.ctx, otherCluster, "Other cluster", domain.SourceID("other-source-"+string(fixture.actionID)), "Other source"); err != nil {
			t.Fatal(err)
		}
		foreign := fixture.entry
		foreign.ClusterID = otherCluster
		foreignInvestigationRequest := fixture.request
		foreignInvestigationRequest.ID = domain.InvestigationID("foreign-" + string(fixture.request.ID))
		foreignInvestigationRequest.ClusterID = otherCluster
		foreignInvestigationRequest.IdempotencyKey = "foreign-" + fixture.request.IdempotencyKey
		foreign.InvestigationID = foreignInvestigationRequest.ID
		foreignInvestigation, err := domain.NewInvestigation(foreignInvestigationRequest)
		if err != nil {
			t.Fatal(err)
		}
		ledger, err := domain.NewEvidenceLedger([]domain.InvestigationEvidence{foreign}, foreignInvestigation)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.LoadInvestigationEvidenceContext(fixture.ctx, application.InvestigationSnapshot{Investigation: foreignInvestigation, Evidence: ledger}); err == nil {
			t.Fatal("cross-cluster diagnostic evidence was admitted")
		}
	})

	t.Run("mismatched action run and evidence", func(t *testing.T) {
		fixture := newDiagnosticContextFixture(t, []string{"comp001"}, nil)
		if _, err := fixture.pool.Exec(fixture.ctx, `UPDATE investigation_actions SET diagnostic_run_id=NULL WHERE action_id=$1`, fixture.actionID); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.load(t); err == nil {
			t.Fatal("evidence without the action-to-run link was admitted")
		}
	})

	t.Run("ledger names another action", func(t *testing.T) {
		fixture := newDiagnosticContextFixture(t, []string{"comp001"}, nil)
		otherActionID := domain.InvestigationActionID("other-" + string(fixture.actionID))
		otherStepID := "step-" + string(otherActionID)
		if _, err := fixture.pool.Exec(fixture.ctx, `INSERT INTO investigation_steps (step_id,cluster_id,investigation_id,step_key,kind,status,investigation_version,available_at) VALUES ($1,$2,$3,$1,'EXECUTE','AVAILABLE',1,$4)`, otherStepID, fixture.request.ClusterID, fixture.request.ID, fixture.request.RequestedAt.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		actionArguments, _ := json.Marshal(map[string]any{"fan_out": 1, "targets": []string{"comp001"}, "start": fixture.request.Scope.Start, "end": fixture.request.Scope.End})
		actionDigest := domain.ChecksumSHA256([]byte(otherActionID))
		if _, err := fixture.pool.Exec(fixture.ctx, `INSERT INTO investigation_actions (action_id,cluster_id,investigation_id,step_id,action_key,tool_id,arguments,purpose,expected_information,action_digest,privilege,operation,status,execution_idempotency_key,execution_receipt,completed_at,completion_recorded_at) VALUES ($1,$2,$3,$4,$1,'gpu.ecc_counters.v1',$5,'p','e',$6,'UNPRIVILEGED','DIAGNOSTIC','SUCCEEDED',$7,$8,$9,clock_timestamp())`, otherActionID, fixture.request.ClusterID, fixture.request.ID, otherStepID, actionArguments, actionDigest[:], "other-key-"+string(otherActionID), "other-receipt-"+string(otherActionID), time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `UPDATE investigation_evidence SET action_id=$2 WHERE investigation_id=$1 AND evidence_id=$3`, fixture.request.ID, otherActionID, fixture.entry.EvidenceID); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.load(t); err == nil {
			t.Fatal("evidence attached through another action was admitted")
		}
	})

	t.Run("evidence names another run", func(t *testing.T) {
		fixture := newDiagnosticContextFixture(t, []string{"comp001"}, nil)
		otherRunID := domain.DiagnosticRunID("other-" + string(fixture.runID))
		digest := domain.ChecksumSHA256([]byte("other-definition"))
		now := time.Now().UTC()
		if _, err := fixture.pool.Exec(fixture.ctx, `INSERT INTO diagnostic_runs (run_id,cluster_id,pack_id,pack_version,definition_id,definition_version,definition_digest,privilege,status,requested_by,idempotency_key,arguments,requested_at,deadline,max_attempts,version) VALUES ($1,$2,'standard.readonly','1.1.0','gpu.ecc_counters','1.0.0',$3,'UNPRIVILEGED','QUEUED','test',$4,'[]',$5,$6,1,1)`, otherRunID, fixture.request.ClusterID, digest[:], "other-"+string(fixture.actionID), now.Add(-time.Minute), now.Add(10*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `UPDATE evidence_envelopes SET diagnostic_run_id=$2 WHERE evidence_id=$1`, fixture.entry.EvidenceID, otherRunID); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.load(t); err == nil {
			t.Fatal("evidence linked to another run was admitted")
		}
	})
}

func TestPostRequestDiagnosticEvidenceAdmissionFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(diagnosticContextFixture) error
	}{
		{name: "out of scope action target", mutate: func(f diagnosticContextFixture) error {
			arguments, _ := json.Marshal(map[string]any{"fan_out": 1, "targets": []string{"comp999"}, "start": f.request.Scope.Start, "end": f.request.Scope.End})
			_, err := f.pool.Exec(f.ctx, `UPDATE investigation_actions SET arguments=$2 WHERE action_id=$1`, f.actionID, arguments)
			return err
		}},
		{name: "out of scope action window", mutate: func(f diagnosticContextFixture) error {
			arguments, _ := json.Marshal(map[string]any{"fan_out": 1, "targets": []string{"comp001"}, "start": f.request.Scope.Start.Add(-time.Second), "end": f.request.Scope.End})
			_, err := f.pool.Exec(f.ctx, `UPDATE investigation_actions SET arguments=$2 WHERE action_id=$1`, f.actionID, arguments)
			return err
		}},
		{name: "status-only failed diagnostic", mutate: func(f diagnosticContextFixture) error {
			if _, err := f.pool.Exec(f.ctx, `UPDATE diagnostic_runs SET status='FAILED' WHERE run_id=$1`, f.runID); err != nil {
				return err
			}
			if _, err := f.pool.Exec(f.ctx, `UPDATE diagnostic_work_items SET status='FAILED' WHERE work_id=$1`, f.workID); err != nil {
				return err
			}
			_, err := f.pool.Exec(f.ctx, `UPDATE diagnostic_work_attempts SET status='FAILED' WHERE work_id=$1 AND attempt=$2`, f.workID, f.attempt)
			return err
		}},
		{name: "incomplete diagnostic", mutate: func(f diagnosticContextFixture) error {
			if _, err := f.pool.Exec(f.ctx, `UPDATE diagnostic_runs SET status='RUNNING',completed_at=NULL WHERE run_id=$1`, f.runID); err != nil {
				return err
			}
			if _, err := f.pool.Exec(f.ctx, `UPDATE diagnostic_work_items SET status='LEASED' WHERE work_id=$1`, f.workID); err != nil {
				return err
			}
			_, err := f.pool.Exec(f.ctx, `UPDATE diagnostic_work_attempts SET status='RUNNING',completed_at=NULL,finalized_at=NULL WHERE work_id=$1 AND attempt=$2`, f.workID, f.attempt)
			return err
		}},
		{name: "evidence server creation precedes attempt finalization", mutate: func(f diagnosticContextFixture) error {
			_, err := f.pool.Exec(f.ctx, `UPDATE evidence_envelopes SET created_at=(SELECT finalized_at - interval '1 microsecond' FROM diagnostic_work_attempts WHERE work_id=$2 AND attempt=$3) WHERE evidence_id=$1`, f.entry.EvidenceID, f.workID, f.attempt)
			return err
		}},
		{name: "action server completion precedes evidence creation", mutate: func(f diagnosticContextFixture) error {
			_, err := f.pool.Exec(f.ctx, `UPDATE investigation_actions SET completion_recorded_at=(SELECT created_at - interval '1 microsecond' FROM evidence_envelopes WHERE evidence_id=$2) WHERE action_id=$1`, f.actionID, f.entry.EvidenceID)
			return err
		}},
		{name: "missing target result", mutate: func(f diagnosticContextFixture) error {
			_, err := f.pool.Exec(f.ctx, `DELETE FROM diagnostic_target_results WHERE work_id=$1 AND attempt=$2`, f.workID, f.attempt)
			return err
		}},
		{name: "unreviewed action tool", mutate: func(f diagnosticContextFixture) error {
			_, err := f.pool.Exec(f.ctx, `UPDATE investigation_actions SET tool_id='gpu.reset.v1' WHERE action_id=$1`, f.actionID)
			return err
		}},
		{name: "reviewed definition mismatch", mutate: func(f diagnosticContextFixture) error {
			_, err := f.pool.Exec(f.ctx, `UPDATE diagnostic_runs SET definition_id='gpu.row_remap' WHERE run_id=$1`, f.runID)
			return err
		}},
		{name: "observation window mismatch", mutate: func(f diagnosticContextFixture) error {
			_, err := f.pool.Exec(f.ctx, `UPDATE evidence_envelopes SET observed_start=observed_start-interval '1 second' WHERE evidence_id=$1`, f.entry.EvidenceID)
			return err
		}},
		{name: "mutable provenance locator", mutate: func(f diagnosticContextFixture) error {
			_, err := f.pool.Exec(f.ctx, `UPDATE evidence_envelopes SET source_reference='https://mutable.invalid/result' WHERE evidence_id=$1`, f.entry.EvidenceID)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDiagnosticContextFixture(t, []string{"comp001"}, nil)
			if err := test.mutate(fixture); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.load(t); err == nil {
				t.Fatal("invalid post-request diagnostic evidence was admitted")
			}
		})
	}
}

func TestPostRequestOrdinaryEvidenceRemainsDeniedAndPreRequestPathStillWorks(t *testing.T) {
	fixture := newDiagnosticContextFixture(t, []string{"comp001"}, nil)
	evidenceStore, _ := storepg.NewEvidenceStore(fixture.pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	ordinary, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{
		ID: domain.EvidenceID("ordinary-" + string(fixture.actionID)), SchemaVersion: domain.EvidenceSchemaVersion, ClusterID: fixture.request.ClusterID, Status: domain.EvidenceComplete,
		Source:    domain.EvidenceSourceReference{SourceID: fixture.ordinarySourceID, Operation: "gpu.telemetry", DefinitionVersion: "1", Reference: "prometheus:telemetry"},
		TimeRange: domain.EvidenceTimeRange{Start: now.Add(-time.Minute), End: now.Add(-30 * time.Second)}, CollectedAt: now.Add(-30 * time.Second),
		Coverage: domain.EvidenceCoverage{Expected: []domain.EvidenceTarget{{Kind: domain.EvidenceTargetNode, ID: "comp001"}}, Covered: []domain.EvidenceTarget{{Kind: domain.EvidenceTargetNode, ID: "comp001"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidenceStore.CreateEvidence(fixture.ctx, ordinary); err != nil {
		t.Fatal(err)
	}
	postEntry := domain.InvestigationEvidence{EvidenceID: ordinary.ID(), InvestigationID: fixture.request.ID, ClusterID: fixture.request.ClusterID, EntityIDs: []string{"comp001"}, Status: ordinary.Status(), ObservedStart: ordinary.TimeRange().Start, ObservedEnd: ordinary.TimeRange().End, RecordedAt: ordinary.CollectedAt()}
	postLedger, err := domain.NewEvidenceLedger([]domain.InvestigationEvidence{postEntry}, fixture.investigation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.LoadInvestigationEvidenceContext(fixture.ctx, application.InvestigationSnapshot{Investigation: fixture.investigation, Evidence: postLedger}); err == nil {
		t.Fatal("arbitrary post-request telemetry evidence was admitted")
	}

	preRequest := fixture.request
	preRequest.ID = domain.InvestigationID("pre-request-" + string(fixture.request.ID))
	preRequest.IdempotencyKey = "pre-request-" + fixture.request.IdempotencyKey
	preRequest.RequestedAt = now.Add(time.Hour)
	preRequest.Deadline = preRequest.RequestedAt.Add(time.Hour)
	preRequest.Scope.Start = ordinary.TimeRange().Start.Add(-time.Minute)
	preRequest.Scope.End = ordinary.TimeRange().End.Add(time.Minute)
	preInvestigation, err := domain.NewInvestigation(preRequest)
	if err != nil {
		t.Fatal(err)
	}
	preEntry := postEntry
	preEntry.InvestigationID = preRequest.ID
	preLedger, err := domain.NewEvidenceLedger([]domain.InvestigationEvidence{preEntry}, preInvestigation)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := fixture.store.LoadInvestigationEvidenceContext(fixture.ctx, application.InvestigationSnapshot{Investigation: preInvestigation, Evidence: preLedger})
	if err != nil || len(inputs) != 1 {
		t.Fatalf("pre-request evidence regression: inputs=%+v err=%v", inputs, err)
	}
}

type replayDiagnosticExecutor struct {
	runID    domain.DiagnosticRunID
	evidence []domain.InvestigationEvidence
	calls    int
}

func (executor *replayDiagnosticExecutor) ExecuteInvestigationAction(context.Context, string, domain.InvestigationAction) (application.InvestigationExecutionResult, error) {
	executor.calls++
	return application.InvestigationExecutionResult{Receipt: "diagnostic-replay-receipt-" + string(executor.runID), DiagnosticRunID: executor.runID, Evidence: append([]domain.InvestigationEvidence(nil), executor.evidence...)}, nil
}

type failFirstDiagnosticCompletionStore struct {
	*storepg.InvestigationStore
	failed bool
}

func (store *failFirstDiagnosticCompletionStore) SaveInvestigation(ctx context.Context, version int, snapshot application.InvestigationSnapshot, event domain.InvestigationEvent) error {
	if snapshot.DiagnosticRunID != "" && !store.failed {
		store.failed = true
		return context.Canceled
	}
	return store.InvestigationStore.SaveInvestigation(ctx, version, snapshot, event)
}

type contextAdmissionClock struct{ now time.Time }

func (clock *contextAdmissionClock) Now() time.Time {
	clock.now = clock.now.Add(time.Second)
	return clock.now
}

func TestDiagnosticCompletionReplayPreservesOneActionToRunAssociation(t *testing.T) {
	ctx, pool := openContextAdmissionDatabase(t)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("m12-link-cluster-" + suffix)
	collections, _ := storepg.NewCollectionStore(pool)
	if err := collections.EnsureSource(ctx, clusterID, "M12 link cluster", domain.SourceID("m12-link-source-"+suffix), "M12 link source"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	incidentID := domain.IncidentID("m12-link-incident-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO incidents (incident_id,cluster_id,title,severity,status,created_by,created_at,updated_at) VALUES ($1,$2,'M12 link replay','HIGH','OPEN','test',$3,$3)`, incidentID, clusterID, now); err != nil {
		t.Fatal(err)
	}
	request := domain.InvestigationRequest{
		ID: domain.InvestigationID("m12-link-investigation-" + suffix), IncidentID: incidentID, ClusterID: clusterID,
		Question: "Preserve the diagnostic linkage", RequestedBy: "test", IdempotencyKey: "m12-link-" + suffix,
		Scope:           domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"comp001"}, Start: now.Add(-time.Hour), End: now},
		SuccessCriteria: []string{"link exactly once"}, Budget: domain.InvestigationBudget{MaxDecisions: 2, MaxToolCalls: 1, MaxDiagnosticCalls: 1, MaxFanOut: 1, MaxModelTokens: 1000, MaxCostMicros: 1000},
		RequestedAt: now, Deadline: now.Add(time.Hour),
	}
	action := domain.InvestigationAction{ID: domain.InvestigationActionID("m12-link-action-" + suffix), ToolID: "gpu.ecc_counters.v1", Digest: domain.ChecksumSHA256([]byte("m12-link-action-" + suffix)), Diagnostic: true, FanOut: 1, Targets: []string{"comp001"}, Start: request.Scope.Start, End: request.Scope.End}
	planner := &application.ScriptedInvestigationPlanner{Decisions: []application.InvestigationDecision{{Action: &action}}}
	store, err := storepg.NewInvestigationStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	runID := domain.DiagnosticRunID("m12-link-run-" + suffix)
	executor := &replayDiagnosticExecutor{runID: runID}
	clock := &contextAdmissionClock{now: now}
	controller, err := application.NewInvestigationController(store, planner, executor, clock, platform.RandomIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := controller.Start(ctx, application.StartInvestigationInput{Request: request}); err != nil || !created {
		t.Fatalf("start: created=%t err=%v", created, err)
	}
	for step := 0; step < 10; step++ {
		snapshot, err := controller.Advance(ctx, request.ID)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Investigation.Status() == domain.InvestigationExecuting {
			break
		}
		if step == 9 {
			t.Fatalf("investigation did not reach EXECUTING: %s", snapshot.Investigation.Status())
		}
	}
	diagnosticStore, _ := storepg.NewDiagnosticStore(pool)
	diagnosticRequest := domain.DiagnosticRequest{
		RunID: runID, ClusterID: clusterID,
		Definition: domain.DiagnosticDefinitionRef{PackID: "standard.readonly", PackVersion: "1.1.0", DefinitionID: "gpu.ecc_counters", DefinitionVersion: "1.0.0", DefinitionDigest: domain.ChecksumSHA256([]byte("m12-link-definition"))},
		Privilege:  domain.DiagnosticUnprivileged, Targets: []domain.DiagnosticTarget{"comp001"}, RequestedBy: "test", IdempotencyKey: "m12-link-run-key-" + suffix,
		RequestedAt: now, Deadline: now.Add(20 * time.Minute), MaxAttempts: 1,
	}
	diagnosticRun, err := domain.NewDiagnosticRun(diagnosticRequest, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := diagnosticStore.CreateDiagnosticRun(ctx, diagnosticRun, domain.DiagnosticWorkID("m12-link-work-"+suffix), contextDiagnosticAudit("m12-link-audit-"+suffix, application.DiagnosticAuditStart, diagnosticRequest, "test", "ALLOWED", now)); err != nil || !created {
		t.Fatalf("create diagnostic: created=%t err=%v", created, err)
	}
	lease, found, err := diagnosticStore.ClaimDiagnosticWork(ctx, clusterID, "head-link", "m12-link-lease-"+suffix, time.Minute, contextDiagnosticAudit("m12-link-claim-"+suffix, application.DiagnosticAuditClaim, diagnosticRequest, "head-link", "CLAIMED", now.Add(time.Minute)))
	if err != nil || !found {
		t.Fatalf("claim diagnostic: found=%t err=%v", found, err)
	}
	terminalAt := now.Add(10 * time.Minute)
	exitCode := 0
	attempt := domain.DiagnosticAttemptResult{
		WorkID: lease.Work.WorkID, RunID: runID, Attempt: lease.Attempt, RunnerID: "head-link",
		PlanDigest: domain.ChecksumSHA256([]byte("m12-link-plan-" + suffix)), StartedAt: terminalAt.Add(-time.Second), CompletedAt: terminalAt,
		Targets: []domain.DiagnosticTargetResult{{Target: "comp001", Status: domain.DiagnosticTargetSucceeded, ExitCode: &exitCode, StdoutSHA256: domain.ChecksumSHA256(nil), StderrSHA256: domain.ChecksumSHA256(nil)}},
	}
	if _, recorded, err := diagnosticStore.RecordDiagnosticAttempt(ctx, clusterID, "head-link", lease, attempt, contextDiagnosticAudit("m12-link-result-"+suffix, application.DiagnosticAuditResult, diagnosticRequest, "head-link", "RECORDED", terminalAt)); err != nil || !recorded {
		t.Fatalf("record diagnostic: recorded=%t err=%v", recorded, err)
	}
	envelope, err := domain.DiagnosticEvidenceForAttempt(diagnosticRequest, attempt, 0)
	if err != nil {
		t.Fatal(err)
	}
	evidenceStore, err := storepg.NewEvidenceStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := evidenceStore.EnsureDiagnosticSource(ctx, clusterID, domain.DiagnosticEvidenceSourceID(clusterID)); err != nil {
		t.Fatal(err)
	}
	if _, err := evidenceStore.CreateEvidence(ctx, envelope); err != nil {
		t.Fatal(err)
	}
	executor.evidence = []domain.InvestigationEvidence{{
		EvidenceID: envelope.ID(), InvestigationID: request.ID, ClusterID: clusterID, EntityIDs: []string{"comp001"}, Status: envelope.Status(),
		ObservedStart: attempt.StartedAt, ObservedEnd: attempt.CompletedAt, RecordedAt: attempt.CompletedAt,
	}}
	crashing := &failFirstDiagnosticCompletionStore{InvestigationStore: store}
	controller, _ = application.NewInvestigationController(crashing, planner, executor, clock, platform.RandomIDGenerator{})
	if _, err := controller.Advance(ctx, request.ID); err == nil || !crashing.failed {
		t.Fatalf("simulated completion crash err=%v failed=%t", err, crashing.failed)
	}
	controller, _ = application.NewInvestigationController(store, planner, executor, clock, platform.RandomIDGenerator{})
	if _, err := controller.Advance(ctx, request.ID); err != nil {
		t.Fatalf("replay completion: %v", err)
	}
	var firstCompletionRecordedAt time.Time
	if err := pool.QueryRow(ctx, `SELECT completion_recorded_at FROM investigation_actions WHERE action_id=$1`, action.ID).Scan(&firstCompletionRecordedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Advance(ctx, request.ID); err != nil {
		t.Fatalf("persist after replay: %v", err)
	}
	var linked domain.DiagnosticRunID
	var actionCompletedAt, actionCompletionRecordedAt, attemptFinalizedAt, evidenceCreatedAt time.Time
	var associations, runs int
	if err := pool.QueryRow(ctx, `SELECT diagnostic_run_id FROM investigation_actions WHERE action_id=$1`, action.ID).Scan(&linked); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT completed_at,completion_recorded_at FROM investigation_actions WHERE action_id=$1`, action.ID).Scan(&actionCompletedAt, &actionCompletionRecordedAt); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT finalized_at FROM diagnostic_work_attempts WHERE work_id=$1 AND attempt=$2`, lease.Work.WorkID, lease.Attempt).Scan(&attemptFinalizedAt); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT created_at FROM evidence_envelopes WHERE evidence_id=$1`, envelope.ID()).Scan(&evidenceCreatedAt); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM investigation_actions WHERE investigation_id=$1 AND diagnostic_run_id=$2`, request.ID, runID).Scan(&associations); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM diagnostic_runs WHERE cluster_id=$1 AND idempotency_key=$2`, clusterID, diagnosticRequest.IdempotencyKey).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if linked != runID || associations != 1 || runs != 1 || executor.calls != 2 {
		t.Fatalf("linked=%s associations=%d runs=%d replay_calls=%d", linked, associations, runs, executor.calls)
	}
	if !actionCompletedAt.Before(terminalAt) {
		t.Fatalf("action completion=%s unexpectedly inherited remote future completion=%s", actionCompletedAt, terminalAt)
	}
	if evidenceCreatedAt.Before(attemptFinalizedAt) || actionCompletionRecordedAt.Before(evidenceCreatedAt) {
		t.Fatalf("server causal order invalid: attempt=%s evidence=%s action=%s", attemptFinalizedAt, evidenceCreatedAt, actionCompletionRecordedAt)
	}
	if !actionCompletionRecordedAt.Equal(firstCompletionRecordedAt) {
		t.Fatalf("action completion marker moved on replay: first=%s replay=%s", firstCompletionRecordedAt, actionCompletionRecordedAt)
	}
	snapshot, found, err := store.LoadInvestigation(ctx, request.ID)
	if err != nil || !found {
		t.Fatalf("load completed investigation: found=%t err=%v", found, err)
	}
	inputs, err := store.LoadInvestigationEvidenceContext(ctx, snapshot)
	if err != nil || len(inputs) != 1 || !inputs[0].AdmittedPostRequestDiagnostic {
		t.Fatalf("clock-ordered diagnostic admission inputs=%+v err=%v", inputs, err)
	}
}

func TestDiagnosticContextIncludesOnlyAllowlistedFailureCode(t *testing.T) {
	fixture := newDiagnosticContextFixture(t, []string{"comp001"}, map[string]bool{"comp001": true})
	for _, code := range []string{"DISPATCH_FAILED", "TARGET_ROLE_UNAVAILABLE", "ssh private-credential=do-not-print"} {
		if _, err := fixture.pool.Exec(fixture.ctx, `UPDATE diagnostic_target_results SET error_code=$2 WHERE work_id=$1`, fixture.workID, code); err != nil {
			t.Fatal(err)
		}
		inputs, err := fixture.load(t)
		if err != nil || len(inputs) != 1 {
			t.Fatalf("inputs=%+v err=%v", inputs, err)
		}
		if !strings.Contains(inputs[0].Summary, "error_code="+domain.SafeDiagnosticFailureCode(code)) || strings.Contains(inputs[0].Summary, "private-credential") {
			t.Fatalf("unsafe or missing code: %s", inputs[0].Summary)
		}
	}
}
