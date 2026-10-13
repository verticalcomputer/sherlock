//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestDiagnosticStoreApprovalAttributionRetryAndIdempotency(t *testing.T) {
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
	collections, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	store, err := storepg.NewDiagnosticStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("diagnostic-cluster-" + suffix)
	if err := collections.EnsureSource(ctx, clusterID, "Diagnostic cluster", domain.SourceID("diagnostic-source-"+suffix), "Diagnostic source"); err != nil {
		t.Fatal(err)
	}
	now := fixtureDatabaseTime(t, ctx, pool)
	definition := domain.DiagnosticDefinitionRef{PackID: "base", PackVersion: "1.0.0", DefinitionID: "gpu-query", DefinitionVersion: "1.0.0", DefinitionDigest: domain.ChecksumSHA256([]byte("definition"))}
	request := domain.DiagnosticRequest{
		RunID: domain.DiagnosticRunID("diagnostic-run-" + suffix), ClusterID: clusterID, Definition: definition,
		Privilege: domain.DiagnosticPrivileged, Targets: []domain.DiagnosticTarget{"node-1"},
		Arguments: []domain.DiagnosticArgument{{Name: "query", Value: "temperature"}}, RequestedBy: "actor-1",
		IdempotencyKey: "diagnostic-request-" + suffix, RequestedAt: now, Deadline: now.Add(10 * time.Minute), MaxAttempts: 2,
	}
	run, err := domain.NewDiagnosticRun(request, true)
	if err != nil {
		t.Fatal(err)
	}
	workID := domain.DiagnosticWorkID("diagnostic-work-" + suffix)
	startAudit := diagnosticAudit("audit-start-"+suffix, application.DiagnosticAuditStart, request, "actor-1", "ALLOWED", now)
	stored, created, err := store.CreateDiagnosticRun(ctx, run, workID, startAudit)
	if err != nil || !created {
		t.Fatalf("create diagnostic: created=%t err=%v", created, err)
	}
	requestReplay := request
	requestReplay.RunID = domain.DiagnosticRunID("ignored-retry-run-" + suffix)
	requestReplay.RequestedAt = now.Add(time.Second)
	replayedRun, err := domain.NewDiagnosticRun(requestReplay, true)
	if err != nil {
		t.Fatal(err)
	}
	_, created, err = store.CreateDiagnosticRun(ctx, replayedRun, domain.DiagnosticWorkID("ignored-work-"+suffix), diagnosticAudit("audit-replay-"+suffix, application.DiagnosticAuditStart, requestReplay, "actor-1", "ALLOWED", now.Add(time.Second)))
	if err != nil || created {
		t.Fatalf("idempotent retry: created=%t err=%v", created, err)
	}
	approval := domain.DiagnosticApproval{
		ApprovalID: domain.DiagnosticApprovalID("approval-" + suffix), RunID: request.RunID,
		DefinitionDigest: definition.DefinitionDigest, TargetDigest: domain.DiagnosticTargetsDigest(request.Targets),
		ApprovedBy: "operator-1", ApprovedAt: now, ExpiresAt: now.Add(5 * time.Minute), RunVersion: stored.Version(),
	}
	approved, err := stored.Approve(approval, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ApproveDiagnosticRun(ctx, approved, approval, diagnosticAudit("audit-approval-"+suffix, application.DiagnosticAuditApproval, request, "operator-1", "APPROVED", now)); err != nil {
		t.Fatal(err)
	}
	lease, found, err := store.ClaimDiagnosticWork(ctx, clusterID, "runner-1", "lease-token-1", time.Minute, application.DiagnosticAuditEvent{EventID: "audit-claim-1-" + suffix, Kind: application.DiagnosticAuditClaim, ClusterID: clusterID, ActorID: "runner-1", Outcome: "CLAIMED", OccurredAt: now})
	if err != nil || !found {
		t.Fatalf("claim attempt 1: found=%t err=%v", found, err)
	}
	// Reconstruct from PostgreSQL exactly as a fresh control process does. No
	// in-memory lease registry is available after restart.
	reconstructed, err := store.LoadDiagnosticWorkLease(ctx, clusterID, "runner-1", workID, 1, "lease-token-1")
	if err != nil {
		t.Fatalf("reconstruct claimed lease after restart: %v", err)
	}
	if reconstructed.Work.WorkID != lease.Work.WorkID || reconstructed.Work.Run.Request().RunID != request.RunID || reconstructed.LeaseToken != "lease-token-1" {
		t.Fatalf("reconstructed lease = %+v", reconstructed)
	}
	if _, err := store.LoadDiagnosticWorkLease(ctx, clusterID, "runner-1", workID, 1, "wrong-token"); !errors.Is(err, application.ErrDiagnosticLeaseInvalid) {
		t.Fatalf("wrong token reconstructed a lease: %v", err)
	}
	lease = reconstructed
	failed := domain.DiagnosticAttemptResult{
		WorkID: workID, RunID: request.RunID, Attempt: 1, RunnerID: "runner-1", PlanDigest: domain.ChecksumSHA256([]byte("plan")), StartedAt: now, CompletedAt: now.Add(time.Second),
		Targets: []domain.DiagnosticTargetResult{{Target: "node-1", Status: domain.DiagnosticTargetTimedOut, Retryable: true, TimedOut: true, ErrorCode: "DEADLINE_EXCEEDED", StdoutSHA256: domain.ChecksumSHA256(nil), StderrSHA256: domain.ChecksumSHA256(nil)}},
	}
	retrying, recorded, err := store.RecordDiagnosticAttempt(ctx, clusterID, "runner-1", lease, failed, diagnosticAudit("audit-result-1-"+suffix, application.DiagnosticAuditResult, request, "runner-1", "RECORDED", now.Add(time.Second)))
	if err != nil || !recorded || retrying.Status() != domain.DiagnosticRunning {
		t.Fatalf("retryable result: status=%s recorded=%t err=%v", retrying.Status(), recorded, err)
	}
	lease, found, err = store.ClaimDiagnosticWork(ctx, clusterID, "runner-1", "lease-token-2", time.Minute, application.DiagnosticAuditEvent{EventID: "audit-claim-2-" + suffix, Kind: application.DiagnosticAuditClaim, ClusterID: clusterID, ActorID: "runner-1", Outcome: "CLAIMED", OccurredAt: now.Add(2 * time.Second)})
	if err != nil || !found || lease.Attempt != 2 {
		t.Fatalf("claim attempt 2: lease=%+v found=%t err=%v", lease, found, err)
	}
	succeeded := failed
	succeeded.Attempt, succeeded.StartedAt, succeeded.CompletedAt = 2, now.Add(2*time.Second), now.Add(3*time.Second)
	succeeded.Targets[0] = domain.DiagnosticTargetResult{Target: "node-1", Status: domain.DiagnosticTargetSucceeded, ExitCode: intPointer(0), StdoutBytes: 10, StdoutSHA256: domain.ChecksumSHA256([]byte("safe output")), StderrSHA256: domain.ChecksumSHA256(nil), StdoutTransformationState: domain.StdoutTransformationUnmodified}
	completed, recorded, err := store.RecordDiagnosticAttempt(ctx, clusterID, "runner-1", lease, succeeded, diagnosticAudit("audit-result-2-"+suffix, application.DiagnosticAuditResult, request, "runner-1", "RECORDED", now.Add(3*time.Second)))
	if err != nil || !recorded || completed.Status() != domain.DiagnosticSucceeded {
		t.Fatalf("successful result: status=%s recorded=%t err=%v", completed.Status(), recorded, err)
	}
	_, recorded, err = store.RecordDiagnosticAttempt(ctx, clusterID, "runner-1", lease, succeeded, diagnosticAudit("audit-result-replay-"+suffix, application.DiagnosticAuditResult, request, "runner-1", "RECORDED", now.Add(4*time.Second)))
	if err != nil || recorded {
		t.Fatalf("idempotent result replay: recorded=%t err=%v", recorded, err)
	}
	var persistedProof string
	if err := pool.QueryRow(ctx, `SELECT stdout_transformation_state FROM diagnostic_target_results WHERE work_id=$1 AND attempt=2 AND target='node-1'`, workID).Scan(&persistedProof); err != nil {
		t.Fatal(err)
	}
	if persistedProof != "UNMODIFIED" {
		t.Fatalf("durable proof = %q", persistedProof)
	}
	changedProof := succeeded
	changedProof.Targets = append([]domain.DiagnosticTargetResult(nil), succeeded.Targets...)
	changedProof.Targets[0].StdoutTransformationState = domain.StdoutTransformationTransformed
	if _, recorded, err := store.RecordDiagnosticAttempt(ctx, clusterID, "runner-1", lease, changedProof, diagnosticAudit("audit-result-conflict-"+suffix, application.DiagnosticAuditResult, request, "runner-1", "RECORDED", now.Add(5*time.Second))); !errors.Is(err, application.ErrDiagnosticConflict) || recorded {
		t.Fatalf("changed proof replay: recorded=%t err=%v", recorded, err)
	}
	var attempts, results, audits int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM diagnostic_work_attempts WHERE work_id=$1), (SELECT count(*) FROM diagnostic_target_results WHERE work_id=$1), (SELECT count(*) FROM diagnostic_audit_events WHERE run_id=$2)`, workID, request.RunID).Scan(&attempts, &results, &audits); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || results != 2 || audits != 8 {
		t.Fatalf("durable attribution counts attempts=%d results=%d audits=%d", attempts, results, audits)
	}
	var forbiddenColumns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name LIKE 'diagnostic_%' AND column_name IN ('credential','credential_value','stdout','stderr','raw_output')`).Scan(&forbiddenColumns); err != nil {
		t.Fatal(err)
	}
	if forbiddenColumns != 0 {
		t.Fatalf("diagnostic persistence exposes %d forbidden secret/raw-output columns", forbiddenColumns)
	}
}

func diagnosticAudit(id string, kind application.DiagnosticAuditKind, request domain.DiagnosticRequest, actor, outcome string, at time.Time) application.DiagnosticAuditEvent {
	return application.DiagnosticAuditEvent{EventID: id, Kind: kind, RunID: request.RunID, ClusterID: request.ClusterID, ActorID: actor, Outcome: outcome, OccurredAt: at, DefinitionDigest: request.Definition.DefinitionDigest, TargetDigest: domain.DiagnosticTargetsDigest(request.Targets)}
}

func intPointer(value int) *int { return &value }

func TestDiagnosticClaimsAndResultsAreClusterAndCollectorScoped(t *testing.T) {
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
	store, _ := storepg.NewDiagnosticStore(pool)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	now := fixtureDatabaseTime(t, ctx, pool)
	definition := domain.DiagnosticDefinitionRef{PackID: "standard.readonly", PackVersion: "1.1.0", DefinitionID: "gpu.ecc_counters", DefinitionVersion: "1.0.0", DefinitionDigest: domain.ChecksumSHA256([]byte("cluster-scope-definition"))}
	type fixture struct {
		cluster domain.ClusterID
		request domain.DiagnosticRequest
		work    domain.DiagnosticWorkID
	}
	fixtures := make([]fixture, 0, 2)
	for _, label := range []string{"a", "b"} {
		clusterID := domain.ClusterID("scope-cluster-" + label + "-" + suffix)
		if err := collections.EnsureSource(ctx, clusterID, "Scope cluster "+label, domain.SourceID("scope-source-"+label+"-"+suffix), "Scope source"); err != nil {
			t.Fatal(err)
		}
		request := domain.DiagnosticRequest{
			RunID: domain.DiagnosticRunID("scope-run-" + label + "-" + suffix), ClusterID: clusterID, Definition: definition,
			Privilege: domain.DiagnosticUnprivileged, Targets: []domain.DiagnosticTarget{"comp001"}, RequestedBy: "scope-test",
			IdempotencyKey: "scope-key-" + label + "-" + suffix, RequestedAt: now, Deadline: now.Add(10 * time.Minute), MaxAttempts: 1,
		}
		run, err := domain.NewDiagnosticRun(request, false)
		if err != nil {
			t.Fatal(err)
		}
		workID := domain.DiagnosticWorkID("scope-work-" + label + "-" + suffix)
		if _, created, err := store.CreateDiagnosticRun(ctx, run, workID, diagnosticAudit("scope-start-"+label+"-"+suffix, application.DiagnosticAuditStart, request, "scope-test", "ALLOWED", now)); err != nil || !created {
			t.Fatalf("create %s: created=%t err=%v", label, created, err)
		}
		fixtures = append(fixtures, fixture{cluster: clusterID, request: request, work: workID})
	}

	clusterB := fixtures[1]
	collectorB := domain.CollectorID("scope-collector-b")
	lease, found, err := store.ClaimDiagnosticWork(ctx, clusterB.cluster, collectorB, "scope-token-b", time.Minute, application.DiagnosticAuditEvent{
		EventID: "scope-claim-b-" + suffix, Kind: application.DiagnosticAuditClaim, ClusterID: clusterB.cluster,
		ActorID: string(collectorB), Outcome: "CLAIMED", OccurredAt: now,
	})
	if err != nil || !found {
		t.Fatalf("cluster B claim: found=%t err=%v", found, err)
	}
	if lease.Work.WorkID != clusterB.work || lease.Work.Run.Request().ClusterID != clusterB.cluster {
		t.Fatalf("cluster B claimed cross-cluster work: %+v", lease.Work.Run.Request())
	}

	exitCode := 0
	result := domain.DiagnosticAttemptResult{
		WorkID: clusterB.work, RunID: clusterB.request.RunID, Attempt: lease.Attempt, RunnerID: string(collectorB),
		PlanDigest: domain.ChecksumSHA256([]byte("scope-plan")), StartedAt: now, CompletedAt: now.Add(time.Second),
		Targets: []domain.DiagnosticTargetResult{{Target: "comp001", Status: domain.DiagnosticTargetSucceeded, ExitCode: &exitCode, StdoutSHA256: domain.ChecksumSHA256([]byte("ok")), StderrSHA256: domain.ChecksumSHA256(nil)}},
	}
	wrongClusterAudit := diagnosticAudit("scope-wrong-cluster-"+suffix, application.DiagnosticAuditResult, clusterB.request, string(collectorB), "RECORDED", now.Add(time.Second))
	wrongClusterAudit.ClusterID = fixtures[0].cluster
	if _, _, err := store.RecordDiagnosticAttempt(ctx, fixtures[0].cluster, collectorB, lease, result, wrongClusterAudit); !errors.Is(err, application.ErrDiagnosticLeaseInvalid) {
		t.Fatalf("cross-cluster result was accepted: %v", err)
	}
	foreignCollector := domain.CollectorID("scope-collector-foreign")
	foreignResult := result
	foreignResult.RunnerID = string(foreignCollector)
	foreignAudit := diagnosticAudit("scope-foreign-collector-"+suffix, application.DiagnosticAuditResult, clusterB.request, string(foreignCollector), "RECORDED", now.Add(time.Second))
	if _, _, err := store.RecordDiagnosticAttempt(ctx, clusterB.cluster, foreignCollector, lease, foreignResult, foreignAudit); !errors.Is(err, application.ErrDiagnosticLeaseInvalid) {
		t.Fatalf("foreign collector result was accepted: %v", err)
	}
	var persisted int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM diagnostic_target_results WHERE work_id=$1`, clusterB.work).Scan(&persisted); err != nil || persisted != 0 {
		t.Fatalf("denied result persistence count=%d err=%v", persisted, err)
	}
	if _, recorded, err := store.RecordDiagnosticAttempt(ctx, clusterB.cluster, collectorB, lease, result, diagnosticAudit("scope-result-b-"+suffix, application.DiagnosticAuditResult, clusterB.request, string(collectorB), "RECORDED", now.Add(time.Second))); err != nil || !recorded {
		t.Fatalf("authorized result: recorded=%t err=%v", recorded, err)
	}

	clusterA := fixtures[0]
	leaseA, found, err := store.ClaimDiagnosticWork(ctx, clusterA.cluster, "scope-collector-a", "scope-token-a", time.Minute, application.DiagnosticAuditEvent{
		EventID: "scope-claim-a-" + suffix, Kind: application.DiagnosticAuditClaim, ClusterID: clusterA.cluster,
		ActorID: "scope-collector-a", Outcome: "CLAIMED", OccurredAt: now.Add(2 * time.Second),
	})
	if err != nil || !found || leaseA.Work.WorkID != clusterA.work {
		t.Fatalf("cluster A claim: lease=%s found=%t err=%v", leaseA.Work.WorkID, found, err)
	}
}

// The full pull path: a queued diagnostic is claimed over the collector lease
// machinery, executed by the head node against a verified pack, and its result
// finalized -- landing as an ordinary evidence envelope. This is the property
// M12 rests on, so it is proved against a real database rather than a fake.
func TestDiagnosticWorkClaimsExecutesAndLandsAsEvidence(t *testing.T) {
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
	collections, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	store, err := storepg.NewDiagnosticStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("m12w-cluster-" + suffix)
	if err := collections.EnsureSource(ctx, clusterID, "M12 work cluster", domain.SourceID("m12w-source-"+suffix), "M12 source"); err != nil {
		t.Fatal(err)
	}
	now := fixtureDatabaseTime(t, ctx, pool)
	definition := domain.DiagnosticDefinitionRef{PackID: "standard.readonly", PackVersion: "1.1.0", DefinitionID: "gpu.ecc_counters", DefinitionVersion: "1.0.0", DefinitionDigest: domain.ChecksumSHA256([]byte("ecc-definition"))}
	request := domain.DiagnosticRequest{
		RunID: domain.DiagnosticRunID("m12w-run-" + suffix), ClusterID: clusterID, Definition: definition,
		Privilege: domain.DiagnosticUnprivileged, Targets: []domain.DiagnosticTarget{"comp001", "comp002"},
		RequestedBy: "sherlock-investigator", IdempotencyKey: "m12w-key-" + suffix,
		RequestedAt: now, Deadline: now.Add(10 * time.Minute), MaxAttempts: 1,
	}
	// An unprivileged diagnostic needs no approval, which is the whole point of
	// closing the ECC gap without a privilege adapter.
	run, err := domain.NewDiagnosticRun(request, false)
	if err != nil {
		t.Fatal(err)
	}
	workID := domain.DiagnosticWorkID("m12w-work-" + suffix)
	if _, created, err := store.CreateDiagnosticRun(ctx, run, workID, diagnosticAudit("m12w-audit-start-"+suffix, application.DiagnosticAuditStart, request, "sherlock-investigator", "ALLOWED", now)); err != nil || !created {
		t.Fatalf("create diagnostic: created=%t err=%v", created, err)
	}

	lease, found, err := store.ClaimDiagnosticWork(ctx, clusterID, "head-1", "m12w-lease-token", time.Minute, application.DiagnosticAuditEvent{EventID: "m12w-audit-claim-" + suffix, Kind: application.DiagnosticAuditClaim, ClusterID: clusterID, ActorID: "head-1", Outcome: "CLAIMED", OccurredAt: now})
	if err != nil || !found {
		t.Fatalf("an unprivileged diagnostic must be claimable without approval: found=%t err=%v", found, err)
	}
	if lease.Work.WorkID != workID || lease.Attempt != 1 {
		t.Fatalf("lease = %+v", lease)
	}
	claimed := lease.Work.Run.Request()
	if claimed.Definition.DefinitionID != "gpu.ecc_counters" || len(claimed.Targets) != 2 {
		t.Fatalf("the claimed invocation lost its definition or targets: %+v", claimed)
	}

	exitCode := 0
	attempt := domain.DiagnosticAttemptResult{
		WorkID: workID, RunID: request.RunID, Attempt: 1, RunnerID: "head-1", PlanDigest: domain.ChecksumSHA256([]byte("m12w-plan")),
		StartedAt: now.Add(time.Second), CompletedAt: now.Add(3 * time.Second),
		Targets: []domain.DiagnosticTargetResult{
			{Target: "comp001", Status: domain.DiagnosticTargetSucceeded, ExitCode: &exitCode, StdoutBytes: 256, StdoutSHA256: domain.ChecksumSHA256([]byte("comp001")), StderrSHA256: domain.ChecksumSHA256(nil), StdoutExcerpt: "volatile_ecc_uncorrected: 4"},
			{Target: "comp002", Status: domain.DiagnosticTargetSucceeded, ExitCode: &exitCode, StdoutBytes: 192, StdoutSHA256: domain.ChecksumSHA256([]byte("comp002")), StderrSHA256: domain.ChecksumSHA256(nil), StdoutExcerpt: "volatile_ecc_uncorrected: 0"},
		},
	}
	completed, recorded, err := store.RecordDiagnosticAttempt(ctx, clusterID, "head-1", lease, attempt, diagnosticAudit("m12w-audit-result-"+suffix, application.DiagnosticAuditResult, request, "head-1", "RECORDED", now.Add(3*time.Second)))
	if err != nil || !recorded {
		t.Fatalf("record: recorded=%t err=%v", recorded, err)
	}
	if completed.Status() != domain.DiagnosticSucceeded {
		t.Fatalf("status = %s, want SUCCEEDED", completed.Status())
	}

	// An exact replay must not execute or record a second time.
	_, recordedAgain, err := store.RecordDiagnosticAttempt(ctx, clusterID, "head-1", lease, attempt, diagnosticAudit("m12w-audit-replay-"+suffix, application.DiagnosticAuditResult, request, "head-1", "RECORDED", now.Add(4*time.Second)))
	if err != nil {
		t.Fatalf("an exact replay must be accepted, not rejected: %v", err)
	}
	if recordedAgain {
		t.Fatal("an exact replay recorded a second attempt")
	}

	// The finalized attempt projects into an ordinary evidence envelope.
	envelope, err := domain.DiagnosticEvidenceForAttempt(claimed, attempt, 0)
	if err != nil {
		t.Fatalf("the finalized attempt did not project into evidence: %v", err)
	}
	if envelope.Status() != domain.EvidenceComplete || !envelope.Coverage().Complete() {
		t.Fatalf("envelope = %s complete=%t", envelope.Status(), envelope.Coverage().Complete())
	}
	if envelope.Source().Operation != domain.EvidenceOperationID("gpu.ecc_counters") {
		t.Fatalf("operation = %q", envelope.Source().Operation)
	}
	if !envelope.TimeRange().Start.Equal(attempt.StartedAt) || !envelope.TimeRange().End.Equal(attempt.CompletedAt) {
		t.Fatalf("the observed window is not the execution window: %s to %s", envelope.TimeRange().Start, envelope.TimeRange().End)
	}

	// The queue is drained: nothing re-claims completed work.
	if _, found, err := store.ClaimDiagnosticWork(ctx, clusterID, "head-1", "m12w-lease-token-2", time.Minute, application.DiagnosticAuditEvent{EventID: "m12w-audit-claim-2-" + suffix, Kind: application.DiagnosticAuditClaim, ClusterID: clusterID, ActorID: "head-1", Outcome: "CLAIMED", OccurredAt: now.Add(5 * time.Second)}); err != nil {
		t.Fatal(err)
	} else if found && lease.Work.WorkID == workID {
		var status string
		if err := pool.QueryRow(ctx, `SELECT status FROM diagnostic_work WHERE work_id=$1`, workID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != "COMPLETED" && status != "SUCCEEDED" {
			t.Fatalf("completed diagnostic work is still queued as %s", status)
		}
	}
}

// A diagnostic used to reach the model with no values. The context builder read
// the observations table by run ID, and a diagnostic writes no observations, so
// the model was told a probe ran and succeeded but never what it found -- which
// is the one thing the probe was run to establish.
func TestKernelXIDTypedExcerptPersistsAndIsLookupable(t *testing.T) {
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
	collections, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	diagnostics, err := storepg.NewDiagnosticStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := storepg.NewEvidenceStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	investigations, err := storepg.NewInvestigationStore(pool)
	if err != nil {
		t.Fatal(err)
	}

	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("m12ctx-cluster-" + suffix)
	if err := collections.EnsureSource(ctx, clusterID, "M12 context cluster", domain.SourceID("m12ctx-source-"+suffix), "M12 source"); err != nil {
		t.Fatal(err)
	}
	now := fixtureDatabaseTime(t, ctx, pool)
	definition := domain.DiagnosticDefinitionRef{PackID: "standard.readonly", PackVersion: "1.1.0", DefinitionID: "node.kernel_xid", DefinitionVersion: "2.0.0", DefinitionDigest: domain.ChecksumSHA256([]byte("kernel-xid-definition"))}
	request := domain.DiagnosticRequest{
		RunID: domain.DiagnosticRunID("m12ctx-run-" + suffix), ClusterID: clusterID, Definition: definition,
		Privilege: domain.DiagnosticUnprivileged, Targets: []domain.DiagnosticTarget{"comp001"},
		RequestedBy: "sherlock-investigator", IdempotencyKey: "m12ctx-key-" + suffix,
		RequestedAt: now, Deadline: now.Add(10 * time.Minute), MaxAttempts: 1,
	}
	run, err := domain.NewDiagnosticRun(request, false)
	if err != nil {
		t.Fatal(err)
	}
	workID := domain.DiagnosticWorkID("m12ctx-work-" + suffix)
	if _, created, err := diagnostics.CreateDiagnosticRun(ctx, run, workID, diagnosticAudit("m12ctx-audit-start-"+suffix, application.DiagnosticAuditStart, request, "sherlock-investigator", "ALLOWED", now)); err != nil || !created {
		t.Fatalf("create diagnostic: created=%t err=%v", created, err)
	}
	lease, found, err := diagnostics.ClaimDiagnosticWork(ctx, clusterID, "head-1", "m12ctx-lease-token", time.Minute, application.DiagnosticAuditEvent{EventID: "m12ctx-audit-claim-" + suffix, Kind: application.DiagnosticAuditClaim, ClusterID: clusterID, ActorID: "head-1", Outcome: "CLAIMED", OccurredAt: now})
	if err != nil || !found {
		t.Fatalf("claim: found=%t err=%v", found, err)
	}
	exitCode := 0
	probeOutput := `{"parser_version":"sherlock.kernel-xid.v1","events":[{"observed_at":"2026-09-22T10:00:00Z","xid_code":94,"pci_bdf":"0000:01:00"}],"gaps":[]}`
	attempt := domain.DiagnosticAttemptResult{
		WorkID: workID, RunID: request.RunID, Attempt: 1, RunnerID: "head-1", PlanDigest: domain.ChecksumSHA256([]byte("m12ctx-plan")),
		StartedAt: now.Add(time.Second), CompletedAt: now.Add(3 * time.Second),
		Targets: []domain.DiagnosticTargetResult{
			{Target: "comp001", Status: domain.DiagnosticTargetSucceeded, ExitCode: &exitCode, StdoutBytes: int64(len(probeOutput)), StdoutSHA256: domain.ChecksumSHA256([]byte(probeOutput)), StderrSHA256: domain.ChecksumSHA256(nil), StdoutExcerpt: probeOutput},
		},
	}
	if _, recorded, err := diagnostics.RecordDiagnosticAttempt(ctx, clusterID, "head-1", lease, attempt, diagnosticAudit("m12ctx-audit-result-"+suffix, application.DiagnosticAuditResult, request, "head-1", "RECORDED", now.Add(3*time.Second))); err != nil || !recorded {
		t.Fatalf("record: recorded=%t err=%v", recorded, err)
	}

	envelope, err := domain.DiagnosticEvidenceForAttempt(lease.Work.Run.Request(), attempt, 0)
	if err != nil {
		t.Fatal(err)
	}
	// A diagnostic's source is the reviewed pack, not a polled system, so no
	// collector provisions it. Without this the commit fails on the envelope's
	// foreign key and the execution is lost after the work was already done.
	if err := evidence.EnsureDiagnosticSource(ctx, clusterID, domain.DiagnosticEvidenceSourceID(clusterID)); err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.CreateEvidence(ctx, envelope); err != nil {
		t.Fatal(err)
	}
	entries, more, err := investigations.FindInvestigationEvidenceByOperations(ctx, "inv-kernel-lookup-"+domain.InvestigationID(suffix), clusterID, []string{"comp001"}, attempt.StartedAt.Add(-time.Minute), attempt.CompletedAt.Add(time.Minute), now.Add(time.Hour), []domain.EvidenceOperationID{"node.kernel_xid"}, 10)
	if err != nil || more || len(entries) != 1 || entries[0].EvidenceID != envelope.ID() {
		t.Fatalf("kernel lookup entries=%+v more=%t err=%v", entries, more, err)
	}

	requestedAt := now.Add(time.Hour)
	contextRequest := domain.InvestigationRequest{
		ID: "inv-diagctx-" + domain.InvestigationID(suffix), IncidentID: "incident-diagctx-" + domain.IncidentID(suffix), ClusterID: clusterID,
		Question: "What did the bounded kernel XID probe find on comp001?", RequestedBy: "test", IdempotencyKey: "diagctx-" + suffix,
		Scope:           domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"comp001"}, Start: attempt.StartedAt.Add(-time.Minute), End: attempt.CompletedAt.Add(time.Minute)},
		SuccessCriteria: []string{"cite the diagnostic result"}, Budget: domain.InvestigationBudget{MaxDecisions: 2, MaxToolCalls: 1, MaxFanOut: 1},
		RequestedAt: requestedAt, Deadline: requestedAt.Add(time.Hour),
	}
	value, err := domain.NewInvestigation(contextRequest)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := domain.NewEvidenceLedger([]domain.InvestigationEvidence{{EvidenceID: envelope.ID(), InvestigationID: contextRequest.ID, ClusterID: clusterID, EntityIDs: []string{"comp001"}, Status: envelope.Status(), ObservedStart: envelope.TimeRange().Start, ObservedEnd: envelope.TimeRange().End, RecordedAt: requestedAt}}, value)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := investigations.LoadInvestigationEvidenceContext(ctx, application.InvestigationSnapshot{Investigation: value, Evidence: ledger})
	if err != nil || len(inputs) != 1 {
		t.Fatalf("context=%+v err=%v", inputs, err)
	}

	// The values must actually be there. This is the whole defect.
	if inputs[0].SummaryQuality != "MEANINGFUL" {
		t.Fatalf("a diagnostic still reaches the model as provenance only: %q", inputs[0].SummaryQuality)
	}
	if !strings.Contains(inputs[0].Excerpt, `"xid_code":94`) || !strings.Contains(inputs[0].Excerpt, `"pci_bdf":"0000:01:00"`) {
		t.Fatalf("the probe's output did not reach the model: %q", inputs[0].Excerpt)
	}
	if !strings.Contains(inputs[0].Summary, "comp001=SUCCEEDED") || !strings.Contains(inputs[0].Summary, "exit=0") {
		t.Fatalf("the summary does not account for the execution: %q", inputs[0].Summary)
	}

	// Host output is untrusted, so it belongs in the excerpt channel only. The
	// summary is Sherlock's own account and must not carry it.
	if strings.Contains(inputs[0].Summary, "xid_code") {
		t.Fatalf("untrusted host output was promoted into the trusted summary: %q", inputs[0].Summary)
	}
	if strings.Contains(inputs[0].Excerpt, databaseURL) {
		t.Fatalf("context leaked connection detail: %q", inputs[0].Excerpt)
	}
}

// TestDiagnosticEvidenceReachesTheModelWithItsValues preserves the generic ECC
// regression independently of the kernel-XID typed-path regression above.
func TestDiagnosticEvidenceReachesTheModelWithItsValues(t *testing.T) {
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
	diagnostics, _ := storepg.NewDiagnosticStore(pool)
	evidence, _ := storepg.NewEvidenceStore(pool)
	investigations, _ := storepg.NewInvestigationStore(pool)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("m12eccctx-cluster-" + suffix)
	if err := collections.EnsureSource(ctx, clusterID, "M12 ECC context cluster", domain.SourceID("m12eccctx-source-"+suffix), "M12 source"); err != nil {
		t.Fatal(err)
	}
	now := fixtureDatabaseTime(t, ctx, pool)
	definition := domain.DiagnosticDefinitionRef{PackID: "standard.readonly", PackVersion: "1.1.0", DefinitionID: "gpu.ecc_counters", DefinitionVersion: "1.0.0", DefinitionDigest: domain.ChecksumSHA256([]byte("ecc-definition"))}
	request := domain.DiagnosticRequest{RunID: domain.DiagnosticRunID("m12eccctx-run-" + suffix), ClusterID: clusterID, Definition: definition, Privilege: domain.DiagnosticUnprivileged, Targets: []domain.DiagnosticTarget{"comp001"}, RequestedBy: "sherlock-investigator", IdempotencyKey: "m12eccctx-key-" + suffix, RequestedAt: now, Deadline: now.Add(10 * time.Minute), MaxAttempts: 1}
	run, err := domain.NewDiagnosticRun(request, false)
	if err != nil {
		t.Fatal(err)
	}
	workID := domain.DiagnosticWorkID("m12eccctx-work-" + suffix)
	if _, created, err := diagnostics.CreateDiagnosticRun(ctx, run, workID, diagnosticAudit("m12eccctx-start-"+suffix, application.DiagnosticAuditStart, request, "sherlock-investigator", "ALLOWED", now)); err != nil || !created {
		t.Fatalf("create created=%t err=%v", created, err)
	}
	lease, found, err := diagnostics.ClaimDiagnosticWork(ctx, clusterID, "head-1", "m12eccctx-lease-token", time.Minute, application.DiagnosticAuditEvent{EventID: "m12eccctx-claim-" + suffix, Kind: application.DiagnosticAuditClaim, ClusterID: clusterID, ActorID: "head-1", Outcome: "CLAIMED", OccurredAt: now})
	if err != nil || !found {
		t.Fatalf("claim found=%t err=%v", found, err)
	}
	exit := 0
	output := "volatile_ecc_uncorrected: 4\nretired_pages_pending: 1"
	attempt := domain.DiagnosticAttemptResult{WorkID: workID, RunID: request.RunID, Attempt: 1, RunnerID: "head-1", PlanDigest: domain.ChecksumSHA256([]byte("m12eccctx-plan")), StartedAt: now.Add(time.Second), CompletedAt: now.Add(3 * time.Second), Targets: []domain.DiagnosticTargetResult{{Target: "comp001", Status: domain.DiagnosticTargetSucceeded, ExitCode: &exit, StdoutBytes: int64(len(output)), StdoutSHA256: domain.ChecksumSHA256([]byte(output)), StderrSHA256: domain.ChecksumSHA256(nil), StdoutExcerpt: output}}}
	if _, recorded, err := diagnostics.RecordDiagnosticAttempt(ctx, clusterID, "head-1", lease, attempt, diagnosticAudit("m12eccctx-result-"+suffix, application.DiagnosticAuditResult, request, "head-1", "RECORDED", now.Add(3*time.Second))); err != nil || !recorded {
		t.Fatalf("record recorded=%t err=%v", recorded, err)
	}
	envelope, err := domain.DiagnosticEvidenceForAttempt(lease.Work.Run.Request(), attempt, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := evidence.EnsureDiagnosticSource(ctx, clusterID, domain.DiagnosticEvidenceSourceID(clusterID)); err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.CreateEvidence(ctx, envelope); err != nil {
		t.Fatal(err)
	}
	requestedAt := now.Add(time.Hour)
	value, err := domain.NewInvestigation(domain.InvestigationRequest{ID: "inv-eccctx-" + domain.InvestigationID(suffix), IncidentID: "incident-eccctx-" + domain.IncidentID(suffix), ClusterID: clusterID, Question: "What did the ECC probe find?", RequestedBy: "test", IdempotencyKey: "eccctx-" + suffix, Scope: domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"comp001"}, Start: attempt.StartedAt.Add(-time.Minute), End: attempt.CompletedAt.Add(time.Minute)}, SuccessCriteria: []string{"cite the diagnostic result"}, Budget: domain.InvestigationBudget{MaxDecisions: 2, MaxToolCalls: 1, MaxFanOut: 1}, RequestedAt: requestedAt, Deadline: requestedAt.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := domain.NewEvidenceLedger([]domain.InvestigationEvidence{{EvidenceID: envelope.ID(), InvestigationID: "inv-eccctx-" + domain.InvestigationID(suffix), ClusterID: clusterID, EntityIDs: []string{"comp001"}, Status: envelope.Status(), ObservedStart: envelope.TimeRange().Start, ObservedEnd: envelope.TimeRange().End, RecordedAt: requestedAt}}, value)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := investigations.LoadInvestigationEvidenceContext(ctx, application.InvestigationSnapshot{Investigation: value, Evidence: ledger})
	if err != nil || len(inputs) != 1 {
		t.Fatalf("context=%+v err=%v", inputs, err)
	}
	if inputs[0].SummaryQuality != "MEANINGFUL" || !strings.Contains(inputs[0].Excerpt, "volatile_ecc_uncorrected: 4") || !strings.Contains(inputs[0].Excerpt, "retired_pages_pending: 1") || strings.Contains(inputs[0].Summary, "volatile_ecc_uncorrected") {
		t.Fatalf("generic ECC context changed: %+v", inputs[0])
	}
}
