//go:build integration

package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adapters/kernelxid"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestKernelXIDArtifactStoreBindsReadsExpiresDeletesAndRejectsCorruption(t *testing.T) {
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
	collections, _ := NewCollectionStore(pool)
	diagnostics, _ := NewDiagnosticStore(pool)
	artifacts, err := NewKernelXIDArtifactStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	cluster := domain.ClusterID("kernel-artifact-cluster-" + suffix)
	if err := collections.EnsureSource(ctx, cluster, "Kernel artifact cluster", domain.SourceID("kernel-artifact-source-"+suffix), "Kernel artifact source"); err != nil {
		t.Fatal(err)
	}
	now := kernelArtifactDatabaseTime(t, ctx, pool)
	definition := domain.DiagnosticDefinitionRef{PackID: "standard.readonly", PackVersion: "1.3.0", DefinitionID: "node.kernel_xid", DefinitionVersion: "2.0.0", DefinitionDigest: domain.ChecksumSHA256([]byte("kernel-artifact-definition"))}
	request := domain.DiagnosticRequest{RunID: domain.DiagnosticRunID("kernel-artifact-run-" + suffix), ClusterID: cluster, Definition: definition, Privilege: domain.DiagnosticUnprivileged, Targets: []domain.DiagnosticTarget{"comp001", "comp002", "comp003", "comp004", "comp005", "comp006", "comp007", "comp008", "comp009"}, RequestedBy: "artifact-test", IdempotencyKey: "kernel-artifact-key-" + suffix, RequestedAt: now, Deadline: now.Add(10 * time.Minute), MaxAttempts: 1}
	run, err := domain.NewDiagnosticRun(request, false)
	if err != nil {
		t.Fatal(err)
	}
	work := domain.DiagnosticWorkID("kernel-artifact-work-" + suffix)
	if _, created, err := diagnostics.CreateDiagnosticRun(ctx, run, work, kernelArtifactAudit("kernel-artifact-start-"+suffix, application.DiagnosticAuditStart, request, "artifact-test", "ALLOWED", now)); err != nil || !created {
		t.Fatalf("create: created=%t err=%v", created, err)
	}
	lease, found, err := diagnostics.ClaimDiagnosticWork(ctx, cluster, "artifact-head", "kernel-artifact-token", time.Minute, application.DiagnosticAuditEvent{EventID: "kernel-artifact-claim-" + suffix, Kind: application.DiagnosticAuditClaim, ClusterID: cluster, ActorID: "artifact-head", Outcome: "CLAIMED", OccurredAt: now, DefinitionDigest: request.Definition.DefinitionDigest, TargetDigest: domain.DiagnosticTargetsDigest(request.Targets)})
	if err != nil || !found {
		t.Fatalf("claim: found=%t err=%v", found, err)
	}
	exitCode := 0
	outputs := map[domain.DiagnosticTarget]string{}
	results := make([]domain.DiagnosticTargetResult, 0, len(request.Targets))
	for _, target := range request.Targets {
		output := "2026-09-22T10:00:00+0000 journal-host kernel: NVRM: Xid (PCI:0000:01:00.0): 94, secret=hunter2 path=/var/log/private"
		outputs[target] = output
		status := domain.DiagnosticTargetSucceeded
		if target == "comp009" {
			status = domain.DiagnosticTargetFailed
		}
		results = append(results, domain.DiagnosticTargetResult{Target: target, Status: status, ExitCode: &exitCode, StdoutBytes: int64(len(output)), StdoutSHA256: domain.ChecksumSHA256([]byte(output)), StderrSHA256: domain.ChecksumSHA256(nil), StdoutTruncated: target == "comp004", StdoutTransformationState: domain.StdoutTransformationUnmodified, StdoutExcerpt: `{"safe":"typed"}`})
	}
	attempt := domain.DiagnosticAttemptResult{WorkID: work, RunID: request.RunID, Attempt: lease.Attempt, RunnerID: "artifact-head", PlanDigest: domain.ChecksumSHA256([]byte("kernel-artifact-plan")), StartedAt: now.Add(time.Second), CompletedAt: now.Add(3 * time.Second), Targets: results}
	if _, recorded, err := diagnostics.RecordDiagnosticAttempt(ctx, cluster, "artifact-head", lease, attempt, kernelArtifactAudit("kernel-artifact-result-"+suffix, application.DiagnosticAuditResult, request, "artifact-head", "RECORDED", attempt.CompletedAt)); err != nil || !recorded {
		t.Fatalf("record: recorded=%t err=%v", recorded, err)
	}

	write := func(target domain.DiagnosticTarget) KernelXIDArtifactWrite {
		gaps, disposition := []kernelxid.Gap(nil), kernelxid.DispositionBounded
		if target == "comp004" {
			gaps, disposition = []kernelxid.Gap{kernelxid.GapOutputTruncated}, kernelxid.DispositionPartial
		}
		typed := kernelxid.TargetEvidence{ParserVersion: kernelxid.ParserVersion, SourceDefinition: string(kernelxid.DefinitionID), SourceDefinitionVersion: kernelxid.DefinitionVersion, Target: string(target), ObservedFrom: attempt.StartedAt.Add(-kernelxid.Lookback), ObservedTo: attempt.CompletedAt, DeclaredLimits: []kernelxid.DeclaredLimit{kernelxid.LimitFixedWindow, kernelxid.LimitLineCap, kernelxid.LimitOutputCap}, Disposition: disposition, Gaps: gaps, Events: []kernelxid.Event{{ObservedAt: now, XIDCode: 94, PCIBDF: "0000:01:00.0"}}}
		scope := KernelXIDArtifactScope{ClusterID: cluster, RunID: request.RunID, WorkID: work, Attempt: lease.Attempt, Target: target}
		sourceDigest := domain.ChecksumSHA256([]byte(outputs[target]))
		artifact, err := kernelxid.BuildArtifact(typed, domain.KernelXIDArtifactBinding{ClusterID: cluster, RunID: request.RunID, WorkID: work, Attempt: lease.Attempt, Target: target, PackID: definition.PackID, PackVersion: definition.PackVersion, DefinitionID: definition.DefinitionID, DefinitionVersion: definition.DefinitionVersion, DefinitionDigest: definition.DefinitionDigest, SourceStdoutSHA256: sourceDigest})
		if err != nil {
			t.Fatal(err)
		}
		return KernelXIDArtifactWrite{Scope: scope, Definition: definition, SourceStdoutSHA256: sourceDigest, Artifact: artifact}
	}
	first := write("comp001")
	if created, err := artifacts.Store(ctx, first); err != nil || !created {
		t.Fatalf("store first: created=%t err=%v", created, err)
	}
	if created, err := artifacts.Store(ctx, first); err != nil || created {
		t.Fatalf("store replay: created=%t err=%v", created, err)
	}
	read, err := artifacts.Read(ctx, first.Scope)
	if err != nil || read.State != KernelXIDArtifactAvailable || read.Artifact == nil {
		t.Fatalf("read available: %+v err=%v", read, err)
	}
	binding, ok := read.Artifact.Binding()
	if !ok || binding.WorkID != work || binding.Target != "comp001" || binding.DefinitionDigest != definition.DefinitionDigest || binding.SourceStdoutSHA256 != first.SourceStdoutSHA256 {
		t.Fatalf("stored canonical binding missing: %+v", binding)
	}
	if _, err := artifacts.Store(ctx, KernelXIDArtifactWrite{Scope: first.Scope, Definition: domain.DiagnosticDefinitionRef{PackID: definition.PackID, PackVersion: definition.PackVersion, DefinitionID: definition.DefinitionID, DefinitionVersion: definition.DefinitionVersion, DefinitionDigest: domain.ChecksumSHA256([]byte("drift"))}, SourceStdoutSHA256: first.SourceStdoutSHA256, Artifact: first.Artifact}); !errors.Is(err, application.ErrKernelXIDArtifactBinding) {
		t.Fatalf("definition drift err=%v", err)
	}
	if _, err := artifacts.Store(ctx, write("comp009")); !errors.Is(err, application.ErrKernelXIDArtifactBinding) {
		t.Fatalf("failed target accepted bounded event artifact: %v", err)
	}
	foreign := first.Scope
	foreign.ClusterID = "foreign-cluster"
	if got, err := artifacts.Read(ctx, foreign); err != nil || got.State != KernelXIDArtifactMissing {
		t.Fatalf("foreign cluster read=%+v err=%v", got, err)
	}
	missing := first.Scope
	missing.RunID = "foreign-run"
	if got, err := artifacts.Read(ctx, missing); err != nil || got.State != KernelXIDArtifactMissing {
		t.Fatalf("foreign run read=%+v err=%v", got, err)
	}
	fastStore, err := newKernelXIDArtifactStore(pool, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	fast := write("comp003")
	if _, err := fastStore.Store(ctx, fast); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := fastStore.Read(ctx, fast.Scope)
		if err != nil {
			t.Fatalf("database-clock expiry read: %v", err)
		}
		if got.State == KernelXIDArtifactExpired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("database-clock expiry did not occur before deadline: %+v", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
	sweepStore, err := newKernelXIDArtifactStore(pool, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sweepOne, sweepTwo := write("comp005"), write("comp006")
	if _, err := sweepStore.Store(ctx, sweepOne); err != nil {
		t.Fatal(err)
	}
	if _, err := sweepStore.Store(ctx, sweepTwo); err != nil {
		t.Fatal(err)
	}
	if count, err := sweepStore.expireDueAt(ctx, now.Add(2*time.Hour), 1); err != nil || count != 1 {
		t.Fatalf("bounded expiry sweep one: count=%d err=%v", count, err)
	}
	if count, err := sweepStore.expireDueAt(ctx, now.Add(2*time.Hour), 1); err != nil || count != 1 {
		t.Fatalf("bounded expiry sweep two: count=%d err=%v", count, err)
	}
	if count, err := sweepStore.expireDueAt(ctx, now.Add(2*time.Hour), 1); err != nil || count != 0 {
		t.Fatalf("idempotent expiry sweep: count=%d err=%v", count, err)
	}

	second := write("comp002")
	insertForgedKernelXIDArtifact(t, ctx, pool, second, []byte(`{}`), domain.ChecksumSHA256([]byte("wrong-checksum")))
	if got, err := artifacts.Read(ctx, second.Scope); err != nil || got.State != KernelXIDArtifactCorrupt || len(got.Gaps) != 1 || got.Gaps[0] != domain.KernelXIDArtifactGapChecksumMismatch {
		t.Fatalf("checksum mismatch=%+v err=%v", got, err)
	}
	if _, err := artifacts.Store(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE kernel_xid_artifacts SET artifact_bytes=decode('7b7d','hex') WHERE work_id=$1 AND attempt=$2 AND target=$3`, work, lease.Attempt, "comp001"); err == nil {
		t.Fatal("immutable artifact bytes were updated")
	}

	fourth := write("comp004")
	if _, err := artifacts.Store(ctx, fourth); err != nil {
		t.Fatal(err)
	}
	if got, err := artifacts.Read(ctx, fourth.Scope); err != nil || got.Artifact == nil || !got.Artifact.HasGap(domain.KernelXIDArtifactGapOutputTruncated) {
		t.Fatalf("truncated artifact=%+v err=%v", got, err)
	}
	if deleted, err := artifacts.Delete(ctx, fourth.Scope); err != nil || !deleted {
		t.Fatalf("delete: deleted=%t err=%v", deleted, err)
	}
	if deleted, err := artifacts.Delete(ctx, fourth.Scope); err != nil || deleted {
		t.Fatalf("idempotent delete: deleted=%t err=%v", deleted, err)
	}
	if got, err := artifacts.Read(ctx, fourth.Scope); err != nil || got.State != KernelXIDArtifactDeleted {
		t.Fatalf("deleted read=%+v err=%v", got, err)
	}

	third := write("comp007")
	insertForgedKernelXIDArtifact(t, ctx, pool, third, first.Artifact.Bytes(), first.Artifact.SHA256())
	if got, err := artifacts.Read(ctx, third.Scope); err != nil || got.State != KernelXIDArtifactCorrupt || len(got.Gaps) != 1 || got.Gaps[0] != domain.KernelXIDArtifactGapBindingMismatch {
		t.Fatalf("cross-target swap=%+v err=%v", got, err)
	}

	fifth := write("comp008")
	if _, err := artifacts.Store(ctx, fifth); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE kernel_xid_artifacts SET pack_version='drift' WHERE work_id=$1 AND attempt=$2 AND target='comp008'`, work, lease.Attempt); err == nil {
		t.Fatal("immutable metadata drift was accepted")
	}
}

func insertForgedKernelXIDArtifact(t *testing.T, ctx context.Context, pool *pgxpool.Pool, input KernelXIDArtifactWrite, payload []byte, checksum domain.SHA256) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		WITH write_time AS MATERIALIZED (SELECT clock_timestamp() AS value)
		INSERT INTO kernel_xid_artifacts (
			cluster_id,run_id,work_id,attempt,target,pack_id,pack_version,definition_id,definition_version,definition_digest,
			source_stdout_sha256,artifact_schema_version,parser_version,redaction_version,artifact_sha256,artifact_bytes,event_count,truncated,state,created_at,expires_at
		) SELECT
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,0,false,'AVAILABLE',write_time.value,write_time.value+interval '30 days'
		FROM write_time`, input.Scope.ClusterID, input.Scope.RunID, input.Scope.WorkID, input.Scope.Attempt, input.Scope.Target, input.Definition.PackID, input.Definition.PackVersion, input.Definition.DefinitionID, input.Definition.DefinitionVersion, input.Definition.DefinitionDigest[:], input.SourceStdoutSHA256[:], domain.KernelXIDArtifactSchemaVersion, domain.KernelXIDArtifactParserVersion, domain.KernelXIDArtifactRedactionVersion, checksum[:], payload); err != nil {
		t.Fatal(err)
	}
}

func kernelArtifactDatabaseTime(t *testing.T, ctx context.Context, pool *pgxpool.Pool) time.Time {
	t.Helper()
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	return now.UTC().Truncate(time.Microsecond)
}
func kernelArtifactAudit(id string, kind application.DiagnosticAuditKind, request domain.DiagnosticRequest, actor, outcome string, at time.Time) application.DiagnosticAuditEvent {
	return application.DiagnosticAuditEvent{EventID: id, Kind: kind, RunID: request.RunID, ClusterID: request.ClusterID, ActorID: actor, Outcome: outcome, OccurredAt: at, DefinitionDigest: request.Definition.DefinitionDigest, TargetDigest: domain.DiagnosticTargetsDigest(request.Targets)}
}
