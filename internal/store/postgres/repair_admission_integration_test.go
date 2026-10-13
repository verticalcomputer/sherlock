//go:build integration

package postgres_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestRepairAdmissionBoundsAndOrdinaryScope(t *testing.T) {
	ctx, pool := openContextAdmissionDatabase(t)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	cluster := domain.ClusterID("repair-cap-" + suffix)
	source := domain.SourceID("repair-source-" + suffix)
	collections, _ := storepg.NewCollectionStore(pool)
	if err := collections.EnsureSource(ctx, cluster, "repair cap", source, "source"); err != nil {
		t.Fatal(err)
	}
	evidenceStore, _ := storepg.NewEvidenceStore(pool)
	old := time.Now().UTC().Truncate(time.Microsecond).Add(-7 * 24 * time.Hour)
	for index := 0; index < 257; index++ {
		envelope, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{ID: domain.EvidenceID(fmt.Sprintf("cap-warning-%d-%s", index, suffix)), SchemaVersion: 1, ClusterID: cluster, Status: domain.EvidenceUnavailable, Source: domain.EvidenceSourceReference{SourceID: source, Operation: domain.EvidenceOperationID(fmt.Sprintf("operation-%d", index)), DefinitionVersion: "v1", Reference: "fixture://repair-cap"}, TimeRange: domain.EvidenceTimeRange{Start: old, End: old}, CollectedAt: old, Coverage: domain.EvidenceCoverage{Expected: []domain.EvidenceTarget{{Kind: domain.EvidenceTargetCluster, ID: domain.EvidenceTargetID(cluster)}}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evidenceStore.CreateEvidence(ctx, envelope); err != nil {
			t.Fatal(err)
		}
	}
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	incident := domain.IncidentID("incident-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO incidents(incident_id,cluster_id,title,severity,status,created_by,created_at,updated_at) VALUES($1,$2,'repair cap','HIGH','OPEN','test',$3,$3)`, incident, cluster, now); err != nil {
		t.Fatal(err)
	}
	store, _ := storepg.NewInvestigationStore(pool)
	controller, _ := application.NewInvestigationController(store, &integrationSynthPlanner{}, &integrationIdempotentExecutor{}, &integrationClock{now: now}, platform.RandomIDGenerator{})
	request := domain.InvestigationRequest{ID: domain.InvestigationID("repair-cap-inv-" + suffix), IncidentID: incident, ClusterID: cluster, Purpose: domain.InvestigationPurposeRepairPlan, Question: "all current repair warnings", RequestedBy: "test", IdempotencyKey: "repair-cap-key-" + suffix, Scope: domain.InvestigationScope{EntityKind: "cluster", EntityIDs: []string{string(cluster)}, Start: now.Add(-48 * time.Hour), End: now}, SuccessCriteria: []string{"all warnings"}, Budget: domain.InvestigationBudget{MaxDecisions: 4, MaxToolCalls: 2, MaxFanOut: 1}, RequestedAt: now, Deadline: now.Add(time.Hour)}
	_, _, err := controller.Start(ctx, application.StartInvestigationInput{Request: request})
	var safe interface{ SafeReasonCode() string }
	if !errors.As(err, &safe) || safe.SafeReasonCode() != application.FailureRepairSnapshot {
		t.Fatalf("257 warnings did not fail closed: %v", err)
	}
	var residual int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM investigations WHERE investigation_id=$1)+(SELECT count(*) FROM investigation_idempotency_records WHERE resource_id=$1)`, request.ID).Scan(&residual); err != nil || residual != 0 {
		t.Fatalf("partial admission rows=%d err=%v", residual, err)
	}
	// Ordinary investigations retain the caller's exact observation scope even
	// with an excessive set of old current warnings in the same cluster.
	request.Purpose = ""
	ordinary, created, err := controller.Start(ctx, application.StartInvestigationInput{Request: request})
	if err != nil || !created || !ordinary.Investigation.Request().Scope.Start.Equal(request.Scope.Start) {
		t.Fatalf("ordinary request changed: created=%t err=%v", created, err)
	}
	// Direct execution of a legacy NULL-snapshot repair request retains a typed
	// failure rather than silently filtering these out-of-window warnings.
	_, _, err = store.FindCurrentRepairEvidence(ctx, request.ID, cluster, request.Scope.Start, request.Scope.End, request.RequestedAt, 256)
	if !errors.As(err, &safe) || safe.SafeReasonCode() != application.FailureRepairSnapshot {
		t.Fatalf("legacy narrow-window classification lost: %v", err)
	}
	// The schema also rejects bypassing the admission bound directly.
	if _, err := pool.Exec(ctx, `UPDATE investigations SET purpose='EVIDENCE_REPAIR_PLAN',repair_warning_ids=array_fill('warning'::text,ARRAY[257]) WHERE investigation_id=$1`, request.ID); err == nil {
		t.Fatal("durable boundary accepted 257 snapshot IDs")
	}
	if _, err := pool.Exec(ctx, `UPDATE investigations SET purpose='EVIDENCE_REPAIR_PLAN',repair_warning_ids=ARRAY[]::text[] WHERE investigation_id=$1`, request.ID); err != nil {
		t.Fatalf("empty admitted snapshot rejected: %v", err)
	}
	entries, more, err := store.FindCurrentRepairEvidence(ctx, request.ID, cluster, request.Scope.Start, request.Scope.End, request.RequestedAt, 256)
	if err != nil || more || len(entries) != 0 {
		t.Fatalf("empty snapshot re-queried live warnings: entries=%d more=%t err=%v", len(entries), more, err)
	}
	missing := []string{"missing-warning-" + suffix}
	if _, err := pool.Exec(ctx, `UPDATE investigations SET repair_warning_ids=$2 WHERE investigation_id=$1`, request.ID, missing); err != nil {
		t.Fatal(err)
	}
	_, _, err = store.FindCurrentRepairEvidence(ctx, request.ID, cluster, request.Scope.Start, request.Scope.End, request.RequestedAt, 256)
	if !errors.As(err, &safe) || safe.SafeReasonCode() != application.FailureRepairSnapshot {
		t.Fatalf("missing frozen identity silently dropped: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE investigations SET repair_warning_ids=ARRAY[]::text[] WHERE investigation_id=$1`, request.ID); err != nil {
		t.Fatal(err)
	}
	_, _, err = store.FindCurrentRepairEvidence(ctx, request.ID, cluster, old, request.Scope.End, request.RequestedAt, 256)
	if !errors.As(err, &safe) || safe.SafeReasonCode() != application.FailureRepairSnapshot {
		t.Fatalf("altered snapshot scope accepted: %v", err)
	}
}
