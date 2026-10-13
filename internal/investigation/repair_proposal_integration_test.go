//go:build integration

package investigation

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adapters/investigationapi"
	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/modelprovider"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"os"
	"slices"
	"testing"
	"time"
)

func TestRepairProposalControllerPersistsCompleteCitedPlanWithoutDiagnostics(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("requires isolated migrated database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	cluster := domain.ClusterID("repair-flow-" + suffix)
	source := domain.SourceID("repair-source-" + suffix)
	collections, _ := storepg.NewCollectionStore(pool)
	if err := collections.EnsureSource(ctx, cluster, "repair flow", source, "repair source"); err != nil {
		t.Fatal(err)
	}
	evidenceStore, _ := storepg.NewEvidenceStore(pool)
	store, _ := storepg.NewInvestigationStore(pool)
	observed := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	var ids []string
	for i, operation := range []string{"gpu.ecc_counters", "gpu.retired_pages", "gpu.row_remap", "dcgm_gpu_xid"} {
		var runID domain.RunID
		if operation == "dcgm_gpu_xid" {
			runID = domain.RunID("repair-xid-run-" + suffix)
			if _, err := pool.Exec(ctx, `INSERT INTO collection_runs(run_id,cluster_id,source_id,query_kind,idempotency_key,status,scheduled_for,started_at,completed_at,series_returned,bytes_read,coverage_complete) VALUES($1,$2,$3,'dcgm_gpu_xid',$1,'FAILED',$4,$4,$4,0,0,false)`, runID, cluster, source, observed); err != nil {
				t.Fatal(err)
			}
		}
		id := domain.EvidenceID(fmt.Sprintf("repair-evidence-%d-%s", i, suffix))
		ids = append(ids, string(id))
		envelope, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{ID: id, SchemaVersion: 1, ClusterID: cluster, Status: domain.EvidenceUnavailable, Source: domain.EvidenceSourceReference{SourceID: source, RunID: runID, Operation: domain.EvidenceOperationID(operation), DefinitionVersion: "v1", Reference: "fixture://repair"}, TimeRange: domain.EvidenceTimeRange{Start: observed, End: observed}, CollectedAt: observed, Coverage: domain.EvidenceCoverage{Expected: []domain.EvidenceTarget{{Kind: domain.EvidenceTargetCluster, ID: domain.EvidenceTargetID(cluster)}}}})
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
	incident := domain.IncidentID("repair-incident-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO incidents(incident_id,cluster_id,title,severity,status,created_by,created_at,updated_at) VALUES($1,$2,'repair','HIGH','OPEN','test',$3,$3)`, incident, cluster, now); err != nil {
		t.Fatal(err)
	}
	response := modelprovider.SynthesisResponse{SchemaVersion: 1,
		WhatIsHappening:    []modelprovider.CitedStatement{{Statement: "The four supplied evidence streams are unavailable.", Severity: "WARNING", EvidenceIDs: ids}},
		Timeline:           []modelprovider.TimelineEntry{{ObservedAt: observed, Statement: "The warning evidence was recorded.", EvidenceIDs: ids}},
		LikelyExplanations: []modelprovider.Explanation{{Statement: "Shared diagnostic dispatch configuration may explain three warnings; exporter coverage needs separate investigation.", Confidence: .5, Severity: "WARNING", EvidenceIDs: ids}},
		WhatRemainsUnknown: []modelprovider.CitedStatement{{Statement: "The precise configuration defect and hardware state remain unknown. No repair was executed.", EvidenceIDs: ids}},
		SuggestedNextSteps: []modelprovider.CitedStatement{{Severity: "WARNING", Statement: "Proposal only: inspect reviewed inventory for the three diagnostic warnings and exporter discovery for XID. Save existing configuration, propose the narrow fix found, verify fresh target coverage in a canary, and restore the saved configuration if verification regresses.", EvidenceIDs: ids}},
		Coverage:           []modelprovider.CitedStatement{{Statement: "All four warning streams are addressed by this proposal; telemetry remains unavailable.", EvidenceIDs: ids}},
	}
	provider, err := modelprovider.NewFakeProvider(nil, []modelprovider.SynthesisStep{{Result: modelprovider.SynthesisResult{Response: response, Metadata: modelprovider.CallMetadata{Provider: "fixture", Model: "planner-v1", ConfigurationID: "config-v1", InputTokens: 30, OutputTokens: 30, CostMicros: 2, Latency: time.Millisecond, Outcome: modelprovider.OutcomeSucceeded}}}})
	if err != nil {
		t.Fatal(err)
	}
	orchestrator := newTestOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{}, now)
	orchestrator.contexts = LedgerContextSource{Loader: store}
	orchestrator.ids = platform.RandomIDGenerator{}
	executor, _ := investigationapi.NewEvidenceExecutor(store, []domain.ClusterID{cluster})
	controller, _ := application.NewInvestigationController(store, orchestrator, executor, fixedClock{now}, platform.RandomIDGenerator{})
	request := domain.InvestigationRequest{ID: domain.InvestigationID("repair-run-" + suffix), IncidentID: incident, ClusterID: cluster, Purpose: domain.InvestigationPurposeRepairPlan, Question: "Generate a combined proposal-only repair plan for three GPU diagnostic warnings and dcgm_gpu_xid. Do not execute repairs.", RequestedBy: "test", IdempotencyKey: "repair-" + suffix, Scope: domain.InvestigationScope{EntityKind: "cluster", EntityIDs: []string{string(cluster)}, Start: now.Add(-24 * time.Hour), End: now}, SuccessCriteria: []string{"Propose cited repairs for every warning without claiming execution."}, Budget: domain.InvestigationBudget{MaxDecisions: 4, MaxToolCalls: 2, MaxFanOut: 1, MaxModelTokens: 100000, MaxCostMicros: 100000}, RequestedAt: now, Deadline: now.Add(time.Hour)}
	if _, _, err := controller.Start(ctx, application.StartInvestigationInput{Request: request}); err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 20; step++ {
		snapshot, found, err := store.LoadInvestigation(ctx, request.ID)
		if err != nil || !found {
			t.Fatalf("load=%t err=%v", found, err)
		}
		if snapshot.Investigation.Status().Terminal() {
			if snapshot.Investigation.Status() != domain.InvestigationCompleted || snapshot.Investigation.StopReason() != domain.StopSuccessCriteriaMet {
				t.Fatalf("terminal=%s/%s", snapshot.Investigation.Status(), snapshot.Investigation.StopReason())
			}
			if len(snapshot.Evidence.Entries()) != 4 || len(snapshot.PriorActions) != 1 || snapshot.PriorActions[0].ToolID != "evidence.lookup.v1" || snapshot.Investigation.Usage().DiagnosticCalls != 0 || len(provider.PlanningCalls()) != 0 || len(provider.SynthesisCalls()) != 1 {
				t.Fatalf("unexpected execution: %+v", snapshot)
			}
			reports, _ := adminmanage.NewPostgresStore(pool)
			report, err := reports.GetInvestigationReport(ctx, string(request.ID))
			if err != nil {
				t.Fatal(err)
			}
			if report.PrimaryAction == nil || len(report.PrimaryAction.EvidenceIDs) != 4 {
				t.Fatalf("report action=%+v", report.PrimaryAction)
			}
			for _, finding := range report.Findings {
				for _, id := range finding.EvidenceIDs {
					if !slices.Contains(ids, id) {
						t.Fatalf("ledger identifier leaked as citation: %s", id)
					}
				}
			}
			return
		}
		if _, err := controller.Advance(ctx, request.ID); err != nil {
			t.Fatalf("advance=%v synthesis calls=%+v", err, provider.SynthesisCalls())
		}
	}
	t.Fatal("proposal never completed")
}
