//go:build integration

package postgres_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adapters/investigationapi"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestXIDCollectionBecomesBoundedInvestigationEvidence(t *testing.T) {
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
	clusterID := domain.ClusterID("xid-cluster-" + suffix)
	sourceID := domain.SourceID("xid-source-" + suffix)
	runID := domain.RunID("xid-run-" + suffix)
	collections, _ := storepg.NewCollectionStore(pool)
	if err := collections.EnsureSource(ctx, clusterID, "XID cluster", sourceID, "XID source"); err != nil {
		t.Fatal(err)
	}
	observedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	completedAt := observedAt.Add(time.Second)
	result := domain.CollectionResult{
		Task:   domain.CollectionTask{RunID: runID, ClusterID: clusterID, SourceID: sourceID, Query: domain.QueryGPUXID, ScheduledFor: observedAt, Deadline: observedAt.Add(time.Minute), MaxSeries: 100, MaxBytes: 1 << 20, IdempotencyKey: "xid-integration-" + suffix},
		Status: domain.ResultSucceeded, StartedAt: observedAt, CompletedAt: completedAt,
		Coverage: domain.Coverage{SeriesReturned: 1, BytesRead: 512, Complete: true},
		Observations: []domain.Observation{{
			ID: "xid-observation-" + domain.ObservationID(suffix), SchemaVersion: 1, ClusterID: clusterID, SourceID: sourceID,
			Kind: "gpu_xid", EntityKey: "node/node-1/gpu/0", Metric: "DCGM_FI_DEV_XID_ERRORS",
			Labels: []domain.Label{{Name: "UUID", Value: "GPU-1"}, {Name: "err_code", Value: "94"}, {Name: "err_msg", Value: "fixture"}, {Name: "hostname", Value: "node-1"}},
			Value:  94, Unit: "xid_code", ObservedAt: observedAt, CollectedAt: completedAt, SourceReference: "prometheus:dcgm_gpu_xid",
		}},
	}
	if inserted, err := collections.RecordResult(ctx, result); err != nil || !inserted {
		t.Fatalf("record inserted=%t err=%v", inserted, err)
	}
	envelope, _, _ := domain.XIDEvidenceForCollection(result)
	investigations, _ := storepg.NewInvestigationStore(pool)
	requestedAt := time.Now().UTC().Add(time.Second)
	entries, more, err := investigations.FindInvestigationEvidenceByOperations(ctx, "inv-lookup-"+domain.InvestigationID(suffix), clusterID, []string{"node-1"}, observedAt.Add(-time.Minute), observedAt.Add(time.Minute), requestedAt, []domain.EvidenceOperationID{domain.EvidenceOperationID(domain.QueryGPUXID)}, 10)
	if err != nil || more || len(entries) != 1 || entries[0].EvidenceID != envelope.ID() {
		t.Fatalf("entries=%+v more=%t err=%v", entries, more, err)
	}
	if entries[0].Status != envelope.Status() || !entries[0].ObservedStart.Equal(envelope.TimeRange().Start) || !entries[0].ObservedEnd.Equal(envelope.TimeRange().End) {
		t.Fatalf("lookup lost evidence provenance: %+v", entries[0])
	}
	healthEnvelope, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{
		ID: "gpu-health-evidence-" + domain.EvidenceID(suffix), SchemaVersion: domain.EvidenceSchemaVersion, ClusterID: clusterID, Status: domain.EvidenceComplete,
		Source:    domain.EvidenceSourceReference{SourceID: sourceID, Operation: domain.EvidenceOperationID(domain.QueryGPUTemperature), DefinitionVersion: "integration-v1", Reference: "integration:gpu-temperature"},
		TimeRange: domain.EvidenceTimeRange{Start: observedAt, End: observedAt}, CollectedAt: completedAt,
		Coverage: domain.EvidenceCoverage{Expected: []domain.EvidenceTarget{{Kind: domain.EvidenceTargetNode, ID: "node-1"}}, Covered: []domain.EvidenceTarget{{Kind: domain.EvidenceTargetNode, ID: "node-1"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	evidenceStore, _ := storepg.NewEvidenceStore(pool)
	if created, err := evidenceStore.CreateEvidence(ctx, healthEnvelope); err != nil || !created {
		t.Fatalf("create GPU-health evidence created=%t err=%v", created, err)
	}
	mixed, more, err := investigations.FindInvestigationEvidenceByOperations(ctx, "inv-mixed-"+domain.InvestigationID(suffix), clusterID, []string{"node-1"}, observedAt.Add(-time.Minute), observedAt.Add(time.Minute), requestedAt, []domain.EvidenceOperationID{domain.EvidenceOperationID(domain.QueryGPUXID), domain.EvidenceOperationID(domain.QueryGPUTemperature)}, 10)
	if err != nil || more || len(mixed) != 2 {
		t.Fatalf("multi-operation entries=%+v more=%t err=%v", mixed, more, err)
	}
	crossClass, more, err := investigations.FindInvestigationEvidenceByOperations(ctx, "inv-cross-class-"+domain.InvestigationID(suffix), clusterID, []string{"node-1"}, observedAt.Add(-time.Minute), observedAt.Add(time.Minute), requestedAt, []domain.EvidenceOperationID{"slurm.jobs.v1"}, 10)
	if err != nil || more || len(crossClass) != 0 {
		t.Fatalf("cross-class evidence leaked: entries=%+v more=%t err=%v", crossClass, more, err)
	}

	incidentID := domain.IncidentID("xid-incident-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO incidents (incident_id,cluster_id,title,severity,status,created_by,created_at,updated_at) VALUES ($1,$2,'XID persistence regression','HIGH','OPEN','test',$3,$3)`, incidentID, clusterID, requestedAt); err != nil {
		t.Fatal(err)
	}
	action := domain.InvestigationAction{ID: domain.InvestigationActionID("xid-action-" + suffix), ToolID: investigationapi.XIDEvidenceToolID, Digest: domain.ChecksumSHA256([]byte("xid-action-" + suffix)), FanOut: 2, Targets: []string{"node-1", "GPU-1"}, Start: observedAt.Add(-time.Minute), End: observedAt.Add(time.Minute)}
	request := domain.InvestigationRequest{
		ID: "inv-persist-" + domain.InvestigationID(suffix), IncidentID: incidentID, ClusterID: clusterID,
		Question: "Which XID evidence affects node-1?", RequestedBy: "test", IdempotencyKey: "xid-persist-" + suffix,
		Scope:           domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"node-1", "GPU-1"}, Start: action.Start, End: action.End},
		SuccessCriteria: []string{"attach normalized XID evidence"}, Budget: domain.InvestigationBudget{MaxDecisions: 2, MaxToolCalls: 1, MaxFanOut: 2},
		RequestedAt: requestedAt, Deadline: requestedAt.Add(time.Hour),
	}
	executor, err := investigationapi.NewEvidenceExecutor(investigations, []domain.ClusterID{clusterID})
	if err != nil {
		t.Fatal(err)
	}
	clock := &integrationClock{now: requestedAt}
	controller, err := application.NewInvestigationController(investigations, application.ScriptedInvestigationPlanner{Decisions: []application.InvestigationDecision{{Action: &action}}}, executor, clock, platform.RandomIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := controller.Start(ctx, application.StartInvestigationInput{Request: request}); err != nil || !created {
		t.Fatalf("start created=%t err=%v", created, err)
	}
	for step := 0; step < 5; step++ {
		if _, err := controller.Advance(ctx, request.ID); err != nil {
			t.Fatalf("advance step %d: %v", step+1, err)
		}
	}
	persisted, found, err := investigations.LoadInvestigation(ctx, request.ID)
	if err != nil || !found || persisted.Investigation.Status() != domain.InvestigationRecordingEvidence {
		t.Fatalf("persisted status=%s found=%t err=%v", persisted.Investigation.Status(), found, err)
	}
	attached := persisted.Evidence.Entries()
	if len(attached) != 1 || attached[0].Status != envelope.Status() || !attached[0].ObservedEnd.Equal(envelope.TimeRange().End) || !attached[0].RecordedAt.Equal(envelope.CollectedAt()) {
		t.Fatalf("persisted evidence lost envelope provenance: %+v", attached)
	}
	if !attached[0].RecordedAt.Before(request.Scope.End) {
		t.Fatal("regression fixture must collect evidence before the requested window ends")
	}
	if len(persisted.PriorActions) != 1 || persisted.PriorActions[0].ToolID != investigationapi.XIDEvidenceToolID || persisted.PriorActions[0].Outcome != "SUCCEEDED" || len(persisted.PriorActions[0].EvidenceIDs) != 1 || persisted.PriorActions[0].EvidenceIDs[0] != envelope.ID() {
		t.Fatalf("durable prior action history=%+v", persisted.PriorActions)
	}
	emptyAction := action
	emptyAction.ID = domain.InvestigationActionID("xid-action-empty-" + suffix)
	emptyAction.Digest = domain.ChecksumSHA256([]byte("xid-action-empty-" + suffix))
	emptyAction.Targets = []string{"node-1"}
	emptyAction.FanOut = 1
	emptyAction.Start = completedAt
	emptyAction.End = completedAt
	emptyRequest := request
	emptyRequest.ID = "inv-empty-" + domain.InvestigationID(suffix)
	emptyRequest.IdempotencyKey = "xid-empty-" + suffix
	emptyRequest.Scope.EntityIDs = []string{"node-1"}
	emptyRequest.Scope.Start = completedAt
	emptyRequest.Scope.End = completedAt
	emptyRequest.Budget.MaxFanOut = 1
	emptyController, err := application.NewInvestigationController(investigations, application.ScriptedInvestigationPlanner{Decisions: []application.InvestigationDecision{{Action: &emptyAction}}}, executor, clock, platform.RandomIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := emptyController.Start(ctx, application.StartInvestigationInput{Request: emptyRequest}); err != nil || !created {
		t.Fatalf("start empty lookup created=%t err=%v", created, err)
	}
	for step := 0; step < 5; step++ {
		if _, err := emptyController.Advance(ctx, emptyRequest.ID); err != nil {
			t.Fatalf("advance empty lookup step %d: %v", step+1, err)
		}
	}
	emptyPersisted, found, err := investigations.LoadInvestigation(ctx, emptyRequest.ID)
	if err != nil || !found {
		t.Fatalf("load empty lookup found=%t err=%v", found, err)
	}
	if len(emptyPersisted.Evidence.Entries()) != 0 || len(emptyPersisted.PriorActions) != 1 || emptyPersisted.PriorActions[0].Outcome != "NO_EVIDENCE" {
		t.Fatalf("empty lookup state evidence=%+v actions=%+v", emptyPersisted.Evidence.Entries(), emptyPersisted.PriorActions)
	}
	novel, more, err := investigations.FindInvestigationEvidenceByOperations(ctx, request.ID, clusterID, action.Targets, action.Start, action.End, request.RequestedAt, []domain.EvidenceOperationID{domain.EvidenceOperationID(domain.QueryGPUXID)}, 10)
	if err != nil || more || len(novel) != 0 {
		t.Fatalf("already attached evidence was returned as novel: entries=%+v more=%t err=%v", novel, more, err)
	}
	secondAction := action
	secondAction.ID = domain.InvestigationActionID("xid-action-reuse-" + suffix)
	secondAction.Digest = domain.ChecksumSHA256([]byte("xid-action-reuse-" + suffix))
	secondRequest := request
	secondRequest.ID = "inv-persist-reuse-" + domain.InvestigationID(suffix)
	secondRequest.IdempotencyKey = "xid-persist-reuse-" + suffix
	secondController, err := application.NewInvestigationController(investigations, application.ScriptedInvestigationPlanner{Decisions: []application.InvestigationDecision{{Action: &secondAction}}}, executor, clock, platform.RandomIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := secondController.Start(ctx, application.StartInvestigationInput{Request: secondRequest}); err != nil || !created {
		t.Fatalf("start evidence-reuse investigation created=%t err=%v", created, err)
	}
	for step := 0; step < 5; step++ {
		if _, err := secondController.Advance(ctx, secondRequest.ID); err != nil {
			t.Fatalf("advance evidence-reuse investigation step %d: %v", step+1, err)
		}
	}
	secondPersisted, found, err := investigations.LoadInvestigation(ctx, secondRequest.ID)
	if err != nil || !found || secondPersisted.Investigation.Status() != domain.InvestigationRecordingEvidence {
		t.Fatalf("evidence-reuse status=%s found=%t err=%v", secondPersisted.Investigation.Status(), found, err)
	}
	secondAttached := secondPersisted.Evidence.Entries()
	if len(secondAttached) != 1 || secondAttached[0].EvidenceID != envelope.ID() {
		t.Fatalf("committed evidence was not reusable across investigations: %+v", secondAttached)
	}
	contextRequest := domain.InvestigationRequest{
		ID: "inv-context-" + domain.InvestigationID(suffix), IncidentID: "incident-" + domain.IncidentID(suffix), ClusterID: clusterID,
		Question: "Which XID samples affect node-1?", RequestedBy: "test", IdempotencyKey: "xid-context-" + suffix,
		Scope:           domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"node-1"}, Start: observedAt.Add(-time.Minute), End: observedAt.Add(time.Minute)},
		SuccessCriteria: []string{"cite normalized XID evidence"}, Budget: domain.InvestigationBudget{MaxDecisions: 2, MaxToolCalls: 1, MaxFanOut: 1},
		RequestedAt: requestedAt, Deadline: requestedAt.Add(time.Hour),
	}
	value, err := domain.NewInvestigation(contextRequest)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := domain.NewEvidenceLedger([]domain.InvestigationEvidence{{EvidenceID: envelope.ID(), InvestigationID: contextRequest.ID, ClusterID: clusterID, EntityIDs: []string{"node-1"}, Status: envelope.Status(), ObservedStart: envelope.TimeRange().Start, ObservedEnd: envelope.TimeRange().End, RecordedAt: requestedAt}}, value)
	if err != nil {
		t.Fatal(err)
	}
	contextInputs, err := investigations.LoadInvestigationEvidenceContext(ctx, application.InvestigationSnapshot{Investigation: value, Evidence: ledger})
	if err != nil || len(contextInputs) != 1 {
		t.Fatalf("context=%+v err=%v", contextInputs, err)
	}
	if !strings.Contains(contextInputs[0].Summary, "1 samples are non-zero") || !strings.Contains(contextInputs[0].Excerpt, `"xid_code":"94"`) || strings.Contains(contextInputs[0].Excerpt, databaseURL) {
		t.Fatalf("unsafe or incomplete XID context: %+v", contextInputs[0])
	}
	if len(contextInputs[0].Coverage.Expected) == 0 || len(contextInputs[0].Coverage.Covered) == 0 || !contextInputs[0].ExpectedFrom.Equal(contextRequest.Scope.Start) || !contextInputs[0].ExpectedTo.Equal(contextRequest.Scope.End) {
		t.Fatalf("expected-versus-observed coverage was not reconstructed: %+v", contextInputs[0])
	}
}
