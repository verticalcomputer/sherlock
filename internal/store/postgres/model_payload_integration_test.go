//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/artifacts"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestModelPayloadEvidenceIsRedactedLinkedAndReadable(t *testing.T) {
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
	clusterID := domain.ClusterID("model-payload-cluster-" + suffix)
	collections, _ := storepg.NewCollectionStore(pool)
	if err := collections.EnsureSource(ctx, clusterID, "Model payload cluster", domain.SourceID("fixture-source-"+suffix), "Fixture source"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	incidentID := domain.IncidentID("model-payload-incident-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO incidents (incident_id,cluster_id,title,severity,status,created_by,created_at,updated_at) VALUES ($1,$2,'Model payload audit','HIGH','OPEN','test',$3,$3)`, incidentID, clusterID, now); err != nil {
		t.Fatal(err)
	}
	request := domain.InvestigationRequest{ID: domain.InvestigationID("model-payload-investigation-" + suffix), IncidentID: incidentID, ClusterID: clusterID, Question: "Audit the model exchange", RequestedBy: "test", IdempotencyKey: "model-payload-" + suffix, Scope: domain.InvestigationScope{EntityKind: "cluster", EntityIDs: []string{string(clusterID)}, Start: now.Add(-time.Minute), End: now}, SuccessCriteria: []string{"retain an auditable exchange"}, Budget: domain.InvestigationBudget{MaxDecisions: 2, MaxToolCalls: 1, MaxFanOut: 1}, RequestedAt: now, Deadline: now.Add(time.Hour)}
	investigation, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := storepg.NewInvestigationStore(pool)
	event := domain.InvestigationEvent{ID: domain.InvestigationEventID("model-payload-event-" + suffix), InvestigationID: request.ID, Sequence: 1, Kind: domain.InvestigationEventCreated, OccurredAt: now}
	if created, err := store.CreateInvestigation(ctx, application.InvestigationSnapshot{Investigation: investigation}, event); err != nil || !created {
		t.Fatalf("create investigation=%t err=%v", created, err)
	}
	objects, err := artifacts.NewLocalStore(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	evidenceStore, _ := storepg.NewEvidenceStore(pool)
	evidenceWriter, _ := application.NewEvidenceRecorder(evidenceStore, objects, 1<<20)
	audits, _ := storepg.NewModelCallAuditStore(pool)
	payloads, _ := application.NewModelPayloadRecorder(audits, evidenceWriter, 1<<20)
	callKey := "investigation/" + string(request.ID) + "/synthesis/2"
	inputID, err := payloads.RecordModelPayload(ctx, application.ModelPayloadEvidence{InvestigationID: request.ID, ClusterID: clusterID, CallKey: callKey, Kind: application.ModelCallSynthesis, Role: application.ModelPayloadInput, Payload: []byte(`{"authorization":"Bearer private-token","question":"audit"}`), OccurredAt: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	outputID, err := payloads.RecordModelPayload(ctx, application.ModelPayloadEvidence{InvestigationID: request.ID, ClusterID: clusterID, CallKey: callKey, Kind: application.ModelCallSynthesis, Role: application.ModelPayloadOutput, Payload: []byte(`{"schema_version":1,"what_is_happening":[]}`), OccurredAt: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	audit := application.ModelCallAudit{CallID: "model-payload-call-" + suffix, CallKey: callKey, InvestigationID: request.ID, ClusterID: clusterID, Kind: application.ModelCallSynthesis, Provider: "fixture", Model: "model-v1", ModelConfigVersion: "config-v1", PromptSchemaVersion: "synthesis-v1", ToolSchemaVersion: "catalog-v1", InputTokens: 10, OutputTokens: 5, CostMicros: 2, Latency: time.Millisecond, Outcome: application.ModelCallRejected, ReasonCode: "INVALID_RESPONSE_SEMANTIC_VALIDATION", InputEvidenceID: inputID, OutputEvidenceID: outputID, OccurredAt: now.Add(time.Second)}
	if err := audits.AppendModelCallAudit(ctx, audit); err != nil {
		t.Fatal(err)
	}
	lookup, more, err := store.FindInvestigationEvidence(ctx, request.ID, clusterID, []string{string(clusterID)}, now, now.Add(2*time.Second), now.Add(2*time.Second), 10)
	if err != nil || more || len(lookup) != 0 {
		t.Fatalf("model payload evidence entered investigation citation authority: entries=%+v more=%t err=%v", lookup, more, err)
	}
	var storedInput, storedOutput domain.EvidenceID
	if err := pool.QueryRow(ctx, `SELECT input_evidence_id,output_evidence_id FROM investigation_model_calls WHERE call_id=$1`, audit.CallID).Scan(&storedInput, &storedOutput); err != nil || storedInput != inputID || storedOutput != outputID {
		t.Fatalf("linked input=%q output=%q err=%v", storedInput, storedOutput, err)
	}
	envelope, availability, found, err := evidenceStore.LoadEvidence(ctx, inputID)
	if err != nil || !found || availability != domain.ArtifactAvailable {
		t.Fatalf("input evidence found=%t availability=%s err=%v", found, availability, err)
	}
	reference, _ := envelope.Artifact()
	stored, err := objects.Read(ctx, reference)
	if err != nil || bytes.Contains(stored, []byte("private-token")) || !bytes.Contains(stored, []byte("[REDACTED]")) {
		t.Fatalf("unsafe stored model input=%s err=%v", stored, err)
	}
}
