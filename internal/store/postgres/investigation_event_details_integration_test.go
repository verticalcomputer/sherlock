//go:build integration

package postgres_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestTerminalEventDetailsDurableBoundary(t *testing.T) {
	ctx, pool := openContextAdmissionDatabase(t)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	cluster := domain.ClusterID("event-details-" + suffix)
	collections, _ := storepg.NewCollectionStore(pool)
	if err := collections.EnsureSource(ctx, cluster, "event details", domain.SourceID("source-"+suffix), "source"); err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	incident := domain.IncidentID("incident-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO incidents(incident_id,cluster_id,title,severity,status,created_by,created_at,updated_at) VALUES($1,$2,'details','HIGH','OPEN','test',$3,$3)`, incident, cluster, now); err != nil {
		t.Fatal(err)
	}
	store, _ := storepg.NewInvestigationStore(pool)
	planner := &integrationSynthPlanner{}
	controller, _ := application.NewInvestigationController(store, planner, &integrationIdempotentExecutor{}, &integrationClock{now: now}, platform.RandomIDGenerator{})
	codes := []string{application.FailureRepairSnapshot, application.FailureRequiredContext, application.FailureRequiredEvidenceContext, application.FailureEncodedContext, application.FailureProviderInputContext, application.FailureEvidenceContextUnusable, application.FailureCheckpointMismatch, application.FailureEstimatorUnderrun, application.FailureBudgetExceeded, "UNCLASSIFIED"}
	stages := []application.InvestigationAdvanceStage{application.InvestigationAdvanceLoad, application.InvestigationAdvancePlanning, application.InvestigationAdvancePolicy, application.InvestigationAdvanceExecution, application.InvestigationAdvanceEvidence, application.InvestigationAdvanceLedger, application.InvestigationAdvanceSynthesis, application.InvestigationAdvancePersistence}
	for index, code := range codes {
		id := domain.InvestigationID(fmt.Sprintf("event-inv-%d-%s", index, suffix))
		request := domain.InvestigationRequest{ID: id, IncidentID: incident, ClusterID: cluster, Question: "classify terminal event", RequestedBy: "test", IdempotencyKey: string(id), Scope: domain.InvestigationScope{EntityKind: "cluster", EntityIDs: []string{string(cluster)}, Start: now.Add(-time.Hour), End: now}, SuccessCriteria: []string{"retain the reason"}, Budget: domain.InvestigationBudget{MaxDecisions: 4, MaxToolCalls: 2, MaxFanOut: 1}, RequestedAt: now, Deadline: now.Add(time.Hour)}
		if _, created, err := controller.Start(ctx, application.StartInvestigationInput{Request: request}); err != nil || !created {
			t.Fatalf("start created=%t err=%v", created, err)
		}
		cause := application.ClassifyInvestigationFailure(errors.New("arbitrary host text never saved"), code)
		stage := stages[index%len(stages)]
		stopped, err := controller.StopAfterFailure(ctx, id, &application.InvestigationAdvanceError{Stage: stage, Err: cause})
		if err != nil {
			t.Fatal(err)
		}
		var raw []byte
		if err := pool.QueryRow(ctx, `SELECT payload FROM investigation_events WHERE investigation_id=$1 AND to_status=$2`, id, stopped.Investigation.Status()).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var details domain.InvestigationEventDetails
		if err := json.Unmarshal(raw, &details); err != nil {
			t.Fatal(err)
		}
		if details.StopReason != stopped.Investigation.StopReason() || details.FailureCode != code || details.FailureStage != string(stage) {
			t.Fatalf("persisted=%s", raw)
		}
		if err := details.Validate(); err != nil {
			t.Fatal(err)
		}
		// Negative-test the durable constraint, then restore with the same exact
		// valid payload. PostgreSQL rejection must leave the row unchanged.
		for _, invalid := range []string{
			`{"stop_reason":"ACCESS_UNAVAILABLE","failure_code":"host text","failure_stage":"EXECUTION"}`,
			`{"stop_reason":"ACCESS_UNAVAILABLE","failure_code":"UNCLASSIFIED","failure_stage":null}`,
			`{"stop_reason":"host text"}`,
			`{"stop_reason":"ACCESS_UNAVAILABLE","error":"host text"}`,
		} {
			if _, err := pool.Exec(ctx, `UPDATE investigation_events SET payload=$2 WHERE investigation_id=$1 AND to_status IS NOT NULL`, id, invalid); err == nil {
				t.Fatalf("durable boundary accepted %s", invalid)
			}
		}
		if _, err := pool.Exec(ctx, `UPDATE investigation_events SET payload=$2 WHERE investigation_id=$1 AND to_status IS NOT NULL`, id, raw); err != nil {
			t.Fatalf("valid payload rejected after negative tests: %v", err)
		}
		// A historical empty transition is still accepted and decodes cleanly.
		if _, err := pool.Exec(ctx, `UPDATE investigation_events SET payload='{}' WHERE investigation_id=$1 AND to_status IS NOT NULL`, id); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT payload FROM investigation_events WHERE investigation_id=$1 AND to_status IS NOT NULL`, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		details = domain.InvestigationEventDetails{}
		if err := json.Unmarshal(raw, &details); err != nil {
			t.Fatal(err)
		}
		if err := details.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}
