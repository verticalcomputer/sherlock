package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type eventRecordingInvestigationStore struct {
	investigationMemoryStore
	event domain.InvestigationEvent
}

func (store *eventRecordingInvestigationStore) SaveInvestigation(ctx context.Context, version int, snapshot InvestigationSnapshot, event domain.InvestigationEvent) error {
	store.event = event
	return store.investigationMemoryStore.SaveInvestigation(ctx, version, snapshot, event)
}

func TestTerminalEventsRetainOnlyReviewedFailureClassification(t *testing.T) {
	for _, test := range []struct{ name, code, stage, wantCode, wantStage string }{
		{"typed", FailureRepairSnapshot, "EXECUTION", FailureRepairSnapshot, "EXECUTION"},
		{"host-code", "host text must not persist", "EXECUTION", "UNCLASSIFIED", "EXECUTION"},
		{"host-stage", FailureRepairSnapshot, "host text must not persist", FailureRepairSnapshot, "PLANNING"},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC()
			request := investigationRequest(now)
			store := &eventRecordingInvestigationStore{}
			controller := newTestInvestigationController(t, store, ScriptedInvestigationPlanner{}, &idempotentInvestigationExecutor{}, &investigationClock{now: now})
			if _, _, err := controller.Start(context.Background(), StartInvestigationInput{Request: request}); err != nil {
				t.Fatal(err)
			}
			cause := &InvestigationAdvanceError{Stage: InvestigationAdvanceStage(test.stage), State: domain.InvestigationExecuting, Err: &classifiedInvestigationFailure{code: test.code, cause: errors.New("sensitive host error must not persist")}}
			if _, err := controller.StopAfterFailure(context.Background(), request.ID, cause); err != nil {
				t.Fatal(err)
			}
			want := domain.InvestigationEventDetails{StopReason: domain.StopAccessUnavailable, FailureCode: test.wantCode, FailureStage: test.wantStage}
			if store.event.Details != want {
				t.Fatalf("details=%+v want=%+v", store.event.Details, want)
			}
		})
	}
}
