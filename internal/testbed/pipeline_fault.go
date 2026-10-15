package testbed

import (
	"context"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type pipelineFault struct {
	pool             *pgxpool.Pool
	prefix, boundary string
	crash            func() error
}

func (f *pipelineFault) fire(ctx context.Context, boundary string) error {
	if f == nil || f.boundary != boundary {
		return nil
	}
	tag, err := f.pool.Exec(ctx, `INSERT INTO testbed_crashes(prefix,boundary,process_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, f.prefix, boundary, os.Getpid())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	if f.crash != nil {
		return f.crash()
	}
	return ErrInjectedCrash
}

type crashBridgeStore struct {
	application.AnomalyBridgeStore
	fault *pipelineFault
}

func (s crashBridgeStore) CommitAnomalyEvaluation(ctx context.Context, consumer string, c application.CommittedCollection, signal *application.AnomalySignal, p application.AutomaticInvestigationPolicy, at time.Time) (*application.PendingAutomaticInvestigation, error) {
	pending, err := s.AnomalyBridgeStore.CommitAnomalyEvaluation(ctx, consumer, c, signal, p, at)
	if err == nil && pending != nil {
		err = s.fault.fire(ctx, "incident_committed")
	}
	return pending, err
}

type crashStarter struct {
	application.InvestigationStartCommand
	fault *pipelineFault
}

func (s crashStarter) Start(ctx context.Context, in application.StartInvestigationInput) (application.InvestigationSnapshot, bool, error) {
	snapshot, created, err := s.InvestigationStartCommand.Start(ctx, in)
	if err == nil {
		err = s.fault.fire(ctx, "start_committed")
	}
	return snapshot, created, err
}

type crashExecutor struct {
	application.InvestigationExecutor
	fault *pipelineFault
}

func (e crashExecutor) ExecuteInvestigationAction(ctx context.Context, key string, action domain.InvestigationAction) (application.InvestigationExecutionResult, error) {
	result, err := e.InvestigationExecutor.ExecuteInvestigationAction(ctx, key, action)
	if err == nil {
		err = e.fault.fire(ctx, "effect_committed")
	}
	return result, err
}

type crashInvestigationStore struct {
	application.InvestigationStore
	fault *pipelineFault
}

func (s crashInvestigationStore) SaveInvestigation(ctx context.Context, v int, snapshot application.InvestigationSnapshot, event domain.InvestigationEvent) error {
	if err := s.InvestigationStore.SaveInvestigation(ctx, v, snapshot, event); err != nil {
		return err
	}
	switch snapshot.Investigation.Status() {
	case domain.InvestigationRecordingEvidence:
		return s.fault.fire(ctx, "evidence_recording_committed")
	default:
		if snapshot.Investigation.Status().Terminal() {
			return s.fault.fire(ctx, "terminal_committed")
		}
	}
	return nil
}
