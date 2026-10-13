package investigationapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	publicapi "github.com/verticalcomputer/sherlock/internal/api"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type Service struct {
	pool       *pgxpool.Pool
	controller investigationMutator
	clock      application.Clock
}

type investigationMutator interface {
	Start(context.Context, application.StartInvestigationInput) (application.InvestigationSnapshot, bool, error)
	CancelExpected(context.Context, domain.InvestigationID, int) (application.InvestigationSnapshot, error)
	Approve(context.Context, domain.InvestigationID, domain.InvestigationApproval) (application.InvestigationSnapshot, error)
}

func NewService(pool *pgxpool.Pool, controller investigationMutator, clock application.Clock) (*Service, error) {
	if pool == nil || controller == nil || clock == nil {
		return nil, fmt.Errorf("investigation API adapter dependencies are required")
	}
	return &Service{pool: pool, controller: controller, clock: clock}, nil
}

func stableID(prefix string, clusterID domain.ClusterID, idempotencyKey string) string {
	digest := sha256.Sum256([]byte(string(clusterID) + "\x00" + idempotencyKey))
	return prefix + hex.EncodeToString(digest[:16])
}

func mapError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, application.ErrInvestigationNotFound):
		return publicapi.ErrInvestigationNotFound
	case errors.Is(err, application.ErrInvestigationConflict):
		return publicapi.ErrInvestigationConflict
	default:
		var conflict domain.TransitionConflictError
		if errors.As(err, &conflict) {
			return publicapi.ErrInvestigationConflict
		}
		return fmt.Errorf("%w: %v", publicapi.ErrInvestigationUnavailable, err)
	}
}

type unavailablePlanner struct{}

func (unavailablePlanner) Decide(context.Context, application.InvestigationSnapshot) (application.InvestigationDecision, error) {
	return application.InvestigationDecision{Stop: true, Outcome: domain.InvestigationBlocked, Reason: domain.StopAccessUnavailable}, nil
}

type unavailableExecutor struct{}

func (unavailableExecutor) ExecuteInvestigationAction(context.Context, string, domain.InvestigationAction) (application.InvestigationExecutionResult, error) {
	return application.InvestigationExecutionResult{}, fmt.Errorf("investigation action execution is not configured")
}

func NewFailClosedController(store application.InvestigationStore, clock application.Clock, ids application.IDGenerator) (*application.InvestigationController, error) {
	return application.NewInvestigationController(store, unavailablePlanner{}, unavailableExecutor{}, clock, ids)
}
