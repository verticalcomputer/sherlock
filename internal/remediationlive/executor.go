// Package remediationlive contains the narrowly scoped Tier 1 collection
// request adapter. It can request one ordinary collector run, but has no
// process, shell, SSH, model, or customer-cluster mutation capability.
package remediationlive

import (
	"context"
	"fmt"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediation"
	"github.com/verticalcomputer/sherlock/internal/remediationrunner"
)

type Request struct {
	Unit    domain.ExecutionUnit
	Now     time.Time
	Catalog *remediation.Catalog
}

// Store owns the authorization linearization point and the durable effect.
// Implementations must commit the repair request and collector work together.
type Store interface {
	RequestCollection(context.Context, Request) (domain.ExecutionResult, error)
	CancelCollection(context.Context, Request) (domain.ExecutionResult, error)
}

type Executor struct {
	store   Store
	catalog *remediation.Catalog
}

func New(catalog *remediation.Catalog, store Store) (*Executor, error) {
	if store == nil || catalog == nil || !catalog.Verified() {
		return nil, fmt.Errorf("verified catalog and live collection request store are required")
	}
	return &Executor{store: store, catalog: catalog}, nil
}

func (e *Executor) Assurance() domain.AssuranceClass { return domain.AssuranceLive }

func (e *Executor) Execute(ctx context.Context, unit domain.ExecutionUnit, now time.Time) (domain.ExecutionResult, error) {
	if err := remediationrunner.ValidateExecutionUnit(e.catalog, unit, now.UTC()); err != nil {
		return domain.ExecutionResult{}, err
	}
	if unit.Recipe.Version != remediation.CollectionRequestRecipeVersion || len(unit.Targets) != 1 {
		return domain.ExecutionResult{}, fmt.Errorf("live collection requires the one-target collection-request release")
	}
	if unit.Stage == domain.RemediationStageRollback {
		if unit.Operation != domain.OperationEvidenceCollectionRestore {
			return domain.ExecutionResult{}, fmt.Errorf("live rollback must use collection restore")
		}
	} else if unit.Operation != domain.OperationEvidenceCollectionRequeue {
		return domain.ExecutionResult{}, fmt.Errorf("live forward execution must use collection requeue")
	}
	if now.IsZero() || now.After(unit.Deadline) {
		return domain.ExecutionResult{}, fmt.Errorf("live collection request deadline has expired")
	}
	request := Request{Unit: unit, Now: now.UTC(), Catalog: e.catalog}
	if unit.Stage == domain.RemediationStageRollback {
		return e.store.CancelCollection(ctx, request)
	}
	return e.store.RequestCollection(ctx, request)
}
