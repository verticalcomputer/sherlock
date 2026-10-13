package application

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type TypedCollectionExecutor interface {
	ExecuteTyped(context.Context, domain.TypedWorkLease) domain.TypedCollectorResult
}

// TypedCollectionSource is constructed locally. A leased plan never supplies
// an adapter, endpoint, credentials, executable, or stable-node mapping.
type TypedCollectionSource struct {
	ClusterID  domain.ClusterID
	SourceID   domain.SourceID
	Kind       domain.CollectionSourceKind
	Operations []domain.CollectionOperationID
	Executor   TypedCollectionExecutor
}

type TypedCollectionRegistry struct {
	sources    map[domain.SourceID]TypedCollectionSource
	operations []domain.CollectionOperationID
	clock      Clock
}

func NewTypedCollectionRegistry(protocol int, sources []TypedCollectionSource, clock Clock) (*TypedCollectionRegistry, error) {
	if protocol != domain.CollectionProtocolVersion || len(sources) == 0 || len(sources) > 100 || clock == nil {
		return nil, fmt.Errorf("typed collection protocol, sources and clock are required")
	}
	r := &TypedCollectionRegistry{sources: make(map[domain.SourceID]TypedCollectionSource), clock: clock}
	for _, source := range sources {
		if source.ClusterID == "" || source.SourceID == "" || source.Executor == nil || len(source.Operations) == 0 {
			return nil, fmt.Errorf("typed source requires local identity, operations and executor")
		}
		if _, exists := r.sources[source.SourceID]; exists {
			return nil, fmt.Errorf("duplicate typed source")
		}
		seen := map[domain.CollectionOperationID]bool{}
		for _, id := range source.Operations {
			op, known := domain.ReviewedCollectionOperation(id)
			if !known || op.Source != source.Kind || seen[id] {
				return nil, fmt.Errorf("typed source operation is unknown, incompatible or duplicated")
			}
			seen[id] = true
			if !slices.Contains(r.operations, id) {
				r.operations = append(r.operations, id)
			}
		}
		source.Operations = slices.Clone(source.Operations)
		r.sources[source.SourceID] = source
	}
	slices.Sort(r.operations)
	return r, nil
}

func (r *TypedCollectionRegistry) Operations() []domain.CollectionOperationID {
	return slices.Clone(r.operations)
}

func (r *TypedCollectionRegistry) SourceIDs() []domain.SourceID {
	ids := make([]domain.SourceID, 0, len(r.sources))
	for id := range r.sources {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func (r *TypedCollectionRegistry) ExecuteTyped(ctx context.Context, lease domain.TypedWorkLease) domain.TypedCollectorResult {
	p := lease.Plan
	source, found := r.sources[p.SourceID]
	if err := domain.ValidateTypedWorkLease(lease); err != nil || !found || source.ClusterID != p.ClusterID || source.Kind != p.SourceKind || !slices.Contains(source.Operations, p.Operation) {
		return FailedTypedCollection(lease, r.clock.Now(), domain.FailureInvalidArgument, "collection source or operation is not locally enabled")
	}
	return source.Executor.ExecuteTyped(ctx, lease)
}

// FailedTypedCollection uses fixed safe messages supplied by the caller. Raw
// adapter errors and response contents must never be copied into this result.
func FailedTypedCollection(lease domain.TypedWorkLease, now time.Time, code domain.FailureCode, message string) domain.TypedCollectorResult {
	p := lease.Plan
	op, _ := domain.ReviewedCollectionOperation(p.Operation)
	payload := domain.CollectionPayload{Kind: op.Payload}
	scope := domain.CoverageMetrics
	switch op.Payload {
	case domain.CollectionPayloadMetrics:
		payload.Metrics = &domain.CollectionMetricsPayload{}
	case domain.CollectionPayloadInventory:
		payload.Inventory = &domain.CollectionInventoryPayload{}
		scope = domain.CoverageInventory
	case domain.CollectionPayloadAllocation:
		payload.Allocation = &domain.CollectionAllocationPayload{}
		scope = domain.CoverageAllocations
	case domain.CollectionPayloadEvents:
		payload.Events = &domain.CollectionEventsPayload{}
		scope = domain.CoverageEvents
	case domain.CollectionPayloadSlurmSnapshot:
		payload.SlurmSnapshot = &domain.SlurmSnapshotPayload{
			InventoryCoverage:  domain.SourceCoverage{SchemaVersion: domain.InventoryContractSchemaVersion, ClusterID: p.ClusterID, SourceID: p.SourceID, Scope: domain.CoverageInventory, State: domain.SourceCoverageUnknown, SourceAt: now.UTC(), EffectiveAt: now.UTC(), ObservedAt: now.UTC()},
			AllocationCoverage: domain.SourceCoverage{SchemaVersion: domain.InventoryContractSchemaVersion, ClusterID: p.ClusterID, SourceID: p.SourceID, Scope: domain.CoverageAllocations, State: domain.SourceCoverageUnknown, SourceAt: now.UTC(), EffectiveAt: now.UTC(), ObservedAt: now.UTC()},
		}
		scope = domain.CoverageAllocations
	case domain.CollectionPayloadGPUProcess:
		nodes := []domain.GPUProcessNodeObservation(nil)
		if len(p.Scope.Nodes) > 0 {
			nodes = []domain.GPUProcessNodeObservation{{NodeID: p.Scope.Nodes[0], ObservedAt: now.UTC(), ComputeVisibility: domain.SourceCoverageUnknown, Gaps: []domain.GPUProcessSourceGap{domain.GPUProcessGapInventoryMissing}}}
		}
		payload.GPUProcess = &domain.GPUProcessSnapshotPayload{Nodes: nodes}
	}
	return domain.TypedCollectorResult{SchemaVersion: domain.CollectionProtocolVersion, WorkID: lease.Lease.Work.WorkID, Attempt: lease.Lease.Attempt,
		Plan: p, Status: domain.ResultFailed, StartedAt: now.UTC(), CompletedAt: now.UTC(), Payload: payload,
		Coverage: domain.SourceCoverage{SchemaVersion: domain.InventoryContractSchemaVersion, ClusterID: p.ClusterID, SourceID: p.SourceID, Scope: scope,
			State: domain.SourceCoverageUnknown, SourceAt: now.UTC(), EffectiveAt: now.UTC(), ObservedAt: now.UTC()},
		Failures: []domain.CollectionFailure{{Code: code, Message: message}}}
}
