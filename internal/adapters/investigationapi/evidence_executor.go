package investigationapi

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	EvidenceLookupToolID     = "evidence.lookup.v1"
	XIDEvidenceToolID        = "metrics.xid_evidence.v1"
	KernelEventsToolID       = "node.kernel_events.v1"
	GPUHealthToolID          = "node.gpu_snapshot.v1"
	WorkloadToolID           = "cluster.workload_snapshot.v1"
	SchedulerToolID          = "cluster.scheduler_snapshot.v1"
	SourceFreshnessToolID    = "cluster.source_freshness.v1"
	BMCSensorsToolID         = "bmc.sensor_snapshot.v1"
	XIDEvidenceMaximumWindow = 5 * time.Minute
	genericEvidenceMaxWindow = 24 * time.Hour
)

type reviewedEvidencePolicy struct {
	maximumWindow time.Duration
	operations    []domain.EvidenceOperationID
}

// evidencePolicy is the complete model-visible operation authority. It returns
// exact immutable-envelope operation identifiers, never prefixes or
// model-provided selectors. Aliases cover the versioned adapter and reviewed
// command-pack identifiers that may have produced the committed envelope.
func evidencePolicy(toolID string) (reviewedEvidencePolicy, bool) {
	switch toolID {
	case XIDEvidenceToolID:
		return reviewedEvidencePolicy{XIDEvidenceMaximumWindow, []domain.EvidenceOperationID{domain.EvidenceOperationID(domain.QueryGPUXID)}}, true
	case KernelEventsToolID:
		return reviewedEvidencePolicy{time.Hour, []domain.EvidenceOperationID{"loki.kernel_events.v1", "kernel.xid.v1", "node.kernel_xid"}}, true
	case GPUHealthToolID:
		return reviewedEvidencePolicy{15 * time.Minute, []domain.EvidenceOperationID{
			domain.EvidenceOperationID(domain.QueryGPUIdentity), domain.EvidenceOperationID(domain.QueryGPUUtilization),
			domain.EvidenceOperationID(domain.QueryGPUTemperature), domain.EvidenceOperationID(domain.QueryGPUPower),
			domain.EvidenceOperationID(domain.QueryGPUMemory), domain.EvidenceOperationID(domain.QueryGPUECC),
			"gpu.inventory", "nvidia.inventory.v1",
		}}, true
	case WorkloadToolID:
		return reviewedEvidencePolicy{24 * time.Hour, []domain.EvidenceOperationID{"slurm.jobs.v1", "slurm.accounting.v1"}}, true
	case SchedulerToolID:
		return reviewedEvidencePolicy{time.Hour, []domain.EvidenceOperationID{"slurm.inventory.v1", "slurm.nodes.v1", "slurm.partitions.v1", "slurm.node_detail", "slurm.node.v1"}}, true
	case SourceFreshnessToolID:
		return reviewedEvidencePolicy{time.Hour, []domain.EvidenceOperationID{domain.EvidenceOperationID(domain.QuerySourceHealth), "source.freshness.v1"}}, true
	case BMCSensorsToolID:
		return reviewedEvidencePolicy{time.Hour, []domain.EvidenceOperationID{"redfish.inventory.v1", "redfish.sensors.v1", "redfish.event_log.v1"}}, true
	default:
		return reviewedEvidencePolicy{}, false
	}
}

type evidenceLookupStore interface {
	LoadInvestigation(context.Context, domain.InvestigationID) (application.InvestigationSnapshot, bool, error)
	FindInvestigationEvidence(context.Context, domain.InvestigationID, domain.ClusterID, []string, time.Time, time.Time, time.Time, int) ([]domain.InvestigationEvidence, bool, error)
	FindInvestigationEvidenceByOperations(context.Context, domain.InvestigationID, domain.ClusterID, []string, time.Time, time.Time, time.Time, []domain.EvidenceOperationID, int) ([]domain.InvestigationEvidence, bool, error)
}

// EvidenceExecutor exposes reviewed read-only actions that attach immutable
// evidence already durable when the investigation was requested. It never
// loads artifact bodies or invokes a collector, shell, or privileged command.
type EvidenceExecutor struct {
	store    evidenceLookupStore
	clusters map[domain.ClusterID]struct{}
}

func NewEvidenceExecutor(store evidenceLookupStore, clusters []domain.ClusterID) (*EvidenceExecutor, error) {
	if store == nil || len(clusters) == 0 {
		return nil, fmt.Errorf("evidence executor store and cluster allow-list are required")
	}
	allowed := make(map[domain.ClusterID]struct{}, len(clusters))
	for _, cluster := range clusters {
		if cluster == "" {
			return nil, fmt.Errorf("evidence executor cluster allow-list is invalid")
		}
		allowed[cluster] = struct{}{}
	}
	return &EvidenceExecutor{store: store, clusters: allowed}, nil
}

func (executor *EvidenceExecutor) ExecuteInvestigationAction(ctx context.Context, idempotencyKey string, action domain.InvestigationAction) (application.InvestigationExecutionResult, error) {
	const prefix = "investigation/"
	const separator = "/action/"
	policy, reviewed := evidencePolicy(action.ToolID)
	if executor == nil || !strings.HasPrefix(idempotencyKey, prefix) || (action.ToolID != EvidenceLookupToolID && !reviewed) || action.Privileged || len(action.Arguments) != 0 || action.Validate() != nil {
		return application.InvestigationExecutionResult{}, fmt.Errorf("evidence lookup invocation is invalid")
	}
	value := strings.TrimPrefix(idempotencyKey, prefix)
	parts := strings.Split(value, separator)
	if len(parts) != 2 || parts[0] == "" || parts[1] != string(action.ID) {
		return application.InvestigationExecutionResult{}, fmt.Errorf("evidence lookup idempotency key is invalid")
	}
	id := domain.InvestigationID(parts[0])
	snapshot, found, err := executor.store.LoadInvestigation(ctx, id)
	if err != nil {
		return application.InvestigationExecutionResult{}, fmt.Errorf("load evidence lookup authority: %w", err)
	}
	if !found {
		return application.InvestigationExecutionResult{}, application.ErrInvestigationNotFound
	}
	request := snapshot.Investigation.Request()
	durable := snapshot.ProposedAction
	if durable == nil || durable.ID != action.ID || durable.ToolID != action.ToolID || durable.Digest != action.Digest || durable.Privileged != action.Privileged || len(durable.Arguments) != 0 || !durable.Start.Equal(action.Start) || !durable.End.Equal(action.End) || !slices.Equal(durable.Targets, action.Targets) {
		return application.InvestigationExecutionResult{}, fmt.Errorf("evidence lookup does not match the durable proposed action")
	}
	if _, allowed := executor.clusters[request.ClusterID]; !allowed || action.Start.Before(request.Scope.Start) || action.End.After(request.Scope.End) || !targetsWithin(action.Targets, request.Scope.EntityIDs) {
		return application.InvestigationExecutionResult{}, fmt.Errorf("evidence lookup is outside durable investigation authority")
	}
	maximumWindow := genericEvidenceMaxWindow
	if reviewed {
		maximumWindow = policy.maximumWindow
	}
	if request.Purpose != domain.InvestigationPurposeRepairPlan && action.End.Sub(action.Start) > maximumWindow {
		return application.InvestigationExecutionResult{}, fmt.Errorf("evidence lookup exceeds its reviewed time bound")
	}
	var entries []domain.InvestigationEvidence
	var more bool
	if request.Purpose == domain.InvestigationPurposeRepairPlan {
		current, ok := executor.store.(interface {
			FindCurrentRepairEvidence(context.Context, domain.InvestigationID, domain.ClusterID, time.Time, time.Time, time.Time, int) ([]domain.InvestigationEvidence, bool, error)
		})
		if !ok || action.ToolID != EvidenceLookupToolID {
			return application.InvestigationExecutionResult{}, fmt.Errorf("repair evidence lookup is unavailable")
		}
		entries, more, err = current.FindCurrentRepairEvidence(ctx, id, request.ClusterID, action.Start, action.End, request.RequestedAt, 256)
	} else if reviewed {
		entries, more, err = executor.store.FindInvestigationEvidenceByOperations(ctx, id, request.ClusterID, action.Targets, action.Start, action.End, request.RequestedAt, policy.operations, 256)
	} else {
		entries, more, err = executor.store.FindInvestigationEvidence(ctx, id, request.ClusterID, action.Targets, action.Start, action.End, request.RequestedAt, 256)
	}
	if err != nil {
		return application.InvestigationExecutionResult{}, fmt.Errorf("find bounded investigation evidence: %w", err)
	}
	if more {
		return application.InvestigationExecutionResult{}, fmt.Errorf("evidence lookup result exceeds the bounded limit")
	}
	for _, entry := range entries {
		if err := entry.ValidateFor(snapshot.Investigation); err != nil {
			return application.InvestigationExecutionResult{}, fmt.Errorf("evidence lookup returned invalid scope: %w", err)
		}
	}
	receiptDigest := domain.ChecksumSHA256([]byte(idempotencyKey))
	return application.InvestigationExecutionResult{Receipt: "evidence-lookup:" + receiptDigest.String(), Evidence: entries}, nil
}

func targetsWithin(values, allowed []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if !slices.Contains(allowed, value) {
			return false
		}
	}
	return true
}

var _ application.InvestigationExecutor = (*EvidenceExecutor)(nil)
