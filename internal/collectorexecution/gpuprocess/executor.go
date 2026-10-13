// Package gpuprocess executes only the two reviewed GP-06e NVIDIA queries
// through a locally supplied sealed head-node source. It never accepts shell
// text, an executable path, credentials, or targets from a collection lease.
package gpuprocess

import (
	"context"
	"fmt"
	"slices"
	"sync"

	adapter "github.com/verticalcomputer/sherlock/internal/adapters/gpuprocess"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type Source interface {
	Observe(context.Context, domain.StableNodeID) (adapter.Result, []adapter.HostStat, []adapter.Gap, error)
}

type NodeConfig struct {
	Node                      *domain.EntityIdentity
	GPUs                      []domain.EntityIdentity
	PIDNamespace              string
	CompleteComputeVisibility bool
	PhysicalOnly              bool
}
type Config struct {
	ClusterID domain.ClusterID
	SourceID  domain.SourceID
	Nodes     map[domain.StableNodeID]NodeConfig
}
type Executor struct {
	source Source
	clock  application.Clock
	cfg    Config
}

func New(source Source, clock application.Clock, cfg Config) (*Executor, error) {
	if source == nil || clock == nil || cfg.ClusterID == "" || cfg.SourceID == "" || len(cfg.Nodes) == 0 || len(cfg.Nodes) > 16 {
		return nil, fmt.Errorf("GPU process executor requires bounded local observation authority")
	}
	for id, node := range cfg.Nodes {
		if id == "" || node.Node == nil || node.Node.ClusterID != cfg.ClusterID || node.Node.NodeID != id {
			return nil, fmt.Errorf("GPU process node inventory is invalid")
		}
	}
	return &Executor{source: source, clock: clock, cfg: cfg}, nil
}

func (e *Executor) ExecuteTyped(ctx context.Context, lease domain.TypedWorkLease) domain.TypedCollectorResult {
	started, p := e.clock.Now().UTC(), lease.Plan
	fail := func(code domain.FailureCode, message string) domain.TypedCollectorResult {
		return application.FailedTypedCollection(lease, e.clock.Now(), code, message)
	}
	if err := domain.ValidateTypedWorkLease(lease); err != nil || p.ClusterID != e.cfg.ClusterID || p.SourceID != e.cfg.SourceID || p.SourceKind != domain.CollectionSourceGPUProcess || p.Operation != domain.OperationGPUProcessObservations || p.PayloadSchema != domain.GPUProcessCollectionSchema || p.Cursor != "" || len(p.Scope.Nodes) != len(e.cfg.Nodes) {
		return fail(domain.FailureInvalidArgument, "GPU process observation requires the complete configured node scope")
	}
	if ctx == nil {
		return fail(domain.FailureInvalidArgument, "GPU process observation requires a context")
	}
	if !p.Deadline.After(started) {
		return fail(domain.FailureDeadlineExceeded, "GPU process observation deadline expired")
	}
	if len(p.Scope.Nodes) > 16 {
		return fail(domain.FailureResultLimit, "GPU process observation exceeds the sixteen-node polling bound")
	}
	if p.Limits.MaxRecords < len(p.Scope.Nodes) {
		return fail(domain.FailureResultLimit, "GPU process observation record budget cannot represent its node scope")
	}
	bounded, cancel := context.WithDeadline(ctx, p.Deadline)
	defer cancel()
	nodes := make([]domain.GPUProcessNodeObservation, len(p.Scope.Nodes))
	failuresByNode := make([]*domain.CollectionFailure, len(p.Scope.Nodes))
	sem := make(chan struct{}, 4)
	var group sync.WaitGroup
	for index, id := range p.Scope.Nodes {
		group.Add(1)
		go func(index int, id domain.StableNodeID) {
			defer group.Done()
			select {
			case sem <- struct{}{}:
			case <-bounded.Done():
				nodes[index] = domain.GPUProcessNodeObservation{NodeID: id, ObservedAt: e.clock.Now().UTC(), ComputeVisibility: domain.SourceCoverageUnavailable, Gaps: []domain.GPUProcessSourceGap{domain.GPUProcessGapTimeout}}
				failuresByNode[index] = &domain.CollectionFailure{Code: domain.FailureDeadlineExceeded, Target: string(id), Message: "GPU process observation deadline expired"}
				return
			}
			defer func() { <-sem }()
			config, ok := e.cfg.Nodes[id]
			if !ok {
				nodes[index] = domain.GPUProcessNodeObservation{NodeID: id, ObservedAt: e.clock.Now().UTC(), ComputeVisibility: domain.SourceCoverageUnknown, Gaps: []domain.GPUProcessSourceGap{domain.GPUProcessGapInventoryMissing}}
				failuresByNode[index] = &domain.CollectionFailure{Code: domain.FailureInvalidArgument, Target: string(id), Message: "GPU process node is not locally configured"}
				return
			}
			result, stats, sourceGaps, err := e.source.Observe(bounded, id)
			now := e.clock.Now().UTC()
			node := domain.GPUProcessNodeObservation{NodeID: id, ObservedAt: now, ComputeVisibility: result.ComputeVisibility}
			if err != nil {
				node.ComputeVisibility = domain.SourceCoverageUnavailable
				node.Gaps = []domain.GPUProcessSourceGap{domain.GPUProcessGapUnsupported}
				failuresByNode[index] = &domain.CollectionFailure{Code: domain.FailureSourceUnavailable, Target: string(id), Message: "GPU process source unavailable"}
			} else {
				result.Observations, result.Gaps = deduplicateProcessObservations(result.Observations, result.Gaps)
				for _, observation := range result.Observations {
					if observation.PID != 0 && observation.GPUUUID != "" {
						node.Processes = append(node.Processes, domain.GPUProcessFact{GPUUUID: observation.GPUUUID, PID: observation.PID, StartKnown: observation.Process != nil})
					}
				}
				for _, stat := range stats {
					node.HostStats = append(node.HostStats, domain.GPUHostStat{GPUUUID: stat.GPUUUID, TemperatureC: stat.TemperatureC, PowerWatts: stat.PowerWatts, MemoryMiB: stat.MemoryMiB})
				}
				for _, gap := range append(result.Gaps, sourceGaps...) {
					node.Gaps = append(node.Gaps, mapGap(gap))
				}
				if !processStartKnown(node) {
					node.Gaps = append(node.Gaps, domain.GPUProcessGapStartUnknown)
				}
			}
			node.Gaps = uniqueGaps(node.Gaps)
			_ = config
			nodes[index] = node
		}(index, id)
	}
	group.Wait()
	failures := []domain.CollectionFailure(nil)
	for _, failure := range failuresByNode {
		if failure != nil {
			failures = append(failures, *failure)
		}
	}
	// MaxRecords is an aggregate payload bound. Retain node order and process
	// rows first, then host stats, and mark the result explicitly when the
	// source produced more records than the leased budget permits.
	remaining := p.Limits.MaxRecords
	for index := range nodes {
		if remaining < 0 {
			remaining = 0
		}
		if len(nodes[index].Processes) > remaining {
			nodes[index].Processes = nodes[index].Processes[:remaining]
			nodes[index].Gaps = uniqueGaps(append(nodes[index].Gaps, domain.GPUProcessGapOutputLimit))
		}
		remaining -= len(nodes[index].Processes)
		if remaining < 0 {
			remaining = 0
		}
		if len(nodes[index].HostStats) > remaining {
			nodes[index].HostStats = nodes[index].HostStats[:remaining]
			nodes[index].Gaps = uniqueGaps(append(nodes[index].Gaps, domain.GPUProcessGapOutputLimit))
		}
		remaining -= len(nodes[index].HostStats)
	}
	completed := e.clock.Now().UTC()
	state := domain.SourceCoverageComplete
	status := domain.ResultSucceeded
	if len(failures) > 0 {
		state, status = domain.SourceCoverageUnknown, domain.ResultPartial
	}
	for _, node := range nodes {
		if len(node.Gaps) > 0 {
			if state == domain.SourceCoverageComplete {
				state, status = domain.SourceCoverageUnknown, domain.ResultPartial
			}
			failures = append(failures, domain.CollectionFailure{Code: domain.FailurePartialData, Target: string(node.NodeID), Message: "GPU process observation contains explicit gaps"})
		}
	}
	expected, observed := len(p.Scope.Nodes), len(nodes)
	if state == domain.SourceCoverageUnknown {
		expected, observed = 0, 0
	}
	coverage := domain.SourceCoverage{SchemaVersion: domain.InventoryContractSchemaVersion, ClusterID: p.ClusterID, SourceID: p.SourceID, Scope: domain.CoverageMetrics, State: state, Expected: expected, Observed: observed, SourceAt: completed, EffectiveAt: completed, ObservedAt: completed}
	return domain.TypedCollectorResult{SchemaVersion: domain.CollectionProtocolVersion, WorkID: lease.Lease.Work.WorkID, Attempt: lease.Lease.Attempt, Plan: p, Status: status, StartedAt: started, CompletedAt: completed, Coverage: coverage, Payload: domain.CollectionPayload{Kind: domain.CollectionPayloadGPUProcess, GPUProcess: &domain.GPUProcessSnapshotPayload{Nodes: nodes}}, Failures: failures}
}

func processStartKnown(node domain.GPUProcessNodeObservation) bool {
	for _, process := range node.Processes {
		if !process.StartKnown {
			return false
		}
	}
	return len(node.Processes) == 0
}
func mapGap(gap adapter.Gap) domain.GPUProcessSourceGap {
	switch gap {
	case adapter.Malformed:
		return domain.GPUProcessGapMalformed
	case adapter.GPUUnknown, adapter.NodeUnknown, adapter.Missing:
		return domain.GPUProcessGapInventoryMissing
	case adapter.Stale:
		return domain.GPUProcessGapInventoryStale
	case adapter.AuthenticationUnavailable:
		return domain.GPUProcessGapAuthUnavailable
	case adapter.PermissionDenied:
		return domain.GPUProcessGapPrivilegeDenied
	case adapter.Timeout:
		return domain.GPUProcessGapTimeout
	case adapter.OutputLimit, adapter.Truncated:
		return domain.GPUProcessGapOutputLimit
	case adapter.Unsupported:
		return domain.GPUProcessGapUnsupported
	default:
		return domain.GPUProcessGapUnsupported
	}
}

func deduplicateProcessObservations(values []adapter.Observation, gaps []adapter.Gap) ([]adapter.Observation, []adapter.Gap) {
	seen := make(map[string]struct{}, len(values))
	result := make([]adapter.Observation, 0, len(values))
	for _, value := range values {
		key := string(value.GPUUUID) + "/" + fmt.Sprint(value.PID)
		if _, exists := seen[key]; exists {
			gaps = append(gaps, adapter.Malformed)
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result, gaps
}
func uniqueGaps(values []domain.GPUProcessSourceGap) []domain.GPUProcessSourceGap {
	slices.Sort(values)
	return slices.Compact(values)
}
