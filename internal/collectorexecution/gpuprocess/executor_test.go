package gpuprocess

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	adapter "github.com/verticalcomputer/sherlock/internal/adapters/gpuprocess"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type fixtureSource struct {
	results map[domain.StableNodeID]adapter.Result
}

func (s fixtureSource) Observe(_ context.Context, node domain.StableNodeID) (adapter.Result, []adapter.HostStat, []adapter.Gap, error) {
	return s.results[node], []adapter.HostStat{{GPUUUID: "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", TemperatureC: pointer(60), MemoryMiB: pointer(1024)}}, nil, nil
}

type fixtureClock struct{ now time.Time }

func (c fixtureClock) Now() time.Time { return c.now }
func pointer(value float64) *float64  { return &value }

func TestExecutorRetainsMultiNodePIDUUIDAndNoSchedulerAttribution(t *testing.T) {
	now := time.Now().UTC()
	result := adapter.Result{ComputeVisibility: domain.SourceCoveragePartial, Observations: []adapter.Observation{{PID: 42, GPUUUID: "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}, Gaps: []adapter.Gap{adapter.StartUnknown}}
	executor, err := New(fixtureSource{results: map[domain.StableNodeID]adapter.Result{"node-1": result, "node-2": result}}, fixtureClock{now}, Config{ClusterID: "cluster-1", SourceID: "gpu-source", Nodes: map[domain.StableNodeID]NodeConfig{"node-1": nodeConfig("node-1"), "node-2": nodeConfig("node-2")}})
	if err != nil {
		t.Fatal(err)
	}
	lease := fixtureLease(now)
	got := executor.ExecuteTyped(context.Background(), lease)
	if got.Status != domain.ResultPartial || len(got.Payload.GPUProcess.Nodes) != 2 || got.Payload.GPUProcess.Nodes[0].Processes[0].PID != 42 || got.Payload.GPUProcess.Nodes[0].Processes[0].StartKnown || got.Payload.GPUProcess.Nodes[0].Gaps[0] == "" {
		t.Fatalf("unexpected result: %+v", got)
	}
	if err := domain.ValidateTypedCollectorResult(got); err != nil {
		t.Fatal(err)
	}
}

func TestExecutorBoundsMultiNodePollingConcurrency(t *testing.T) {
	var active, maximum atomic.Int32
	started := make(chan struct{}, 8)
	release := make(chan struct{})
	source := boundedSource{active: &active, maximum: &maximum, started: started, release: release}
	nodes := make(map[domain.StableNodeID]NodeConfig, 8)
	ids := make([]domain.StableNodeID, 0, 8)
	for index := 0; index < 8; index++ {
		id := domain.StableNodeID("node-" + string(rune('1'+index)))
		nodes[id] = nodeConfig(id)
		ids = append(ids, id)
	}
	now := time.Now().UTC()
	executor, err := New(source, fixtureClock{now}, Config{ClusterID: "cluster-1", SourceID: "gpu-source", Nodes: nodes})
	if err != nil {
		t.Fatal(err)
	}
	lease := fixtureLeaseNodes(now, ids)
	done := make(chan domain.TypedCollectorResult, 1)
	go func() { done <- executor.ExecuteTyped(context.Background(), lease) }()
	for range 4 {
		<-started
	}
	close(release)
	result := <-done
	if result.Status != domain.ResultSucceeded && result.Status != domain.ResultPartial {
		t.Fatalf("unexpected result status: %s", result.Status)
	}
	if maximum.Load() > 4 {
		t.Fatalf("maximum observation concurrency = %d, want <= 4", maximum.Load())
	}
}

func TestExecutorDeduplicatesProcessFactsWithMalformedGap(t *testing.T) {
	values := []adapter.Observation{{GPUUUID: "GPU-11111111-2222-3333-4444-555555555555", PID: 7}, {GPUUUID: "GPU-11111111-2222-3333-4444-555555555555", PID: 7}}
	values, gaps := deduplicateProcessObservations(values, nil)
	if len(values) != 1 || len(gaps) != 1 || gaps[0] != adapter.Malformed {
		t.Fatalf("deduplicated values=%+v gaps=%v", values, gaps)
	}
}

type boundedSource struct {
	active, maximum *atomic.Int32
	started         chan<- struct{}
	release         <-chan struct{}
}

func (s boundedSource) Observe(ctx context.Context, _ domain.StableNodeID) (adapter.Result, []adapter.HostStat, []adapter.Gap, error) {
	current := s.active.Add(1)
	for {
		prior := s.maximum.Load()
		if current <= prior || s.maximum.CompareAndSwap(prior, current) {
			break
		}
	}
	s.started <- struct{}{}
	select {
	case <-s.release:
	case <-ctx.Done():
	}
	s.active.Add(-1)
	return adapter.Result{ComputeVisibility: domain.SourceCoverageComplete}, nil, nil, nil
}
func nodeConfig(id domain.StableNodeID) NodeConfig {
	return NodeConfig{Node: &domain.EntityIdentity{ClusterID: "cluster-1", Kind: domain.EntityNode, NodeID: id}}
}
func fixtureLease(now time.Time) domain.TypedWorkLease {
	return fixtureLeaseNodes(now, []domain.StableNodeID{"node-1", "node-2"})
}
func fixtureLeaseNodes(now time.Time, nodes []domain.StableNodeID) domain.TypedWorkLease {
	p := domain.CollectionPlan{SchemaVersion: 2, RunID: "run-1", ClusterID: "cluster-1", SourceID: "gpu-source", SourceKind: domain.CollectionSourceGPUProcess, Operation: domain.OperationGPUProcessObservations, PayloadSchema: domain.GPUProcessCollectionSchema, Scope: domain.CollectionScope{Nodes: nodes}, Interval: &domain.CollectionInterval{Start: now.Add(-time.Minute), End: now}, ScheduledFor: now, Deadline: now.Add(time.Minute), Limits: domain.CollectionLimits{MaxRecords: 200, MaxBytes: 1 << 20}, IdempotencyKey: "key-1"}
	return domain.TypedWorkLease{Plan: p, Lease: domain.WorkLease{CollectorID: "collector-1", Attempt: 1, LeaseToken: strings.Repeat("a", 32), LeaseExpires: p.Deadline, Work: domain.CollectorWork{WorkID: "work-1", WorkExpiresAt: p.Deadline, Task: domain.CollectionTask{RunID: p.RunID, ClusterID: p.ClusterID, SourceID: p.SourceID, IdempotencyKey: p.IdempotencyKey}}}}
}
