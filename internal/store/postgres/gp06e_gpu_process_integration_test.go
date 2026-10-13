//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// TestGP06EDurableProcessAuthority proves that the new source family enters
// the same operator-controlled durable path as the existing typed sources.
// The fixture deliberately exercises the gates independently: source kind,
// cadence, configured node scope, protocol, capability, and the canonical
// typed-result artifact path.
func TestGP06EDurableProcessAuthority(t *testing.T) {
	p := durableTestDatabase(t)
	s, err := storepg.NewCollectionStore(p)
	if err != nil {
		t.Fatal(err)
	}
	c, err := storepg.NewCollectorControlStore(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	cluster := domain.ClusterID("gp06e-cluster-" + suffix)
	source := domain.SourceID("gp06e-source-" + suffix)
	collector := domain.CollectorID("gp06e-collector-" + suffix)
	if err := s.EnsureSource(ctx, cluster, "GP06e fixture", source, "GPU process fixture"); err != nil {
		t.Fatal(err)
	}

	// EnsureSource intentionally creates the ordinary Prometheus kind. The
	// operation cannot be configured until the operator changes the source to
	// the separately enrolled gpu_process family.
	badSource := gpuProcessSchedule(cluster, source, true, 5*time.Minute, 2*time.Minute, 16)
	if _, err := s.CreateDesiredSchedule(ctx, badSource); err == nil {
		t.Fatal("gpu process schedule was accepted for a Prometheus source")
	}
	if _, err := p.Exec(ctx, `UPDATE sources SET kind='gpu_process' WHERE cluster_id=$1 AND source_id=$2`, cluster, source); err != nil {
		t.Fatal(err)
	}

	// Five minutes and two minutes are the accepted lower/upper bounds. The
	// adjacent values are rejected before they can create durable authority.
	for name, schedule := range map[string]domain.DesiredSchedule{
		"interval below five minutes": gpuProcessSchedule(cluster, source, true, 5*time.Minute-time.Second, 2*time.Minute, 16),
		"timeout above two minutes":   gpuProcessSchedule(cluster, source, true, 5*time.Minute, 2*time.Minute+time.Millisecond, 16),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.CreateDesiredSchedule(ctx, schedule); err == nil {
				t.Fatal("out-of-bound schedule was accepted")
			}
		})
	}

	created, err := s.CreateDesiredSchedule(ctx, badSource)
	if err != nil {
		t.Fatal("valid five-minute/two-minute schedule was rejected:", err)
	}
	nodes := make([]domain.StableNodeID, 16)
	for i := range nodes {
		nodes[i] = domain.StableNodeID(fmt.Sprintf("compute-%02d", i))
	}
	if err := c.RegisterCollector(ctx, storepg.CollectorRegistration{CollectorID: collector, ClusterID: cluster, DisplayName: "GP06e fixture", Version: "fixture", ProtocolMin: 1, ProtocolMax: 2, OperatingSystem: "linux", Architecture: "amd64"}); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureDurableExecution(ctx, domain.DurableExecution{ScheduleKey: created.ScheduleKey, Revision: created.Revision, CollectorID: collector, Nodes: nodes}); err != nil {
		t.Fatal("sixteen configured nodes were rejected:", err)
	}
	tooMany := append(append([]domain.StableNodeID(nil), nodes...), "compute-16")
	if err := s.ConfigureDurableExecution(ctx, domain.DurableExecution{ScheduleKey: created.ScheduleKey, Revision: created.Revision, CollectorID: collector, Nodes: tooMany}); err == nil {
		t.Fatal("seventeen configured nodes were accepted")
	}

	report := func(protocolMin, protocolMax int, capability string) {
		t.Helper()
		now := time.Now().UTC()
		heartbeat := collectorcontrol.Heartbeat{CollectorID: collector, ProtocolMin: protocolMin, ProtocolMax: protocolMax, Version: "fixture", ReportedAt: now,
			Capabilities: []collectorcontrol.CapabilityReport{{Name: capability, Version: "1"}}}
		if err := c.RecordHeartbeat(ctx, heartbeat); err != nil {
			t.Fatal(err)
		}
	}
	policy := domain.DurableAdmissionPolicy{GlobalLimit: 10, ClusterLimit: 10}
	report(2, 2, "unrelated.capability.v1")
	if _, found, err := s.AdmitDueSchedule(ctx, policy); err != nil || found {
		t.Fatalf("missing capability admitted schedule: found=%t err=%v", found, err)
	}
	report(1, 1, string(domain.OperationGPUProcessObservations))
	if _, found, err := s.AdmitDueSchedule(ctx, policy); err != nil || found {
		t.Fatalf("protocol-one collector admitted v2 schedule: found=%t err=%v", found, err)
	}
	report(2, 2, string(domain.OperationGPUProcessObservations))
	admission, found, err := s.AdmitDueSchedule(ctx, policy)
	if err != nil || !found {
		t.Fatalf("compatible collector did not admit schedule: %+v found=%t err=%v", admission, found, err)
	}
	if admission.Occurrence != 1 || admission.Revision != created.Revision {
		t.Fatalf("unexpected first admission: %+v", admission)
	}

	var encodedPlan []byte
	if err := p.QueryRow(ctx, `SELECT typed_plan FROM collector_work_items WHERE work_id=$1`, admission.WorkID).Scan(&encodedPlan); err != nil {
		t.Fatal(err)
	}
	var admittedPlan domain.CollectionPlan
	if err := json.Unmarshal(encodedPlan, &admittedPlan); err != nil {
		t.Fatal(err)
	}
	if admittedPlan.SourceKind != domain.CollectionSourceGPUProcess || admittedPlan.Operation != domain.OperationGPUProcessObservations || len(admittedPlan.Scope.Nodes) != 16 {
		t.Fatalf("admitted plan lost source or scope: %+v", admittedPlan)
	}
	if got := admittedPlan.Deadline.Sub(admittedPlan.ScheduledFor); got != 2*time.Minute {
		t.Fatalf("admitted timeout=%s want 2m", got)
	}

	// The SQL admission predicate repeats the node bound. Corrupting a test
	// row directly proves that a malformed execution cannot enter the queue.
	tooManyJSON, _ := json.Marshal(tooMany)
	if _, err := p.Exec(ctx, `UPDATE durable_schedule_executions SET nodes=$4 WHERE cluster_id=$1 AND source_id=$2 AND operation=$3 AND revision=$5`, cluster, source, domain.OperationGPUProcessObservations, tooManyJSON, created.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `UPDATE durable_schedule_state SET next_due_at=clock_timestamp() WHERE cluster_id=$1 AND source_id=$2 AND operation=$3`, cluster, source, domain.OperationGPUProcessObservations); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.AdmitDueSchedule(ctx, policy); err != nil || found {
		t.Fatalf("seventeen-node execution admitted: found=%t err=%v", found, err)
	}
	if _, err := p.Exec(ctx, `UPDATE durable_schedule_executions SET nodes=$4 WHERE cluster_id=$1 AND source_id=$2 AND operation=$3 AND revision=$5`, cluster, source, domain.OperationGPUProcessObservations, mustJSON(t, nodes), created.Revision); err != nil {
		t.Fatal(err)
	}

	// Restore the valid execution row only for the typed-result proof. The
	// already-admitted work retains its immutable sixteen-node plan.
	lease, claimed, err := c.ClaimTypedWork(ctx, cluster, collector, strings.Repeat("a", 32), time.Minute, []domain.SourceID{source})
	if err != nil || !claimed {
		t.Fatalf("typed work claim=%t err=%v", claimed, err)
	}
	result := gp06eResult(lease)
	outcome, err := c.SubmitTypedResult(ctx, cluster, collector, collectorcontrol.LeaseRef{WorkID: lease.Lease.Work.WorkID, Attempt: lease.Lease.Attempt, LeaseToken: lease.Lease.LeaseToken}, result, typedChecksum(result))
	if err != nil || outcome.PreviouslyFinalized {
		t.Fatalf("typed result finalization=%+v err=%v", outcome, err)
	}
	replayed, err := c.SubmitTypedResult(ctx, cluster, collector, collectorcontrol.LeaseRef{WorkID: lease.Lease.Work.WorkID, Attempt: lease.Lease.Attempt, LeaseToken: lease.Lease.LeaseToken}, result, typedChecksum(result))
	if err != nil || !replayed.PreviouslyFinalized {
		t.Fatalf("typed result replay=%+v err=%v", replayed, err)
	}
	stored, present, err := c.LoadFinalizedTypedResult(ctx, cluster, lease.Lease.Work.WorkID)
	if err != nil || !present || typedChecksum(stored) != typedChecksum(result) {
		t.Fatalf("stored GPU process result present=%t err=%v", present, err)
	}
	if _, present, err := c.LoadFinalizedTypedResult(ctx, domain.ClusterID("other-cluster"), lease.Lease.Work.WorkID); err != nil || present {
		t.Fatalf("cross-cluster result lookup present=%t err=%v", present, err)
	}
}

func gpuProcessSchedule(cluster domain.ClusterID, source domain.SourceID, enabled bool, interval, timeout time.Duration, maxTargets int) domain.DesiredSchedule {
	return domain.DesiredSchedule{ScheduleKey: domain.ScheduleKey{ClusterID: cluster, SourceID: source, Operation: domain.OperationGPUProcessObservations}, Enabled: enabled, Mode: domain.SchedulingDurable, Interval: interval, Timeout: timeout, MaxTargets: maxTargets, MaxBytes: 2 << 20, Priority: 10}
}

func gp06eResult(lease domain.TypedWorkLease) domain.TypedCollectorResult {
	now := lease.Plan.ScheduledFor.Add(time.Second)
	temperature, power, memory := 70.0, 250.0, 1024.0
	const gpuUUID = domain.PhysicalGPUUUID("GPU-11111111-2222-3333-4444-555555555555")
	nodes := make([]domain.GPUProcessNodeObservation, len(lease.Plan.Scope.Nodes))
	for index, nodeID := range lease.Plan.Scope.Nodes {
		nodes[index] = domain.GPUProcessNodeObservation{NodeID: nodeID, ObservedAt: now, ComputeVisibility: domain.SourceCoverageComplete}
	}
	// Keep the result within the plan's 16-record bound while still proving
	// that process attribution and reviewed host fields share one payload.
	nodes[0].Processes = []domain.GPUProcessFact{{GPUUUID: gpuUUID, PID: 42}}
	nodes[0].HostStats = []domain.GPUHostStat{{GPUUUID: gpuUUID, TemperatureC: &temperature, PowerWatts: &power, MemoryMiB: &memory}}
	return domain.TypedCollectorResult{SchemaVersion: domain.CollectionProtocolVersion, WorkID: lease.Lease.Work.WorkID, Attempt: lease.Lease.Attempt, Plan: lease.Plan,
		Status: domain.ResultSucceeded, StartedAt: now, CompletedAt: now.Add(time.Second), Coverage: domain.SourceCoverage{SchemaVersion: domain.InventoryContractSchemaVersion, ClusterID: lease.Plan.ClusterID, SourceID: lease.Plan.SourceID, Scope: domain.CoverageMetrics, State: domain.SourceCoverageComplete, Expected: len(lease.Plan.Scope.Nodes), Observed: len(lease.Plan.Scope.Nodes), SourceAt: now, EffectiveAt: now, ObservedAt: now.Add(time.Second)},
		Payload: domain.CollectionPayload{Kind: domain.CollectionPayloadGPUProcess, GPUProcess: &domain.GPUProcessSnapshotPayload{Nodes: nodes}}}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
