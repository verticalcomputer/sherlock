package investigationapi

import (
	"context"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestEvidenceExecutorRevalidatesDurableScopeAndReturnsBoundedReferences(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := evidenceExecutorSnapshot(t, now)
	store := &evidenceExecutorStore{snapshot: snapshot, entries: []domain.InvestigationEvidence{{EvidenceID: "evidence-1", InvestigationID: "inv-1", ClusterID: "cluster-a", EntityIDs: []string{"node-1"}, Status: domain.EvidenceComplete, ObservedStart: now.Add(-time.Minute), ObservedEnd: now, RecordedAt: now}}}
	executor, err := NewEvidenceExecutor(store, []domain.ClusterID{"cluster-a"})
	if err != nil {
		t.Fatal(err)
	}
	action := domain.InvestigationAction{ID: "action-1", ToolID: EvidenceLookupToolID, Digest: domain.ChecksumSHA256([]byte("action")), FanOut: 1, Targets: []string{"node-1"}, Start: now.Add(-time.Hour), End: now}
	store.snapshot.ProposedAction = &action
	result, err := executor.ExecuteInvestigationAction(context.Background(), "investigation/inv-1/action/action-1", action)
	if err != nil || len(result.Evidence) != 1 || result.Receipt == "" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !store.committedBefore.Equal(snapshot.Investigation.Request().RequestedAt) {
		t.Fatalf("evidence visibility cutoff=%s", store.committedBefore)
	}
	action.Targets = []string{"node-2"}
	if _, err := executor.ExecuteInvestigationAction(context.Background(), "investigation/inv-1/action/action-1", action); err == nil {
		t.Fatal("out-of-scope action succeeded")
	}
}

func TestEvidenceExecutorRejectsUnboundedResult(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	store := &evidenceExecutorStore{snapshot: evidenceExecutorSnapshot(t, now), more: true}
	executor, _ := NewEvidenceExecutor(store, []domain.ClusterID{"cluster-a"})
	action := domain.InvestigationAction{ID: "action-1", ToolID: EvidenceLookupToolID, Digest: domain.ChecksumSHA256([]byte("action")), FanOut: 1, Targets: []string{"node-1"}, Start: now.Add(-time.Hour), End: now}
	store.snapshot.ProposedAction = &action
	if _, err := executor.ExecuteInvestigationAction(context.Background(), "investigation/inv-1/action/action-1", action); err == nil {
		t.Fatal("truncated evidence result succeeded")
	}
}

func TestEvidenceExecutorUsesXIDOnlyLookupForXIDTool(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	store := &evidenceExecutorStore{snapshot: evidenceExecutorSnapshot(t, now), entries: []domain.InvestigationEvidence{{EvidenceID: "xid-1", InvestigationID: "inv-1", ClusterID: "cluster-a", EntityIDs: []string{"node-1"}, Status: domain.EvidencePartial, ObservedStart: now.Add(-time.Minute), ObservedEnd: now, RecordedAt: now}}}
	executor, _ := NewEvidenceExecutor(store, []domain.ClusterID{"cluster-a"})
	action := domain.InvestigationAction{ID: "action-1", ToolID: XIDEvidenceToolID, Digest: domain.ChecksumSHA256([]byte("action")), FanOut: 1, Targets: []string{"node-1"}, Start: now.Add(-XIDEvidenceMaximumWindow), End: now}
	store.snapshot.ProposedAction = &action
	if _, err := executor.ExecuteInvestigationAction(context.Background(), "investigation/inv-1/action/action-1", action); err != nil {
		t.Fatal(err)
	}
	if len(store.operations) != 1 || store.operations[0] != domain.EvidenceOperationID(domain.QueryGPUXID) {
		t.Fatalf("XID operation filter=%v", store.operations)
	}
	action.Start = now.Add(-XIDEvidenceMaximumWindow - time.Second)
	store.snapshot.ProposedAction = &action
	if _, err := executor.ExecuteInvestigationAction(context.Background(), "investigation/inv-1/action/action-1", action); err == nil {
		t.Fatal("XID tool exceeded its reviewed time window")
	}
}

func TestEvidenceExecutorDispatchesReviewedEvidenceClasses(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		tool      string
		operation domain.EvidenceOperationID
		maxWindow time.Duration
	}{
		{KernelEventsToolID, "loki.kernel_events.v1", time.Hour},
		{GPUHealthToolID, domain.EvidenceOperationID(domain.QueryGPUTemperature), 15 * time.Minute},
		{WorkloadToolID, "slurm.jobs.v1", 24 * time.Hour},
		{SchedulerToolID, "slurm.nodes.v1", time.Hour},
		{SourceFreshnessToolID, domain.EvidenceOperationID(domain.QuerySourceHealth), time.Hour},
		{BMCSensorsToolID, "redfish.sensors.v1", time.Hour},
	}
	for _, test := range tests {
		t.Run(test.tool, func(t *testing.T) {
			store := &evidenceExecutorStore{snapshot: evidenceExecutorSnapshot(t, now)}
			executor, _ := NewEvidenceExecutor(store, []domain.ClusterID{"cluster-a"})
			queryWindow := min(test.maxWindow, time.Hour)
			action := domain.InvestigationAction{ID: "action-1", ToolID: test.tool, Digest: domain.ChecksumSHA256([]byte(test.tool)), FanOut: 1, Targets: []string{"node-1"}, Start: now.Add(-queryWindow), End: now}
			store.snapshot.ProposedAction = &action
			if _, err := executor.ExecuteInvestigationAction(context.Background(), "investigation/inv-1/action/action-1", action); err != nil {
				t.Fatal(err)
			}
			if !containsOperation(store.operations, test.operation) {
				t.Fatalf("operation filter=%v; want %s", store.operations, test.operation)
			}
			if test.maxWindow <= time.Hour {
				action.Start = action.Start.Add(-time.Second)
				store.snapshot.ProposedAction = &action
				if _, err := executor.ExecuteInvestigationAction(context.Background(), "investigation/inv-1/action/action-1", action); err == nil {
					t.Fatal("tool exceeded reviewed window")
				}
			}
		})
	}
}

func TestEvidenceExecutorRejectsUnknownOrArgumentBearingTools(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	store := &evidenceExecutorStore{snapshot: evidenceExecutorSnapshot(t, now)}
	executor, _ := NewEvidenceExecutor(store, []domain.ClusterID{"cluster-a"})
	for _, action := range []domain.InvestigationAction{
		{ID: "action-1", ToolID: "logs.search_template.v1", Digest: domain.ChecksumSHA256([]byte("unknown")), FanOut: 1, Targets: []string{"node-1"}, Start: now.Add(-time.Minute), End: now},
		{ID: "action-1", ToolID: KernelEventsToolID, Digest: domain.ChecksumSHA256([]byte("argument")), FanOut: 1, Targets: []string{"node-1"}, Start: now.Add(-time.Minute), End: now, Arguments: []domain.InvestigationArgument{{Name: "query", Kind: "STRING", String: "{job=\"kernel\"}"}}},
	} {
		store.snapshot.ProposedAction = &action
		if _, err := executor.ExecuteInvestigationAction(context.Background(), "investigation/inv-1/action/action-1", action); err == nil {
			t.Fatalf("tool %s succeeded", action.ToolID)
		}
	}
}

type evidenceExecutorStore struct {
	snapshot        application.InvestigationSnapshot
	entries         []domain.InvestigationEvidence
	more            bool
	committedBefore time.Time
	operations      []domain.EvidenceOperationID
}

func (store *evidenceExecutorStore) FindInvestigationEvidenceByOperations(_ context.Context, _ domain.InvestigationID, _ domain.ClusterID, _ []string, _, _, committedBefore time.Time, operations []domain.EvidenceOperationID, _ int) ([]domain.InvestigationEvidence, bool, error) {
	store.committedBefore = committedBefore
	store.operations = append([]domain.EvidenceOperationID(nil), operations...)
	return store.entries, store.more, nil
}

func (store *evidenceExecutorStore) LoadInvestigation(context.Context, domain.InvestigationID) (application.InvestigationSnapshot, bool, error) {
	return store.snapshot, true, nil
}

func (store *evidenceExecutorStore) FindInvestigationEvidence(_ context.Context, _ domain.InvestigationID, _ domain.ClusterID, _ []string, _, _, committedBefore time.Time, _ int) ([]domain.InvestigationEvidence, bool, error) {
	store.committedBefore = committedBefore
	return store.entries, store.more, nil
}

func evidenceExecutorSnapshot(t *testing.T, now time.Time) application.InvestigationSnapshot {
	t.Helper()
	request := domain.InvestigationRequest{ID: "inv-1", IncidentID: "incident-1", ClusterID: "cluster-a", Question: "Why is node-1 unhealthy?", RequestedBy: "actor-1", IdempotencyKey: "request-1", Scope: domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"node-1"}, Start: now.Add(-time.Hour), End: now}, SuccessCriteria: []string{"Find cited evidence"}, Budget: domain.InvestigationBudget{MaxDecisions: 3, MaxToolCalls: 2, MaxFanOut: 1}, RequestedAt: now.Add(-time.Minute), Deadline: now.Add(time.Hour)}
	value, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	return application.InvestigationSnapshot{Investigation: value}
}

func containsOperation(values []domain.EvidenceOperationID, want domain.EvidenceOperationID) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type repairEvidenceStore struct {
	evidenceExecutorStore
	currentCalls int
}

func (store *repairEvidenceStore) FindCurrentRepairEvidence(_ context.Context, _ domain.InvestigationID, _ domain.ClusterID, _, _, before time.Time, _ int) ([]domain.InvestigationEvidence, bool, error) {
	store.currentCalls++
	store.committedBefore = before
	return store.entries, store.more, nil
}
func TestRepairExecutorReadsFrozenWarningsAcrossSources(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	snapshot := evidenceExecutorSnapshot(t, now)
	request := snapshot.Investigation.Request()
	request.Purpose = domain.InvestigationPurposeRepairPlan
	request.Scope.EntityKind = "cluster"
	request.Scope.EntityIDs = []string{"cluster-a"}
	var err error
	snapshot.Investigation, err = domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	store := &repairEvidenceStore{evidenceExecutorStore: evidenceExecutorStore{snapshot: snapshot}}
	action := domain.InvestigationAction{ID: "action-1", ToolID: EvidenceLookupToolID, Digest: domain.ChecksumSHA256([]byte("repair")), FanOut: 1, Targets: []string{"cluster-a"}, Start: request.Scope.Start, End: request.Scope.End}
	store.snapshot.ProposedAction = &action
	executor, _ := NewEvidenceExecutor(store, []domain.ClusterID{"cluster-a"})
	if _, err := executor.ExecuteInvestigationAction(context.Background(), "investigation/inv-1/action/action-1", action); err != nil {
		t.Fatal(err)
	}
	if store.currentCalls != 1 || !store.committedBefore.Equal(request.RequestedAt) {
		t.Fatal("did not use request-time current warning query")
	}
	action.ToolID = XIDEvidenceToolID
	action.Start = now.Add(-time.Minute)
	store.snapshot.ProposedAction = &action
	if _, err := executor.ExecuteInvestigationAction(context.Background(), "investigation/inv-1/action/action-1", action); err == nil {
		t.Fatal("repair accepted a source-specific substitute")
	}
}
