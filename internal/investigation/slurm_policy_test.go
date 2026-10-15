package investigation

import (
	"context"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationtools"
)

func TestSlurmPolicyRequiresOneReadOnlyPassAndRetainsPartialClosure(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	snapshot := planningSnapshot(t, now)
	request := snapshot.Investigation.Request()
	request.IdempotencyKey = "auto-slurm-fixture"
	request.Scope.EntityIDs = []string{"slurm-source", "n1"}
	request.Scope.EntityKind = "entity"
	inv, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	inv, err = inv.BeginPlanning(now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Investigation = inv
	provider := fakePlanningProvider(t, nil)
	o := newTestOrchestrator(t, provider, &auditMemory{}, &duplicateMemory{}, now)
	catalog, err := investigationtools.NewCatalog([]investigationtools.Definition{{SchemaVersion: 1, ID: "cluster.slurm_failure_evidence.v1", Description: "Read frozen Slurm correlation", Operation: investigationtools.OperationReadOnly, AllowedClusters: []domain.ClusterID{request.ClusterID}, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, RequiredClusterCapabilities: []investigationtools.ClusterCapability{"dcgm.read"}, Scope: investigationtools.ScopePolicy{EntityKinds: []string{"entity"}, MaxTargets: 64, MaxWindow: 24 * time.Hour}, Timeout: time.Second, CostWeight: 1}})
	if err != nil {
		t.Fatal(err)
	}
	o.catalog = catalog
	decision, err := o.Decide(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action == nil || decision.Action.ToolID != "cluster.slurm_failure_evidence.v1" || decision.Action.Diagnostic || decision.Action.Privileged || len(decision.Action.Targets) != 1 || decision.Action.Targets[0] != "slurm-source" {
		t.Fatalf("Slurm pass changed authority: %+v", decision)
	}
	snapshot.PriorActions = []application.InvestigationActionHistory{{ToolID: decision.Action.ToolID, Outcome: "SUCCEEDED"}}
	decision, err = o.Decide(context.Background(), snapshot)
	if err != nil || !decision.Stop || decision.Outcome != domain.InvestigationPartial {
		t.Fatalf("Slurm pass falsely closed or repeated: %+v %v", decision, err)
	}
	if len(provider.PlanningCalls()) != 0 {
		t.Fatal("required Slurm evidence was delegated to model discretion")
	}
}
