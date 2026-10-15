package main

import (
	"testing"
	"time"

	investigationapi "github.com/verticalcomputer/sherlock/internal/adapters/investigationapi"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationtools"
)

func TestM94ToolDefinitionsAreBoundedReadOnlyAndArgumentFree(t *testing.T) {
	definitions := toolDefinitions([]domain.ClusterID{"cluster-a"})
	if len(definitions) != 9 {
		t.Fatalf("definitions=%d; want 9", len(definitions))
	}
	windows := map[investigationtools.ToolID]time.Duration{
		investigationapi.SlurmFailureToolID:    24 * time.Hour,
		investigationapi.KernelEventsToolID:    time.Hour,
		investigationapi.GPUHealthToolID:       15 * time.Minute,
		investigationapi.WorkloadToolID:        24 * time.Hour,
		investigationapi.SchedulerToolID:       time.Hour,
		investigationapi.SourceFreshnessToolID: time.Hour,
		investigationapi.BMCSensorsToolID:      time.Hour,
	}
	seen := map[investigationtools.ToolID]bool{}
	for _, definition := range definitions {
		if definition.Operation != investigationtools.OperationReadOnly || len(definition.AllowedClusters) != 1 || definition.Scope.MaxTargets < 1 || len(definition.Arguments) != 0 {
			t.Fatalf("unsafe definition: %+v", definition)
		}
		if want, ok := windows[definition.ID]; ok {
			seen[definition.ID] = true
			if definition.Scope.MaxWindow != want {
				t.Fatalf("tool %s window=%s; want %s", definition.ID, definition.Scope.MaxWindow, want)
			}
		}
	}
	if len(seen) != len(windows) {
		t.Fatalf("M9.4 definitions=%v", seen)
	}
	if _, err := investigationtools.NewCatalog(definitions); err != nil {
		t.Fatal(err)
	}
}

func TestInvestigatorAuthorityIncludesEveryDefinitionCapability(t *testing.T) {
	allowed := map[investigationtools.ClusterCapability]bool{}
	for _, capability := range investigatorClusterCapabilities() {
		allowed[capability] = true
	}
	for _, definition := range toolDefinitions([]domain.ClusterID{"cluster-a"}) {
		for _, capability := range definition.RequiredClusterCapabilities {
			if !allowed[capability] {
				t.Fatalf("tool %s capability %s is not composed", definition.ID, capability)
			}
		}
	}
}
