package main

import (
	"slices"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adapters/investigationapi"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationtools"
)

// Diagnostic execution is opt-in per cluster. A deployment that has not named a
// cluster must advertise no diagnostic at all, so the catalog it builds is
// byte-identical to the pre-M12 one.
func TestDiagnosticToolsAreAbsentUntilAClusterOptsIn(t *testing.T) {
	if got := diagnosticToolDefinitions(nil); got != nil {
		t.Fatalf("an unconfigured deployment offered %d diagnostics", len(got))
	}
	clusters := []domain.ClusterID{"pilot-cluster"}
	catalog, err := investigationtools.NewCatalog(append(toolDefinitions(clusters), diagnosticToolDefinitions(nil)...))
	if err != nil {
		t.Fatal(err)
	}
	filter := investigationtools.Filter{
		ClusterID: "pilot-cluster", ActorCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun},
		ClusterCapabilities: investigatorClusterCapabilities(), AllowDiagnostics: true,
		Scope: domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"comp001"}, Start: time.Now().Add(-time.Hour), End: time.Now()},
	}
	for _, definition := range catalog.Available(filter) {
		if definition.Diagnostic() {
			t.Fatalf("an unconfigured deployment exposed %s even with the grant and capability present", definition.ID)
		}
	}
}

// With a cluster opted in, all three reviewed diagnostics become reachable --
// but only for that cluster, only with a diagnostic grant, and only with the
// execution cluster capability.
func TestOptedInClusterReachesTheReviewedDiagnostics(t *testing.T) {
	clusters := []domain.ClusterID{"pilot-cluster", "other-cluster"}
	diagnostics := []domain.ClusterID{"pilot-cluster"}
	catalog, err := investigationtools.NewCatalog(append(toolDefinitions(clusters), diagnosticToolDefinitions(diagnostics)...))
	if err != nil {
		t.Fatal(err)
	}
	scope := domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"comp001"}, Start: time.Now().Add(-time.Hour), End: time.Now()}
	granted := investigationtools.Filter{
		ClusterID: "pilot-cluster", ActorCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun},
		ClusterCapabilities: investigatorClusterCapabilities(), AllowDiagnostics: true, Scope: scope,
	}
	available := map[investigationtools.ToolID]investigationtools.Definition{}
	for _, definition := range catalog.Available(granted) {
		available[definition.ID] = definition
	}
	for _, id := range []investigationtools.ToolID{investigationapi.ECCCountersToolID, investigationapi.RetiredPagesToolID, investigationapi.RowRemapToolID, investigationtools.DiagnosticKernelXIDToolID} {
		definition, present := available[id]
		if !present {
			t.Fatalf("%s is not reachable on an opted-in cluster", id)
		}
		if !definition.Diagnostic() || definition.MinimumReexecutionInterval <= 0 {
			t.Fatalf("%s is not a well-formed diagnostic: %+v", id, definition)
		}
		if !slices.Contains(definition.Scope.EntityKinds, "node") {
			t.Fatalf("%s does not target nodes: %v", id, definition.Scope.EntityKinds)
		}
	}

	tests := map[string]func(*investigationtools.Filter){
		"cluster not opted in": func(f *investigationtools.Filter) { f.ClusterID = "other-cluster" },
		"no diagnostic grant":  func(f *investigationtools.Filter) { f.AllowDiagnostics = false },
		"no execution capability": func(f *investigationtools.Filter) {
			f.ClusterCapabilities = []investigationtools.ClusterCapability{"evidence.read"}
		},
		"scope is not a node kind": func(f *investigationtools.Filter) { f.Scope.EntityKind = "job" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := granted
			candidate.ClusterCapabilities = slices.Clone(granted.ClusterCapabilities)
			mutate(&candidate)
			for _, definition := range catalog.Available(candidate) {
				if definition.Diagnostic() {
					t.Fatalf("%s was reachable with a gate closed", definition.ID)
				}
			}
		})
	}

	// The evidence lookups an existing deployment relies on are unchanged by any
	// of this: they stay reachable with no diagnostic grant at all.
	ungranted := granted
	ungranted.AllowDiagnostics = false
	if len(catalog.Available(ungranted)) != len(toolDefinitions(clusters)) {
		t.Fatal("adding diagnostics changed which evidence lookups an ungranted run sees")
	}
}
