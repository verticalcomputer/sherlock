package investigation

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationcontext"
	"github.com/verticalcomputer/sherlock/internal/investigationtools"
	"github.com/verticalcomputer/sherlock/internal/modelprovider"
)

// Pilot investigations are dominated by identifier repetition, not prose: the
// observed scope carried 44 GPU and node identifiers and every planning call
// re-sent them through tool schemas, coverage, evidence, and prior actions.
// Measured pilot payloads tokenize at ~2.32 characters per token, so byte
// ceilings here are a direct proxy for provider tokens.
const pilotCharsPerToken = 2.32

func pilotScopeIDs() []string {
	ids := make([]string, 0, 44)
	for index := 0; index < 38; index++ {
		ids = append(ids, fmt.Sprintf("GPU-%08x-ac19-650f-e14a-c0a7c79c88%02d", index*2654435761, index))
	}
	for index := 3; index < 9; index++ {
		ids = append(ids, fmt.Sprintf("fixture1-zone1-comp%03d", index))
	}
	return ids
}

// pilotToolDefinitions mirrors the eight read-only production tools, including
// the differing target ceilings and reviewed windows that the shared-schema
// factoring must normalize away.
func pilotToolDefinitions() ([]investigationtools.Definition, []investigationtools.ClusterCapability) {
	type spec struct {
		id         string
		maxTargets int
		window     time.Duration
		kinds      []string
	}
	specs := []spec{
		{"evidence.lookup.v1", 64, 24 * time.Hour, []string{"cluster", "node", "gpu", "job", "source", "entity"}},
		{"metrics.xid_evidence.v1", 64, time.Hour, []string{"cluster", "node", "gpu", "entity"}},
		{"node.kernel_events.v1", 32, time.Hour, []string{"node", "entity"}},
		{"node.gpu_snapshot.v1", 64, 15 * time.Minute, []string{"cluster", "node", "gpu", "entity"}},
		{"cluster.workload_snapshot.v1", 64, 24 * time.Hour, []string{"cluster", "node", "job", "entity"}},
		{"cluster.scheduler_snapshot.v1", 64, time.Hour, []string{"cluster", "node", "job", "entity"}},
		{"cluster.source_freshness.v1", 64, time.Hour, []string{"cluster", "node", "source", "entity"}},
		{"bmc.sensor_snapshot.v1", 32, time.Hour, []string{"cluster", "node", "source", "entity"}},
	}
	definitions := make([]investigationtools.Definition, 0, len(specs))
	capabilities := make([]investigationtools.ClusterCapability, 0, len(specs))
	for _, item := range specs {
		capability := investigationtools.ClusterCapability("cap." + item.id)
		capabilities = append(capabilities, capability)
		definitions = append(definitions, investigationtools.Definition{
			SchemaVersion: investigationtools.SchemaVersion, ID: investigationtools.ToolID(item.id),
			Description: "Attach only precommitted bounded evidence for " + item.id + ".",
			Operation:   investigationtools.OperationReadOnly, AllowedClusters: []domain.ClusterID{"pilot-cluster"},
			RequiredCapabilities:        []auth.Capability{auth.CapabilityInvestigationsRun},
			RequiredClusterCapabilities: []investigationtools.ClusterCapability{capability},
			Scope:                       investigationtools.ScopePolicy{EntityKinds: item.kinds, MaxTargets: item.maxTargets, MaxWindow: item.window},
			Timeout:                     5 * time.Second, CostWeight: 1,
		})
	}
	return definitions, capabilities
}

// TestSharedToolSchemaFactoringRemovesTheRepeatedScopeEnum measures the saving
// that factoring provides at pilot scale. The scope enum is embedded in every
// tool's target schema, so without factoring 44 identifiers are re-sent eight
// times in each planning call.
func TestSharedToolSchemaFactoringRemovesTheRepeatedScopeEnum(t *testing.T) {
	ids := pilotScopeIDs()
	at := time.Date(2026, 8, 21, 11, 15, 26, 562000000, time.UTC)
	scope := domain.InvestigationScope{EntityKind: "entity", EntityIDs: ids, Start: at.Add(-time.Hour), End: at}
	definitions, capabilities := pilotToolDefinitions()
	catalog, err := investigationtools.NewCatalog(definitions)
	if err != nil {
		t.Fatal(err)
	}
	schemas, err := catalog.AvailableSchemas(investigationtools.Filter{ClusterID: "pilot-cluster", ActorCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, ClusterCapabilities: capabilities, Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	tools := make([]modelprovider.AvailableTool, 0, len(schemas))
	for _, schema := range schemas {
		tools = append(tools, modelprovider.AvailableTool{ToolID: string(schema.ToolID), Description: schema.Description, ArgumentSchema: schema.ArgumentSchema, SchemaVersion: schema.SchemaVersion, ReadOnly: schema.ReadOnly, MaximumFanOut: schema.MaximumFanOut, CostWeight: schema.CostWeight})
	}
	unfactored, err := json.Marshal(tools)
	if err != nil {
		t.Fatal(err)
	}
	factored, shared := factorToolSchemas(tools)
	factoredBytes, err := json.Marshal(factored)
	if err != nil {
		t.Fatal(err)
	}
	before, after := len(unfactored), len(factoredBytes)+len(shared)
	saved := before - after
	t.Logf("tool schemas: %d -> %d bytes, saved %d (~%.0f provider tokens per planning call)", before, after, saved, float64(saved)/pilotCharsPerToken)
	if len(shared) == 0 {
		t.Fatal("factoring did not engage at pilot scale")
	}
	// The saving is the dominant per-call reduction available; guard it against
	// any change that makes one tool's common contract diverge from the rest.
	if saved < 12_000 {
		t.Errorf("factoring saved only %d bytes at pilot scale, expected at least 12000", saved)
	}
}

// TestPilotScalePlanningPromptStaysWithinMeasuredCeilings pins the size of a
// realistic planning prompt. The pilot's own runs grew to 41,003 provider
// tokens against a 32,000 allowance and died BUDGET_EXCEEDED, so an unnoticed
// inflation here is the difference between an investigation that finishes and
// one that runs out of budget mid-loop.
func TestPilotScalePlanningPromptStaysWithinMeasuredCeilings(t *testing.T) {
	ids := pilotScopeIDs()
	at := time.Date(2026, 8, 21, 11, 15, 26, 562000000, time.UTC)
	scope := domain.InvestigationScope{EntityKind: "entity", EntityIDs: ids, Start: at.Add(-time.Hour), End: at}
	definitions, capabilities := pilotToolDefinitions()
	catalog, err := investigationtools.NewCatalog(definitions)
	if err != nil {
		t.Fatal(err)
	}
	filter := investigationtools.Filter{ClusterID: "pilot-cluster", ActorCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, ClusterCapabilities: capabilities, Scope: scope}
	schemas, err := catalog.AvailableSchemas(filter)
	if err != nil {
		t.Fatal(err)
	}
	tools := make([]modelprovider.AvailableTool, 0, len(schemas))
	for _, schema := range schemas {
		tools = append(tools, modelprovider.AvailableTool{ToolID: string(schema.ToolID), Description: schema.Description, ArgumentSchema: schema.ArgumentSchema, SchemaVersion: schema.SchemaVersion, ReadOnly: schema.ReadOnly, MaximumFanOut: schema.MaximumFanOut, CostWeight: schema.CostWeight})
	}

	request := domain.InvestigationRequest{
		ID: "investigation-pilot", IncidentID: "incident-pilot", ClusterID: "pilot-cluster",
		Question: "Why did the affected GPU entities report non-zero DCGM XID errors?", RequestedBy: "actor-1",
		IdempotencyKey: "pilot-1", Scope: scope,
		SuccessCriteria: []string{"Explain the XID signal using cited committed evidence", "State coverage gaps and uncertainty"},
		Budget:          domain.InvestigationBudget{MaxDecisions: 64, MaxToolCalls: 64, MaxFanOut: 64, MaxModelTokens: 200_000, MaxCostMicros: 2_000_000},
		RequestedAt:     at, Deadline: at.Add(time.Hour),
	}
	investigation, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	if investigation, err = investigation.BeginPlanning(at); err != nil {
		t.Fatal(err)
	}
	snapshot := application.InvestigationSnapshot{Investigation: investigation}

	// Five admitted actions and two attached evidence blocks reproduce the
	// deepest observed pilot turn, where input reached 41,003 tokens.
	coverage := make([]investigationcontext.CoverageTarget, 0, len(ids))
	for _, id := range ids {
		coverage = append(coverage, investigationcontext.CoverageTarget{Kind: domain.EvidenceTargetGPU, ID: domain.EvidenceTargetID(id)})
	}
	blocks := []investigationcontext.EvidenceBlock{}
	for index := 0; index < 2; index++ {
		blocks = append(blocks, investigationcontext.EvidenceBlock{
			Trust: investigationcontext.UntrustedEvidenceData, EvidenceID: domain.EvidenceID(fmt.Sprintf("evidence-%d", index)),
			Status: domain.EvidencePartial, EntityIDs: ids, Source: "dcgm:xid",
			ObservedFrom: at.Add(-time.Hour), ObservedTo: at, CollectedAt: at, ExpectedFrom: at.Add(-time.Hour), ExpectedTo: at,
			ExpectedTargets: coverage, ObservedTargets: coverage,
			UntrustedSummary: "The bounded XID lookup reports non-zero DCGM XID errors across the requested GPUs.",
		})
	}
	modelContext := investigationcontext.Context{
		SchemaVersion: 2, Header: investigationcontext.TrustedHeader{
			Trust: investigationcontext.TrustedControllerData, InvestigationID: request.ID, ClusterID: request.ClusterID,
			Question: request.Question, Scope: scope, SuccessCriteria: request.SuccessCriteria,
		},
		Evidence: blocks,
	}
	for index := 0; index < 5; index++ {
		snapshot.PriorActions = append(snapshot.PriorActions, application.InvestigationActionHistory{
			Digest: domain.ChecksumSHA256([]byte(fmt.Sprintf("action-%d", index))), ToolID: string(definitions[index%len(definitions)].ID),
			Outcome: "SUCCEEDED", Targets: ids, Start: at.Add(-time.Hour), End: at,
			EvidenceIDs: []domain.EvidenceID{domain.EvidenceID(fmt.Sprintf("evidence-%d", index%2))},
		})
	}

	planning := planningRequest(snapshot, modelContext, tools, Config{PlanningPrompt: "planning-v2", ToolSchemaVersion: "catalog-v1"})

	// The shared targets/start/end contract must be factored out. Without it the
	// 44-identifier enum is repeated in all eight tool schemas.
	if len(planning.SharedToolArguments) == 0 {
		t.Fatal("shared tool arguments were not factored; every tool repeats the scope enum")
	}
	for _, tool := range planning.AvailableTools {
		if len(tool.ArgumentSchema) != 0 {
			t.Fatalf("tool %s still carries a per-tool prompt schema", tool.ToolID)
		}
	}

	encoded, err := json.Marshal(planning)
	if err != nil {
		t.Fatal(err)
	}
	sections := map[string]json.RawMessage{}
	if err := json.Unmarshal(encoded, &sections); err != nil {
		t.Fatal(err)
	}
	// Ceilings are set just above measured current size. They are regression
	// guards, not targets: a change that inflates a section trips the ceiling and
	// reports the provider-token cost it just added.
	for name, bytes := range map[string]int{
		"available_tools":       5_000,
		"shared_tool_arguments": 3_000,
		"evidence":              16_000,
		"coverage":              14_000,
		"prior_actions":         14_000,
	} {
		if got := len(sections[name]); got > bytes {
			t.Errorf("section %q is %d bytes, over the %d ceiling (~%.0f provider tokens)", name, got, bytes, float64(got)/pilotCharsPerToken)
		}
	}
	total := len(encoded)
	t.Logf("pilot planning prompt: %d bytes, ~%.0f provider tokens", total, float64(total)/pilotCharsPerToken)
	// The whole request must leave room for repeated turns inside a 200,000
	// token run budget. 32,000 provider tokens is the configured allowance.
	if estimated := float64(total) / pilotCharsPerToken; estimated > 32_000 {
		t.Errorf("pilot planning prompt is ~%.0f provider tokens, over the 32,000 allowance", estimated)
	}
}
