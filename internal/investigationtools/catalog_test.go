package investigationtools

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestCatalogFailsClosedAndFiltersEveryAuthorityDimension(t *testing.T) {
	catalog := mustCatalog(t, baseDefinition())
	filter := baseFilter()
	if got := catalog.Available(filter); len(got) != 1 || got[0].ID != "gpu.xid_events.v1" {
		t.Fatalf("available=%v", got)
	}

	tests := []struct {
		name   string
		mutate func(*Filter)
	}{
		{"missing cluster", func(f *Filter) { f.ClusterID = "" }},
		{"wrong cluster", func(f *Filter) { f.ClusterID = "cluster-b" }},
		{"missing actor capability", func(f *Filter) { f.ActorCapabilities = nil }},
		{"missing cluster capability", func(f *Filter) { f.ClusterCapabilities = nil }},
		{"wrong entity kind", func(f *Filter) { f.Scope.EntityKind = "job" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := baseFilter()
			test.mutate(&candidate)
			if got := catalog.Available(candidate); len(got) != 0 {
				t.Fatalf("default-deny filter returned %d tools", len(got))
			}
		})
	}
}

func TestCatalogRejectsMutatingAndImplicitOperationDefinitions(t *testing.T) {
	for _, operation := range []OperationClass{"", "MUTATING"} {
		definition := baseDefinition()
		definition.Operation = operation
		if _, err := NewCatalog([]Definition{definition}); err == nil {
			t.Fatalf("operation %q was accepted", operation)
		}
	}
	definition := baseDefinition()
	definition.AllowedClusters = nil
	if _, err := NewCatalog([]Definition{definition}); err == nil {
		t.Fatal("empty cluster allow-list was accepted")
	}
	definition = baseDefinition()
	definition.RequiredCapabilities = nil
	if _, err := NewCatalog([]Definition{definition}); err == nil {
		t.Fatal("tool without actor capability was accepted")
	}
	definition = baseDefinition()
	definition.RequiredClusterCapabilities = nil
	if _, err := NewCatalog([]Definition{definition}); err == nil {
		t.Fatal("tool without cluster capability was accepted")
	}
}

func TestDiagnosticBindingsAreExactAndFailClosed(t *testing.T) {
	tests := []struct {
		tool       ToolID
		definition domain.DiagnosticDefinitionID
		version    string
	}{
		{DiagnosticECCCountersToolID, "gpu.ecc_counters", "1.0.0"},
		{DiagnosticRowRemapToolID, "gpu.row_remap", "1.1.0"},
		{DiagnosticRetiredPagesToolID, "gpu.retired_pages", "1.0.0"},
		// The unprivileged kernel journal read, not the 1.0.0 sudo variant the
		// executor refuses.
		{DiagnosticKernelXIDToolID, "node.kernel_xid", "2.0.0"},
	}
	for _, test := range tests {
		binding, ok := DiagnosticBindingForTool(test.tool)
		if !ok || binding.DefinitionID != test.definition || binding.DefinitionVersion != test.version {
			t.Fatalf("binding %q = %+v, found=%t", test.tool, binding, ok)
		}
	}
	if _, ok := DiagnosticBindingForTool("gpu.reset.v1"); ok {
		t.Fatal("an unreviewed tool acquired a diagnostic definition")
	}
}

func TestValidateCallEnforcesTypedArgumentsAndExactScope(t *testing.T) {
	catalog := mustCatalog(t, baseDefinition())
	filter := baseFilter()
	call := baseCall()
	if err := catalog.ValidateCall(filter, call); err != nil {
		t.Fatalf("validate call: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Call)
	}{
		{"out of scope target", func(c *Call) { c.Targets = []string{"n9"} }},
		{"duplicate target", func(c *Call) { c.Targets = []string{"n1", "n1"} }},
		{"wrong type", func(c *Call) { c.Arguments[0] = Integer("severity", 1) }},
		{"unknown argument", func(c *Call) { c.Arguments = append(c.Arguments, String("command", "rm")) }},
		{"enum bypass", func(c *Call) { c.Arguments[0] = String("severity", "critical; mutate") }},
		{"pattern bypass", func(c *Call) { c.Arguments[1] = StringList("gpus", []string{"0", "--query"}) }},
		{"duplicate list", func(c *Call) { c.Arguments[1] = StringList("gpus", []string{"0", "0"}) }},
		{"time escape", func(c *Call) { c.Start = filter.Scope.Start.Add(-time.Second) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := baseCall()
			test.mutate(&candidate)
			if err := catalog.ValidateCall(filter, candidate); !errors.Is(err, ErrInvalidCall) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestCanonicalCallKeyDetectsEquivalentCalls(t *testing.T) {
	catalog := mustCatalog(t, baseDefinition())
	filter := baseFilter()
	left := baseCall()
	left.Targets = []string{"n2", "n1"}
	left.Arguments = []ArgumentValue{StringList("gpus", []string{"1", "0"}), String("severity", "warning")}
	right := baseCall()
	right.Targets = []string{"n1", "n2"}
	right.Arguments = []ArgumentValue{String("severity", "warning"), StringList("gpus", []string{"0", "1"})}
	leftKey, err := catalog.CanonicalCallKey(filter, left)
	if err != nil {
		t.Fatal(err)
	}
	rightKey, err := catalog.CanonicalCallKey(filter, right)
	if err != nil {
		t.Fatal(err)
	}
	if leftKey != rightKey {
		t.Fatalf("equivalent keys differ: %s != %s", leftKey, rightKey)
	}
	right.Arguments[0] = String("severity", "critical")
	different, err := catalog.CanonicalCallKey(filter, right)
	if err != nil {
		t.Fatal(err)
	}
	if different == leftKey {
		t.Fatal("materially different call shared a key")
	}
}

func TestCatalogReturnsDefensiveCopiesInDeterministicOrder(t *testing.T) {
	second := baseDefinition()
	second.ID = "cluster.scheduler_snapshot.v1"
	catalog := mustCatalog(t, baseDefinition(), second)
	first := catalog.Available(baseFilter())
	if first[0].ID != second.ID {
		t.Fatalf("catalog not sorted: %v", []ToolID{first[0].ID, first[1].ID})
	}
	first[0].AllowedClusters[0] = "changed"
	first[0].Arguments[0].AllowedValues[0] = "changed"
	secondRead := catalog.Available(baseFilter())
	if secondRead[0].AllowedClusters[0] != "cluster-a" || secondRead[0].Arguments[0].AllowedValues[0] != "warning" {
		t.Fatal("caller mutated catalog state")
	}
}

func TestDecodeCallStrictlyNormalizesRawModelArguments(t *testing.T) {
	catalog := mustCatalog(t, baseDefinition())
	filter := baseFilter()
	raw := json.RawMessage(`{"targets":["n2","n1"],"start":"2026-08-20T10:00:00Z","end":"2026-08-20T11:00:00Z","severity":"warning","gpus":["1","0"]}`)
	call, err := catalog.DecodeCall(filter, "gpu.xid_events.v1", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(call.Arguments) != 2 || call.EntityKind != "node" || len(call.Targets) != 2 {
		t.Fatalf("call=%+v", call)
	}

	bad := []json.RawMessage{
		json.RawMessage(`{"targets":["n1"],"targets":["n2"],"start":"2026-08-20T10:00:00Z","end":"2026-08-20T11:00:00Z","severity":"warning"}`),
		json.RawMessage(`{"targets":["n9"],"start":"2026-08-20T10:00:00Z","end":"2026-08-20T11:00:00Z","severity":"warning"}`),
		json.RawMessage(`{"targets":["n1"],"start":"2026-08-20T10:00:00Z","end":"2026-08-20T11:00:00Z","severity":"warning","executable":"/bin/sh"}`),
		json.RawMessage(`{"targets":["n1"],"start":"2026-08-20T10:00:00Z","end":"2026-08-20T11:00:00Z","severity":1}`),
		json.RawMessage(`{"targets":["n1"],"start":"2026-08-20T10:00:00Z","end":"2026-08-20T11:00:00Z","severity":"warning"} trailing`),
	}
	for index, candidate := range bad {
		if _, err := catalog.DecodeCall(filter, "gpu.xid_events.v1", candidate); !errors.Is(err, ErrInvalidCall) {
			t.Fatalf("case %d error=%v", index, err)
		}
	}
}

func TestDecodeCallBatchesOversizedProposalDeterministically(t *testing.T) {
	definition := baseDefinition()
	definition.Scope.MaxTargets = 2
	catalog := mustCatalog(t, definition)
	filter := baseFilter()
	filter.Scope.EntityIDs = []string{"n5", "n2", "n4", "n1", "n3"}
	raw := json.RawMessage(`{"targets":["n5","n2","n4","n1","n3"],"start":"2026-08-20T10:00:00Z","end":"2026-08-20T11:00:00Z","severity":"warning","gpus":["1","0"]}`)
	batches, err := catalog.DecodeCallBatches(filter, "gpu.xid_events.v1", raw, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"n1", "n2"}, {"n3", "n4"}, {"n5"}}
	if len(batches) != len(want) {
		t.Fatalf("batches=%+v", batches)
	}
	for index := range want {
		if !slices.Equal(batches[index].Targets, want[index]) {
			t.Fatalf("batch %d targets=%v want=%v", index, batches[index].Targets, want[index])
		}
		if err := catalog.ValidateCall(filter, batches[index]); err != nil {
			t.Fatalf("batch %d invalid: %v", index, err)
		}
	}
}

func TestAvailableSchemasAreReadOnlyBoundedAndDeterministic(t *testing.T) {
	catalog := mustCatalog(t, baseDefinition())
	first, err := catalog.AvailableSchemas(baseFilter())
	if err != nil {
		t.Fatal(err)
	}
	second, err := catalog.AvailableSchemas(baseFilter())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || !first[0].ReadOnly || first[0].MaximumFanOut != len(baseFilter().Scope.EntityIDs) || !json.Valid(first[0].ArgumentSchema) {
		t.Fatalf("schemas=%+v", first)
	}
	if string(first[0].ArgumentSchema) != string(second[0].ArgumentSchema) {
		t.Fatal("schema generation is nondeterministic")
	}
	var schema struct {
		AdditionalProperties bool                       `json:"additionalProperties"`
		Required             []string                   `json:"required"`
		Properties           map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(first[0].ArgumentSchema, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.AdditionalProperties || len(schema.Properties) != 5 || len(schema.Required) != 4 {
		t.Fatalf("schema=%s", first[0].ArgumentSchema)
	}
}

func baseDefinition() Definition {
	return Definition{
		SchemaVersion: SchemaVersion, ID: "gpu.xid_events.v1", Description: "Read bounded GPU XID events.", Operation: OperationReadOnly,
		AllowedClusters: []domain.ClusterID{"cluster-a"}, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun},
		RequiredClusterCapabilities: []ClusterCapability{"gpu:xid"}, Scope: ScopePolicy{EntityKinds: []string{"node"}, MaxTargets: 2, MaxWindow: time.Hour},
		Arguments: []ArgumentSpec{
			{Name: "severity", Description: "Minimum event severity.", Kind: ArgumentString, Required: true, MaxLength: 16, AllowedValues: []string{"warning", "critical"}},
			{Name: "gpus", Description: "GPU indexes.", Kind: ArgumentStringList, MinItems: 1, MaxItems: 8, MaxLength: 2, Pattern: `^[0-7]$`, OrderInsensitive: true},
		}, Timeout: 30 * time.Second, CostWeight: 2,
	}
}

func baseFilter() Filter {
	start := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	return Filter{ClusterID: "cluster-a", ActorCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, ClusterCapabilities: []ClusterCapability{"gpu:xid"}, Scope: domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"n1", "n2"}, Start: start, End: start.Add(time.Hour)}}
}

func baseCall() Call {
	filter := baseFilter()
	return Call{ToolID: "gpu.xid_events.v1", EntityKind: "node", Targets: []string{"n1"}, Start: filter.Scope.Start, End: filter.Scope.End, Arguments: []ArgumentValue{String("severity", "warning"), StringList("gpus", []string{"0"})}}
}

func mustCatalog(t *testing.T, definitions ...Definition) *Catalog {
	t.Helper()
	catalog, err := NewCatalog(definitions)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func diagnosticDefinition() Definition {
	return Definition{
		SchemaVersion: SchemaVersion, ID: "gpu.ecc_counters.v1", Description: "Read current and aggregate GPU ECC counters.", Operation: OperationDiagnostic,
		AllowedClusters: []domain.ClusterID{"cluster-a"}, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun},
		RequiredClusterCapabilities: []ClusterCapability{"gpu:diagnostics"}, Scope: ScopePolicy{EntityKinds: []string{"node"}, MaxTargets: 2, MaxWindow: time.Hour},
		Timeout: 30 * time.Second, CostWeight: 20, MinimumReexecutionInterval: time.Minute,
	}
}

// A diagnostic is reach the model does not otherwise have, so every dimension
// that gates it must fail closed independently: the budget grant, the cluster
// allow-list, the actor capability, the cluster capability, and the scope.
func TestDiagnosticToolIsAdmittedOnlyByEveryGateTogether(t *testing.T) {
	catalog := mustCatalog(t, baseDefinition(), diagnosticDefinition())

	withoutGrant := baseFilter()
	withoutGrant.ClusterCapabilities = []ClusterCapability{"gpu:xid", "gpu:diagnostics"}
	if got := catalog.Available(withoutGrant); len(got) != 1 || got[0].ID != "gpu.xid_events.v1" {
		t.Fatalf("a filter with no diagnostic grant must see only the read-only tool, got %v", toolIDs(got))
	}

	granted := withoutGrant
	granted.AllowDiagnostics = true
	if got := toolIDs(catalog.Available(granted)); !slices.Equal(got, []ToolID{"gpu.ecc_counters.v1", "gpu.xid_events.v1"}) {
		t.Fatalf("a granted filter must see both tools, got %v", got)
	}

	tests := []struct {
		name   string
		mutate func(*Filter)
	}{
		{"no diagnostic grant", func(f *Filter) { f.AllowDiagnostics = false }},
		{"wrong cluster", func(f *Filter) { f.ClusterID = "cluster-b" }},
		{"missing actor capability", func(f *Filter) { f.ActorCapabilities = nil }},
		{"missing cluster capability", func(f *Filter) { f.ClusterCapabilities = []ClusterCapability{"gpu:xid"} }},
		{"wrong entity kind", func(f *Filter) { f.Scope.EntityKind = "job" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := granted
			test.mutate(&candidate)
			if slices.Contains(toolIDs(catalog.Available(candidate)), "gpu.ecc_counters.v1") {
				t.Fatal("the diagnostic was admitted with a gate closed")
			}
			if _, available := catalog.ToolBounds(candidate, "gpu.ecc_counters.v1"); available {
				t.Fatal("bounds for an unreachable diagnostic must not be disclosed")
			}
		})
	}
}

// The catalog is the only place the operation class is decided, and the model
// must be told what a diagnostic costs it before proposing one.
func TestDiagnosticSchemaAdvertisesExecutionAndCurrency(t *testing.T) {
	catalog := mustCatalog(t, baseDefinition(), diagnosticDefinition())
	filter := baseFilter()
	filter.ClusterCapabilities = []ClusterCapability{"gpu:xid", "gpu:diagnostics"}
	filter.AllowDiagnostics = true
	schemas, err := catalog.AvailableSchemas(filter)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[ToolID]AvailableToolSchema{}
	for _, schema := range schemas {
		byID[schema.ToolID] = schema
	}
	diagnostic, lookup := byID["gpu.ecc_counters.v1"], byID["gpu.xid_events.v1"]
	if !diagnostic.Diagnostic || diagnostic.ReadOnly {
		t.Fatalf("a diagnostic must not be advertised as read-only: %+v", diagnostic)
	}
	if lookup.Diagnostic || !lookup.ReadOnly {
		t.Fatalf("an evidence lookup must stay read-only: %+v", lookup)
	}
	if diagnostic.MinimumReexecutionInterval != time.Minute {
		t.Fatalf("MinimumReexecutionInterval = %s, want 1m0s", diagnostic.MinimumReexecutionInterval)
	}
	for _, want := range []string{"1m0s", "diagnostic budget", "live state"} {
		if !strings.Contains(diagnostic.Description, want) {
			t.Fatalf("diagnostic description does not state %q: %s", want, diagnostic.Description)
		}
	}
	if strings.Contains(lookup.Description, "diagnostic budget") {
		t.Fatalf("an evidence lookup must not carry diagnostic guidance: %s", lookup.Description)
	}
	bounds, available := catalog.ToolBounds(filter, "gpu.ecc_counters.v1")
	if !available || !bounds.Diagnostic || bounds.MinimumReexecutionInterval != time.Minute {
		t.Fatalf("bounds did not report the operation class: available=%t %+v", available, bounds)
	}
	if lookupBounds, _ := catalog.ToolBounds(filter, "gpu.xid_events.v1"); lookupBounds.Diagnostic {
		t.Fatal("an evidence lookup must not report itself as a diagnostic")
	}
}

// The re-execution interval is what makes the freshness rule decidable, so a
// definition that omits it, or claims an unreviewable currency, must not load.
func TestDefinitionValidationBindsOperationClassToReexecutionInterval(t *testing.T) {
	missing := diagnosticDefinition()
	missing.MinimumReexecutionInterval = 0
	if _, err := NewCatalog([]Definition{missing}); err == nil {
		t.Fatal("a diagnostic without a re-execution interval was accepted")
	}
	tooLong := diagnosticDefinition()
	tooLong.MinimumReexecutionInterval = 2 * time.Hour
	if _, err := NewCatalog([]Definition{tooLong}); err == nil {
		t.Fatal("a diagnostic claiming an unreviewable currency was accepted")
	}
	negative := diagnosticDefinition()
	negative.MinimumReexecutionInterval = -time.Minute
	if _, err := NewCatalog([]Definition{negative}); err == nil {
		t.Fatal("a negative re-execution interval was accepted")
	}
	strayInterval := baseDefinition()
	strayInterval.MinimumReexecutionInterval = time.Minute
	if _, err := NewCatalog([]Definition{strayInterval}); err == nil {
		t.Fatal("a read-only tool with a re-execution interval was accepted")
	}
	if _, err := NewCatalog([]Definition{diagnosticDefinition()}); err != nil {
		t.Fatalf("a well-formed diagnostic must load: %v", err)
	}
}

func toolIDs(definitions []Definition) []ToolID {
	ids := make([]ToolID, 0, len(definitions))
	for _, definition := range definitions {
		ids = append(ids, definition.ID)
	}
	return ids
}

// The lookback is reviewed configuration that decides how much history a
// diagnostic's evidence claims to cover, so it must be bounded, unambiguous
// per definition, and zero for anything that only samples live state.
func TestDiagnosticObservationLookbacksAreBoundedAndUnambiguous(t *testing.T) {
	seen := map[domain.DiagnosticDefinitionID]string{}
	for _, toolID := range DiagnosticToolIDs() {
		binding, reviewed := DiagnosticBindingForTool(toolID)
		if !reviewed {
			t.Fatalf("%s is listed as a diagnostic tool but has no binding", toolID)
		}
		if binding.ObservationLookback < 0 || binding.ObservationLookback > domain.MaximumDiagnosticObservationLookback {
			t.Fatalf("%s declares an out-of-bound lookback: %s", toolID, binding.ObservationLookback)
		}
		// DiagnosticObservationLookback resolves by definition alone, which is
		// only sound while one version of a definition is bound.
		if previous, duplicate := seen[binding.DefinitionID]; duplicate {
			t.Fatalf("definition %s is bound twice (%s and %s)", binding.DefinitionID, previous, binding.DefinitionVersion)
		}
		seen[binding.DefinitionID] = binding.DefinitionVersion
		if got := DiagnosticObservationLookback(binding.DefinitionID); got != binding.ObservationLookback {
			t.Fatalf("reverse lookup for %s = %s, want %s", binding.DefinitionID, got, binding.ObservationLookback)
		}
	}

	kernel, _ := DiagnosticBindingForTool(DiagnosticKernelXIDToolID)
	if kernel.ObservationLookback != 7*24*time.Hour {
		t.Fatalf("kernel journal lookback = %s, want seven days", kernel.ObservationLookback)
	}
	for _, toolID := range []ToolID{DiagnosticECCCountersToolID, DiagnosticRowRemapToolID, DiagnosticRetiredPagesToolID} {
		binding, _ := DiagnosticBindingForTool(toolID)
		if binding.ObservationLookback != 0 {
			t.Fatalf("%s samples live state but declares %s of history", toolID, binding.ObservationLookback)
		}
	}
	if got := DiagnosticObservationLookback("gpu.reset"); got != 0 {
		t.Fatalf("an unbound definition reported %s of history", got)
	}
}
