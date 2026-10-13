package azureopenai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/modelprovider"
)

func TestPlanUsesAzureV1StrictResponsesBoundary(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/openai/v1/responses" || request.Method != http.MethodPost {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("api-key") != "runtime-secret" || request.Header.Get("Idempotency-Key") == "" {
			t.Fatalf("authentication or idempotency header missing")
		}
		if err := json.NewDecoder(request.Body).Decode(&captured); err != nil {
			t.Fatal(err)
		}
		writeResponse(t, writer, planningOutput(), 17, 8)
	}))
	defer server.Close()

	provider := testProvider(t, server.URL)
	result, err := provider.Plan(context.Background(), planningRequest())
	if err != nil {
		t.Fatal(err)
	}
	if result.Response.Actions[0].ToolID != "gpu.xid_events.v1" || result.Metadata.Provider != "azure-openai" || result.Metadata.Model != "deployment-a" || result.Metadata.InputTokens != 17 || result.Metadata.OutputTokens != 8 || result.Metadata.CostMicros != 33 {
		t.Fatalf("result = %+v", result)
	}
	encoded, _ := json.Marshal(captured)
	if strings.Contains(string(encoded), "runtime-secret") {
		t.Fatal("API key entered the request body")
	}
	if captured["store"] != false || captured["model"] != "deployment-a" {
		t.Fatalf("request options = %s", encoded)
	}
	if instructions, _ := captured["instructions"].(string); !strings.Contains(instructions, "exactly one action") || !strings.Contains(instructions, "wait for its durable result") {
		t.Fatalf("planning instructions do not enforce the single-action controller contract")
	}
	text := captured["text"].(map[string]any)
	format := text["format"].(map[string]any)
	if format["type"] != "json_schema" || format["strict"] != true || format["name"] != "sherlock_planning_v1" {
		t.Fatalf("structured format = %#v", format)
	}
	schema := format["schema"].(map[string]any)
	actions := schema["properties"].(map[string]any)["actions"].(map[string]any)
	variants := actions["items"].(map[string]any)["anyOf"].([]any)
	argumentSchema := variants[0].(map[string]any)["properties"].(map[string]any)["arguments"].(map[string]any)
	if argumentSchema["additionalProperties"] != false {
		t.Fatalf("tool arguments are not strict: %#v", argumentSchema)
	}
}

func TestSynthesizeDecodesAndValidatesStructuredOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeResponse(t, writer, synthesisOutput(), 23, 11)
	}))
	defer server.Close()
	result, err := testProvider(t, server.URL).Synthesize(context.Background(), synthesisRequest())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Response.WhatIsHappening) != 1 || result.Response.WhatIsHappening[0].EvidenceIDs[0] != "ev-1" || result.Metadata.InputTokens != 23 {
		t.Fatalf("result = %+v", result)
	}
}

func TestSynthesisSchemaBindsPartialXIDCitationsAndTimestamps(t *testing.T) {
	request := partialXIDSynthesisRequest(t)
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
		if err := json.NewDecoder(incoming.Body).Decode(&captured); err != nil {
			t.Fatal(err)
		}
		id := request.Evidence[0].EvidenceID
		writeResponse(t, writer, `{"schema_version":1,"what_is_happening":[{"statement":"Thirty XID 94 gauge samples were observed across five nodes.","severity":"WARNING","evidence_ids":["`+id+`"]}],"timeline":[{"observed_at":"2026-08-20T11:08:21.801Z","statement":"The bounded snapshot was observed.","evidence_ids":["`+id+`"]}],"likely_explanations":[{"statement":"The snapshot is consistent with previously retained XID 94 values; onset is unverified.","severity":"WARNING","confidence":0.4,"evidence_ids":["`+id+`"],"counter_evidence_ids":[]}],"what_remains_unknown":[{"statement":"Coverage of the remaining GPU population is unknown.","evidence_ids":["`+id+`"]}],"suggested_next_steps":[{"statement":"Compare later snapshots for transitions.","severity":"INFO","evidence_ids":["`+id+`"]}],"investigation_coverage":[{"statement":"Coverage is partial: 30 samples across five nodes.","evidence_ids":["`+id+`"]}]}`, 900, 220)
	}))
	defer server.Close()
	result, err := testProvider(t, server.URL).Synthesize(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Response.WhatIsHappening) != 1 || result.Response.WhatIsHappening[0].EvidenceIDs[0] != request.Evidence[0].EvidenceID {
		t.Fatalf("result=%+v", result)
	}
	format := captured["text"].(map[string]any)["format"].(map[string]any)
	schema := format["schema"].(map[string]any)
	definitions := schema["$defs"].(map[string]any)
	citations := definitions["required_cited_statement"].(map[string]any)["properties"].(map[string]any)["evidence_ids"].(map[string]any)
	enum := citations["items"].(map[string]any)["enum"].([]any)
	if len(enum) != 1 || enum[0] != request.Evidence[0].EvidenceID {
		t.Fatalf("citation schema=%#v", citations)
	}
	timeline := schema["properties"].(map[string]any)["timeline"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	if len(timeline["observed_at"].(map[string]any)["enum"].([]any)) != 1 {
		t.Fatalf("timeline schema=%#v", timeline)
	}
}

func TestPlanningWithoutEvidenceMustUseAvailableReadOnlyTool(t *testing.T) {
	request := planningRequest()
	request.Evidence = nil
	request.Hypotheses = nil
	schema, err := planningSchemaFor(request)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(schema, &root); err != nil {
		t.Fatal(err)
	}
	properties := root["properties"].(map[string]any)
	if values := properties["stop"].(map[string]any)["enum"].([]any); len(values) != 1 || values[0] != false {
		t.Fatalf("stop=%#v", properties["stop"])
	}
	response := modelprovider.PlanningResponse{SchemaVersion: 1, StateSummary: "No evidence yet.", Stop: false}
	if err := response.ValidateFor(request); err == nil {
		t.Fatal("semantic boundary accepted an empty action list when stop=false")
	}
}

func TestGeneratedSchemasUseAzureSupportedSubset(t *testing.T) {
	planning := planningRequest()
	planning.AvailableTools[0].ArgumentSchema = json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"nodes":{"type":"array","minItems":1,"maxItems":2,"uniqueItems":true,"items":{"type":"string","pattern":"^[a-z0-9-]+$","maxLength":64}}},"required":["nodes"]}`)
	planningSchema, err := planningSchemaFor(planning)
	if err != nil {
		t.Fatal(err)
	}
	var planningDocument map[string]any
	if err := json.Unmarshal(planningSchema, &planningDocument); err != nil {
		t.Fatal(err)
	}
	hypothesisID := planningDocument["properties"].(map[string]any)["hypothesis_updates"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["hypothesis_id"].(map[string]any)["enum"].([]any)
	if len(hypothesisID) != 2 || hypothesisID[0] != modelprovider.NewHypothesisID || hypothesisID[1] != "hyp-1" {
		t.Fatalf("hypothesis ID authority=%+v", hypothesisID)
	}
	synthesisSchema, err := synthesisSchemaFor(synthesisRequest())
	if err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string]json.RawMessage{"planning": planningSchema, "synthesis": synthesisSchema} {
		t.Run(name, func(t *testing.T) {
			var schema map[string]any
			if err := json.Unmarshal(encoded, &schema); err != nil {
				t.Fatal(err)
			}
			assertNoUnsupportedAzureKeywords(t, schema)
		})
	}
}

func TestProviderRetriesOnlyBoundedTransientFailures(t *testing.T) {
	var attempts atomic.Int32
	var keysMu sync.Mutex
	var keys []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		keysMu.Lock()
		keys = append(keys, request.Header.Get("Idempotency-Key"))
		keysMu.Unlock()
		if attempts.Add(1) < 3 {
			http.Error(writer, `sensitive upstream body runtime-secret`, http.StatusTooManyRequests)
			return
		}
		writeResponse(t, writer, planningOutput(), 1, 1)
	}))
	defer server.Close()
	provider := testProvider(t, server.URL)
	provider.maxRetries = 2
	provider.sleep = func(context.Context, time.Duration) error { return nil }
	if _, err := provider.Plan(context.Background(), planningRequest()); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 3 || len(keys) != 3 || keys[0] == "" || keys[0] != keys[1] || keys[1] != keys[2] {
		t.Fatalf("attempts=%d keys=%v", attempts.Load(), keys)
	}
}

func TestProviderErrorsAreClassifiedAndSafe(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		http.Error(writer, `{"error":{"message":"runtime-secret customer evidence"}}`, http.StatusUnauthorized)
	}))
	defer server.Close()
	provider := testProvider(t, server.URL)
	provider.maxRetries = 2
	_, err := provider.Plan(context.Background(), planningRequest())
	var providerErr *Error
	if !errors.As(err, &providerErr) || providerErr.Code != ErrorUnauthorized || providerErr.Retryable || providerErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("error = %#v", err)
	}
	if attempts.Load() != 1 || strings.Contains(err.Error(), "runtime-secret") || strings.Contains(err.Error(), "customer evidence") {
		t.Fatalf("unsafe or retried error = %v attempts=%d", err, attempts.Load())
	}
}

func TestProviderRejectsInvalidOutputWithoutExposingIt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeResponse(t, writer, `{"schema_version":1,"state_summary":"secret-output","hypothesis_updates":[],"actions":[],"stop":true,"stop_reason":"invented"}`, 1, 1)
	}))
	defer server.Close()
	_, err := testProvider(t, server.URL).Plan(context.Background(), planningRequest())
	var providerErr *Error
	if !errors.As(err, &providerErr) || providerErr.Code != ErrorInvalidResponse || providerErr.Stage != StageSemanticValidation || providerErr.SafeReasonCode() != "INVALID_RESPONSE_SEMANTIC_VALIDATION" || strings.Contains(err.Error(), "secret-output") {
		t.Fatalf("error = %v", err)
	}
	metadata, ok := providerErr.ModelCallMetadata()
	trace := providerErr.ModelCallTrace()
	if !ok || metadata.InputTokens != 1 || metadata.OutputTokens != 1 || len(trace.Input) == 0 || !bytes.Contains(trace.Output, []byte("secret-output")) {
		t.Fatalf("rejected call lost auditable metadata or payload trace: metadata=%+v trace=%+v", metadata, trace)
	}
}

func TestProviderClassifiesStructuredDecodeAndIncompleteOutputSafely(t *testing.T) {
	for _, test := range []struct {
		name  string
		write func(http.ResponseWriter)
		stage ErrorStage
	}{
		{name: "structured decode", stage: StageStructuredDecode, write: func(writer http.ResponseWriter) { writeResponse(t, writer, `{not-json`, 1, 1) }},
		{name: "incomplete", stage: StageOutputIncomplete, write: func(writer http.ResponseWriter) {
			writer.Header().Set("Content-Type", "application/json")
			fmt.Fprint(writer, `{"model":"gpt-5","status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"output":[],"usage":{"input_tokens":1,"output_tokens":1}}`)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { test.write(writer) }))
			defer server.Close()
			_, err := testProvider(t, server.URL).Plan(context.Background(), planningRequest())
			var providerErr *Error
			if !errors.As(err, &providerErr) || providerErr.Stage != test.stage || strings.Contains(err.Error(), "max_output_tokens") {
				t.Fatalf("error=%v stage=%s", err, providerErr.Stage)
			}
		})
	}
}

func TestProviderMapsRefusalToValidatedRefusedResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `{"model":"gpt-5","status":"completed","output":[{"type":"message","content":[{"type":"refusal","refusal":"private refusal detail"}]}],"usage":{"input_tokens":2,"output_tokens":1}}`)
	}))
	defer server.Close()
	request := planningRequest()
	result, err := testProvider(t, server.URL).Plan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Metadata.Outcome != modelprovider.OutcomeRefused || !result.Response.Stop || result.Response.StopReason == nil {
		t.Fatalf("refused result = %+v", result)
	}
	if err := result.ValidateFor(request); err != nil {
		t.Fatalf("fallback did not satisfy provider boundary: %v", err)
	}
}

func TestDeploymentHealthUsesStrictProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		format := body["text"].(map[string]any)["format"].(map[string]any)
		if format["strict"] != true || format["name"] != "sherlock_health_v1" || body["store"] != false {
			t.Fatalf("health request = %#v", body)
		}
		writeResponse(t, writer, `{"ok":true}`, 1, 1)
	}))
	defer server.Close()
	health, err := testProvider(t, server.URL).CheckHealth(context.Background())
	if err != nil || !health.Healthy || health.Deployment != "deployment-a" || health.ConfigurationID != "config-v1" {
		t.Fatalf("health=%+v err=%v", health, err)
	}
}

func TestProviderConfigurationRequiresTLSAndNeverPrintsSecret(t *testing.T) {
	base := Config{APIKey: "runtime-secret", Deployment: "deployment-a", ConfigurationID: "config-v1", InputTokenMicrosPerMillion: 1, OutputTokenMicrosPerMillion: 1}
	invalid := base
	invalid.Endpoint = "http://resource.openai.azure.com/openai/v1/"
	_, err := NewProvider(invalid)
	if err == nil || strings.Contains(err.Error(), "runtime-secret") || strings.Contains(err.Error(), "azure.example") {
		t.Fatalf("error = %v", err)
	}
	for _, endpoint := range []string{
		"https://azure.example/not-v1/",
		"https://resource.openai.azure.com.attacker.example/openai/v1/",
		"https://resource.services.ai.azure.com.attacker.example/openai/v1/",
		"https://resource.openai.azure.com@attacker.example/openai/v1/",
		"https://runtime-secret@resource.openai.azure.com/openai/v1/",
		"https://resource.services.ai.azure.com/other/openai/v1/",
	} {
		invalid = base
		invalid.Endpoint = endpoint
		if _, err := NewProvider(invalid); err == nil {
			t.Fatalf("accepted endpoint %q", endpoint)
		}
	}
	valid := base
	valid.Endpoint = "https://resource.openai.azure.com/openai/v1/"
	if _, err := NewProvider(valid); err != nil {
		t.Fatalf("rejected Azure endpoint: %v", err)
	}
	valid.Endpoint = "https://resource.services.ai.azure.com/openai/v1"
	provider, err := NewProvider(valid)
	if err != nil {
		t.Fatalf("rejected Azure AI Foundry endpoint: %v", err)
	}
	if provider.endpoint.Path != "/openai/v1/" {
		t.Fatalf("endpoint path was not normalized: %q", provider.endpoint.Path)
	}
	invalid = base
	invalid.Endpoint = "https://resource.openai.azure.com/not-v1/"
	if _, err := NewProvider(invalid); err == nil {
		t.Fatal("accepted a non-v1 endpoint")
	}
}

func TestProviderDoesNotForwardCredentialsAcrossRedirect(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		destinationCalls.Add(1)
		if request.Header.Get("api-key") != "" {
			t.Error("API key reached redirect destination")
		}
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Location", destination.URL)
		writer.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	_, err := testProvider(t, source.URL).Plan(context.Background(), planningRequest())
	var providerErr *Error
	if !errors.As(err, &providerErr) || destinationCalls.Load() != 0 {
		t.Fatalf("error=%v destination calls=%d", err, destinationCalls.Load())
	}
}

func TestPlanFailsBeforeCallWhenRemainingTokenBudgetIsBelowMinimum(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	request := planningRequest()
	request.RemainingBudget.ModelTokens = 127
	_, err := testProvider(t, server.URL).Plan(context.Background(), request)
	var providerErr *Error
	if !errors.As(err, &providerErr) || providerErr.Code != ErrorBudgetExceeded || calls.Load() != 0 {
		t.Fatalf("error=%v calls=%d", err, calls.Load())
	}
}

func TestTokenCostRoundsUpAndRejectsOverflow(t *testing.T) {
	if cost, ok := tokenCost(1, 1); !ok || cost != 1 {
		t.Fatalf("cost=%d ok=%v", cost, ok)
	}
	if cost, ok := tokenCost(1_500_000, 2_000_000); !ok || cost != 3_000_000 {
		t.Fatalf("cost=%d ok=%v", cost, ok)
	}
	if _, ok := tokenCost(1<<62, 1_000_000_000_000); ok {
		t.Fatal("accepted overflowing cost")
	}
}

func testProvider(t *testing.T, endpoint string) *Provider {
	t.Helper()
	provider, err := NewProvider(Config{Endpoint: endpoint + "/openai/v1/", APIKey: "runtime-secret", Deployment: "deployment-a", ConfigurationID: "config-v1", MaxRetries: 0, InputTokenMicrosPerMillion: 1_000_000, OutputTokenMicrosPerMillion: 2_000_000})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func planningRequest() modelprovider.PlanningRequest {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	return modelprovider.PlanningRequest{
		SchemaVersion: 1, InvestigationID: "inv-1", Question: "Why is node-1 unhealthy?",
		Scope:        modelprovider.Scope{ClusterID: "cluster-1", EntityKind: "node", EntityIDs: []string{"node-1"}, Start: now, End: now.Add(time.Hour)},
		StateSummary: "The cause is unknown.", SuccessCriteria: []string{"Find cited evidence."},
		RemainingBudget: modelprovider.RemainingBudget{Decisions: 2, ToolCalls: 2, FanOut: 1, ModelTokens: 1000, CostMicros: 10},
		AvailableTools:  []modelprovider.AvailableTool{{ToolID: "gpu.xid_events.v1", Description: "Read XID events.", ArgumentSchema: json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"nodes":{"type":"array","items":{"type":"string"}}},"required":["nodes"]}`), SchemaVersion: "catalog.v1", ReadOnly: true, MaximumFanOut: 1, CostWeight: 1}},
		Evidence:        []modelprovider.EvidenceContext{{EvidenceID: "ev-1", EntityIDs: []string{"node-1"}, ObservedFrom: now, ObservedTo: now.Add(time.Minute), Status: "COMPLETE", Source: "dcgm", Summary: "XID 79 observed.", ExpectedTargets: []modelprovider.CoverageTarget{{Kind: "NODE", ID: "node-1"}}, ObservedTargets: []modelprovider.CoverageTarget{{Kind: "NODE", ID: "node-1"}}, ExpectedFrom: now, ExpectedTo: now.Add(time.Minute), TimeComplete: true}},
		Hypotheses:      []modelprovider.HypothesisContext{{HypothesisID: "hyp-1", Statement: "GPU fault.", Status: "PROPOSED", Confidence: .5, SupportingEvidence: []string{"ev-1"}}},
		Coverage:        modelprovider.Coverage{TargetsChecked: []string{"node-1"}, ExpectedTargets: []modelprovider.CoverageTarget{{Kind: "NODE", ID: "node-1"}}, ObservedTargets: []modelprovider.CoverageTarget{{Kind: "NODE", ID: "node-1"}}, ExpectedFrom: now, ExpectedTo: now.Add(time.Hour), ObservedFrom: now, ObservedTo: now.Add(time.Hour), TimeComplete: true, EvidenceSelected: 1, Sources: []string{"dcgm"}},
		PromptVersion:   "planning-v1", ToolSchemaVersion: "catalog-v1",
	}
}

func synthesisRequest() modelprovider.SynthesisRequest {
	planning := planningRequest()
	return modelprovider.SynthesisRequest{SchemaVersion: 1, InvestigationID: planning.InvestigationID, Question: planning.Question, Scope: planning.Scope, Outcome: "COMPLETED", Evidence: planning.Evidence, Hypotheses: planning.Hypotheses, Findings: []modelprovider.ValidatedFinding{{FindingID: "finding-1", Kind: "OBSERVATION", Statement: "XID 79 observed.", EntityIDs: []string{"node-1"}, Severity: "HIGH", EvidenceIDs: []string{"ev-1"}}}, Coverage: planning.Coverage, PromptVersion: "synthesis-v1"}
}

func partialXIDSynthesisRequest(t *testing.T) modelprovider.SynthesisRequest {
	t.Helper()
	contextBody, err := os.ReadFile("testdata/partial-xid-context.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Records []json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal(contextBody, &fixture); err != nil || len(fixture.Records) != 30 {
		t.Fatalf("partial XID fixture records=%d err=%v", len(fixture.Records), err)
	}
	observed := time.Date(2026, 8, 20, 11, 8, 21, 801000000, time.UTC)
	evidenceID := "xid-387621bc6d75a281dc5aabf72bf1de882a33d2dfdd82b4368f734c9a41b8366f"
	return modelprovider.SynthesisRequest{
		SchemaVersion: 1, InvestigationID: "investigation-xid-partial", Question: "Analyze the committed DCGM XID evidence.",
		Scope:    modelprovider.Scope{ClusterID: "local-cluster", EntityKind: "CLUSTER", EntityIDs: []string{"local-cluster"}, Start: observed.Add(-21 * time.Second), End: observed.Add(39 * time.Second)},
		Outcome:  "PARTIAL",
		Evidence: []modelprovider.EvidenceContext{{EvidenceID: evidenceID, EntityIDs: []string{"local-cluster"}, ObservedFrom: observed, ObservedTo: observed, Status: "PARTIAL", Source: "local-prometheus:dcgm_gpu_xid", Summary: "Thirty normalized XID samples across five nodes; fleet coverage is partial and event onset is unverified.", UntrustedData: string(contextBody), ExpectedTargets: []modelprovider.CoverageTarget{{Kind: "CLUSTER", ID: "local-cluster"}}, MissingTargets: []modelprovider.CoverageTarget{{Kind: "CLUSTER", ID: "local-cluster"}}, ExpectedFrom: observed.Add(-21 * time.Second), ExpectedTo: observed.Add(39 * time.Second)}},
		Coverage: modelprovider.Coverage{TargetsMissed: []string{"local-cluster"}, ExpectedTargets: []modelprovider.CoverageTarget{{Kind: "CLUSTER", ID: "local-cluster"}}, MissingTargets: []modelprovider.CoverageTarget{{Kind: "CLUSTER", ID: "local-cluster"}}, ExpectedFrom: observed.Add(-21 * time.Second), ExpectedTo: observed.Add(39 * time.Second), EvidenceSelected: 1, Sources: []string{"local-prometheus"}, StopReason: "NO_USEFUL_ACTION"}, PromptVersion: "synthesis-v1",
	}
}

func planningOutput() string {
	return `{"schema_version":1,"state_summary":"Confirm the XID.","hypothesis_updates":[{"hypothesis_id":"hyp-1","statement":"GPU fault.","status":"SUPPORTED","confidence":0.8,"supporting_evidence_ids":["ev-1"],"contradicting_evidence_ids":[],"unresolved_tests":[]}],"actions":[{"tool_id":"gpu.xid_events.v1","arguments":{"nodes":["node-1"]},"purpose":"Confirm fault.","expected_information":"Timestamped XID events.","priority":1}],"stop":false,"stop_reason":null}`
}

func synthesisOutput() string {
	return `{"schema_version":1,"what_is_happening":[{"statement":"XID 79 was observed.","severity":"CRITICAL","evidence_ids":["ev-1"]}],"timeline":[{"observed_at":"2026-08-20T10:00:00Z","statement":"The XID was observed.","evidence_ids":["ev-1"]}],"likely_explanations":[{"statement":"A GPU fault is likely.","severity":"CRITICAL","confidence":0.8,"evidence_ids":["ev-1"],"counter_evidence_ids":[]}],"what_remains_unknown":[{"statement":"Recovery is unverified.","evidence_ids":["ev-1"]}],"suggested_next_steps":[{"statement":"Inspect GPU 3.","severity":"WARNING","evidence_ids":[]}],"investigation_coverage":[{"statement":"node-1 was checked.","evidence_ids":["ev-1"]}]}`
}

func writeResponse(t *testing.T, writer http.ResponseWriter, output string, inputTokens, outputTokens int64) {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{"model": "gpt-5", "status": "completed", "output": []any{map[string]any{"type": "message", "content": []any{map[string]any{"type": "output_text", "text": output}}}}, "usage": map[string]any{"input_tokens": inputTokens, "output_tokens": outputTokens}})
	if err != nil {
		t.Fatal(err)
	}
	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write(encoded)
}

func assertNoUnsupportedAzureKeywords(t *testing.T, value any) {
	t.Helper()
	unsupported := map[string]struct{}{
		"minLength": {}, "maxLength": {}, "pattern": {}, "format": {},
		"minimum": {}, "maximum": {}, "multipleOf": {},
		"patternProperties": {}, "unevaluatedProperties": {}, "propertyNames": {}, "minProperties": {}, "maxProperties": {},
		"unevaluatedItems": {}, "contains": {}, "minContains": {}, "maxContains": {}, "minItems": {}, "maxItems": {}, "uniqueItems": {},
	}
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				if _, forbidden := unsupported[key]; forbidden {
					t.Errorf("unsupported Azure schema keyword %q", key)
				}
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
}
