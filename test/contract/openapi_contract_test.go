package contract_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

func loadContract(t *testing.T) map[string]any {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	payload, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "api", "openapi", "sherlock-v1.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("OpenAPI document must be valid JSON (and therefore valid YAML): %v", err)
	}
	return document
}

func TestPublicContractOperationsAndScoping(t *testing.T) {
	document := loadContract(t)
	if document["openapi"] != "3.1.0" {
		t.Fatalf("openapi = %v", document["openapi"])
	}
	want := map[string]string{
		"/clusters": "listClusters", "/clusters/{cluster_id}": "getCluster", "/clusters/{cluster_id}/health": "getHealth",
		"/clusters/{cluster_id}/sources": "listSources", "/clusters/{cluster_id}/observations": "listObservations",
		"/clusters/{cluster_id}/gpus": "listGPUSummaries", "/clusters/{cluster_id}/collection-runs": "listCollectionRuns",
		"/clusters/{cluster_id}/evidence": "listEvidence", "/clusters/{cluster_id}/evidence/{evidence_id}": "getEvidence",
		"/clusters/{cluster_id}/events":                   "streamEvents",
		"/clusters/{cluster_id}/diagnostic-runs/{run_id}": "getDiagnosticRun",
	}
	paths := object(t, document["paths"])
	for path, operationID := range want {
		get := object(t, object(t, paths[path])["get"])
		if get["operationId"] != operationID {
			t.Errorf("%s operationId = %v, want %s", path, get["operationId"], operationID)
		}
		if path != "/clusters" && !strings.Contains(path, "{cluster_id}") {
			t.Errorf("resource path is not cluster scoped: %s", path)
		}
	}
	security := array(t, document["security"])
	if len(security) != 1 || object(t, security[0])["bearerAuth"] == nil {
		t.Fatalf("global bearer security missing: %#v", security)
	}
}

func TestM5DiagnosticContractContainsNoCommandOrCredentialPayload(t *testing.T) {
	document := loadContract(t)
	schemas := object(t, object(t, document["components"])["schemas"])
	for _, name := range []string{"DiagnosticRun", "DiagnosticAttempt", "DiagnosticTargetResult", "DiagnosticRunRequest"} {
		encoded, err := json.Marshal(schemas[name])
		if err != nil {
			t.Fatal(err)
		}
		text := string(encoded)
		for _, forbidden := range []string{`"credential"`, `"password"`, `"stdout"`, `"stderr"`, `"executable"`, `"argv"`} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s exposes forbidden field %s", name, forbidden)
			}
		}
	}
	paths := object(t, document["paths"])
	postOperations := map[string]string{
		"/clusters/{cluster_id}/diagnostic-runs/preview":           "previewDiagnosticRun",
		"/clusters/{cluster_id}/diagnostic-runs":                   "startDiagnosticRun",
		"/clusters/{cluster_id}/diagnostic-runs/{run_id}/approval": "approveDiagnosticRun",
	}
	for path, operationID := range postOperations {
		post := object(t, object(t, paths[path])["post"])
		if post["operationId"] != operationID {
			t.Errorf("%s operationId = %v", path, post["operationId"])
		}
	}
}

// The M12.1 pilot uses an unattended head-local authentication profile. An
// interactive challenge is intentionally not a public contract unless a future
// deployment proves that per-run operator entry is required.
func TestM121PilotDoesNotExposeInteractiveCredentialRelay(t *testing.T) {
	document := loadContract(t)
	paths := object(t, document["paths"])
	for path := range paths {
		lower := strings.ToLower(path)
		if strings.Contains(lower, "credential") {
			t.Errorf("public contract exposes deferred interactive credential path %q", path)
		}
	}
	schemas := object(t, object(t, document["components"])["schemas"])
	for name := range schemas {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "credential") {
			t.Errorf("public contract exposes deferred interactive credential schema %q", name)
		}
	}
	status := object(t, schemas["InvestigationStatus"])
	for _, value := range array(t, status["enum"]) {
		if value == "AWAITING_CREDENTIAL" {
			t.Fatal("pilot state machine unexpectedly requires interactive credentials")
		}
	}
}

func TestM6InvestigationContractIsDurableBoundedAndCited(t *testing.T) {
	document := loadContract(t)
	paths := object(t, document["paths"])
	operations := map[string]string{
		"/clusters/{cluster_id}/incidents":              "listIncidents",
		"/incidents/{incident_id}":                      "getIncident",
		"/investigations/{investigation_id}":            "getInvestigation",
		"/investigations/{investigation_id}/events":     "listInvestigationEvents",
		"/investigations/{investigation_id}/evidence":   "listInvestigationEvidence",
		"/investigations/{investigation_id}/hypotheses": "listInvestigationHypotheses",
		"/investigations/{investigation_id}/findings":   "listInvestigationFindings",
	}
	for path, operationID := range operations {
		if got := object(t, object(t, paths[path])["get"])["operationId"]; got != operationID {
			t.Errorf("%s operationId = %v, want %s", path, got, operationID)
		}
	}
	postOperations := map[string]string{
		"/clusters/{cluster_id}/incidents":             "createIncident",
		"/investigations":                              "startInvestigation",
		"/investigations/{investigation_id}/cancel":    "cancelInvestigation",
		"/investigations/{investigation_id}/approvals": "approveInvestigationAction",
	}
	for path, operationID := range postOperations {
		if got := object(t, object(t, paths[path])["post"])["operationId"]; got != operationID {
			t.Errorf("%s operationId = %v, want %s", path, got, operationID)
		}
	}
	schemas := object(t, object(t, document["components"])["schemas"])
	assertEnum(t, schemas, "InvestigationStatus", "INITIALIZING", "PLANNING", "POLICY_CHECK", "AWAITING_APPROVAL", "EXECUTING", "AWAITING_EVIDENCE", "RECORDING_EVIDENCE", "UPDATING_LEDGER", "SYNTHESIZING", "COMPLETED", "PARTIAL", "BLOCKED", "CANCELLED")
	for _, name := range []string{"StartInvestigationRequest", "Investigation", "InvestigationAction", "InvestigationEvent", "InvestigationEvidence", "Hypothesis", "Finding"} {
		encoded, err := json.Marshal(schemas[name])
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{`"credential"`, `"password"`, `"raw_output"`, `"command"`} {
			if strings.Contains(string(encoded), forbidden) {
				t.Errorf("%s exposes forbidden field %s", name, forbidden)
			}
		}
	}
	findingRequired := stringSet(t, object(t, schemas["Finding"])["required"])
	for _, field := range []string{"evidence_ids", "counter_evidence_ids", "validation_status", "validation_errors"} {
		if !findingRequired[field] {
			t.Errorf("Finding does not require %s", field)
		}
	}
}

func TestPublicContractPreservesCollectionState(t *testing.T) {
	document := loadContract(t)
	schemas := object(t, object(t, document["components"])["schemas"])
	for _, name := range []string{"Cluster", "Source", "Observation", "GPUSummary", "CollectionRun", "HealthSummary"} {
		required := stringSet(t, object(t, schemas[name])["required"])
		for _, field := range []string{"observed_at", "collected_at", "freshness", "coverage", "collection_status"} {
			if !required[field] {
				t.Errorf("%s does not require %s", name, field)
			}
		}
	}
	assertEnum(t, schemas, "Freshness", "FRESH", "STALE", "UNKNOWN")
	assertEnum(t, schemas, "CollectionStatus", "SUCCEEDED", "NO_DATA", "PARTIAL", "FAILED")
	assertEnum(t, schemas, "HealthState", "NORMAL", "PARTIAL", "STALE", "UNAVAILABLE", "NO_DATA", "XID", "ECC", "THERMAL", "MEMORY", "POWER", "UTILIZATION")
	assertEnum(t, schemas, "EvidenceStatus", "COMPLETE", "PARTIAL", "NO_DATA", "UNAVAILABLE")
	coverageRequired := stringSet(t, object(t, schemas["Coverage"])["required"])
	for _, field := range []string{"requested", "successful", "failed", "complete"} {
		if !coverageRequired[field] {
			t.Errorf("Coverage does not require %s", field)
		}
	}
}

func TestGoodputCoverageContractSeparatesSupportAndProvenance(t *testing.T) {
	document := loadContract(t)
	schemas := object(t, object(t, document["components"])["schemas"])
	assertEnum(t, schemas, "SourceSupport", "SUPPORTED", "NOT_SUPPORTED", "UNKNOWN")
	assertEnum(t, schemas, "CoverageScope", "INVENTORY", "ALLOCATIONS", "PROGRESS", "METRICS", "EVENTS")
	for _, name := range []string{"SourceProvenance", "SourceCoverage"} {
		if _, ok := schemas[name]; !ok {
			t.Fatalf("missing additive schema %s", name)
		}
	}
	coverageRequired := stringSet(t, object(t, schemas["SourceCoverage"])["required"])
	for _, field := range []string{"scope", "support", "state", "expected", "observed", "provenance"} {
		if !coverageRequired[field] {
			t.Errorf("SourceCoverage does not require %s", field)
		}
	}
	provenanceRequired := stringSet(t, object(t, schemas["SourceProvenance"])["required"])
	for _, field := range []string{"source_id", "source_at", "effective_at", "observed_at"} {
		if !provenanceRequired[field] {
			t.Errorf("SourceProvenance does not require %s", field)
		}
	}
	source := object(t, schemas["Source"])
	if _, ok := object(t, source["properties"])["coverage_by_scope"]; !ok {
		t.Fatal("Source does not expose additive coverage_by_scope")
	}
}

func TestOpenAPIReferencesAndExamplesValidate(t *testing.T) {
	document := loadContract(t)
	if err := walkRefs(document, document, "$"); err != nil {
		t.Fatal(err)
	}
	components := object(t, document["components"])
	examples := object(t, components["examples"])
	cases := map[string]string{
		"ClusterListSuccess": "ClusterListResponse", "ClusterPartial": "Cluster", "HealthPartial": "HealthSummary",
		"SourceListPartial": "SourceListResponse", "ObservationListSuccess": "ObservationListResponse",
		"GPUSummaryIncident": "GPUSummaryListResponse", "CollectionRunPartial": "CollectionRunListResponse",
		"EvidencePartial": "Evidence", "EvidenceListPartial": "EvidenceListResponse", "InvalidRequest": "Problem",
		"DiagnosticPreviewAllowed": "DiagnosticAuthorizationPreview", "DiagnosticRunQueued": "DiagnosticRun",
		"Unauthorized": "Problem", "Forbidden": "Problem", "NotFound": "Problem", "Unavailable": "Problem",
	}
	for exampleName, schemaName := range cases {
		example := object(t, examples[exampleName])["value"]
		schema := resolve(t, document, "#/components/schemas/"+schemaName)
		if err := validate(document, schema, example, "$example."+exampleName); err != nil {
			t.Errorf("%s: %v", exampleName, err)
		}
	}
}

func TestSSEContractIsReconnectableAndVersioned(t *testing.T) {
	document := loadContract(t)
	operation := object(t, object(t, object(t, document["paths"])["/clusters/{cluster_id}/events"])["get"])
	parameters := array(t, operation["parameters"])
	var lastEventID bool
	for _, raw := range parameters {
		parameter := object(t, raw)
		if parameter["name"] == "Last-Event-ID" && parameter["in"] == "header" {
			lastEventID = true
		}
	}
	if !lastEventID {
		t.Fatal("SSE operation does not expose Last-Event-ID")
	}
	content := object(t, object(t, object(t, object(t, operation["responses"])["200"])["content"])["text/event-stream"])
	if !strings.Contains(fmt.Sprint(content["x-sse-framing-example"]), "id: evt_") {
		t.Fatal("SSE example lacks a durable event ID")
	}
	schemas := object(t, object(t, document["components"])["schemas"])
	for _, name := range []string{"CollectionRunEvent", "SourceEvent"} {
		required := stringSet(t, object(t, schemas[name])["required"])
		for _, field := range []string{"schema_version", "cluster_id", "occurred_at"} {
			if !required[field] {
				t.Errorf("%s does not require %s", name, field)
			}
		}
	}
}

func object(t *testing.T, value any) map[string]any {
	t.Helper()
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("want object, got %T", value)
	}
	return result
}
func array(t *testing.T, value any) []any {
	t.Helper()
	result, ok := value.([]any)
	if !ok {
		t.Fatalf("want array, got %T", value)
	}
	return result
}
func stringSet(t *testing.T, value any) map[string]bool {
	t.Helper()
	result := map[string]bool{}
	for _, item := range array(t, value) {
		result[fmt.Sprint(item)] = true
	}
	return result
}
func assertEnum(t *testing.T, schemas map[string]any, name string, want ...string) {
	t.Helper()
	got := make([]string, 0)
	for _, item := range array(t, object(t, schemas[name])["enum"]) {
		got = append(got, fmt.Sprint(item))
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s enum = %v, want %v", name, got, want)
	}
}

func resolve(t *testing.T, document map[string]any, ref string) map[string]any {
	t.Helper()
	value, err := resolveRef(document, ref)
	if err != nil {
		t.Fatal(err)
	}
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s is %T", ref, value)
	}
	return result
}
func resolveRef(document map[string]any, ref string) (any, error) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, fmt.Errorf("external reference is not allowed: %s", ref)
	}
	var current any = document
	for _, component := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		part := strings.ReplaceAll(strings.ReplaceAll(component, "~1", "/"), "~0", "~")
		object, ok := current.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s traverses non-object", ref)
		}
		current, ok = object[part]
		if !ok {
			return nil, fmt.Errorf("unresolved reference %s", ref)
		}
	}
	return current, nil
}
func walkRefs(document map[string]any, value any, path string) error {
	switch typed := value.(type) {
	case map[string]any:
		if raw, ok := typed["$ref"]; ok {
			if _, err := resolveRef(document, fmt.Sprint(raw)); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
		}
		for key, child := range typed {
			if err := walkRefs(document, child, path+"."+key); err != nil {
				return err
			}
		}
	case []any:
		for index, child := range typed {
			if err := walkRefs(document, child, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	}
	return nil
}

func validate(document map[string]any, schema map[string]any, value any, path string) error {
	if ref, ok := schema["$ref"]; ok {
		resolved, err := resolveRef(document, fmt.Sprint(ref))
		if err != nil {
			return err
		}
		return validate(document, resolved.(map[string]any), value, path)
	}
	if variants, ok := schema["oneOf"].([]any); ok {
		for _, raw := range variants {
			if validate(document, raw.(map[string]any), value, path) == nil {
				return nil
			}
		}
		return fmt.Errorf("%s matches no oneOf variant", path)
	}
	if expected, ok := schema["const"]; ok && !reflect.DeepEqual(expected, value) {
		return fmt.Errorf("%s = %v, want const %v", path, value, expected)
	}
	if enum, ok := schema["enum"].([]any); ok {
		found := false
		for _, allowed := range enum {
			if reflect.DeepEqual(allowed, value) {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("%s = %v, not in enum", path, value)
		}
	}
	typeValue, hasType := schema["type"]
	if types, ok := typeValue.([]any); ok {
		for _, raw := range types {
			copy := cloneMap(schema)
			copy["type"] = raw
			if validate(document, copy, value, path) == nil {
				return nil
			}
		}
		return fmt.Errorf("%s has invalid union type %T", path, value)
	}
	if !hasType {
		return nil
	}
	switch typeValue {
	case "null":
		if value != nil {
			return fmt.Errorf("%s must be null", path)
		}
	case "object":
		objectValue, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s must be object, got %T", path, value)
		}
		properties, _ := schema["properties"].(map[string]any)
		for _, raw := range asArray(schema["required"]) {
			key := fmt.Sprint(raw)
			if _, ok := objectValue[key]; !ok {
				return fmt.Errorf("%s.%s is required", path, key)
			}
		}
		for key, child := range objectValue {
			if property, ok := properties[key].(map[string]any); ok {
				if err := validate(document, property, child, path+"."+key); err != nil {
					return err
				}
			} else if schema["additionalProperties"] == false {
				return fmt.Errorf("%s.%s is not allowed", path, key)
			}
		}
	case "array":
		items, ok := value.([]any)
		if !ok {
			return fmt.Errorf("%s must be array, got %T", path, value)
		}
		if itemSchema, ok := schema["items"].(map[string]any); ok {
			for index, item := range items {
				if err := validate(document, itemSchema, item, fmt.Sprintf("%s[%d]", path, index)); err != nil {
					return err
				}
			}
		}
	case "string":
		text, ok := value.(string)
		if !ok {
			return fmt.Errorf("%s must be string, got %T", path, value)
		}
		if schema["format"] == "date-time" {
			if _, err := time.Parse(time.RFC3339Nano, text); err != nil {
				return fmt.Errorf("%s is not RFC3339: %w", path, err)
			}
		}
		if pattern, ok := schema["pattern"].(string); ok {
			matched, _ := regexp.MatchString(pattern, text)
			if !matched {
				return fmt.Errorf("%s does not match %s", path, pattern)
			}
		}
	case "integer":
		if number, ok := value.(float64); !ok || number != float64(int64(number)) {
			return fmt.Errorf("%s must be integer, got %v", path, value)
		}
	case "number":
		if _, ok := value.(float64); !ok {
			return fmt.Errorf("%s must be number, got %T", path, value)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s must be boolean, got %T", path, value)
		}
	}
	return nil
}
func asArray(value any) []any { result, _ := value.([]any); return result }
func cloneMap(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
