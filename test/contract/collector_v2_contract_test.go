package contract_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestCollectorV2ContractClosedSchemasAndWireParity(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	encoded, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "api", "collector-openapi", "v2.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(encoded, &doc); err != nil {
		t.Fatal(err)
	}
	schemas := object(t, object(t, doc["components"])["schemas"])
	for name, wire := range map[string]any{
		"CollectionPlan": domain.CollectionPlan{}, "CollectionScope": domain.CollectionScope{}, "CollectionInterval": domain.CollectionInterval{}, "CollectionLimits": domain.CollectionLimits{},
		"TypedClaimResponse": collectorcontrol.TypedClaimResponse{}, "TypedResultRequest": collectorcontrol.TypedResultRequest{}, "TypedCollectorResult": domain.TypedCollectorResult{},
		"MetricsPayload": domain.CollectionMetricsPayload{}, "InventoryPayload": domain.CollectionInventoryPayload{}, "AllocationPayload": domain.CollectionAllocationPayload{}, "EventsPayload": domain.CollectionEventsPayload{},
		"SlurmSnapshotPayload": domain.SlurmSnapshotPayload{}, "SlurmAllocationFact": domain.SlurmAllocationFact{}, "SlurmJobLifecycle": domain.SlurmJobLifecycle{}, "SlurmUnresolvedAccounting": domain.SlurmUnresolvedAccounting{}, "SlurmAccountingProvenance": domain.SlurmAccountingProvenance{}, "SlurmNormalizationIssue": domain.SlurmNormalizationIssue{}, "SlurmSourceObservation": domain.SlurmSourceObservation{},
		"Observation": domain.Observation{}, "InventoryRevision": domain.InventoryRevision{}, "AllocationSnapshot": domain.AllocationSnapshot{}, "SourceCoverage": domain.SourceCoverage{}, "EntityIdentity": domain.EntityIdentity{}, "JobIdentity": domain.JobIdentity{}, "CollectionEvent": domain.CollectionEvent{}, "Label": domain.Label{}, "CollectionFailure": domain.CollectionFailure{},
		"CollectionMetric": domain.CollectionMetric{},
	} {
		schema := object(t, schemas[name])
		if schema["additionalProperties"] != false {
			t.Errorf("%s is not closed", name)
		}
		properties := object(t, schema["properties"])
		typ := reflect.TypeOf(wire)
		wireFields := 0
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
			if jsonName == "-" {
				continue
			}
			wireFields++
			if jsonName == "" {
				jsonName = field.Name
			}
			if properties[jsonName] == nil {
				t.Errorf("%s lacks wire field %s", name, jsonName)
			}
		}
		if len(properties) != wireFields {
			t.Errorf("%s field count: schema=%d wire=%d", name, len(properties), wireFields)
		}
	}
	variants := array(t, object(t, schemas["CollectionPayload"])["oneOf"])
	if len(variants) != 5 {
		t.Fatalf("payload variant count = %d", len(variants))
	}
	for _, raw := range variants {
		variant := object(t, raw)
		properties := object(t, variant["properties"])
		kind := object(t, properties["kind"])["const"].(string)
		if variant["additionalProperties"] != false || len(properties) != 2 || properties[kind] == nil {
			t.Errorf("variant %s admits arbitrary fields", kind)
		}
	}
	paths := object(t, doc["paths"])
	for _, path := range []string{"/work/claim", "/work/{work_id}/attempts/{attempt}/start", "/work/{work_id}/attempts/{attempt}/renew", "/work/{work_id}/attempts/{attempt}/results"} {
		method := "post"
		if path == "/work/claim" {
			method = "get"
		}
		operation := object(t, object(t, paths[path])[method])
		responses := object(t, operation["responses"])
		if responses["401"] == nil || responses["426"] == nil || responses["503"] == nil {
			t.Errorf("%s lacks denial/unavailable responses", path)
		}
	}
}
