package domain

import "testing"

func TestCollectionOperationRegistryIsClosedAndPreservesV1Mapping(t *testing.T) {
	operation, ok := ReviewedCollectionOperation(OperationPrometheusGPUUtilization)
	if !ok || operation.Source != CollectionSourcePrometheus || operation.Query != QueryGPUUtilization {
		t.Fatalf("operation=%+v known=%t", operation, ok)
	}
	if _, ok := ReviewedCollectionOperation("prometheus.shell.v1"); ok {
		t.Fatal("unknown operation was accepted")
	}
	if _, ok := CollectionOperationForQuery(QueryKind("arbitrary")); ok {
		t.Fatal("unknown v1 query was accepted")
	}
	operations, err := CollectionOperationsForLegacyCapabilities([]string{string(QuerySourceHealth), string(QueryGPUXID)})
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := LegacyCollectionCapabilities(operations)
	if err != nil {
		t.Fatal(err)
	}
	if len(capabilities) != 2 || capabilities[0] != string(QuerySourceHealth) || capabilities[1] != string(QueryGPUXID) {
		t.Fatalf("legacy capabilities=%v", capabilities)
	}
}

func TestCollectionOperationRegistryRejectsUnknownAndDuplicateConfiguration(t *testing.T) {
	if _, err := CollectionOperationsForLegacyCapabilities([]string{"not-reviewed"}); err == nil {
		t.Fatal("unknown legacy capability was accepted")
	}
	if _, err := LegacyCollectionCapabilities([]CollectionOperationID{OperationPrometheusGPUXID, OperationPrometheusGPUXID}); err == nil {
		t.Fatal("duplicate operation was accepted")
	}
	if _, err := LegacyCollectionCapabilities([]CollectionOperationID{"unreviewed.operation.v1"}); err == nil {
		t.Fatal("unknown operation was accepted")
	}
}
