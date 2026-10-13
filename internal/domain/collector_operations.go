package domain

import "fmt"

// CollectionSourceKind identifies the locally configured adapter family that
// executes a reviewed collection operation. It is deliberately not a remote
// source identifier: SourceID remains the configured instance identity.
type CollectionSourceKind string

const (
	CollectionSourcePrometheus CollectionSourceKind = "prometheus"
	CollectionSourceSlurm      CollectionSourceKind = "slurm"
	CollectionSourceGPUProcess CollectionSourceKind = "gpu_process"
)

// CollectionOperationID is a reviewed, closed operation identifier. v1 work
// continues to carry QueryKind; the mapping below is the compatibility bridge
// until the versioned plan envelope is introduced.
type CollectionOperationID string

const (
	OperationPrometheusSourceHealth   CollectionOperationID = "prometheus.source_health.v1"
	OperationPrometheusGPUIdentity    CollectionOperationID = "prometheus.gpu_identity.v1"
	OperationPrometheusGPUUtilization CollectionOperationID = "prometheus.gpu_utilization.v1"
	OperationPrometheusGPUTemperature CollectionOperationID = "prometheus.gpu_temperature.v1"
	OperationPrometheusGPUPower       CollectionOperationID = "prometheus.gpu_power.v1"
	OperationPrometheusGPUMemory      CollectionOperationID = "prometheus.gpu_memory.v1"
	OperationPrometheusGPUECC         CollectionOperationID = "prometheus.gpu_ecc.v1"
	OperationPrometheusGPUXID         CollectionOperationID = "prometheus.gpu_xid.v1"
	OperationSlurmInventory           CollectionOperationID = "slurm.inventory.v1"
	OperationSlurmSnapshot            CollectionOperationID = "slurm.snapshot.v1"
	OperationSlurmAllocation          CollectionOperationID = "slurm.allocation.v1"
	OperationSlurmEvents              CollectionOperationID = "slurm.events.v1"
	OperationGPUProcessObservations   CollectionOperationID = "gpu.process_observations.v1"
)

// CollectionOperation describes one reviewed operation and its v1 wire
// equivalent. Do not add arbitrary operation IDs from configuration: additions
// require a code review here and an adapter selected by the composition root.
type CollectionOperation struct {
	ID      CollectionOperationID
	Source  CollectionSourceKind
	Query   QueryKind
	Schema  CollectionPayloadSchema
	Payload CollectionPayloadKind
}

var collectionOperations = []CollectionOperation{
	{ID: OperationPrometheusSourceHealth, Source: CollectionSourcePrometheus, Query: QuerySourceHealth},
	{ID: OperationPrometheusGPUIdentity, Source: CollectionSourcePrometheus, Query: QueryGPUIdentity},
	{ID: OperationPrometheusGPUUtilization, Source: CollectionSourcePrometheus, Query: QueryGPUUtilization},
	{ID: OperationPrometheusGPUTemperature, Source: CollectionSourcePrometheus, Query: QueryGPUTemperature},
	{ID: OperationPrometheusGPUPower, Source: CollectionSourcePrometheus, Query: QueryGPUPower},
	{ID: OperationPrometheusGPUMemory, Source: CollectionSourcePrometheus, Query: QueryGPUMemory},
	{ID: OperationPrometheusGPUECC, Source: CollectionSourcePrometheus, Query: QueryGPUECC},
	{ID: OperationPrometheusGPUXID, Source: CollectionSourcePrometheus, Query: QueryGPUXID},
}

func ReviewedCollectionOperation(id CollectionOperationID) (CollectionOperation, bool) {
	// These protocol contracts do not advertise an installed Slurm adapter.
	switch id {
	case OperationSlurmInventory:
		return CollectionOperation{ID: id, Source: CollectionSourceSlurm, Schema: CollectionInventorySchema, Payload: CollectionPayloadInventory}, true
	case OperationSlurmSnapshot:
		return CollectionOperation{ID: id, Source: CollectionSourceSlurm, Schema: CollectionSlurmSnapshotSchema, Payload: CollectionPayloadSlurmSnapshot}, true
	case OperationSlurmAllocation:
		return CollectionOperation{ID: id, Source: CollectionSourceSlurm, Schema: CollectionAllocationSchema, Payload: CollectionPayloadAllocation}, true
	case OperationSlurmEvents:
		return CollectionOperation{ID: id, Source: CollectionSourceSlurm, Schema: CollectionEventsSchema, Payload: CollectionPayloadEvents}, true
	case OperationGPUProcessObservations:
		return CollectionOperation{ID: id, Source: CollectionSourceGPUProcess, Schema: GPUProcessCollectionSchema, Payload: CollectionPayloadGPUProcess}, true
	}
	for _, operation := range collectionOperations {
		if operation.ID == id {
			operation.Schema, operation.Payload = CollectionMetricsSchema, CollectionPayloadMetrics
			return operation, true
		}
	}
	return CollectionOperation{}, false
}

func CollectionOperationForQuery(query QueryKind) (CollectionOperation, bool) {
	for _, operation := range collectionOperations {
		if operation.Query == query {
			operation.Schema, operation.Payload = CollectionMetricsSchema, CollectionPayloadMetrics
			return operation, true
		}
	}
	return CollectionOperation{}, false
}

// CollectionOperationsForLegacyCapabilities translates the existing v1
// capability names into reviewed operation IDs. It keeps v1 control-plane work
// compatible while refusing claims that have no reviewed operation.
func CollectionOperationsForLegacyCapabilities(capabilities []string) ([]CollectionOperationID, error) {
	operations := make([]CollectionOperationID, 0, len(capabilities))
	seen := make(map[CollectionOperationID]struct{}, len(capabilities))
	for _, capability := range capabilities {
		operation, ok := CollectionOperationForQuery(QueryKind(capability))
		if !ok {
			return nil, fmt.Errorf("legacy collection capability %q has no reviewed operation", capability)
		}
		if _, duplicate := seen[operation.ID]; duplicate {
			return nil, fmt.Errorf("duplicate collection operation %q", operation.ID)
		}
		seen[operation.ID] = struct{}{}
		operations = append(operations, operation.ID)
	}
	return operations, nil
}

// LegacyCollectionCapabilities returns the v1 capability names corresponding
// to a reviewed local operation selection.
func LegacyCollectionCapabilities(operations []CollectionOperationID) ([]string, error) {
	capabilities := make([]string, 0, len(operations))
	seen := make(map[CollectionOperationID]struct{}, len(operations))
	for _, id := range operations {
		operation, ok := ReviewedCollectionOperation(id)
		if !ok {
			return nil, fmt.Errorf("unknown collection operation %q", id)
		}
		if operation.Query == "" {
			return nil, fmt.Errorf("collection operation %q has no v1 capability", id)
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("duplicate collection operation %q", id)
		}
		seen[id] = struct{}{}
		capabilities = append(capabilities, string(operation.Query))
	}
	return capabilities, nil
}
