package adminclient

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/url"

	"github.com/verticalcomputer/sherlock/internal/adminui"
	"github.com/verticalcomputer/sherlock/internal/adminview"
)

// GetClusterGPUMetrics reads the private API's expanded-DCGM projection for
// one cluster. The mapping preserves every explicit state: a value crosses
// this boundary only when the projection marked the field SUPPORTED.
func (client *Client) GetClusterGPUMetrics(ctx context.Context, id string) (adminui.GPUMetrics, error) {
	if !validClusterID(id) {
		return adminui.GPUMetrics{}, errors.New("admin API cluster ID is invalid")
	}
	request, err := client.request(ctx, http.MethodGet, "/internal/admin/v1/clusters/"+url.PathEscape(id)+"/gpu-metrics", nil)
	if err != nil {
		return adminui.GPUMetrics{}, err
	}
	responseBody, err := client.do(request)
	if err != nil {
		return adminui.GPUMetrics{}, err
	}
	var snapshot adminview.GPUMetricsSnapshot
	if err := decodeStrict(responseBody, &snapshot); err != nil {
		return adminui.GPUMetrics{}, errors.New("decode admin API GPU metrics response")
	}
	return mapGPUMetrics(snapshot), nil
}

func mapGPUMetrics(snapshot adminview.GPUMetricsSnapshot) adminui.GPUMetrics {
	metrics := adminui.GPUMetrics{
		ClusterID: snapshot.ClusterID, GeneratedAt: snapshot.GeneratedAt,
		Truncated: snapshot.Truncated, SourcesTruncated: snapshot.SourcesTruncated,
		Sources:      make([]adminui.GPUMetricsSource, 0, len(snapshot.Sources)),
		Fields:       make([]adminui.GPUMetricsField, 0, len(snapshot.Fields)),
		GPUs:         make([]adminui.GPUMetricsRow, 0, len(snapshot.GPUs)),
		OtherSources: make([]adminui.GPUMetricsOtherSource, 0, len(snapshot.OtherSources)),
	}
	for _, other := range snapshot.OtherSources {
		metrics.OtherSources = append(metrics.OtherSources, adminui.GPUMetricsOtherSource{
			SourceID: other.SourceID, DisplayName: other.DisplayName,
			ObservedNodes: other.ObservedNodes, ObservedGPUs: other.ObservedGPUs,
		})
	}
	for _, field := range snapshot.Fields {
		metrics.Fields = append(metrics.Fields, adminui.GPUMetricsField{
			Name: field.Name, Unit: field.Unit, Semantics: field.Semantics, Operation: field.Operation,
		})
	}
	for _, source := range snapshot.Sources {
		mapped := adminui.GPUMetricsSource{
			SourceID: source.SourceID, DisplayName: source.DisplayName, Primary: source.Primary,
			Operations: make([]adminui.GPUMetricsOperation, 0, len(source.Operations)),
		}
		for _, operation := range source.Operations {
			mapped.Operations = append(mapped.Operations, mapGPUMetricsOperation(operation))
		}
		metrics.Sources = append(metrics.Sources, mapped)
	}
	for _, row := range snapshot.GPUs {
		mapped := adminui.GPUMetricsRow{
			SourceID: row.SourceID, NodeID: row.NodeID, GPUUUID: row.GPUUUID, MIGIdentity: row.MIGIdentity,
			Expected: row.Expected, Observed: row.Observed, ObservedAt: row.ObservedAt,
			ObservedState: string(row.ObservedState),
			Values:        make(map[string]adminui.GPUMetricsCell, len(row.Values)),
			Conditions:    row.Conditions,
		}
		for name, value := range row.Values {
			cell := adminui.GPUMetricsCell{
				Field: name, Unit: value.Unit, Semantics: value.Semantics,
				State: string(value.State), ObservedAt: value.ObservedAt, ResetObserved: value.ResetObserved,
			}
			// A non-finite sample cannot be rendered, so it crosses the boundary
			// as UNKNOWN rather than as a value the page would have to drop.
			if value.State == adminview.GPUMetricSupported && value.Value != nil &&
				!math.IsNaN(*value.Value) && !math.IsInf(*value.Value, 0) {
				number := *value.Value
				cell.Value = &number
			} else if value.State == adminview.GPUMetricSupported {
				cell.State = string(adminview.GPUMetricUnknown)
			}
			mapped.Values[name] = cell
		}
		metrics.GPUs = append(metrics.GPUs, mapped)
	}
	metrics.Inventory = mapGPUMetricsInventory(snapshot.Inventory)
	return metrics
}

func mapGPUMetricsOperation(operation adminview.GPUMetricsOperation) adminui.GPUMetricsOperation {
	mapped := adminui.GPUMetricsOperation{
		OperationID: operation.OperationID, QueryKind: operation.QueryKind,
		Enrolled: operation.Enrolled, Enabled: operation.Enabled, Mode: operation.Mode,
		IntervalSeconds: operation.IntervalSeconds, Revision: operation.Revision,
		Freshness: string(operation.Freshness), FreshWindowSeconds: operation.FreshWindowSeconds,
		Fields: make([]adminui.GPUMetricsFieldSummary, 0, len(operation.FieldSummaries)),
	}
	if operation.LastRun != nil {
		mapped.HasRun = true
		mapped.RunID, mapped.RunStatus = operation.LastRun.RunID, operation.LastRun.Status
		mapped.ScheduledFor, mapped.CompletedAt = operation.LastRun.ScheduledFor, operation.LastRun.CompletedAt
		mapped.CoverageComplete = operation.LastRun.CoverageComplete
	}
	units := make(map[string]adminview.GPUMetricsFieldColumn, len(operation.Fields))
	for _, field := range operation.Fields {
		units[field.Name] = field
	}
	for _, summary := range operation.FieldSummaries {
		mapped.Fields = append(mapped.Fields, adminui.GPUMetricsFieldSummary{
			Field: summary.Field, Unit: units[summary.Field].Unit, Semantics: units[summary.Field].Semantics,
			Supported: summary.Supported, NotSupported: summary.NotSupported, Unknown: summary.Unknown,
			Assessed: summary.Assessed, Expected: summary.Expected,
			UnassessedExpected: summary.UnassessedExpected,
			Dominant:           string(summary.Dominant),
		})
	}
	return mapped
}

func mapGPUMetricsInventory(inventory adminview.GPUMetricsInventory) adminui.GPUMetricsInventory {
	mapped := adminui.GPUMetricsInventory{
		SourceID: inventory.SourceID, HasExpectedRevision: inventory.HasExpectedRevision,
		RevisionID: inventory.RevisionID, EffectiveAt: inventory.EffectiveAt,
		SourceAt: inventory.SourceAt, ObservedAt: inventory.ObservedAt,
		ExpectedNodes: inventory.ExpectedNodes, ExpectedGPUs: inventory.ExpectedGPUs,
		MIGCount:      inventory.MIGCount,
		ObservedNodes: inventory.ObservedNodes, ObservedGPUs: inventory.ObservedGPUs,
		FreshObservedNodes: inventory.FreshObservedNodes, FreshObservedGPUs: inventory.FreshObservedGPUs,
		StaleObservedGPUs: inventory.StaleObservedGPUs,
		CoveredNodes:      inventory.CoveredNodes, CoveredGPUs: inventory.CoveredGPUs,
		CoverageComplete:         inventory.CoverageComplete,
		ObservationWindowSeconds: inventory.ObservationWindowSeconds,
		Truncated:                inventory.Truncated,
		ExpectedNotObserved:      mapGPUMetricsRefs(inventory.ExpectedNotObserved),
		ObservedNotExpected:      mapGPUMetricsRefs(inventory.ObservedNotExpected),
	}
	return mapped
}

func mapGPUMetricsRefs(refs []adminview.GPUMetricsEntityRef) []adminui.GPUMetricsEntityRef {
	mapped := make([]adminui.GPUMetricsEntityRef, 0, len(refs))
	for _, ref := range refs {
		mapped = append(mapped, adminui.GPUMetricsEntityRef{
			NodeID: ref.NodeID, GPUUUID: ref.GPUUUID, Stale: ref.Stale, Unknown: ref.Unknown, ObservedAt: ref.ObservedAt,
		})
	}
	return mapped
}
