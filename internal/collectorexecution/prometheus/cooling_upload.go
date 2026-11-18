package prometheus

import (
	"context"
	"errors"
	"time"

	adapter "github.com/verticalcomputer/sherlock/internal/adapters/prometheus"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// ExecuteCooling retains only original-timestamp physical samples belonging to
// the exact profile. Ambiguous, missing and unsupported cells remain incomplete.
func (e *Executor) ExecuteCooling(ctx context.Context, profile domain.CoolingUploadProfile, task domain.CollectionTask) domain.CollectionResult {
	result := domain.CollectionResult{Task: task, Status: domain.ResultFailed, StartedAt: e.clock.Now().UTC()}
	sourceCtx, cancel := context.WithDeadline(ctx, task.ScheduledFor.Add(domain.CoolingUploadSourceTimeout))
	defer cancel()
	var sourceResult adapter.QueryResult
	client, err := e.client.WithTaskBounds(task.MaxSeries, task.MaxBytes, time.Time{})
	if err == nil {
		sourceResult, err = client.CoolingInstant(sourceCtx, profile, task.Query, task.ScheduledFor)
	}
	result.CompletedAt = e.clock.Now().UTC()
	result.Coverage.BytesRead = sourceResult.BytesRead
	if err != nil {
		var sourceErr *adapter.Error
		failure := domain.CollectionFailure{Code: domain.FailureInternal, Message: "cooling collection failed"}
		if errors.As(err, &sourceErr) {
			failure.Code = sourceErr.Code
			failure.Retryable = sourceErr.Retryable
			failure.Message = sourceErr.Message
		}
		result.Failures = []domain.CollectionFailure{failure}
		return result
	}

	field, _ := domain.CoolingUploadField(task.Query)
	type cell struct {
		count  int
		sample adapter.Sample
	}
	cells := make(map[domain.CoolingUploadAsset]cell, len(profile.Assets))
	for _, asset := range profile.Assets {
		cells[asset] = cell{}
	}
	complete := sourceResult.WarningCount == 0
	for _, sample := range sourceResult.Samples {
		node, gpu, valid := domain.DCGMIdentity(domain.SortedLabels(sample.Metric), task)
		asset := domain.CoolingUploadAsset{NodeID: domain.StableNodeID(node), GPUUUID: domain.PhysicalGPUUUID(gpu)}
		current, found := cells[asset]
		if !valid || !found {
			complete = false
			continue
		}
		current.count++
		if sample.Metric["__name__"] == field.Name && domain.CoolingUploadValueValid(task.Query, sample.Value) &&
			sample.ObservedAt.After(task.ScheduledFor.Add(-domain.CoolingUploadInterval)) &&
			!sample.ObservedAt.After(task.ScheduledFor) && !sample.ObservedAt.Before(profile.StartsAt) &&
			sample.ObservedAt.Equal(sample.ObservedAt.Truncate(time.Millisecond)) {
			current.sample = sample
		}
		cells[asset] = current
	}
	for _, asset := range profile.Assets {
		current := cells[asset]
		if current.count != 1 || current.sample.ObservedAt.IsZero() {
			complete = false
			continue
		}
		id, err := e.ids.NewID()
		if err != nil {
			result.Observations = nil
			result.Failures = []domain.CollectionFailure{{Code: domain.FailureInternal, Message: "create cooling observation identifier"}}
			return result
		}
		identity := domain.EntityIdentity{ClusterID: task.ClusterID, Kind: domain.EntityGPU, NodeID: asset.NodeID, PhysicalGPUUUID: asset.GPUUUID}
		result.Observations = append(result.Observations, domain.Observation{
			ID: domain.ObservationID(id), SchemaVersion: 1, ClusterID: task.ClusterID, SourceID: task.SourceID,
			Kind: observationKind(task.Query), EntityKey: identity.Key(), Metric: field.Name, Unit: field.Unit,
			Labels: []domain.Label{{Name: "Hostname", Value: string(asset.NodeID)}, {Name: "UUID", Value: string(asset.GPUUUID)}},
			Value:  current.sample.Value, ObservedAt: current.sample.ObservedAt, CollectedAt: result.CompletedAt,
			SourceReference: domain.DCGMSourceReference(task.Query),
		})
	}
	result.Coverage.SeriesReturned = len(result.Observations)
	result.Coverage.Complete = complete
	if complete {
		result.Status = domain.ResultSucceeded
	} else {
		result.Status = domain.ResultPartial
		result.Failures = []domain.CollectionFailure{{Code: domain.FailurePartialData, Message: "cooling source coverage is incomplete"}}
	}
	return result
}
