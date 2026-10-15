// Package prometheus executes the reviewed Prometheus/DCGM collection
// operations. It is kept outside application so the generic coordinator does
// not acquire a vendor dependency as new sources are added.
package prometheus

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	adapter "github.com/verticalcomputer/sherlock/internal/adapters/prometheus"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type Clock interface{ Now() time.Time }
type IDGenerator interface{ NewID() (string, error) }

type Executor struct {
	client       *adapter.Client
	clock        Clock
	ids          IDGenerator
	taskDeadline bool
}

// NewScheduled selects durable task deadlines for the in-process worker.
// New retains the remote collector's independently configured local timeout.
func NewScheduled(client *adapter.Client, clock Clock, ids IDGenerator) (*Executor, error) {
	executor, err := New(client, clock, ids)
	if err != nil {
		return nil, err
	}
	executor.taskDeadline = true
	return executor, nil
}

func New(client *adapter.Client, clock Clock, ids IDGenerator) (*Executor, error) {
	if client == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("prometheus executor dependencies are required")
	}
	return &Executor{client: client, clock: clock, ids: ids}, nil
}

func (e *Executor) Execute(ctx context.Context, task domain.CollectionTask) domain.CollectionResult {
	started := e.clock.Now().UTC()
	result := domain.CollectionResult{Task: task, Status: domain.ResultFailed, StartedAt: started}
	queryContext, cancel := context.WithDeadline(ctx, task.Deadline)
	defer cancel()
	var queryResult adapter.QueryResult
	var deadline time.Time
	if e.taskDeadline {
		deadline = task.Deadline
	}
	client, err := e.client.WithTaskBounds(task.MaxSeries, task.MaxBytes, deadline)
	if err == nil {
		if task.Range == nil {
			queryResult, err = client.Instant(queryContext, task.Query, task.Node, task.ScheduledFor)
		} else {
			queryResult, err = client.Range(queryContext, task.Query, task.Node, *task.Range)
		}
	}
	result.CompletedAt = e.clock.Now().UTC()
	if err != nil {
		var sourceErr *adapter.Error
		failure := domain.CollectionFailure{Code: domain.FailureInternal, Message: "collection failed"}
		if errors.As(err, &sourceErr) {
			failure.Code = sourceErr.Code
			failure.Retryable = sourceErr.Retryable
			failure.Message = sourceErr.Message
		}
		result.Failures = []domain.CollectionFailure{failure}
		result.Coverage = domain.Coverage{BytesRead: queryResult.BytesRead, Complete: false}
		return result
	}
	result.Coverage = domain.Coverage{SeriesReturned: queryResult.SeriesReturned, BytesRead: queryResult.BytesRead, Complete: queryResult.WarningCount == 0}
	if task.Query == domain.QuerySourceHealth && queryResult.WarningCount == 0 {
		expected := queryResult.SeriesReturned
		result.Coverage.SeriesExpected = &expected
	}
	if queryResult.WarningCount > 0 {
		result.Status = domain.ResultPartial
		result.Failures = []domain.CollectionFailure{{Code: domain.FailurePartialData, Message: "Prometheus returned a partial result"}}
	} else if len(queryResult.Samples) == 0 {
		result.Status = domain.ResultNoData
		return result
	} else {
		result.Status = domain.ResultSucceeded
	}
	result.Observations = make([]domain.Observation, 0, len(queryResult.Samples))
	for _, sample := range queryResult.Samples {
		if fields := domain.DCGMFields(task.Query); len(fields) > 0 && task.Range == nil {
			node, gpu, valid := domain.DCGMIdentity(domain.SortedLabels(sample.Metric), task)
			known := false
			for _, field := range fields {
				if field.Name == sample.Metric["__name__"] {
					known = true
				}
			}
			if !valid || !known || math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) {
				result.Status = domain.ResultPartial
				result.Coverage.Complete = false
				result.Failures = []domain.CollectionFailure{{Code: domain.FailurePartialData, Message: "DCGM returned an invalid metric or ambiguous identity"}}
				continue
			}
			// Strip every free-form/exporter label before transport or journal
			// persistence; only the exact node/UUID mapping inputs survive.
			sample.Metric = map[string]string{"__name__": sample.Metric["__name__"], "Hostname": node, "UUID": gpu}
		}
		entity, entityErr := entityKey(task, sample.Metric)
		if entityErr != nil {
			result.Status = domain.ResultPartial
			result.Coverage.Complete = false
			result.Failures = []domain.CollectionFailure{{Code: domain.FailurePartialData, Message: "Prometheus returned a sample without a complete entity identity"}}
			continue
		}
		id, idErr := e.ids.NewID()
		if idErr != nil {
			result.Status = domain.ResultFailed
			result.Observations = nil
			result.Coverage.Complete = false
			result.Failures = []domain.CollectionFailure{{Code: domain.FailureInternal, Message: "create observation identifier"}}
			return result
		}
		metric := sample.Metric["__name__"]
		if metric == "" {
			metric = string(task.Query)
		}
		result.Observations = append(result.Observations, domain.Observation{
			ID: domain.ObservationID(id), SchemaVersion: 1,
			ClusterID: task.ClusterID, SourceID: task.SourceID,
			Kind: observationKind(task.Query), EntityKey: entity, Metric: metric,
			Labels: domain.SortedLabels(sample.Metric), Value: sample.Value, Unit: observationUnit(task.Query),
			ObservedAt: sample.ObservedAt, CollectedAt: result.CompletedAt,
			SourceReference: "prometheus:" + string(task.Query),
		})
		if len(domain.DCGMFields(task.Query)) > 0 && task.Range == nil {
			result.Observations[len(result.Observations)-1].SourceReference = domain.DCGMSourceReference(task.Query)
		}
	}
	if task.Query == domain.QuerySourceHealth && queryResult.WarningCount == 0 {
		seen := make(map[domain.EvidenceTarget]struct{}, len(result.Observations))
		for _, observation := range result.Observations {
			for _, target := range domain.CollectionObservationTargets(task.Query, observation) {
				if _, exists := seen[target]; exists {
					continue
				}
				seen[target] = struct{}{}
				result.Coverage.ExpectedTargets = append(result.Coverage.ExpectedTargets, target)
			}
		}
	}
	return result
}

func observationKind(kind domain.QueryKind) string {
	switch kind {
	case domain.QueryGPUIdentity:
		return "gpu_identity"
	case domain.QueryGPUUtilization:
		return "gpu_utilization"
	case domain.QueryGPUTemperature:
		return "gpu_temperature"
	case domain.QueryGPUPower:
		return "gpu_power"
	case domain.QueryGPUMemory:
		return "gpu_memory"
	case domain.QueryGPUECC:
		return "gpu_ecc"
	case domain.QueryGPUXID:
		return "gpu_xid"
	default:
		return "source_metric"
	}
}

func observationUnit(kind domain.QueryKind) string {
	switch kind {
	case domain.QueryGPUIdentity:
		return "count"
	case domain.QueryGPUUtilization:
		return "percent"
	case domain.QueryGPUTemperature:
		return "celsius"
	case domain.QueryGPUPower:
		return "watts"
	case domain.QueryGPUMemory:
		return "mebibytes"
	case domain.QueryGPUECC:
		return "count"
	case domain.QueryGPUXID:
		return "xid_code"
	default:
		return "boolean"
	}
}

func entityKey(task domain.CollectionTask, labels map[string]string) (string, error) {
	if task.Query == domain.QuerySourceHealth {
		if instance := labels["instance"]; instance != "" {
			return "prometheus-target/" + instance, nil
		}
		return "source/" + string(task.SourceID), nil
	}
	// Legacy XID does not use expanded DCGM normalization. Preserve its index-
	// based compatibility while rejecting contradictory identity aliases here.
	for _, pair := range [][2]string{{"Hostname", "hostname"}, {"UUID", "uuid"}} {
		if labels[pair[0]] != "" && labels[pair[1]] != "" && labels[pair[0]] != labels[pair[1]] {
			return "", fmt.Errorf("GPU sample has conflicting identity aliases")
		}
	}
	host := labels["Hostname"]
	if host == "" {
		host = labels["hostname"]
	}
	if host == "" {
		host = task.Node
	}
	if host == "" {
		host = labels["instance"]
	}
	gpu := labels["gpu"]
	if gpu == "" {
		gpu = labels["UUID"]
	}
	if gpu == "" {
		gpu = labels["uuid"]
	}
	if gpu == "" {
		gpu = labels["device"]
	}
	if host == "" || gpu == "" {
		return "", fmt.Errorf("GPU sample requires host and GPU identity labels")
	}
	return "node/" + host + "/gpu/" + gpu, nil
}
