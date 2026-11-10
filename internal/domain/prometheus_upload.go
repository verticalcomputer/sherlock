package domain

import (
	"fmt"
	"time"
)

const (
	PrometheusUploadPath      = "/collector/v1/prometheus/reports"
	PrometheusUploadVersion   = 1
	PrometheusUploadInterval  = time.Minute
	PrometheusUploadRetention = 15 * time.Minute
	PrometheusUploadMaxSeries = 1024
	PrometheusUploadMaxBytes  = 1 << 20
)

type PrometheusReport struct {
	Version int              `json:"version"`
	Result  CollectionResult `json:"result"`
}

func PrometheusUploadQueries() []QueryKind {
	// Keep the original spool positions stable across upgrades.
	return []QueryKind{QueryGPUIdentity, QueryGPUUtilization, QueryGPUXID,
		QueryGPUTemperature, QueryGPUPower, QueryGPUMemory, QueryGPUECC}
}

// PrometheusUploadFields limits the added scheduled queries to fields exposed
// by the reviewed upload profile, independent of the general collector plans.
func PrometheusUploadFields(query QueryKind) []DCGMField {
	fields := DCGMFields(query)
	switch query {
	case QueryGPUTemperature, QueryGPUMemory:
		return fields
	case QueryGPUPower, QueryGPUECC:
		out := make([]DCGMField, 0, 2)
		for _, f := range fields {
			switch f.Name {
			case "DCGM_FI_DEV_POWER_USAGE", "DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS", "DCGM_FI_DEV_UNCORRECTABLE_REMAPPED_ROWS":
				out = append(out, f)
			}
		}
		return out
	}
	return nil
}

func PrometheusUploadTask(cluster ClusterID, source SourceID, query QueryKind, slot time.Time) CollectionTask {
	slot = slot.UTC()
	key := ChecksumSHA256([]byte(fmt.Sprintf("prometheus-scheduled-v1\x00%s\x00%s\x00%s\x00%s", cluster, source, query, slot.Format(time.RFC3339))))
	id := "prometheus-scheduled-v1-" + key.String()
	return CollectionTask{RunID: RunID(id), ClusterID: cluster, SourceID: source, Query: query, ScheduledFor: slot,
		Deadline: slot.Add(PrometheusUploadInterval), MaxSeries: PrometheusUploadMaxSeries,
		MaxBytes: PrometheusUploadMaxBytes, IdempotencyKey: id}
}

func (r PrometheusReport) Validate(cluster ClusterID, source SourceID, now time.Time) error {
	task := r.Result.Task
	switch task.Query {
	case QueryGPUIdentity, QueryGPUUtilization, QueryGPUXID, QueryGPUTemperature, QueryGPUPower, QueryGPUMemory, QueryGPUECC:
	default:
		return fmt.Errorf("query is not part of the scheduled Prometheus profile")
	}
	slot := task.ScheduledFor
	if r.Version != PrometheusUploadVersion || cluster == "" || source == "" || slot.IsZero() ||
		!slot.Equal(slot.Truncate(PrometheusUploadInterval)) || slot.After(now) || slot.Before(now.Add(-PrometheusUploadRetention)) {
		return fmt.Errorf("invalid scheduled Prometheus report version or slot")
	}
	result := r.Result
	if result.StartedAt.Before(slot) || result.CompletedAt.After(task.Deadline) || result.CompletedAt.After(now.Add(time.Second)) ||
		result.Coverage.SeriesExpected != nil || len(result.Coverage.ExpectedTargets) != 0 ||
		len(result.Observations) > result.Coverage.SeriesReturned || len(result.Failures) > 1 {
		return fmt.Errorf("invalid scheduled Prometheus result bounds")
	}
	for _, o := range result.Observations {
		if len(o.Labels) > 32 || o.ObservedAt.Before(slot.Add(-DCGMFreshFor)) || o.ObservedAt.After(slot) {
			return fmt.Errorf("invalid scheduled Prometheus observation bounds")
		}
		for _, label := range o.Labels {
			if len(label.Name) > 128 || len(label.Value) > 512 {
				return fmt.Errorf("invalid scheduled Prometheus label bounds")
			}
		}
	}
	return validateCollectionResult(result, PrometheusUploadTask(cluster, source, task.Query, slot))
}
