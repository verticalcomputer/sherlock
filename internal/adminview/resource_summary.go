package adminview

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// The extra record only proves truncation. Counts are lower bounds and usage
// is unavailable when the current-projection scan cannot cover the cluster.
const resourceProjectionLimit = 20000

func (store *PostgresStore) loadResources(ctx context.Context, ids []string, byID map[string]*ClusterSummary, at time.Time, freshFor time.Duration) error {
	rows, err := store.pool.Query(ctx, `
		SELECT selected.cluster_id, p.source_id, p.entity_key, p.metric,
		       o.cluster_id,o.source_id,o.observation_id,o.entity_key,o.metric,o.labels,
		       o.value,o.observed_at,o.collected_at,o.unit,o.metric_semantics
		FROM unnest($1::text[]) AS selected(cluster_id)
		CROSS JOIN LATERAL (
			SELECT source_id, entity_key, metric, observation_id
			FROM current_projections WHERE cluster_id=selected.cluster_id
			ORDER BY entity_key,metric,source_id LIMIT $2
		) p
		JOIN observations o ON o.observation_id=p.observation_id
		ORDER BY selected.cluster_id,p.entity_key,p.metric,p.source_id`, ids, resourceProjectionLimit+1)
	if err != nil {
		return fmt.Errorf("load dashboard resource summary: %w", err)
	}
	defer rows.Close()
	accumulators := map[string]*resourceAccumulator{}
	counts := map[string]int{}
	for rows.Next() {
		var clusterID string
		var sourceID domain.SourceID
		var entityKey, metric string
		var observation domain.Observation
		var labels, semantics []byte
		if err := rows.Scan(&clusterID, &sourceID, &entityKey, &metric,
			&observation.ClusterID, &observation.SourceID, &observation.ID, &observation.EntityKey, &observation.Metric, &labels,
			&observation.Value, &observation.ObservedAt, &observation.CollectedAt, &observation.Unit, &semantics); err != nil {
			return fmt.Errorf("scan dashboard resource summary: %w", err)
		}
		counts[clusterID]++
		if counts[clusterID] > resourceProjectionLimit {
			byID[clusterID].Resources.Truncated = true
			continue
		}
		if observation.ClusterID != domain.ClusterID(clusterID) || observation.SourceID != sourceID ||
			observation.EntityKey != entityKey || observation.Metric != metric {
			continue
		}
		if string(labels) != "{}" && len(labels) > 0 {
			if err := json.Unmarshal(labels, &observation.Labels); err != nil {
				return fmt.Errorf("decode dashboard resource labels: %w", err)
			}
		}
		if len(semantics) > 0 && string(semantics) != "null" {
			if err := json.Unmarshal(semantics, &observation.Semantics); err != nil {
				return fmt.Errorf("decode dashboard resource semantics: %w", err)
			}
		}
		if accumulators[clusterID] == nil {
			accumulators[clusterID] = newResourceAccumulator(at, freshFor)
		}
		accumulators[clusterID].add(observation)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate dashboard resource summary: %w", err)
	}
	for clusterID, accumulator := range accumulators {
		truncated := byID[clusterID].Resources.Truncated
		byID[clusterID].Resources = accumulator.summary()
		byID[clusterID].Resources.Truncated = truncated
		if truncated {
			// A subset average is not the cluster's utilization.
			byID[clusterID].Resources.GPUUtilizationPercent = nil
		}
	}
	return nil
}

type resourceAccumulator struct {
	at          time.Time
	freshFor    time.Duration
	nodes       map[string]bool
	gpus        map[string]bool
	utilization map[string]domain.Observation
	conflicting map[string]bool
}

func newResourceAccumulator(at time.Time, freshFor time.Duration) *resourceAccumulator {
	return &resourceAccumulator{at: at, freshFor: freshFor, nodes: map[string]bool{}, gpus: map[string]bool{}, utilization: map[string]domain.Observation{}, conflicting: map[string]bool{}}
}

func (accumulator *resourceAccumulator) add(observation domain.Observation) {
	identity, ok := domain.ResolveGPUObservationIdentity(observation.ClusterID, observation.SourceID, observation)
	if ok {
		key := identity.EntityKey
		if !identity.Canonical {
			// Index-only evidence from separate sources cannot prove it describes
			// the same physical device. Keep it separate rather than infer UUIDs.
			key = string(observation.SourceID) + "\x00" + key
		}
		accumulator.nodes[string(identity.NodeID)], accumulator.gpus[key] = true, true
		if observation.Metric == "DCGM_FI_DEV_GPU_UTIL" {
			current, exists := accumulator.utilization[key]
			if !exists || observation.ObservedAt.After(current.ObservedAt) {
				accumulator.utilization[key] = observation
				accumulator.conflicting[key] = false
			} else if observation.ObservedAt.Equal(current.ObservedAt) &&
				(observation.Value != current.Value || observation.Unit != current.Unit || !reflect.DeepEqual(observation.Semantics, current.Semantics)) {
				accumulator.conflicting[key] = true
			}
		}
		return
	}
	// An invalid GPU observation must not escape through the node-only path.
	parts := strings.Split(observation.EntityKey, "/")
	var node string
	switch {
	case len(parts) >= 2 && parts[0] == "node" && (len(parts) < 3 || parts[2] != "gpu"):
		node = parts[1]
	case len(parts) == 5 && parts[0] == string(observation.ClusterID) && parts[1] == string(domain.EntityNode) && parts[3] == "" && parts[4] == "":
		node = parts[2]
	default:
		return
	}
	_, err := domain.CreateEntityIdentity(domain.EntityIdentity{ClusterID: observation.ClusterID, Kind: domain.EntityNode, NodeID: domain.StableNodeID(node)})
	if err == nil {
		accumulator.nodes[node] = true
	}
}

func (accumulator *resourceAccumulator) summary() ResourceSummary {
	summary := ResourceSummary{ObservedNodes: int64(len(accumulator.nodes)), ObservedGPUs: int64(len(accumulator.gpus))}
	var total float64
	for key, observation := range accumulator.utilization {
		if accumulator.conflicting[key] || !domain.ValidGPUHealthObservation(observation) || observation.ObservedAt.IsZero() ||
			observation.ObservedAt.After(accumulator.at) || observation.CollectedAt.After(accumulator.at) ||
			accumulator.at.Sub(observation.ObservedAt) > accumulator.freshFor {
			continue
		}
		summary.GPUUtilizationSamples++
		total += observation.Value
		if summary.LastObservedAt == nil || observation.ObservedAt.After(*summary.LastObservedAt) {
			instant := observation.ObservedAt.UTC()
			summary.LastObservedAt = &instant
		}
	}
	if summary.GPUUtilizationSamples > 0 {
		average := total / float64(summary.GPUUtilizationSamples)
		summary.GPUUtilizationPercent = &average
	}
	return summary
}
