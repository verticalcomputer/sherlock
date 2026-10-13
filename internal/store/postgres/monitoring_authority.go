package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/monitoring"
)

type monitoringAuthority struct {
	mode                  domain.SchedulingMode
	query                 domain.QueryKind
	jobID                 string
	configurationRevision int64
}

func monitoringID(value string, max int) bool {
	return value != "" && len(value) <= max && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "*?") && strings.IndexFunc(value, unicode.IsControl) < 0
}
func monitoringScope(scope domain.CollectionScope) domain.CollectionScope {
	nodes := append([]domain.StableNodeID(nil), scope.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i] < nodes[j] })
	if nodes == nil {
		nodes = []domain.StableNodeID{}
	}
	return domain.CollectionScope{Nodes: nodes}
}
func monitoringScopeKey(scope domain.CollectionScope) string {
	body, _ := json.Marshal(monitoringScope(scope))
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}
func monitoringDigest(parts ...string) string {
	body, _ := json.Marshal(parts)
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}

// Revalidate source/schedule under shared row locks, then lock the same
// fact stream used by expected-inventory writers. These locks last
// through the incident/episode/outbox transaction, fencing authority changes.
func validateMonitoringAuthority(ctx context.Context, tx pgx.Tx, policy monitoring.Policy, at time.Time) (monitoringAuthority, error) {
	operation, ok := domain.ReviewedCollectionOperation(policy.Binding.Operation)
	if !ok || operation.Source != domain.CollectionSourcePrometheus {
		return monitoringAuthority{}, ErrMonitoringAuthority
	}
	var authority monitoringAuthority
	authority.query = operation.Query
	var kind string
	var removed *time.Time
	var enabled bool
	var revision int64
	var jobID, nodeFilter *string
	var active *bool
	var configuration, desired *int64
	var nodes []byte
	err := tx.QueryRow(ctx, `SELECT s.kind,k.removed_at,d.enabled,d.revision,d.mode,d.legacy_job_id,j.node_filter,j.active,j.configuration_revision,j.desired_revision,e.nodes
 FROM sources s JOIN clusters k ON k.cluster_id=s.cluster_id
 JOIN desired_schedules d ON d.cluster_id=s.cluster_id AND d.source_id=s.source_id AND d.operation=$3
 LEFT JOIN collection_jobs j ON j.job_id=d.legacy_job_id AND j.cluster_id=d.cluster_id AND j.source_id=d.source_id AND j.query_kind=$4
 LEFT JOIN durable_schedule_executions e ON e.cluster_id=d.cluster_id AND e.source_id=d.source_id AND e.operation=d.operation AND e.revision=d.revision
 WHERE s.cluster_id=$1 AND s.source_id=$2 FOR SHARE OF s,k,d`, policy.ClusterID, policy.SourceID, policy.Binding.Operation, operation.Query).Scan(&kind, &removed, &enabled, &revision, &authority.mode, &jobID, &nodeFilter, &active, &configuration, &desired, &nodes)
	if errors.Is(err, pgx.ErrNoRows) {
		return authority, ErrMonitoringAuthority
	}
	if err != nil {
		return authority, err
	}
	if kind != "prometheus" || removed != nil || !enabled || revision != policy.Binding.ScheduleRevision {
		return authority, ErrMonitoringAuthority
	}
	var actual domain.CollectionScope
	switch authority.mode {
	case domain.SchedulingLegacy:
		if jobID == nil || nodeFilter == nil || *nodeFilter != "" || active == nil || !*active || configuration == nil || desired == nil || *desired != revision {
			return authority, ErrMonitoringAuthority
		}
		authority.jobID = *jobID
		authority.configurationRevision = *configuration
		// Outer joins cannot lock their nullable side. Fence the owned job in
		// a separate exact row lock, then compare the captured configuration.
		var lockedActive bool
		var lockedConfig, lockedDesired int64
		if err = tx.QueryRow(ctx, `SELECT active,configuration_revision,desired_revision FROM collection_jobs WHERE job_id=$1 FOR SHARE`, *jobID).Scan(&lockedActive, &lockedConfig, &lockedDesired); err != nil {
			return authority, err
		}
		if !lockedActive || lockedConfig != *configuration || lockedDesired != revision {
			return authority, ErrMonitoringAuthority
		}
	case domain.SchedulingDurable:
		var lockedNodes []byte
		if err = tx.QueryRow(ctx, `SELECT nodes FROM durable_schedule_executions WHERE cluster_id=$1 AND source_id=$2 AND operation=$3 AND revision=$4 FOR SHARE`, policy.ClusterID, policy.SourceID, policy.Binding.Operation, revision).Scan(&lockedNodes); err != nil {
			return authority, err
		}
		nodes = lockedNodes
		if len(nodes) == 0 || json.Unmarshal(nodes, &actual.Nodes) != nil || len(actual.Nodes) != 0 {
			return authority, ErrMonitoringAuthority
		}
	default:
		return authority, ErrMonitoringAuthority
	}
	if monitoringScopeKey(actual) != monitoringScopeKey(policy.Binding.Scope) {
		return authority, ErrMonitoringAuthority
	}
	if policy.Rule == monitoring.RuleTelemetryLoss {
		if policy.EntityKey != "source/"+string(policy.SourceID) {
			return authority, ErrMonitoringAuthority
		}
		if policy.Binding.InventoryRevisionID == "" {
			return authority, nil
		}
	}
	if policy.Binding.InventoryRevisionID == "" {
		return authority, ErrMonitoringAuthority
	}
	if err = lockGoodputFactStream(ctx, tx, "inventory", policy.ClusterID, policy.SourceID, string(application.InventoryExpected)); err != nil {
		return authority, err
	}
	var current string
	var inventorySourceAt time.Time
	err = tx.QueryRow(ctx, `SELECT revision_id,source_at FROM goodput_inventory_revisions
 WHERE cluster_id=$1 AND source_id=$2 AND inventory_class='EXPECTED' AND effective_at<=$3 AND observed_at<=$3
 ORDER BY effective_at DESC,observed_at DESC,source_at DESC,revision_id DESC LIMIT 1`, policy.ClusterID, policy.SourceID, at).Scan(&current, &inventorySourceAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return authority, ErrMonitoringAuthority
	}
	if err != nil {
		return authority, err
	}
	if inventorySourceAt.After(at) || current != policy.Binding.InventoryRevisionID {
		return authority, ErrMonitoringAuthority
	}
	if policy.Rule == monitoring.RuleTelemetryLoss {
		return authority, nil
	}
	identity, valid := domain.ResolveGPUObservationIdentity(policy.ClusterID, policy.SourceID, domain.Observation{ClusterID: policy.ClusterID, SourceID: policy.SourceID, EntityKey: policy.EntityKey})
	if !valid || !identity.Canonical || identity.EntityKey != policy.EntityKey {
		return authority, ErrMonitoringAuthority
	}
	var exact, ambiguous bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM goodput_inventory_revision_entities WHERE cluster_id=$1 AND revision_id=$2 AND entity_kind='GPU' AND stable_node_id=$3 AND physical_gpu_uuid=$4),
 EXISTS(SELECT 1 FROM goodput_inventory_revision_entities WHERE cluster_id=$1 AND revision_id=$2 AND physical_gpu_uuid=$4 AND (entity_kind='MIG' OR entity_kind='GPU' AND stable_node_id<>$3))`, policy.ClusterID, current, identity.NodeID, identity.PhysicalGPUUUID).Scan(&exact, &ambiguous)
	if err != nil {
		return authority, err
	}
	if !exact || ambiguous {
		return authority, ErrMonitoringAuthority
	}
	return authority, nil
}
