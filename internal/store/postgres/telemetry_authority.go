package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

// Current expected inventory, source membership, cluster and gateway membership
// are fenced through commit, including matching receipt replay. Facts never
// enroll authority by hostname or broaden source permissions.
func validateTelemetryAuthority(ctx context.Context, tx pgx.Tx, g telemetry.Grant, at time.Time) error {
	var live bool
	if err := tx.QueryRow(ctx, `SELECT c.status='ACTIVE' AND k.removed_at IS NULL FROM collectors c JOIN clusters k USING(cluster_id) WHERE c.cluster_id=$1 AND c.collector_id=$2 FOR SHARE OF c,k`, g.ClusterID, g.GatewayCollectorID).Scan(&live); err != nil {
		return err
	}
	if !live {
		return telemetry.ErrUnauthorized
	}
	for _, source := range g.Sources {
		var id string
		if err := tx.QueryRow(ctx, `SELECT source_id FROM sources WHERE cluster_id=$1 AND source_id=$2 FOR SHARE`, g.ClusterID, source.SourceID).Scan(&id); err != nil {
			return err
		}
	}
	var inventorySource domain.SourceID
	var class string
	if err := tx.QueryRow(ctx, `SELECT source_id,inventory_class FROM goodput_inventory_revisions WHERE cluster_id=$1 AND revision_id=$2`, g.ClusterID, g.InventoryRevisionID).Scan(&inventorySource, &class); err != nil {
		return err
	}
	allowed := false
	for _, source := range g.Sources {
		allowed = allowed || source.SourceID == string(inventorySource)
	}
	if !allowed || class != "EXPECTED" {
		return telemetry.ErrUnauthorized
	}
	if err := lockGoodputFactStream(ctx, tx, "inventory", domain.ClusterID(g.ClusterID), inventorySource, "EXPECTED"); err != nil {
		return err
	}
	// A wait may cross a known future effective-time boundary. Refresh both
	// source history visibility (READ COMMITTED) and the governing DB clock only
	// after the stream is fenced through commit.
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return err
	}
	var revision string
	var sourceAt time.Time
	if err := tx.QueryRow(ctx, `SELECT revision_id,source_at FROM goodput_inventory_revisions WHERE cluster_id=$1 AND source_id=$2 AND inventory_class='EXPECTED' AND effective_at<=$3 AND observed_at<=$3 ORDER BY effective_at DESC,observed_at DESC,source_at DESC,revision_id DESC LIMIT 1`, g.ClusterID, inventorySource, at).Scan(&revision, &sourceAt); err != nil {
		return err
	}
	if revision != g.InventoryRevisionID || sourceAt.After(at) {
		return telemetry.ErrUnauthorized
	}
	var nodeProof, ambiguous bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM goodput_inventory_revision_entities WHERE cluster_id=$1 AND revision_id=$2 AND stable_node_id=$3 AND entity_kind IN ('NODE','GPU')),
 EXISTS(SELECT 1 FROM goodput_inventory_revision_entities a JOIN goodput_inventory_revision_entities b ON b.cluster_id=a.cluster_id AND b.revision_id=a.revision_id AND b.physical_gpu_uuid=a.physical_gpu_uuid WHERE a.cluster_id=$1 AND a.revision_id=$2 AND a.stable_node_id=$3 AND a.entity_kind='GPU' AND b.entity_kind='GPU' AND b.stable_node_id<>a.stable_node_id)`, g.ClusterID, g.InventoryRevisionID, g.NodeID).Scan(&nodeProof, &ambiguous); err != nil {
		return err
	}
	if !nodeProof || ambiguous {
		return telemetry.ErrUnauthorized
	}
	return nil
}
