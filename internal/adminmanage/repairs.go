package adminmanage

import (
	"context"
	"github.com/jackc/pgx/v5"
	"time"
)

// repairOverview deliberately degrades to unavailable without hiding the existing
// tickets view. A bounded read-only snapshot never grants execution authority.
func (store *PostgresStore) repairOverview(ctx context.Context, clusterID string) RepairOverview {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return RepairOverview{}
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var out RepairOverview
	err = tx.QueryRow(ctx, `SELECT remediation_enabled,
 (SELECT count(*) FROM collection_repair_requests WHERE ($1='' OR cluster_id=$1) AND status IN ('REQUESTED','CLAIMED','CANCEL_REQUESTED')),
 (SELECT count(*) FROM remediation_runs WHERE ($1='' OR cluster_id=$1) AND assurance='LIVE' AND state='VERIFYING'),
 (SELECT count(*) FROM remediation_runs WHERE ($1='' OR cluster_id=$1) AND assurance='LIVE' AND state='SUCCEEDED'),
 (SELECT count(*) FROM remediation_runs WHERE ($1='' OR cluster_id=$1) AND assurance='LIVE' AND state IN ('CONTAINED','ROLLBACK_FAILED','FAILED','EXPIRED')),
 (SELECT count(*) FROM remediation_runs WHERE ($1='' OR cluster_id=$1) AND assurance='LIVE' AND state='CANCELLED'),
 (SELECT count(*) FROM remediation_runs WHERE ($1='' OR cluster_id=$1) AND assurance='LIVE' AND state='ROLLED_BACK')
 FROM remediation_global_state WHERE id=true`, clusterID).Scan(&out.GlobalEnabled, &out.ActiveRequests, &out.PendingVerification, &out.Succeeded, &out.Contained, &out.Cancelled, &out.RolledBack)
	if err != nil {
		return RepairOverview{}
	}
	rows, err := tx.Query(ctx, `SELECT CASE WHEN code IN ('SCHEDULE_DISPATCH_GAP','SCHEDULE_FACTS_UNKNOWN','STREAM_DISABLED','COLLECTION_ACTIVE','SOURCE_UNAVAILABLE','COLLECTOR_UNAVAILABLE','INVENTORY_MISSING','COVERAGE_INCOMPLETE','COLLECTION_FAILED','STREAM_FRESH','NORMAL_SCHEDULER_DUE') THEN code ELSE 'OTHER' END AS category,count(*)
 FROM schedule_repair_decisions WHERE ($1='' OR cluster_id=$1) GROUP BY category ORDER BY category LIMIT 12`, clusterID)
	if err != nil {
		return RepairOverview{}
	}
	for rows.Next() {
		var d RepairDecision
		if err := rows.Scan(&d.Code, &d.Count); err != nil {
			rows.Close()
			return RepairOverview{}
		}
		out.Decisions = append(out.Decisions, d)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return RepairOverview{}
	}
	if err := tx.Commit(ctx); err != nil {
		return RepairOverview{}
	}
	out.Available = true
	return out
}
