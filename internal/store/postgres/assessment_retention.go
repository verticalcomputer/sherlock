package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Cleanup removes at most100 rows, counting every table row. The run is the
// retention unit; a live or unexpired run is never pruned to meet capacity.
func (s *AssessmentStore) Cleanup(ctx context.Context) (int, error) {
	tx, err := beginAssessmentTx(ctx, s.pool)
	if err != nil {
		return 0, err
	}
	defer rollbackMonitoringTx(tx)
	var run string
	if err = tx.QueryRow(ctx, `SELECT run_id FROM assessment_runs WHERE state='CLOSED' AND closed_at<=clock_timestamp()-interval '7 days' ORDER BY closed_at,run_id LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&run); errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	deleted := 0
	for _, table := range []string{"assessment_decisions", "assessment_failures", "assessment_candidates"} {
		tag, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE (run_id,id) IN (SELECT run_id,id FROM `+table+` WHERE run_id=$1 ORDER BY id LIMIT $2)`, run, 100-deleted)
		if err != nil {
			return 0, err
		}
		deleted += int(tag.RowsAffected())
		if deleted == 100 {
			break
		}
	}
	for deleted < 100 {
		var table, id string
		err = tx.QueryRow(ctx, `SELECT table_name,id FROM (SELECT 'bundles' AS table_name,id FROM assessment_bundles WHERE run_id=$1 UNION ALL SELECT 'facts',id FROM assessment_facts WHERE run_id=$1) nodes WHERE NOT EXISTS(SELECT 1 FROM assessment_edges e WHERE e.run_id=$1 AND e.to_table=nodes.table_name AND e.to_id=nodes.id) ORDER BY table_name,id LIMIT 1`, run).Scan(&table, &id)
		if errors.Is(err, pgx.ErrNoRows) {
			break
		}
		if err != nil {
			return 0, err
		}
		if table != "facts" && table != "bundles" {
			return 0, fmt.Errorf("HOST_STATE")
		}
		if _, err = tx.Exec(ctx, `DELETE FROM assessment_`+table+` WHERE run_id=$1 AND id=$2`, run, id); err != nil {
			return 0, err
		}
		deleted++
	}
	if deleted < 100 {
		var graph bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM assessment_facts WHERE run_id=$1) OR EXISTS(SELECT 1 FROM assessment_bundles WHERE run_id=$1)`, run).Scan(&graph); err != nil {
			return 0, err
		}
		if graph {
			return 0, fmt.Errorf("assessment retention graph has no removable node")
		}
		tag, err := tx.Exec(ctx, `DELETE FROM assessment_enrollments WHERE (run_id,category,asset) IN (SELECT run_id,category,asset FROM assessment_enrollments WHERE run_id=$1 ORDER BY category,asset LIMIT $2)`, run, 100-deleted)
		if err != nil {
			return 0, err
		}
		deleted += int(tag.RowsAffected())
		if deleted < 100 {
			if _, err = tx.Exec(ctx, `DELETE FROM assessment_runs WHERE run_id=$1`, run); err != nil {
				return 0, err
			}
			deleted++
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return deleted, nil
}
