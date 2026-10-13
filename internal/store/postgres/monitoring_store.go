package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/monitoring"
)

type MonitoringStore struct{ pool *pgxpool.Pool }

func NewMonitoringStore(pool *pgxpool.Pool) *MonitoringStore { return &MonitoringStore{pool: pool} }

const monitoringEnrollmentColumns = `policy,enabled,control_revision,evaluator_state,next_due_at,last_failure_code,last_attempt_at,history_coverage`

func scanMonitoringEnrollment(row pgx.Row) (MonitoringEnrollment, error) {
	var out MonitoringEnrollment
	var policy, state, history []byte
	err := row.Scan(&policy, &out.Enabled, &out.Revision, &state, &out.NextDueAt, &out.LastFailureCode, &out.LastAttemptAt, &history)
	if err != nil {
		return out, err
	}
	if err = json.Unmarshal(policy, &out.Policy); err != nil {
		return out, err
	}
	if string(history) != "{}" {
		if err = json.Unmarshal(history, &out.HistoryCoverage); err != nil {
			return out, err
		}
	}
	err = json.Unmarshal(state, &out.State)
	return out, err
}
func beginMonitoringTx(ctx context.Context, pool *pgxpool.Pool) (pgx.Tx, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout='1s'; SET LOCAL lock_timeout='250ms'`); err != nil {
		rollbackMonitoringTx(tx)
		return nil, err
	}
	return tx, nil
}
func rollbackMonitoringTx(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func monitoringOperatorAudit(ctx context.Context, tx pgx.Tx, cluster domain.ClusterID, id string, revision, occurrence int64, action, actor string, details any, at time.Time) error {
	body, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO gp09_monitor_audit(cluster_id,policy_id,control_revision,occurrence,action,actor,details,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, cluster, id, revision, occurrence, action, actor, body, at)
	return err
}

// Enroll creates explicit authority, or re-enables an identical immutable policy
// with a control revision fence. An expected-zero retry never re-enables a
// disabled row. Semantic changes require an explicit new ID after disable;
// old open episodes and all evidence remain visible under the old policy.
func (store *MonitoringStore) Enroll(ctx context.Context, policy monitoring.Policy, expectedRevision int64, actor string) (MonitoringEnrollment, error) {
	if !monitoringID(actor, 128) || expectedRevision < 0 || policy.Revision != 0 || !policy.EnrolledAt.IsZero() || !monitoringID(policy.ID, 128) || !monitoringID(string(policy.ClusterID), 128) || !monitoringID(string(policy.SourceID), 128) || len(policy.EntityKey) > 256 {
		return MonitoringEnrollment{}, fmt.Errorf("invalid monitoring enrollment input")
	}
	if policy.Binding.InventoryRevisionID != "" && !monitoringID(policy.Binding.InventoryRevisionID, 128) {
		return MonitoringEnrollment{}, fmt.Errorf("invalid monitoring inventory reference")
	}
	for _, node := range policy.Binding.Scope.Nodes {
		if !monitoringID(string(node), 128) {
			return MonitoringEnrollment{}, fmt.Errorf("invalid monitoring scope")
		}
	}
	policy.Binding.Scope = monitoringScope(policy.Binding.Scope)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := beginMonitoringTx(ctx, store.pool)
	if err != nil {
		return MonitoringEnrollment{}, err
	}
	defer rollbackMonitoringTx(tx)
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return MonitoringEnrollment{}, err
	}
	policy.Revision = 1
	policy.EnrolledAt = now
	if err = monitoring.ValidatePolicy(policy); err != nil {
		return MonitoringEnrollment{}, err
	}
	if _, err = validateMonitoringAuthority(ctx, tx, policy, now); err != nil {
		return MonitoringEnrollment{}, err
	}
	out, err := scanMonitoringEnrollment(tx.QueryRow(ctx, `SELECT `+monitoringEnrollmentColumns+` FROM gp09_monitor_enrollments WHERE cluster_id=$1 AND policy_id=$2 FOR UPDATE`, policy.ClusterID, policy.ID))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return MonitoringEnrollment{}, err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		if expectedRevision != 0 {
			return MonitoringEnrollment{}, ErrMonitoringRevision
		}
		body, _ := json.Marshal(policy)
		state, _ := json.Marshal(monitoring.State{Version: monitoring.StateVersion, PolicyID: policy.ID, EnrollmentRevision: 1})
		tag, e := tx.Exec(ctx, `INSERT INTO gp09_monitor_enrollments(policy_id,cluster_id,source_id,entity_key,rule_id,rule_version,operation,scope_key,policy,evaluator_state,created_at,updated_at,next_due_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11,$11) ON CONFLICT(policy_id) DO NOTHING`, policy.ID, policy.ClusterID, policy.SourceID, policy.EntityKey, policy.Rule, policy.RuleVersion, policy.Binding.Operation, monitoringScopeKey(policy.Binding.Scope), body, state, now)
		if e != nil {
			return MonitoringEnrollment{}, e
		}
		if tag.RowsAffected() == 1 {
			if err = monitoringOperatorAudit(ctx, tx, policy.ClusterID, policy.ID, 1, 0, "ENROLLED", actor, map[string]any{"rule": policy.Rule, "rule_version": policy.RuleVersion, "policy_revision": 1}, now); err != nil {
				return MonitoringEnrollment{}, err
			}
			out = MonitoringEnrollment{Policy: policy, Enabled: true, Revision: 1, State: monitoring.State{Version: monitoring.StateVersion, PolicyID: policy.ID, EnrollmentRevision: 1}, NextDueAt: now}
			if err = tx.Commit(ctx); err != nil {
				return MonitoringEnrollment{}, err
			}
			return out, nil
		}
		out, err = scanMonitoringEnrollment(tx.QueryRow(ctx, `SELECT `+monitoringEnrollmentColumns+` FROM gp09_monitor_enrollments WHERE cluster_id=$1 AND policy_id=$2 FOR UPDATE`, policy.ClusterID, policy.ID))
		if err != nil {
			return MonitoringEnrollment{}, ErrMonitoringPolicyConflict
		}
	}
	// Enrollment time and immutable revision are database-owned, not semantic
	// configuration changes. Compare the exact remaining versioned document.
	policy.EnrolledAt = out.Policy.EnrolledAt
	policy.Revision = out.Policy.Revision
	incoming, _ := json.Marshal(policy)
	stored, _ := json.Marshal(out.Policy)
	if string(incoming) != string(stored) {
		return MonitoringEnrollment{}, ErrMonitoringPolicyConflict
	}
	if expectedRevision == 0 {
		if !out.Enabled {
			return MonitoringEnrollment{}, ErrMonitoringRevision
		}
	} else {
		if out.Revision != expectedRevision {
			return MonitoringEnrollment{}, ErrMonitoringRevision
		}
		out.Enabled = true
		out.Revision++
		out.NextDueAt = now
		out.LastFailureCode = ""
		if _, err = tx.Exec(ctx, `UPDATE gp09_monitor_enrollments SET enabled=true,control_revision=control_revision+1,next_due_at=$3,last_failure_code='',updated_at=$3 WHERE cluster_id=$1 AND policy_id=$2`, policy.ClusterID, policy.ID, now); err != nil {
			return MonitoringEnrollment{}, err
		}
		if err = monitoringOperatorAudit(ctx, tx, policy.ClusterID, policy.ID, out.Revision, 0, "REENABLED", actor, map[string]any{"policy_revision": out.Policy.Revision}, now); err != nil {
			return MonitoringEnrollment{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return MonitoringEnrollment{}, err
	}
	return out, nil
}
func (store *MonitoringStore) Disable(ctx context.Context, cluster domain.ClusterID, id string, expectedRevision int64, actor string) (MonitoringEnrollment, error) {
	if !monitoringID(string(cluster), 128) || !monitoringID(id, 128) || !monitoringID(actor, 128) || expectedRevision < 1 {
		return MonitoringEnrollment{}, fmt.Errorf("invalid monitoring disable input")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := beginMonitoringTx(ctx, store.pool)
	if err != nil {
		return MonitoringEnrollment{}, err
	}
	defer rollbackMonitoringTx(tx)
	out, err := scanMonitoringEnrollment(tx.QueryRow(ctx, `SELECT `+monitoringEnrollmentColumns+` FROM gp09_monitor_enrollments WHERE cluster_id=$1 AND policy_id=$2 FOR UPDATE`, cluster, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return MonitoringEnrollment{}, ErrMonitoringNotFound
	}
	if err != nil {
		return out, err
	}
	if out.Revision != expectedRevision {
		return MonitoringEnrollment{}, ErrMonitoringRevision
	}
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `UPDATE gp09_monitor_enrollments SET enabled=false,control_revision=control_revision+1,updated_at=$3 WHERE cluster_id=$1 AND policy_id=$2`, cluster, id, now); err != nil {
		return out, err
	}
	out.Enabled = false
	out.Revision++
	if err = monitoringOperatorAudit(ctx, tx, cluster, id, out.Revision, 0, "DISABLED", actor, map[string]any{"open_episode_preserved": out.State.Open}, now); err != nil {
		return out, err
	}
	if err = tx.Commit(ctx); err != nil {
		return out, err
	}
	return out, nil
}
