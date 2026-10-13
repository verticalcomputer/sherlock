package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/monitoring"
)

// Refresh evaluates at most 32 due enrollments with database time. Each policy
// is atomic; a rolled-back failure is separately deferred and sanitized so a
// permanently bad row cannot starve later policies. Caller cancellation aborts.
func (store *MonitoringStore) Refresh(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	var failures []error
	for count := 0; count < 32; count++ {
		// Reserve time to record a failed policy before the whole pass expires.
		// No new policy starts with less than one bounded evaluation plus ledger.
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < 1800*time.Millisecond {
			break
		}
		policyCtx, policyCancel := context.WithTimeout(ctx, 1250*time.Millisecond)
		id, found, err := store.refreshOne(policyCtx)
		policyCancel()
		if err != nil {
			failures = append(failures, fmt.Errorf("monitoring evaluation failed"))
			if ctx.Err() != nil {
				return errors.Join(append(failures, ctx.Err())...)
			}
			if id != "" {
				if e := store.deferMonitoringFailure(ctx, id); e != nil {
					failures = append(failures, fmt.Errorf("monitoring failure state unavailable"))
					break
				}
			} else {
				break
			}
		}
		if !found && err == nil {
			break
		}
	}
	if err := ctx.Err(); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}
func (store *MonitoringStore) refreshOne(ctx context.Context) (id string, found bool, err error) {
	tx, err := beginMonitoringTx(ctx, store.pool)
	if err != nil {
		return "", false, err
	}
	defer rollbackMonitoringTx(tx)
	var body []byte
	err = tx.QueryRow(ctx, `SELECT policy_id FROM gp09_monitor_enrollments WHERE enabled AND next_due_at<=clock_timestamp() ORDER BY next_due_at,last_attempt_at NULLS FIRST,policy_id FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	found = true
	enrollment, err := scanMonitoringEnrollment(tx.QueryRow(ctx, `SELECT `+monitoringEnrollmentColumns+` FROM gp09_monitor_enrollments WHERE policy_id=$1`, id))
	if err != nil {
		return id, true, err
	}
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return id, true, err
	}
	if err = tx.QueryRow(ctx, `SELECT state_evidence FROM gp09_monitor_enrollments WHERE policy_id=$1`, id).Scan(&body); err != nil {
		return id, true, err
	}
	var previous []MonitoringEvidenceSnapshot
	if err = json.Unmarshal(body, &previous); err != nil {
		return id, true, err
	}
	authority, authorityErr := validateMonitoringAuthority(ctx, tx, enrollment.Policy, now)
	input := monitoring.Input{At: now, AuthorityValid: false}
	historyTruncated := false
	history := MonitoringHistoryCoverage{}
	var current []MonitoringEvidenceSnapshot
	if authorityErr == nil {
		input, current, err = loadMonitoringInput(ctx, tx, enrollment.Policy, enrollment.State, authority, now, &history)
		if errors.Is(err, errMonitoringHistoryTruncated) {
			historyTruncated = true
			enrollment.State.Pending = nil
			enrollment.State.RecoveryPending = nil
			enrollment.State.PendingCount = 0
			enrollment.State.RecoveryCount = 0
			enrollment.State.LastGap = monitoring.ReasonMissing
		} else if err != nil {
			return id, true, err
		}
	} else if !errors.Is(authorityErr, ErrMonitoringAuthority) {
		return id, true, authorityErr
	}
	if err = monitoringCursorTieInput(enrollment.Policy, enrollment.State, &input, previous); err != nil {
		return id, true, err
	}
	decision, err := monitoring.Evaluate(enrollment.Policy, enrollment.State, input)
	if err != nil {
		return id, true, err
	}
	cache, err := monitoringStateCache(decision.State, previous, current)
	if err != nil {
		return id, true, err
	}
	if decision.Transition != nil {
		all := append(append([]MonitoringEvidenceSnapshot{}, previous...), current...)
		if err = publishMonitoringTransition(ctx, tx, enrollment.Policy, *decision.Transition, all); err != nil {
			return id, true, err
		}
	}
	historyBody := []byte("{}")
	if historyTruncated {
		historyBody, _ = json.Marshal(history)
	} else if enrollment.HistoryCoverage != nil {
		historyBody, _ = json.Marshal(enrollment.HistoryCoverage)
	}
	stateBody, err := json.Marshal(decision.State)
	if err != nil {
		return id, true, err
	}
	cacheBody, err := json.Marshal(cache)
	if err != nil {
		return id, true, err
	}
	failure := ""
	if historyTruncated {
		failure = "HISTORY_TRUNCATED"
	}
	if authorityErr != nil {
		failure = "AUTHORITY_UNAVAILABLE"
	}
	_, err = tx.Exec(ctx, `UPDATE gp09_monitor_enrollments SET evaluator_state=$2,state_evidence=$3,next_due_at=$4::timestamptz+interval '15 seconds',last_attempt_at=$4,updated_at=$4,last_failure_code=$5,history_coverage=$6 WHERE policy_id=$1`, id, stateBody, cacheBody, now, failure, historyBody)
	if err != nil {
		return id, true, err
	}
	if err = tx.Commit(ctx); err != nil {
		return id, true, err
	}
	return id, true, nil
}
func (store *MonitoringStore) deferMonitoringFailure(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	_, err := store.pool.Exec(ctx, `UPDATE gp09_monitor_enrollments SET next_due_at=clock_timestamp()+interval '15 seconds',last_attempt_at=clock_timestamp(),updated_at=clock_timestamp(),last_failure_code='EVALUATION_FAILED' WHERE policy_id=$1 AND enabled AND next_due_at<=clock_timestamp()`, id)
	return err
}
