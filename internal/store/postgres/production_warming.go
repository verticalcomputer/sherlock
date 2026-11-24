package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
)

// queueWarming retains the original nonurgent OPEN and fixes its reference.
// A missing terminal reading does not authorize immediate delivery.
func queueWarming(ctx context.Context, tx pgx.Tx, d a.Decision, initial a.Payload, revision int64) (bool, error) {
	hostFallback := d.DecisionSource == "HOST_FALLBACK" && d.HostCause == "DEADLINE_FALLBACK" && d.Outcome == ""
	if d.Kind != "TERMINAL" || d.Action != "INVESTIGATE" || (!hostFallback && d.Outcome != cooling.CategoryID+"/UNRESOLVED_WARMING") || len(d.UrgentOccurrences) != 0 {
		return false, nil
	}
	var state cooling.State
	if err := json.Unmarshal(initial.Body, &state); err != nil {
		return false, err
	}
	if !slices.Equal(state.Branches, []string{"SLOW"}) {
		return false, nil
	}
	var refAt, anchor *time.Time
	var refC *float64
	if state.Reference != nil && state.EntryEndpoint != nil && !state.Reference.SourceAt.IsZero() && state.Reference.SourceAt.Before(state.EntryEndpoint.SourceAt) && !state.EntryEndpoint.SourceAt.After(d.LogicalAt) {
		refAt, refC, anchor = &state.Reference.SourceAt, &state.Reference.Value, &state.EntryEndpoint.SourceAt
	}
	_, err := tx.Exec(ctx, `UPDATE production_assessment_decisions SET warming_revision=$2,warming_reference_at=$3,warming_reference_c=$4,warming_anchor=$5,warming_next_at=CASE WHEN $3::timestamptz IS NOT NULL THEN clock_timestamp() END WHERE event_id=$1 AND warming_revision IS NULL`, d.ID, revision, refAt, refC, anchor)
	return true, err
}

type warmingWork struct {
	id, occurrence, asset        string
	at, referenceAt, anchor, now time.Time
	referenceC                   float64
	last                         *time.Time
	attempt                      int64
	evidence, snapshot           []byte
}

func (w warmingWork) confirmation() (cooling.WarmingContext, bool, error) {
	var ledger, working struct {
		Facts []a.Fact `json:"facts"`
	}
	if err := json.Unmarshal(w.evidence, &ledger); err != nil {
		return cooling.WarmingContext{}, false, err
	}
	if err := json.Unmarshal(w.snapshot, &working); err != nil {
		return cooling.WarmingContext{}, false, err
	}
	samples, negatives, err := cooling.WarmingInputsFromFacts(append(ledger.Facts, working.Facts...), w.asset)
	if err != nil {
		return cooling.WarmingContext{}, false, err
	}
	var last time.Time
	if w.last != nil {
		last = *w.last
	}
	payload, ok := cooling.ConfirmedWarming(samples, w.referenceAt, w.referenceC, w.anchor, w.now, last, negatives...)
	return payload, ok, nil
}

// Claim one scoped item and release the database before any model inference.
// The attempt fence invalidates late results after lease expiry or restart.
func (s *ProductionAssessmentStore) claimWarming(ctx context.Context) (w warmingWork, found bool, err error) {
	tx, err := beginProductionAssessmentTx(ctx, s.pool)
	if err != nil {
		return w, false, err
	}
	defer rollbackMonitoringTx(tx)
	err = tx.QueryRow(ctx, `WITH due AS (
 SELECT d.event_id FROM production_assessment_decisions d
 JOIN production_assessment_enrollments e USING(enrollment_id)
 WHERE e.enrollment_id=$1 AND e.cluster_id=$2 AND e.notifications_enabled AND e.warming_triage
 AND d.warming_revision=e.revision AND d.closed_at IS NULL AND d.warming_next_at<=clock_timestamp()
 AND d.warming_anchor>=clock_timestamp()-interval '10 minutes 45 seconds'
 ORDER BY d.warming_next_at,d.event_id FOR UPDATE OF d SKIP LOCKED LIMIT 1
) UPDATE production_assessment_decisions d SET warming_attempt=warming_attempt+1,warming_next_at=clock_timestamp()+interval '90 seconds'
 FROM due,production_assessment_states s WHERE due.event_id=d.event_id AND s.enrollment_id=d.enrollment_id AND s.asset=d.asset
 RETURNING d.event_id,d.occurrence_id,d.asset,d.logical_at,d.warming_reference_at,d.warming_reference_c,d.warming_anchor,d.warming_last_endpoint,d.warming_attempt,d.evidence,s.snapshot,clock_timestamp()`, s.config.Assessment.RunID, s.config.Assessment.ClusterID).Scan(&w.id, &w.occurrence, &w.asset, &w.at, &w.referenceAt, &w.referenceC, &w.anchor, &w.last, &w.attempt, &w.evidence, &w.snapshot, &w.now)
	if errors.Is(err, pgx.ErrNoRows) {
		return w, false, nil
	}
	if err != nil {
		return w, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return w, false, err
	}
	return w, true, nil
}

// ProcessWarmingTriage checks one live occurrence. Errors and WATCH never
// release an outbox row. All retries are bounded by the original source horizon.
func (s *ProductionAssessmentStore) ProcessWarmingTriage(ctx context.Context, infer func(context.Context, json.RawMessage) (string, string, error)) error {
	if !s.config.WarmingTriage || infer == nil {
		return a.ErrInvalid
	}
	w, found, err := s.claimWarming(ctx)
	if err != nil || !found {
		return err
	}
	assessment, confirmed, err := w.confirmation()
	if err != nil {
		return err
	}
	if !confirmed {
		_, err = s.pool.Exec(ctx, `UPDATE production_assessment_decisions SET warming_next_at=clock_timestamp()+interval '5 seconds' WHERE event_id=$1 AND warming_attempt=$2`, w.id, w.attempt)
		return err
	}
	body, err := json.Marshal(assessment)
	if err != nil {
		return err
	}
	call, cancel := context.WithTimeout(ctx, 30*time.Second)
	action, reason, modelErr := infer(call, body)
	cancel()
	if modelErr != nil || action != "WATCH" && action != "NOTIFY" {
		action = "ERROR"
		if modelErr == nil {
			modelErr = errors.New("invalid warming assessment")
		}
	}
	return errors.Join(modelErr, s.finishWarming(ctx, w, assessment, action, reason))
}

func (s *ProductionAssessmentStore) finishWarming(ctx context.Context, w warmingWork, c cooling.WarmingContext, action, reason string) error {
	tx, err := beginProductionAssessmentTx(ctx, s.pool)
	if err != nil {
		return err
	}
	defer rollbackMonitoringTx(tx)
	// Lock scope authority in host/Slack lock order, then atomically fence the
	// result against disable/re-enable, recovery and a superseding claim.
	var revision int64
	err = tx.QueryRow(ctx, `SELECT revision FROM production_assessment_enrollments WHERE enrollment_id=$1 AND cluster_id=$2 AND notifications_enabled AND warming_triage FOR SHARE`, s.config.Assessment.RunID, s.config.Assessment.ClusterID).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if action == "NOTIFY" {
		// The caller held no database locks during inference. A fresh snapshot
		// must still corroborate the very same crossing that the model saw.
		// The shared enrollment lock excludes a concurrent evaluator commit.
		err = tx.QueryRow(ctx, `SELECT snapshot,clock_timestamp() FROM production_assessment_states WHERE enrollment_id=$1 AND asset=$2 FOR SHARE`, s.config.Assessment.RunID, w.asset).Scan(&w.snapshot, &w.now)
		if err != nil {
			return err
		}
		w.last = nil // cooldown controls dispatch, never confirmation of a response
		current, ok, err := w.confirmation()
		if err != nil {
			return err
		}
		if !ok || w.now.Sub(c.EndpointAt) > 45*time.Second || current.EndpointAt.Before(c.EndpointAt) || !current.QualifiedSinceAt.Equal(c.QualifiedSinceAt) || !reviewedRowsUnchanged(c, current) {
			action = "DISCARDED"
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE production_assessment_decisions SET warming_result=$4,warming_last_endpoint=CASE WHEN $4='DISCARDED' THEN NULL ELSE $5::timestamptz END,warming_next_at=CASE WHEN $4='NOTIFY' THEN NULL ELSE clock_timestamp()+interval '5 seconds' END WHERE event_id=$1 AND warming_attempt=$2 AND warming_revision=$3 AND closed_at IS NULL AND warming_next_at>clock_timestamp() AND warming_anchor>=clock_timestamp()-interval '10 minutes 45 seconds'`, w.id, w.attempt, revision, action, c.EndpointAt)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	if action == "NOTIFY" {
		o, err := scanProductionOccurrence(tx.QueryRow(ctx, `SELECT `+productionOccurrenceColumns+` FROM production_notification_occurrences WHERE occurrence_id=$1 AND enrollment_id=$2 AND closed_at IS NULL FOR UPDATE`, w.occurrence, s.config.Assessment.RunID))
		if err != nil {
			return err
		}
		summary := fmt.Sprintf("Investigate sustained GPU warming\nTemperature: %g → %g °C\nConfirmed at: %s UTC\nAssessment: %s", w.referenceC, c.EndpointC, c.EndpointAt.UTC().Format(time.DateTime), reason)
		message, err := productionMessage(o, "OPEN", c.EndpointAt, summary)
		if err != nil {
			return err
		}
		tag, err = tx.Exec(ctx, `UPDATE gp09_alert_outbox SET status='PENDING',message=$2,available_at=clock_timestamp(),updated_at=clock_timestamp(),last_code='' WHERE event_key=$1 AND assessment_occurrence=$3 AND assessment_enrollment=$4 AND status='DISABLED' AND last_code='WARMING_REVIEW'`, w.id, message, w.occurrence, s.config.Assessment.RunID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("warming notification intent missing")
		}
		tag, err = tx.Exec(ctx, `UPDATE production_notification_intents i SET display_summary=$2 FROM gp09_alert_outbox q WHERE q.alert_id=i.alert_id AND q.event_key=$1 AND q.assessment_enrollment=$3 AND i.occurrence_id=$4`, w.id, summary, s.config.Assessment.RunID, w.occurrence)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("warming intent summary missing")
		}
	}
	return tx.Commit(ctx)
}

// Later points may strengthen a continuous crossing. Backfilled or invalidated
// measurements in the model's original context require a fresh inference.
func reviewedRowsUnchanged(review, current cooling.WarmingContext) bool {
	// A newly recorded power or utilization gap between scrapes can invalidate
	// a load plateau even when every original measurement is unchanged.
	var reviewedGaps []cooling.WarmingUnknownInterval
	for _, gap := range current.UnknownIntervals {
		if gap.Start <= review.Now {
			gap.Through = min(gap.Through, review.Now)
			reviewedGaps = append(reviewedGaps, gap)
		}
	}
	if !slices.Equal(review.UnknownIntervals, reviewedGaps) || len(review.Rows) > len(current.Rows) {
		return false
	}
	for i, row := range review.Rows {
		for j, old := range row {
			now := current.Rows[i][j]
			if old == nil || now == nil {
				if old != now {
					return false
				}
			} else if *old != *now {
				return false
			}
		}
	}
	return true
}
