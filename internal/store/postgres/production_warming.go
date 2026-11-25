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

// queueWarming retains the original nonurgent OPEN and its source-time anchor.
// A missing terminal reading does not authorize immediate delivery.
func queueWarming(ctx context.Context, tx pgx.Tx, d a.Decision, initial a.Payload, entered time.Time, revision int64) (bool, error) {
	hostFallback := d.DecisionSource == "HOST_FALLBACK" && d.HostCause == "DEADLINE_FALLBACK" && d.Outcome == ""
	unresolved := d.Kind == "TERMINAL" && (hostFallback || d.Outcome == cooling.CategoryID+"/UNRESOLVED_WARMING")
	suspected := d.Kind == "TERMINAL" && d.Outcome == cooling.CategoryID+"/COOLING_SUSPECTED"
	firstWorsening := d.Kind == "UPDATE" && slices.Contains(d.Codes, "higher_temperature")
	if d.Action != "INVESTIGATE" || len(d.UrgentOccurrences) != 0 || (!unresolved && !suspected && !firstWorsening) {
		return false, nil
	}
	var anchor *time.Time
	if suspected || firstWorsening {
		// This decision is the first actionable proof (including an UPDATE
		// after a benign terminal). Freeze the review and load comparison
		// at the decision's logical time.
		anchor = &d.LogicalAt
		entered = d.LogicalAt
	} else {
		var state cooling.State
		if err := json.Unmarshal(initial.Body, &state); err != nil {
			return false, err
		}
		if state.EntryEndpoint != nil && !state.EntryEndpoint.SourceAt.IsZero() && !state.EntryEndpoint.SourceAt.After(d.LogicalAt) {
			anchor = &state.EntryEndpoint.SourceAt
		}
	}
	_, err := tx.Exec(ctx, `UPDATE production_assessment_decisions SET warming_revision=$2,warming_comparable=true,warming_anchor=$3,warming_known_at=$4,warming_gate=jsonb_build_object('status', CASE WHEN $3::timestamptz IS NULL THEN 'missing_entry' ELSE 'awaiting_confirmation' END),warming_next_at=CASE WHEN $3::timestamptz IS NOT NULL THEN clock_timestamp() END WHERE event_id=$1 AND warming_revision IS NULL`, d.ID, revision, anchor, entered)
	return true, err
}

func warmingOpenHeld(ctx context.Context, tx pgx.Tx, enrollment, occurrence string) (bool, error) {
	var held bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM production_assessment_decisions WHERE enrollment_id=$1 AND occurrence_id=$2 AND warming_revision IS NOT NULL AND warming_result IS DISTINCT FROM 'NOTIFY')`, enrollment, occurrence).Scan(&held)
	return held, err
}

func retireWarmingForUrgent(ctx context.Context, tx pgx.Tx, enrollment string, d a.Decision) error {
	_, err := tx.Exec(ctx, `UPDATE production_assessment_decisions
 SET warming_urgent_event=$3,warming_next_at=NULL,
 warming_gate=coalesce(warming_gate,'{}'::jsonb) || jsonb_build_object('closed_by','independent_urgent_route')
 WHERE enrollment_id=$1 AND occurrence_id=$2 AND warming_revision IS NOT NULL
 AND warming_result IS DISTINCT FROM 'NOTIFY' AND warming_urgent_event IS NULL AND closed_at IS NULL`,
		enrollment, d.CandidateID, d.ID)
	return err
}

type warmingWork struct {
	id, occurrence, asset                 string
	at, referenceAt, anchor, knownAt, now time.Time
	referenceC                            float64
	last                                  *time.Time
	attempt                               int64
	comparable, suspected                 bool
	evidence, snapshot, profile           []byte
	entryIDs                              map[string]struct{}
	entrySamples                          []cooling.WarmingSample
	entryNegatives                        []cooling.WarmingNegative
}

// Decode the immutable decision proof once per attempt, outside either
// transaction. It is the only source allowed to establish the entry baseline.
func (w *warmingWork) prepareEntry() error {
	var ledger struct {
		Facts    []a.Fact `json:"facts"`
		Decision struct {
			Outcome string `json:"outcome"`
		} `json:"decision"`
	}
	if err := json.Unmarshal(w.evidence, &ledger); err != nil {
		return err
	}
	w.suspected = ledger.Decision.Outcome == cooling.CategoryID+"/COOLING_SUSPECTED"
	w.entryIDs = make(map[string]struct{}, len(ledger.Facts))
	for _, f := range ledger.Facts {
		if f.Asset == w.asset && f.ID != "" {
			w.entryIDs[f.ID] = struct{}{}
		}
	}
	var err error
	w.entrySamples, w.entryNegatives, err = cooling.WarmingInputsFromFacts(ledger.Facts, w.asset)
	return err
}

func (w warmingWork) confirmation() (cooling.WarmingContext, bool, error) {
	var working struct {
		Facts []a.Fact `json:"facts"`
	}
	if err := json.Unmarshal(w.snapshot, &working); err != nil {
		return cooling.WarmingContext{}, false, err
	}
	newFacts := slices.DeleteFunc(working.Facts, func(f a.Fact) bool { _, known := w.entryIDs[f.ID]; return known })
	extraSamples, extraNegatives, err := cooling.WarmingInputsFromFacts(newFacts, w.asset)
	if err != nil {
		return cooling.WarmingContext{}, false, err
	}
	samples := append(w.entrySamples, extraSamples...)
	negatives := append(w.entryNegatives, extraNegatives...)
	var last time.Time
	if w.last != nil {
		last = *w.last
	}
	if w.suspected {
		payload, ok := cooling.SuspectedWarmingContextFromEvidence(w.entrySamples, w.entryNegatives, samples, negatives, w.anchor, w.now, last)
		return payload, ok, nil
	}
	if w.comparable {
		payload, ok := cooling.ConfirmedComparableWarmingFromEvidence(w.entrySamples, w.entryNegatives, samples, w.anchor, w.knownAt, w.now, last, negatives...)
		return payload, ok, nil
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
 RETURNING d.event_id,d.occurrence_id,d.asset,d.logical_at,coalesce(d.warming_reference_at,d.warming_anchor),coalesce(d.warming_reference_c,0),d.warming_anchor,coalesce(d.warming_known_at,d.warming_anchor),d.warming_last_endpoint,d.warming_attempt,d.warming_comparable,d.evidence,s.snapshot,d.warming_profile,clock_timestamp()`, s.config.Assessment.RunID, s.config.Assessment.ClusterID).Scan(&w.id, &w.occurrence, &w.asset, &w.at, &w.referenceAt, &w.referenceC, &w.anchor, &w.knownAt, &w.last, &w.attempt, &w.comparable, &w.evidence, &w.snapshot, &w.profile, &w.now)
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
	if err = w.prepareEntry(); err != nil {
		return err
	}
	assessment, confirmed, err := w.confirmation()
	if err != nil {
		return err
	}
	if w.comparable && (assessment.ComparableLoad != nil || w.suspected && assessment.ReviewPowerW != nil) {
		if len(w.profile) > 0 {
			if err := json.Unmarshal(w.profile, &assessment.HistoricalProfile); err != nil {
				return err
			}
		} else {
			// Freeze both qualified and unknown history. Subsequent retries
			// and configuration reloads must use the same as-of reference.
			if s.warmingProfileLookup != nil {
				assessment.HistoricalProfile = s.warmingProfileLookup(ctx, w.asset, w.knownAt, assessment)
			}
			profile, err := json.Marshal(assessment.HistoricalProfile)
			if err != nil {
				return err
			}
			tag, err := s.pool.Exec(ctx, `UPDATE production_assessment_decisions SET warming_profile=$3::jsonb
 WHERE event_id=$1 AND warming_attempt=$2 AND warming_profile IS NULL
 AND closed_at IS NULL AND warming_next_at>clock_timestamp()`, w.id, w.attempt, profile)
			if err != nil || tag.RowsAffected() == 0 {
				return err
			}
		}
	}
	if !confirmed {
		gate, err := warmingGate(w, assessment, false)
		if err != nil {
			return err
		}
		_, err = s.pool.Exec(ctx, `UPDATE production_assessment_decisions SET warming_gate=$3,warming_next_at=clock_timestamp()+interval '5 seconds'
 WHERE event_id=$1 AND warming_attempt=$2 AND closed_at IS NULL AND warming_next_at>clock_timestamp()
 AND warming_anchor>=clock_timestamp()-interval '10 minutes 45 seconds'`, w.id, w.attempt, gate)
		return err
	}
	if w.suspected {
		// Peers are evidence for the OPEN. Retried model calls can include
		// newer target rows but cannot backfill the original peer comparison.
		atOpen := assessment
		atOpen.Rows = assessment.OpenPeerRows
		assessment.Peers = s.suspectedPeers(ctx, w.asset, w.at, atOpen)
	}
	body, err := json.Marshal(assessment)
	if err != nil {
		return err
	}
	call, cancel := context.WithTimeout(ctx, 30*time.Second)
	action, reason, modelErr := infer(call, body)
	cancel()
	if modelErr != nil || action != "WATCH" && action != "NOTIFY" {
		action, reason = "ERROR", ""
		if modelErr == nil {
			modelErr = errors.New("invalid warming assessment")
		}
	}
	if w.suspected && action != "ERROR" {
		reason = "The decision model selected continued observation."
		if action == "NOTIFY" {
			reason = "The decision model selected hardware investigation."
		}
	}
	return errors.Join(modelErr, s.finishWarming(ctx, w, assessment, action, reason))
}

// Store the small evidence summary used for routing, excluding raw model input
// and provider errors. Full source evidence remains in the existing ledger.
func warmingGate(w warmingWork, c cooling.WarmingContext, confirmed bool) ([]byte, error) {
	status := "awaiting_sustained_crossing"
	if w.comparable && c.ComparableLoad == nil {
		status = "missing_comparable_load"
	}
	if confirmed {
		status = "confirmed"
	}
	if w.suspected {
		status = "awaiting_fresh_evidence"
		if confirmed {
			status = "suspected_cooling_review"
		}
	}
	var since *time.Time
	if confirmed {
		since = &c.QualifiedSinceAt
	}
	return json.Marshal(struct {
		QualifiedSince *time.Time                 `json:"qualified_since,omitempty"`
		Status         string                     `json:"status"`
		CheckedAt      time.Time                  `json:"checked_at"`
		EndpointC      float64                    `json:"endpoint_c,omitempty"`
		Comparable     *cooling.WarmingReference  `json:"comparable_load,omitempty"`
		Historical     *cooling.HistoricalProfile `json:"historical_profile,omitempty"`
		Peers          *cooling.PeerContext       `json:"peers,omitempty"`
		ReviewPowerW   *float64                   `json:"review_power_w,omitempty"`
	}{since, status, w.now, c.EndpointC, c.ComparableLoad, c.HistoricalProfile, c.Peers, c.ReviewPowerW})
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
	gate, err := warmingGate(w, c, true)
	if err != nil {
		return err
	}
	choice := action
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
		// A suspected OPEN has no fixed crossing threshold. Reassess when
		// subsequent telemetry materially cooled while inference was in flight.
		cooled := w.suspected && c.EndpointC-current.EndpointC > cooling.DefaultPolicy().ReferenceToleranceC
		if !ok || cooled || w.now.Sub(c.EndpointAt) > 45*time.Second || current.EndpointAt.Before(c.EndpointAt) || !current.QualifiedSinceAt.Equal(c.QualifiedSinceAt) || !reviewedRowsUnchanged(c, current) {
			action = "DISCARDED"
		}
	}
	record, err := json.Marshal(struct {
		Gate     json.RawMessage `json:"gate"`
		Endpoint time.Time       `json:"endpoint_at"`
		Choice   string          `json:"choice"`
		Result   string          `json:"result"`
		Reason   string          `json:"reason,omitempty"`
	}{gate, c.EndpointAt, choice, action, boundedNotificationText(reason, 512)})
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE production_assessment_decisions SET warming_result=$4,warming_gate=$6,
 warming_calls=(CASE WHEN jsonb_array_length(warming_calls)>=16 THEN warming_calls - 0 ELSE warming_calls END) || jsonb_build_array($7::jsonb),
 warming_last_endpoint=CASE WHEN $4='DISCARDED' THEN NULL ELSE $5::timestamptz END,warming_next_at=CASE WHEN $4='NOTIFY' THEN NULL ELSE clock_timestamp()+interval '5 seconds' END WHERE event_id=$1 AND warming_attempt=$2 AND warming_revision=$3 AND closed_at IS NULL AND warming_next_at>clock_timestamp() AND warming_anchor>=clock_timestamp()-interval '10 minutes 45 seconds'`, w.id, w.attempt, revision, action, c.EndpointAt, gate, record)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	if action == "NOTIFY" {
		o, err := scanProductionOccurrence(tx.QueryRow(ctx, `SELECT `+productionOccurrenceColumns+` FROM production_notification_occurrences WHERE occurrence_id=$1 AND enrollment_id=$2 AND closed_at IS NULL FOR UPDATE`, w.occurrence, s.config.Assessment.RunID))
		if err != nil {
			return err
		}
		summary := fmt.Sprintf("Investigate sustained GPU warming\nTemperature: %g → %g °C\nConfirmed at: %s UTC\nAssessment: %s", c.ReferenceC, c.EndpointC, c.EndpointAt.UTC().Format(time.DateTime), reason)
		if w.suspected {
			summary = fmt.Sprintf("Investigate GPU cooling\nReviewed temperature: %g °C at %s UTC\nAssessment: %s", c.EndpointC, c.EndpointAt.UTC().Format(time.DateTime), reason)
		}
		if r := c.ComparableLoad; r != nil {
			summary += fmt.Sprintf("\nComparable load: %g W, %g °C from %d readings over %.0f s", r.PowerW, r.MedianC, r.Samples, r.Through-r.Start)
			if !w.suspected {
				summary += fmt.Sprintf("\nRise: +%g °C, confirmed for %.0f s", c.EndpointC-r.MedianC, c.EndpointAt.Sub(c.QualifiedSinceAt).Seconds())
			}
		}
		if c.ComparableLoad != nil || w.suspected {
			if h := c.HistoricalProfile; h != nil && h.Status == "qualified" && h.MedianC != nil && h.P95C != nil {
				summary += fmt.Sprintf("\nHistorical profile near %d W: median %g °C, 95th percentile %g °C (%d days, %d periods)", h.CenterW, *h.MedianC, *h.P95C, h.Days, h.Periods)
			} else {
				summary += "\nHistorical profile: insufficient or unavailable history"
			}
		}
		if peers := c.Peers; peers != nil && peers.Status == "available" {
			for i := len(peers.Rows) - 1; i >= 0; i-- {
				row := peers.Rows[i]
				if row.Peers >= 2 {
					summary += fmt.Sprintf("\nAt OPEN: GPU %g °C near %.0f W, %d same-load peers, median %g °C, hottest %g °C", row.TargetC, row.TargetW, row.Peers, row.MedianC, row.MaxC)
					break
				}
			}
		}
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
	if (review.ReviewPowerW == nil) != (current.ReviewPowerW == nil) || review.ReviewPowerW != nil && *review.ReviewPowerW != *current.ReviewPowerW {
		return false
	}
	if (review.ComparableLoad == nil) != (current.ComparableLoad == nil) || review.ComparableLoad != nil && *review.ComparableLoad != *current.ComparableLoad {
		return false
	}
	if !slices.Equal(review.UnknownIntervals, reviewedGaps) || len(review.Rows) > len(current.Rows) {
		return false
	}
	if len(current.Rows) > len(review.Rows) {
		next := current.Rows[len(review.Rows)][0]
		if next == nil || *next <= review.Now {
			return false
		}
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
