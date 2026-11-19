package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

// Refresh has one serial pass and a dedicated pool. Writers lock run first,
// enrollment assets second, then arm budgets. No transaction spans collection.
func (s *AssessmentStore) Refresh(ctx context.Context) error {
	if s.lifecycle.Load() == assessmentRetentionOnly {
		return nil
	}
	started := time.Now() // Monotonic elapsed duration only; never a durable clock.
	pass, cancel := context.WithTimeout(ctx, a.ShadowRefreshBudget)
	defer cancel()
	// Flush a previously rolled-back attempt before a closing transaction can
	// make this run immutable. With no pending failure this performs no I/O.
	flushErr := s.flushAssessmentFailure(pass)
	if errors.Is(flushErr, errAssessmentCommitUnresolved) {
		return flushErr
	}
	// Commit already-due retained work before source reads: an unavailable source
	// must not roll back a deadline disposition that needs no new acquisition.
	err := s.refreshAssessment(pass, true)
	if errors.Is(err, ErrAssessmentCapacity) {
		// The failed due unit admitted nothing. Retain the capacity cause, then
		// retry once using only the trusted entry bundle and host fallback.
		s.noteAssessmentFailure(started, err, "deadline_capacity")
		flushErr = errors.Join(flushErr, s.flushAssessmentFailure(pass))
		if errors.Is(flushErr, errAssessmentCommitUnresolved) {
			return errors.Join(err, flushErr)
		}
		err = s.refreshAssessment(pass, true, "CAPACITY")
	}
	if err == nil && s.lifecycle.Load() != assessmentRetentionOnly {
		err = s.refreshAssessment(pass, false)
	}
	if s.lifecycle.Load() == assessmentRetentionOnly {
		return nil
	}
	if err != nil && !errors.Is(ctx.Err(), context.Canceled) {
		s.noteAssessmentFailure(started, err)
		flushErr = errors.Join(flushErr, s.flushAssessmentFailure(pass)) // A failed write remains pending.
	}
	return errors.Join(err, flushErr)
}

func (s *AssessmentStore) refreshAssessment(pass context.Context, dueOnly bool, forcedFailure ...string) error {
	tx, err := beginAssessmentTx(pass, s.pool)
	if err != nil {
		return err
	}
	defer rollbackMonitoringTx(tx)
	return s.refreshAssessmentTx(pass, tx, dueOnly, forcedFailure...)
}

func (s *AssessmentStore) refreshAssessmentTx(pass context.Context, tx pgx.Tx, dueOnly bool, forcedFailure ...string) (result error) {
	stage, started, outcome := "refresh.load", time.Now(), "not_attempted"
	defer func() { result = assessmentTransactionError(stage, started, result, outcome) }()
	var at time.Time
	if err := tx.QueryRow(pass, `SELECT transaction_timestamp()`).Scan(&at); err != nil {
		return err
	}
	at = at.UTC()
	if dueOnly {
		var due bool
		if err := tx.QueryRow(pass, `SELECT EXISTS(SELECT 1 FROM assessment_runs r WHERE r.run_id=$1 AND r.state<>'CLOSED' AND (r.state='DRAINING' OR r.admission_end_at<=$2 OR EXISTS(SELECT 1 FROM assessment_candidates c WHERE c.run_id=r.run_id AND c.phase='OBSERVING' AND c.due_at<=$2)))`, s.config.RunID, at).Scan(&due); err != nil {
			return err
		}
		if !due {
			return nil
		}
	}
	var engine *a.Engine
	var snapshot assessmentSnapshot
	var err error
	if len(forcedFailure) > 0 {
		engine, snapshot, err = s.loadEngineForFallback(pass, tx, at, forcedFailure[0])
	} else {
		engine, snapshot, err = s.loadEngine(pass, tx, at, dueOnly)
	}
	if errors.Is(err, errAssessmentRunClosed) {
		stage, started, outcome = "refresh.commit", time.Now(), "unknown"
		return s.commitAssessmentRetention(pass, tx)
	}
	if err != nil {
		return err
	}
	if dueOnly {
		due := engine.State == "DRAINING" || !at.Before(engine.AdmissionEndAt)
		for _, c := range engine.Candidates {
			due = due || c.Phase == "OBSERVING" && !c.DueAt.After(at)
		}
		if !due {
			return nil
		}
	}
	selected := snapshot.selected
	if dueOnly {
		selected = []string{}
	}
	if err = recordAssessmentAcquisitionGap(pass, tx, engine, at); err != nil {
		return err
	}
	var retainedBytes int64
	if err = tx.QueryRow(pass, `SELECT payload_bytes FROM assessment_runs WHERE run_id=$1`, s.config.RunID).Scan(&retainedBytes); err != nil {
		return err
	}
	if retainedBytes >= s.config.Limits.PayloadBytes-(4<<20) {
		engine.BeginDrain("CAPACITY")
		selected = []string{}
	}
	stage, started = "refresh.input", time.Now()
	facts := []a.Fact{}
	if engine.State == "ACTIVE" && at.Before(engine.AdmissionEndAt) {
		for _, key := range selected {
			if engine.ExpiryFailure[key] != "" || engine.ExpiryFailure[""] != "" {
				continue
			}
			for _, asset := range s.config.Assets {
				if asset.EntityKey != key {
					continue
				}
				batch, loadErr := loadAssessmentInput(pass, tx, s.config, asset, at, engine.Facts)
				if loadErr != nil {
					if strings.Contains(loadErr.Error(), "AUTHORITY_LOST") {
						engine.BeginDrain("AUTHORITY_LOST")
					} else if errors.Is(loadErr, ErrAssessmentCapacity) {
						engine.BeginDrain("CAPACITY")
					} else {
						return loadErr
					}
					break
				}
				facts = append(facts, batch...)
			}
		}
	}
	admissionWork := engine.State == "ACTIVE" && at.Before(engine.AdmissionEndAt) && len(selected) > 0
	if err = prefetchAssessmentAdmissions(pass, tx, engine, facts); err != nil {
		return err
	}
	var executed time.Time
	if err = tx.QueryRow(pass, `SELECT clock_timestamp()`).Scan(&executed); err != nil {
		return err
	}
	executed = executed.UTC()
	engine.CommitClock = assessmentDatabaseClock(executed)
	stage, started = "refresh.evaluate", time.Now()
	if err = engine.AdvanceAssets(pass, at, executed, executed, facts, nil, selected); err != nil {
		return err
	}
	var committed time.Time
	if err = tx.QueryRow(pass, `SELECT clock_timestamp()`).Scan(&committed); err != nil {
		return err
	}
	committed = committed.UTC()
	overdue := false
	for _, candidate := range engine.Candidates {
		overdue = overdue || (candidate.Phase == "OBSERVING" && !candidate.DueAt.After(committed))
	}
	if overdue {
		catchUpAt := committed
		stage, started = "refresh.input", time.Now()
		if err = reloadAssessmentExpiryWindows(pass, tx, engine, snapshot, catchUpAt); err != nil {
			return err
		}
		if err = tx.QueryRow(pass, `SELECT clock_timestamp()`).Scan(&executed); err != nil {
			return err
		}
		executed = executed.UTC()
		engine.CommitClock = assessmentDatabaseClock(executed)
		stage, started = "refresh.evaluate", time.Now()
		if err = engine.AdvanceAssets(pass, catchUpAt, executed, executed, nil, nil, []string{}); err != nil {
			return err
		}
		if err = tx.QueryRow(pass, `SELECT clock_timestamp()`).Scan(&committed); err != nil {
			return err
		}
		committed = committed.UTC()
	}
	for i := range engine.Decisions {
		d := &engine.Decisions[i]
		if d.LogicalAt.After(committed) || d.ExecutedAt.After(committed) {
			return fmt.Errorf("assessment database clock precedes decision cutoff")
		}
		d.CommittedAt = committed
		for _, c := range engine.Candidates {
			if c.ID == d.CandidateID && d.Kind == "TERMINAL" {
				d.LatenessUS = max(int64(0), committed.Sub(c.DueAt).Microseconds())
			}
		}
	}
	// Terminal decisions may commit even when the independent failure-summary
	// write was temporarily unavailable. Keep the run writable until that summary
	// is durable; the next successful pass can close it without losing evidence.
	s.failureMu.Lock()
	pendingFailure := s.pendingFailure != nil
	s.failureMu.Unlock()
	if engine.State == "CLOSED" && pendingFailure {
		engine.State, engine.ClosedAt = "DRAINING", time.Time{}
	}
	stage, started = "refresh.persist", time.Now()
	if err = s.saveEngine(pass, tx, engine, snapshot, committed, selected); err != nil {
		if strings.Contains(err.Error(), "assessment capacity") || strings.Contains(err.Error(), "acquisition reserve") {
			rollbackMonitoringTx(tx)
			if drainErr := s.drainCapacity(pass); drainErr != nil {
				return errors.Join(ErrAssessmentCapacity, drainErr)
			}
			return ErrAssessmentCapacity
		}
		return err
	}
	// The whole acquisition/evaluation unit, including derived features and bundles,
	// must leave the reserve. A crossing rolls back admission, then drains retained work.
	var payloadAfter int64
	if err = tx.QueryRow(pass, `SELECT payload_bytes FROM assessment_runs WHERE run_id=$1`, s.config.RunID).Scan(&payloadAfter); err != nil {
		return err
	}
	if admissionWork && payloadAfter > s.config.Limits.PayloadBytes-(4<<20) && payloadAfter > retainedBytes {
		rollbackMonitoringTx(tx)
		if drainErr := s.drainCapacity(pass); drainErr != nil {
			return errors.Join(ErrAssessmentCapacity, drainErr)
		}
		return ErrAssessmentCapacity
	}
	if engine.State == "CLOSED" {
		stage, started, outcome = "refresh.commit", time.Now(), "unknown"
		return s.commitAssessmentRetention(pass, tx)
	}
	stage, started, outcome = "refresh.commit", time.Now(), "unknown"
	return tx.Commit(pass)
}

// Anchor intra-evaluation deadline checks to the database sample and monotonic
// elapsed time. A different control-host wall clock cannot advance a cutoff.
func assessmentDatabaseClock(sample time.Time) func() time.Time {
	anchor := time.Now()
	return func() time.Time { return sample.Add(time.Since(anchor)).UTC().Truncate(time.Microsecond) }
}

func minAssessmentTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func maxAssessmentTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

type assessmentCoverageInterval struct {
	From    time.Time `json:"from"`
	Through time.Time `json:"through"`
	Code    string    `json:"code"`
	Count   int64     `json:"count"`
}

// A resumed pass can prove that acquisition was not recorded during this gap,
// not why it stopped. Deadline lateness during drain is reported independently.
func recordAssessmentAcquisitionGap(ctx context.Context, tx pgx.Tx, engine *a.Engine, at time.Time) error {
	var previous time.Time
	var stopped *time.Time
	if err := tx.QueryRow(ctx, `SELECT coalesce(last_success_at,start_at),stopped_at FROM assessment_runs WHERE run_id=$1`, engine.Config.RunID).Scan(&previous, &stopped); err != nil {
		return err
	}
	through := at
	if through.After(engine.AdmissionEndAt) {
		through = engine.AdmissionEndAt
	}
	if stopped != nil && through.After(*stopped) {
		through = stopped.UTC()
	}
	previous = previous.UTC()
	if through.Sub(previous) <= 5*time.Second {
		return nil
	}
	engine.RecordCoverageGap(previous, through)
	return nil
}

// loadAssessmentFaults restores coalesced diagnostic and telemetry routing facts,
// so repeated polling or restart cannot turn an annotation into a new preview.
func loadAssessmentFaults(ctx context.Context, tx pgx.Tx, engine *a.Engine) error {
	rows, err := tx.Query(ctx, `SELECT id,asset,kind,code,scope_key,first_at,last_at,count,body FROM assessment_failures WHERE run_id=$1 ORDER BY id LIMIT 1025`, engine.Config.RunID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, kind, code, scope string
		var asset *string
		var first, last time.Time
		var count int64
		var body []byte
		if err = rows.Scan(&id, &asset, &kind, &code, &scope, &first, &last, &count, &body); err != nil {
			return err
		}
		if len(engine.Failures)+len(engine.Telemetry) >= 1024 {
			return ErrAssessmentCapacity
		}
		if asset == nil {
			blank := ""
			asset = &blank
		}
		if kind == "QUALIFIED_TELEMETRY" {
			var b assessmentTelemetryBody
			if err = a.DecodeStrict(body, &b, 16384); err != nil {
				return err
			}
			engine.Telemetry[id] = &a.TelemetryRecord{ID: id, Asset: *asset, PolicyID: b.PolicyID, Occurrence: b.Occurrence, Disposition: b.Disposition, PhysicalSequence: b.PhysicalSequence, OpenFact: b.OpenFact, RecoverFact: b.RecoverFact, BundleID: b.BundleID, Summary: b.Summary, PreviewID: b.PreviewID, FirstAt: first, LastAt: last, Count: count}
		} else {
			var b assessmentFailureBody
			if err = a.DecodeStrict(body, &b, 16384); err != nil {
				return err
			}
			from, through := b.From.UTC(), b.Through.UTC()
			engine.Failures = append(engine.Failures, a.Failure{ID: id, Kind: kind, ScopeKey: scope, FirstAt: first.UTC(), Count: count, BundleID: b.BundleID, FactIDs: b.FactIDs, Code: code, Asset: *asset, At: last.UTC(), LogicalFrom: &from, LogicalThrough: &through})
		}
	}
	return rows.Err()
}

type assessmentFailureBody struct {
	Schema   int64     `json:"schema"`
	BundleID string    `json:"bundle_id,omitempty"`
	FactIDs  []string  `json:"fact_ids"`
	Message  string    `json:"message"`
	From     time.Time `json:"from"`
	Through  time.Time `json:"through"`
}
type assessmentTelemetryBody struct {
	Schema           int64  `json:"schema"`
	PolicyID         string `json:"policy_id"`
	Occurrence       int64  `json:"occurrence"`
	Disposition      string `json:"disposition"`
	PhysicalSequence int64  `json:"physical_sequence,omitempty"`
	OpenFact         string `json:"open_fact"`
	RecoverFact      string `json:"recover_fact,omitempty"`
	BundleID         string `json:"bundle_id"`
	Summary          string `json:"summary"`
	PreviewID        string `json:"preview_id,omitempty"`
}

func (s *AssessmentStore) drainCapacity(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	_, err := s.pool.Exec(bounded, `UPDATE assessment_runs SET state='DRAINING',stopped_at=coalesce(stopped_at,clock_timestamp()),stop_reason=coalesce(stop_reason,'CAPACITY'),overflow_count=overflow_count+1,unknown_from=coalesce(unknown_from,last_success_at,start_at),unknown_through=clock_timestamp() WHERE run_id=$1 AND state IN ('ACTIVE','DRAINING')`, s.config.RunID)
	return err
}
