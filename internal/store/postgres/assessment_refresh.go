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
	started := time.Now() // Monotonic elapsed duration only; never a durable clock.
	pass, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer cancel()
	// Flush a previously rolled-back attempt before a closing transaction can
	// make this run immutable. With no pending failure this performs no I/O.
	flushErr := s.flushAssessmentFailure(pass)
	// Commit already-due retained work before source reads: an unavailable source
	// must not roll back a deadline disposition that needs no new acquisition.
	err := s.refreshAssessment(pass, true)
	if errors.Is(err, ErrAssessmentCapacity) {
		// The failed due unit admitted nothing. Retain the capacity cause, then
		// retry once using only the trusted entry bundle and host fallback.
		s.noteAssessmentFailure(started, err, "deadline_capacity")
		_ = s.flushAssessmentFailure(pass)
		err = s.refreshAssessment(pass, true, "CAPACITY")
	}
	if err == nil {
		err = s.refreshAssessment(pass, false)
	}
	if err != nil && !errors.Is(ctx.Err(), context.Canceled) {
		s.noteAssessmentFailure(started, err)
		_ = s.flushAssessmentFailure(pass) // A failed write remains pending.
	}
	return errors.Join(err, flushErr)
}

func (s *AssessmentStore) refreshAssessment(pass context.Context, dueOnly bool, forcedFailure ...string) error {
	tx, err := beginAssessmentTx(pass, s.pool)
	if err != nil {
		return err
	}
	defer rollbackMonitoringTx(tx)
	var at time.Time
	if err = tx.QueryRow(pass, `SELECT transaction_timestamp()`).Scan(&at); err != nil {
		return err
	}
	at = at.UTC()
	if dueOnly {
		var due bool
		if err = tx.QueryRow(pass, `SELECT EXISTS(SELECT 1 FROM assessment_runs r WHERE r.run_id=$1 AND r.state<>'CLOSED' AND (r.state='DRAINING' OR r.admission_end_at<=$2 OR EXISTS(SELECT 1 FROM assessment_candidates c WHERE c.run_id=r.run_id AND c.phase='OBSERVING' AND c.due_at<=$2)))`, s.config.RunID, at).Scan(&due); err != nil {
			return err
		}
		if !due {
			return nil
		}
	}
	var engine *a.Engine
	var snapshot assessmentSnapshot
	if len(forcedFailure) > 0 {
		engine, snapshot, err = s.loadEngineForFallback(pass, tx, at, forcedFailure[0])
	} else {
		engine, snapshot, err = s.loadEngine(pass, tx, at, dueOnly)
	}
	if err != nil {
		return err
	}
	if engine.State == "CLOSED" {
		return tx.Commit(pass)
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
		if err = engine.AdvanceAssets(pass, committed, committed, committed, nil, nil, []string{}); err != nil {
			return err
		}
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
	if err = tx.Commit(pass); err != nil {
		return err
	}
	return nil
}

// Anchor intra-evaluation deadline checks to the database sample and monotonic
// elapsed time. A different control-host wall clock cannot advance a cutoff.
func assessmentDatabaseClock(sample time.Time) func() time.Time {
	anchor := time.Now()
	return func() time.Time { return sample.Add(time.Since(anchor)).UTC().Truncate(time.Microsecond) }
}

type assessmentPendingFailure struct {
	started  time.Time
	count    int64
	code     string
	scope    string
	capacity bool
}

func (s *AssessmentStore) noteAssessmentFailure(started time.Time, err error, scopes ...string) {
	scope := "refresh"
	if len(scopes) > 0 {
		scope = scopes[0]
	}
	code := "STORE_UNAVAILABLE"
	if errors.Is(err, context.DeadlineExceeded) {
		code = "TIME_BUDGET"
	}
	if errors.Is(err, ErrAssessmentCapacity) {
		code = "CAPACITY"
	}
	if errors.Is(err, a.ErrInvalid) {
		code = "HOST_STATE"
	}
	s.failureMu.Lock()
	defer s.failureMu.Unlock()
	if s.pendingFailure == nil {
		s.pendingFailure = &assessmentPendingFailure{started: started, code: code, scope: scope}
	}
	s.pendingFailure.capacity = s.pendingFailure.capacity || errors.Is(err, ErrAssessmentCapacity)
	if scope == "deadline_capacity" {
		s.pendingFailure.code, s.pendingFailure.scope = "CAPACITY", scope
	} else if s.pendingFailure.code != code && s.pendingFailure.scope != "deadline_capacity" {
		s.pendingFailure.code = "COVERAGE"
	}
	s.pendingFailure.count++
}

// This small independent transaction cannot be rolled back by the next source
// query. It preserves first evidence, coalesces counts, and leaves last_success
// unchanged so successful deadline work cannot hide failed acquisition.
func (s *AssessmentStore) flushAssessmentFailure(ctx context.Context) error {
	s.failureMu.Lock()
	defer s.failureMu.Unlock()
	pending := s.pendingFailure
	if pending == nil {
		return nil
	}
	bounded, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	tx, err := beginAssessmentTx(bounded, s.pool)
	if err != nil {
		return err
	}
	defer rollbackMonitoringTx(tx)
	var state string
	var at, start time.Time
	var encoded []byte
	if err = tx.QueryRow(bounded, `SELECT state,start_at,coverage,date_trunc('microseconds',clock_timestamp()) FROM assessment_runs WHERE run_id=$1 FOR UPDATE`, s.config.RunID).Scan(&state, &start, &encoded, &at); err != nil {
		return err
	}
	if state == "CLOSED" {
		s.pendingFailure = nil
		return nil
	}
	at, start = at.UTC(), start.UTC()
	from := at.Add(-time.Since(pending.started)).Truncate(time.Microsecond)
	if from.Before(start) {
		from = start
	}
	if from.After(at) {
		from = at
	}
	intervals := []assessmentCoverageInterval{}
	if err = a.DecodeStrict(encoded, &intervals, 256<<10); err != nil || len(intervals) > 1024 {
		return a.ErrInvalid
	}
	unknownFrom, unknownThrough := from, at
	code := pending.code
	if pending.scope == "deadline_capacity" {
		// Unlike the failure ledger, this bounded summary must retain the retry
		// mode even when every failure slot has already been consumed.
		code = "DEADLINE_CAPACITY"
	}
	overflow := int64(0)
	merged := false
	if code == "DEADLINE_CAPACITY" {
		for i := range intervals {
			if intervals[i].Code == code {
				intervals[i].From = minAssessmentTime(intervals[i].From, from)
				intervals[i].Through = maxAssessmentTime(intervals[i].Through, at)
				intervals[i].Count += pending.count
				merged = true
				break
			}
		}
	}
	if !merged {
		if len(intervals) < 1024 {
			intervals = append(intervals, assessmentCoverageInterval{from, at, code, pending.count})
		} else {
			// Retain interior gaps even at capacity. Coalesce two ordinary
			// summaries conservatively and keep any retry marker intact.
			first := -1
			for i := range intervals {
				if intervals[i].Code == "DEADLINE_CAPACITY" {
					continue
				}
				if first < 0 {
					first = i
					continue
				}
				a, b := intervals[first], intervals[i]
				joined := assessmentCoverageInterval{minAssessmentTime(a.From, b.From), maxAssessmentTime(a.Through, b.Through), "COVERAGE", a.Count + b.Count}
				intervals[first], intervals[i] = joined, assessmentCoverageInterval{from, at, code, pending.count}
				unknownFrom = minAssessmentTime(unknownFrom, joined.From)
				unknownThrough = maxAssessmentTime(unknownThrough, joined.Through)
				merged = true
				break
			}
			if !merged {
				// Multiple duplicate retry markers are redundant; preserve at
				// least one while widening a remaining summary for this gap.
				if first < 0 {
					first = len(intervals) - 1
				}
				prior := intervals[first]
				intervals[first] = assessmentCoverageInterval{minAssessmentTime(prior.From, from), maxAssessmentTime(prior.Through, at), "COVERAGE", prior.Count + pending.count}
			}
		}

	}
	encoded, err = a.Canonical(intervals)
	if err != nil {
		return err
	}
	id, err := a.Identity("failure", s.config.Category, map[string]any{"run": s.config.RunID, "code": pending.code, "scope_key": pending.scope})
	if err != nil {
		return err
	}
	var room bool
	if err = tx.QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM assessment_failures WHERE run_id=$1 AND id=$2) OR (SELECT count(*) FROM assessment_failures WHERE run_id=$1)<1024`, s.config.RunID, id).Scan(&room); err != nil {
		return err
	}
	if room {
		body, err := a.Canonical(assessmentFailureBody{Schema: 1, FactIDs: []string{}, Message: "Assessment refresh failed; evidence or execution coverage is incomplete.", From: from, Through: at})
		if err != nil {
			return err
		}
		if _, err = tx.Exec(bounded, `INSERT INTO assessment_failures(run_id,id,category,kind,code,scope_key,first_at,last_at,count,body) VALUES($1,$2,$3,'COMPONENT',$4,$8,$5,$5,$6,$7) ON CONFLICT(run_id,id) DO UPDATE SET last_at=greatest(assessment_failures.last_at,EXCLUDED.last_at),count=assessment_failures.count+EXCLUDED.count`, s.config.RunID, id, s.config.Category, pending.code, at, pending.count, body, pending.scope); err != nil {
			return err
		}
	} else {
		overflow += pending.count
	}
	if _, err = tx.Exec(bounded, `UPDATE assessment_runs SET coverage=$2,overflow_count=overflow_count+$3,unknown_from=least(coalesce(unknown_from,$4),$4),unknown_through=greatest(coalesce(unknown_through,$5),$5),state=CASE WHEN $6 THEN 'DRAINING' ELSE state END,stopped_at=CASE WHEN $6 THEN coalesce(stopped_at,$7) ELSE stopped_at END,stop_reason=CASE WHEN $6 THEN coalesce(stop_reason,'CAPACITY') ELSE stop_reason END WHERE run_id=$1`, s.config.RunID, encoded, overflow, unknownFrom, unknownThrough, pending.capacity, at); err != nil {
		return err
	}
	if err = tx.Commit(bounded); err != nil {
		return err
	}
	s.pendingFailure = nil
	return nil
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
