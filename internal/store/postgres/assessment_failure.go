package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"time"
)

var errAssessmentCommitUnresolved = errors.New("assessment failure commit outcome unresolved")

type assessmentPendingFailure struct {
	started  time.Time
	count    int64
	code     string
	scope    string
	capacity bool
	xid      string // Frozen after COMMIT is attempted; resolve before replay.
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
	slot := &s.pendingFailure
	if s.queuedFailure != nil || (s.pendingFailure != nil && s.pendingFailure.xid != "") {
		slot = &s.queuedFailure
	}
	if *slot == nil {
		*slot = &assessmentPendingFailure{started: started, code: code, scope: scope}
	}
	pending := *slot
	pending.capacity = pending.capacity || errors.Is(err, ErrAssessmentCapacity)
	if scope == "deadline_capacity" {
		pending.code, pending.scope = "CAPACITY", scope
	} else if pending.code != code && pending.scope != "deadline_capacity" {
		pending.code = "COVERAGE"
	}
	pending.count++
}

// This small independent transaction cannot be rolled back by the next source
// query. It preserves first evidence, coalesces counts, and leaves last_success
// unchanged so successful deadline work cannot hide failed acquisition.
func (s *AssessmentStore) flushAssessmentFailure(ctx context.Context) error {
	return s.flushAssessmentFailureWithCommit(ctx, func(ctx context.Context, tx pgx.Tx) error { return tx.Commit(ctx) })
}

// The injectable boundary exercises lost acknowledgements against a real database.
func (s *AssessmentStore) flushAssessmentFailureWithCommit(ctx context.Context, commit func(context.Context, pgx.Tx) error) (result error) {
	stage, started, outcome := "failure_flush.begin", time.Now(), "not_attempted"
	defer func() { result = assessmentTransactionError(stage, started, result, outcome) }()
	s.failureMu.Lock()
	defer s.failureMu.Unlock()
	pending := s.pendingFailure
	if pending == nil {
		return nil
	}
	bounded, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if pending.xid != "" {
		stage, started, outcome = "failure_flush.resolve", time.Now(), "unavailable"
		var status *string
		if err := s.pool.QueryRow(bounded, `SELECT pg_catalog.pg_xact_status($1::xid8)`, pending.xid).Scan(&status); err != nil {
			return errors.Join(errAssessmentCommitUnresolved, err)
		}
		if status == nil {
			outcome = "unknown"
			return errAssessmentCommitUnresolved
		}
		switch *status {
		case "committed":
			s.finishAssessmentFailure()
			pending = s.pendingFailure
			if pending == nil {
				return nil
			}
		case "aborted":
			pending.xid = ""
		default:
			outcome = "in_progress"
			return errAssessmentCommitUnresolved
		}
	}
	stage, started, outcome = "failure_flush.begin", time.Now(), "not_attempted"
	tx, err := beginAssessmentTx(bounded, s.pool)
	if err != nil {
		return err
	}
	defer rollbackMonitoringTx(tx)
	stage, started = "failure_flush.read", time.Now()
	var xid, state string
	var at, start time.Time
	var encoded []byte
	err = tx.QueryRow(bounded, `SELECT state,start_at,coverage,date_trunc('microseconds',clock_timestamp()),pg_catalog.pg_current_xact_id()::text FROM assessment_runs WHERE run_id=$1 FOR UPDATE`, s.config.RunID).Scan(&state, &start, &encoded, &at, &xid)
	if (err == nil && state == "CLOSED") || (errors.Is(err, pgx.ErrNoRows) && s.lifecycle.Load() == assessmentStarted) {
		s.pendingFailure, s.queuedFailure = nil, nil
		return nil
	}
	if err != nil {
		return err
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
	stage, started = "failure_flush.write", time.Now()
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
	stage, started, outcome = "failure_flush.commit", time.Now(), "unknown"
	pending.xid = xid
	if err = commit(bounded, tx); err != nil {
		return errors.Join(errAssessmentCommitUnresolved, err)
	}
	s.finishAssessmentFailure()
	return nil
}

// Caller holds failureMu. At most one frozen batch and one coalesced successor exist.
func (s *AssessmentStore) finishAssessmentFailure() {
	s.pendingFailure, s.queuedFailure = s.queuedFailure, nil
}
