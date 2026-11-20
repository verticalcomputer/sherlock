package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

const assessmentDiagnosticNodeLimit = 32
const assessmentDiagnosticLimit = 4

// assessmentDiagnostic contains only bounded, controlled values. PostgreSQL
// messages, SQL, parameters and connection strings must never enter this type.
type assessmentDiagnostic struct {
	Stage         string `json:"stage"`
	ElapsedMS     int64  `json:"elapsed_ms"`
	SQLState      string `json:"sqlstate,omitempty"`
	ErrorClass    string `json:"error_class"`
	CommitOutcome string `json:"commit_outcome"`
}

type assessmentTxError struct {
	cause      error
	diagnostic assessmentDiagnostic
}

func (e *assessmentTxError) Error() string {
	return "assessment transaction failed at " + e.diagnostic.Stage
}
func (e *assessmentTxError) Unwrap() error { return e.cause }

// assessmentTransactionError preserves the original error for errors.Is/As,
// while capturing phase timing at the failure boundary. An existing lower-level
// diagnostic is more specific and is retained, including joined sibling errors.
func assessmentTransactionError(stage string, started time.Time, err error, commitOutcome string) error {
	if err == nil {
		return nil
	}
	found := false
	walkAssessmentErrors(err, func(candidate error) bool {
		if _, ok := candidate.(*assessmentTxError); ok {
			found = true
			return false
		}
		return true
	})
	if found {
		return err
	}
	elapsed := int64(-1) // No phase clock was available.
	if !started.IsZero() {
		elapsed = time.Since(started).Milliseconds()
		if elapsed < 0 {
			elapsed = 0
		}
		// Bound even malformed clocks without obscuring ordinary budget overruns.
		if elapsed > int64((24*time.Hour)/time.Millisecond) {
			elapsed = int64((24 * time.Hour) / time.Millisecond)
		}
	}
	state, class := assessmentErrorClass(err)
	return &assessmentTxError{cause: err, diagnostic: assessmentDiagnostic{
		Stage: assessmentDiagnosticStage(stage), ElapsedMS: elapsed,
		SQLState: state, ErrorClass: class, CommitOutcome: assessmentCommitOutcome(commitOutcome),
	}}
}

// AssessmentDiagnosticFields supplies safe structured slog fields. Joined primary
// and accounting errors remain separate, with at most four diagnostics and 32
// visited error nodes. Uninstrumented errors still receive a safe classification;
// elapsed_ms=-1 means no measured phase timing. No error's Error method is used.
func AssessmentDiagnosticFields(err error) []any {
	if err == nil {
		return nil
	}
	diagnostics := make([]assessmentDiagnostic, 0, assessmentDiagnosticLimit)
	discarded := false
	truncated := walkAssessmentErrors(err, func(candidate error) bool {
		if len(diagnostics) >= assessmentDiagnosticLimit {
			discarded = true
			return false
		}
		if wrapped, ok := candidate.(*assessmentTxError); ok {
			diagnostics = append(diagnostics, wrapped.diagnostic)
			return false
		}
		if hasAssessmentErrorChildren(candidate) {
			return true
		}
		state, class := assessmentErrorClass(candidate)
		diagnostics = append(diagnostics, assessmentDiagnostic{Stage: "unknown", ElapsedMS: -1, SQLState: state, ErrorClass: class, CommitOutcome: "unknown"})
		return false
	})
	// Cyclic or excessively deep external wrappers can exhaust traversal before
	// a leaf is reached. Always retain a bounded, useful fallback in that case.
	if len(diagnostics) == 0 {
		diagnostics = append(diagnostics, assessmentDiagnostic{Stage: "unknown", ElapsedMS: -1, ErrorClass: "store_error", CommitOutcome: "unknown"})
	}
	return []any{"transaction_diagnostics", diagnostics, "diagnostics_truncated", truncated || discarded}
}

// walkAssessmentErrors visits a bounded number of nodes breadth first. A false
// visitor result makes that node terminal (e.g. an already captured diagnostic).
func walkAssessmentErrors(err error, visit func(error) bool) bool {
	pending := []error{err}
	visited := 0
	truncated := false
	for len(pending) > 0 && visited < assessmentDiagnosticNodeLimit {
		current := pending[0]
		pending = pending[1:]
		if current == nil {
			continue
		}
		visited++
		if !visit(current) {
			continue
		}
		var children []error
		switch e := current.(type) {
		case interface{ Unwrap() []error }:
			children = e.Unwrap()
		case interface{ Unwrap() error }:
			children = []error{e.Unwrap()}
		}
		remaining := assessmentDiagnosticNodeLimit - visited - len(pending)
		if len(children) > remaining {
			children = children[:remaining]
			truncated = true
		}
		pending = append(pending, children...)
	}
	return truncated || len(pending) > 0
}

func hasAssessmentErrorChildren(err error) bool {
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		return len(e.Unwrap()) > 0
	case interface{ Unwrap() error }:
		return e.Unwrap() != nil
	default:
		return false
	}
}

func assessmentErrorClass(err error) (string, string) {
	state, class := "", "store_error"
	walkAssessmentErrors(err, func(candidate error) bool {
		switch candidate {
		case ErrMonitoringAuthority:
			if class == "store_error" {
				class = "authority_lost"
			}
		case context.DeadlineExceeded:
			class = "context_deadline"
		case context.Canceled:
			if class != "context_deadline" {
				class = "context_canceled"
			}
		}
		if pg, ok := candidate.(*pgconn.PgError); ok && state == "" && validAssessmentSQLState(pg.Code) {
			state = pg.Code
		}
		return true
	})
	if class != "store_error" || state == "" {
		return state, class
	}
	switch state {
	case "40001":
		class = "serialization_failure"
	case "40P01":
		class = "deadlock_detected"
	case "55P03":
		class = "lock_unavailable"
	case "57014":
		class = "statement_canceled"
	case "42501":
		class = "privilege_failure"
	default:
		switch state[:2] {
		case "08":
			class = "connection_failure"
		case "53":
			class = "resource_failure"
		default:
			class = "sql_error"
		}
	}
	return state, class
}

func validAssessmentSQLState(state string) bool {
	if len(state) != 5 {
		return false
	}
	for i := range state {
		if !(state[i] >= '0' && state[i] <= '9') && !(state[i] >= 'A' && state[i] <= 'Z') {
			return false
		}
	}
	return true
}

func assessmentDiagnosticStage(stage string) string {
	switch stage {
	case "begin", "load", "input", "evaluate", "persist", "commit", "rollback", "cleanup",
		"refresh.begin", "refresh.load", "refresh.input", "refresh.evaluate", "refresh.persist", "refresh.commit",
		"failure_flush.begin", "failure_flush.read", "failure_flush.write", "failure_flush.commit", "failure_flush.resolve",
		"production.input.profile_family_lock", "production.input.profile_revision_lock", "production.input.profile", "production.input.profile_active", "production.input.inventory", "production.input.inventory_assets",
		"production.input.receipts", "production.input.samples",
		"production.begin", "production.load", "production.input", "production.evaluate", "production.persist", "production.commit", "production.cleanup", "production.claim_attempt", "production.failure_account":
		return stage
	default:
		return "unknown"
	}
}

func assessmentCommitOutcome(outcome string) string {
	switch outcome {
	case "not_attempted", "unknown", "committed", "aborted", "in_progress", "unavailable":
		return outcome
	default:
		return "unknown"
	}
}
