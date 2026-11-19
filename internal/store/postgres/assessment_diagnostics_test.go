package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestAssessmentDiagnosticClassificationAndRedaction(t *testing.T) {
	for _, tc := range []struct{ state, class string }{
		{"40001", "serialization_failure"}, {"40P01", "deadlock_detected"},
		{"55P03", "lock_unavailable"}, {"57014", "statement_canceled"},
		{"08006", "connection_failure"}, {"42501", "privilege_failure"},
		{"53300", "resource_failure"}, {"23505", "sql_error"},
		{"private", "store_error"}, {"abcde", "store_error"}, {"12\n45", "store_error"},
	} {
		t.Run(tc.state, func(t *testing.T) {
			pg := &pgconn.PgError{Code: tc.state, Message: "private-message", Detail: "private-detail", Hint: "private-hint", Where: "private-query", SchemaName: "private-schema", TableName: "private-table", ConstraintName: "private-constraint"}
			err := assessmentTransactionError("refresh.persist", time.Now().Add(-12*time.Millisecond), fmt.Errorf("private-DSN: %w", pg), "not_attempted")
			fields := AssessmentDiagnosticFields(err)
			d := fields[1].([]assessmentDiagnostic)[0]
			if d.ErrorClass != tc.class || d.ElapsedMS < 12 || d.Stage != "refresh.persist" || d.CommitOutcome != "not_attempted" {
				t.Fatalf("unexpected diagnostic: %+v", d)
			}
			if tc.class == "store_error" && d.SQLState != "" {
				t.Fatalf("invalid SQLSTATE escaped: %q", d.SQLState)
			}
			encoded, _ := json.Marshal(fields)
			if strings.Contains(string(encoded)+err.Error(), "private") {
				t.Fatalf("sensitive data escaped: %s", encoded)
			}
			var recovered *pgconn.PgError
			if !errors.Is(err, pg) || !errors.As(err, &recovered) || recovered != pg {
				t.Fatal("wrapper lost error identity")
			}
		})
	}
}

func TestAssessmentDiagnosticJoinedPhasesAndFallback(t *testing.T) {
	primary := assessmentTransactionError("refresh.persist", time.Now(), context.DeadlineExceeded, "not_attempted")
	flush := assessmentTransactionError("failure_flush.commit", time.Now(), &pgconn.PgError{Code: "08006", Message: "private"}, "unknown")
	joined := errors.Join(primary, flush, fmt.Errorf("private: %w", context.Canceled))
	wrapped := assessmentTransactionError("refresh.commit", time.Now(), joined, "unknown")
	if wrapped != joined || !errors.Is(wrapped, context.DeadlineExceeded) || !errors.Is(wrapped, context.Canceled) {
		t.Fatal("specific diagnostics or error identities were overwritten")
	}
	diagnostics := AssessmentDiagnosticFields(wrapped)[1].([]assessmentDiagnostic)
	if len(diagnostics) != 3 || diagnostics[0].Stage != "refresh.persist" || diagnostics[1].Stage != "failure_flush.commit" || diagnostics[2].ErrorClass != "context_canceled" || diagnostics[2].ElapsedMS != -1 {
		t.Fatalf("unexpected joined diagnostics: %+v", diagnostics)
	}
	if diagnostics[0].ErrorClass != "context_deadline" || diagnostics[1].CommitOutcome != "unknown" {
		t.Fatalf("unexpected classifications: %+v", diagnostics)
	}
}

type assessmentCyclicError struct{}

func (e *assessmentCyclicError) Error() string { panic("must not stringify unknown errors") }
func (e *assessmentCyclicError) Unwrap() error { return e }

type assessmentOpaqueError struct{}

func (assessmentOpaqueError) Error() string { panic("must not stringify unknown errors") }

func TestAssessmentDiagnosticBounds(t *testing.T) {
	many := make([]error, 1000)
	for i := range many {
		many[i] = assessmentOpaqueError{}
	}
	for _, err := range []error{errors.Join(many...), &assessmentCyclicError{}} {
		fields := AssessmentDiagnosticFields(err)
		if n := len(fields[1].([]assessmentDiagnostic)); n < 1 || n > assessmentDiagnosticLimit || fields[3] != true {
			t.Fatalf("unbounded or unmarked truncation: %+v", fields)
		}
	}
	five := errors.Join(many[:5]...)
	if fields := AssessmentDiagnosticFields(five); fields[3] != true {
		t.Fatalf("diagnostic-count truncation not marked: %+v", fields)
	}
	for _, tc := range []struct {
		start    time.Time
		expected int64
	}{
		{time.Time{}, -1}, {time.Now().Add(time.Hour), 0}, {time.Now().Add(-48 * time.Hour), int64((24 * time.Hour) / time.Millisecond)},
	} {
		err := assessmentTransactionError("private-query", tc.start, assessmentOpaqueError{}, "private-outcome")
		d := AssessmentDiagnosticFields(err)[1].([]assessmentDiagnostic)[0]
		if d.Stage != "unknown" || d.CommitOutcome != "unknown" || d.ElapsedMS != tc.expected {
			t.Fatalf("invalid controlled fields: %+v", d)
		}
	}
	if assessmentTransactionError("commit", time.Now(), nil, "committed") != nil || AssessmentDiagnosticFields(nil) != nil {
		t.Fatal("nil errors must not generate diagnostics")
	}
}
