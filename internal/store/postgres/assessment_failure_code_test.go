package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestAssessmentFailureCodePreservesWrappedProductionClassification(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{context.DeadlineExceeded, "TIME_BUDGET"},
		{fmt.Errorf("TIME_BUDGET"), "TIME_BUDGET"},
		{fmt.Errorf("AUTHORITY_LOST: private-reason"), "AUTHORITY_LOST"},
		{fmt.Errorf("CAPACITY: production snapshot"), "CAPACITY"},
		{fmt.Errorf("private-unknown"), "STORE_FAILURE"},
		{&pgconn.PgError{Code: "42501", Severity: "ERROR", Message: "access denied for AUTHORITY_LOST"}, "STORE_FAILURE"},
		{errors.Join(fmt.Errorf("CAPACITY"), context.DeadlineExceeded), "TIME_BUDGET"},
	} {
		wrapped := assessmentTransactionError("production.persist", time.Now(), tc.err, "not_attempted")
		wrapped = fmt.Errorf("operation failed: %w", wrapped)
		if got := assessmentFailureCode(wrapped); got != tc.code {
			t.Fatalf("classification changed: got %q, want %q", got, tc.code)
		}
	}
}
