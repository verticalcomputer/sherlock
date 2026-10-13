package remediationruntime

import (
	"context"
	"errors"
	"fmt"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/store/postgres"
	"testing"
)

func TestIterationOutcomeIsClosedAndRedacted(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{nil, "ok"}, {context.DeadlineExceeded, "deadline"}, {context.Canceled, "cancelled"},
		{fmt.Errorf("wrapped: %w", postgres.ErrRemediationAuthorityBusy), "lock_timeout"},
		{application.ErrRemediationLeaseInvalid, "lease_fence"},
		{application.ErrRemediationConflict, "state_fence"},
		{application.ErrRemediationPlanUnauthorized, "signature_authority"},
		{application.ErrRemediationForbidden, "authority_refused"},
		{errors.New("synthetic-private-error-marker"), "iteration_error"},
	} {
		if got := iterationOutcome(tc.err); got != tc.want {
			t.Fatalf("got %q want %q", got, tc.want)
		}
	}
}
