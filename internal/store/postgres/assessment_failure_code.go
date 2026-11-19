package postgres

import (
	"context"
	"strings"
)

// assessmentFailureCode preserves the production engine's existing text-based
// failure classification through redacted diagnostic wrappers. Only a fixed code
// leaves this function; underlying error text is never supplied to diagnostics.
// The walk is bounded even for joined or cyclic errors.
func assessmentFailureCode(err error) string {
	code := "STORE_FAILURE"
	walkAssessmentErrors(err, func(candidate error) bool {
		if _, diagnostic := candidate.(*assessmentTxError); diagnostic {
			return true
		}
		if _, joined := candidate.(interface{ Unwrap() []error }); joined {
			// A joined error's Error method recursively formats every branch;
			// traverse its children under our node bound instead.
			return true
		}
		if candidate == context.DeadlineExceeded {
			code = "TIME_BUDGET"
			return false
		}
		message := candidate.Error()
		switch {
		case strings.Contains(message, "TIME_BUDGET"):
			code = "TIME_BUDGET"
		case code != "TIME_BUDGET" && strings.Contains(message, "AUTHORITY_LOST"):
			code = "AUTHORITY_LOST"
		case code == "STORE_FAILURE" && strings.Contains(message, "CAPACITY"):
			code = "CAPACITY"
		}
		return true
	})
	return code
}
