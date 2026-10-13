package domain

// SafeDiagnosticFailureCode never promotes transport-provided text to trusted
// model context or dashboard text. Unknown codes remain explicitly unknown.
func SafeDiagnosticFailureCode(code string) string {
	switch code {
	case "", "TARGET_ROLE_UNAVAILABLE", "DISPATCH_FAILED", "DISPATCH_DEADLINE_EXCEEDED", "DISPATCH_CANCELLED", "NO_RESULT_REPORTED", "PRIOR_EXECUTION_OUTCOME_UNKNOWN", "PRIOR_EXECUTION_NOT_REPEATED", "INVALID_REQUEST", "START_FAILED", "EXIT_NON_ZERO", "EXIT_NONZERO", "TIMED_OUT", "CANCELLED", "EXECUTABLE_REPLACED", "DEFINITION_INACTIVE", "DEADLINE_EXCEEDED":
		return code
	default:
		return "DIAGNOSTIC_FAILURE_UNCLASSIFIED"
	}
}

func DiagnosticFailureReason(code string) string {
	switch SafeDiagnosticFailureCode(code) {
	case "":
		return ""
	case "TARGET_ROLE_UNAVAILABLE":
		return "The requested target has no confirmed role in the collector's reviewed diagnostic inventory."
	case "DISPATCH_FAILED":
		return "The diagnostic dispatcher rejected the invocation before recording a target execution result."
	case "DISPATCH_DEADLINE_EXCEEDED", "DEADLINE_EXCEEDED", "TIMED_OUT":
		return "The diagnostic exceeded its execution deadline."
	default:
		return "The diagnostic did not complete successfully; review its recorded target status and safe failure code."
	}
}
