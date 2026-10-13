package adminui

import "testing"

func TestDisplayFormatting(t *testing.T) {
	for input, want := range map[int64]string{0: "$0.00", 4_000: "<$0.01", 431_510: "$0.43", 15_000_000: "$15.00"} {
		if got := formatCost(input); got != want {
			t.Errorf("formatCost(%d) = %q, want %q", input, got, want)
		}
	}
	for input, want := range map[int64]string{7: "7", 1_000: "1,000", 59_537: "59,537", 1_234_567: "1,234,567", -2_500: "-2,500"} {
		if got := formatCount(input); got != want {
			t.Errorf("formatCount(%d) = %q, want %q", input, got, want)
		}
	}
	if got := entitySummary([]string{"a", "b", "c", "d", "e"}); got != "a, b, c +2 more" {
		t.Errorf("entitySummary = %q", got)
	}
	if got := shortQuestion(evidenceRepairQuestionPrefix + " Current blocker groups: ..."); got != "Combined evidence repair plan" {
		t.Errorf("shortQuestion(repair) = %q", got)
	}
}

func TestStatusAndSeverityShareTheStatePalette(t *testing.T) {
	for status, want := range map[string]string{
		"COMPLETED": "healthy", "COMPLETE": "healthy", "AVAILABLE": "healthy",
		"PARTIAL": "degraded", "BLOCKED": "degraded",
		"FAILED": "unavailable", "REJECTED": "unavailable",
		"NOT_RECORDED": "no-data", "COLLECTING": "neutral", "OPEN": "neutral", "": "neutral",
	} {
		if got := statusClass(status); got != want {
			t.Errorf("statusClass(%q) = %q, want %q", status, got, want)
		}
	}
	for severity, want := range map[string]string{"CRITICAL": "unavailable", "HIGH": "unavailable", "medium": "degraded", "LOW": "neutral", "": "neutral"} {
		if got := severityClass(severity); got != want {
			t.Errorf("severityClass(%q) = %q, want %q", severity, got, want)
		}
	}
}
