package adminui

import (
	"fmt"
	"strconv"
	"strings"
)

// Display helpers shared by the admin templates. They only format values from
// redacted projections; none of them infers health or remediation.

func countLabel(count int, singular, plural string) string {
	if count == 1 {
		return "1 " + singular
	}
	return strconv.Itoa(count) + " " + plural
}

func entitySummary(ids []string) string {
	const shown = 3
	if len(ids) <= shown {
		return strings.Join(ids, ", ")
	}
	return fmt.Sprintf("%s +%d more", strings.Join(ids[:shown], ", "), len(ids)-shown)
}

// shortQuestion keeps headings and lists scannable. Combined repair runs carry
// a multi-kilobyte generated question that is available in full on request.
func shortQuestion(question string) string {
	if strings.HasPrefix(question, evidenceRepairQuestionPrefix) {
		return "Combined evidence repair plan"
	}
	return boundedProposalText(question, 180)
}

// formatCost rounds to cents for reading; templates keep the exact audited
// amount available through formatUSD.
func formatCost(microunits int64) string {
	switch {
	case microunits <= 0:
		return "$0.00"
	case microunits < 10_000:
		return "<$0.01"
	default:
		return fmt.Sprintf("$%.2f", float64(microunits)/1_000_000)
	}
}

func formatCount(value int64) string {
	digits := strconv.FormatInt(value, 10)
	negative := strings.HasPrefix(digits, "-")
	digits = strings.TrimPrefix(digits, "-")
	var grouped strings.Builder
	for index, digit := range digits {
		if index > 0 && (len(digits)-index)%3 == 0 {
			grouped.WriteByte(',')
		}
		grouped.WriteRune(digit)
	}
	if negative {
		return "-" + grouped.String()
	}
	return grouped.String()
}

// statusClass maps workflow, evidence, and payload status words onto the same
// palette as operational states. Unrecognized or in-progress statuses stay
// neutral instead of borrowing a health color.
func statusClass(status string) string {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "COMPLETED", "COMPLETE", "SUCCEEDED", "AVAILABLE", "RESOLVED":
		return "healthy"
	case "PARTIAL", "BLOCKED", "DEGRADED", "STALE":
		return "degraded"
	case "FAILED", "CANCELLED", "UNAVAILABLE", "REJECTED", "EXPIRED":
		return "unavailable"
	case "NO_DATA", "NOT_RECORDED":
		return "no-data"
	default:
		return "neutral"
	}
}

func severityClass(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL", "HIGH":
		return "unavailable"
	case "MEDIUM", "WARNING":
		return "degraded"
	default:
		return "neutral"
	}
}
