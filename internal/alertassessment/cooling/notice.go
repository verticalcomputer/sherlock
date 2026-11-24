package cooling

import (
	"fmt"
	"strings"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

// WarmingNotice describes the recorded entry and deadline for an inconclusive assessment.
func WarmingNotice(d a.Decision, initial a.Payload) string {
	if d.Outcome != CategoryID+"/UNRESOLVED_WARMING" {
		return ""
	}
	lines := []string{"Investigate warming · cause unconfirmed"}
	s, err := decodePayload[State](initial, "candidate", stateLimit)
	if err == nil && s.Reference != nil && s.EntryEndpoint != nil {
		elapsed := s.EntryEndpoint.SourceAt.Sub(s.Reference.SourceAt)
		if elapsed > 0 {
			lines = append(lines, fmt.Sprintf("Temperature trend: %g → %g °C over %s", s.Reference.Value, s.EntryEndpoint.Value, elapsed.Round(time.Second)))
		}
	}
	if d.TerminalEndpoint != nil {
		lines = append(lines, fmt.Sprintf("Latest temperature: %g °C (%s UTC)", d.TerminalEndpoint.Value, d.TerminalEndpoint.SourceAt.UTC().Format("15:04:05")))
	}
	return strings.Join(append(lines, "Observation ended before Sherlock could confirm sustained warming at stable power or a return to the settling range."), "\n")
}
