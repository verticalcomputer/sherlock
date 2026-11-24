package cooling

import (
	"strings"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

func TestWarmingNotice(t *testing.T) {
	at := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	entry, err := payload("candidate", State{Schema: 1, Reference: &a.FeatureRef{Value: 48, SourceAt: at}, EntryEndpoint: &a.FeatureRef{Value: 54, SourceAt: at.Add(10 * time.Minute)}})
	if err != nil {
		t.Fatal(err)
	}
	decision := a.Decision{Outcome: CategoryID + "/UNRESOLVED_WARMING", TerminalEndpoint: &a.FeatureRef{Value: 53, SourceAt: at.Add(12 * time.Minute)}}
	msg := WarmingNotice(decision, *entry)
	for _, want := range []string{"cause unconfirmed", "48 → 54 °C over 10m0s", "53 °C (12:12:00 UTC)"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("missing %q from %s", want, msg)
		}
	}
	if strings.Contains(WarmingNotice(decision, a.Payload{}), "Temperature trend:") {
		t.Fatal("missing reference displayed as measurement")
	}
	decision.Outcome = CategoryID + "/TRANSIENT_SUPPORTED"
	if WarmingNotice(decision, *entry) != "" {
		t.Fatal("unrelated decision used warming notice")
	}
}
