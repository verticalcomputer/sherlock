package postgres

import (
	"slices"
	"testing"
	"time"
)

func TestSlurmCorrelationDoesNotUseUnionOfUnrelatedAttemptWindows(t *testing.T) {
	at := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	windows := []slurmAttemptWindow{{AttemptKey: "earlier-attempt", Nodes: []string{"node-1"}, Start: at.Add(-30 * time.Minute), End: at.Add(-20 * time.Minute)}, {AttemptKey: "later-attempt", Nodes: []string{"node-2"}, Start: at.Add(-5 * time.Minute), End: at}}
	for _, test := range []struct {
		name, node string
		at         time.Time
		want       []string
	}{
		{"exact earlier node", "node-1", at.Add(-25 * time.Minute), []string{"earlier-attempt"}},
		{"exact later node", "node-2", at.Add(-time.Minute), []string{"later-attempt"}},
		{"same cluster wrong attempt node", "node-1", at.Add(-time.Minute), []string{}},
		{"same cluster wrong attempt time", "node-2", at.Add(-25 * time.Minute), []string{}},
		{"foreign node", "node-3", at, []string{}},
		{"after recorded window", "node-2", at.Add(time.Second), []string{}},
		{"inclusive window boundary", "node-1", at.Add(-20 * time.Minute), []string{"earlier-attempt"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := matchingSlurmAttempts(windows, test.node, test.at); !slices.Equal(got, test.want) {
				t.Fatalf("observation attributed to wrong attempt: %v want %v", got, test.want)
			}
		})
	}
}
