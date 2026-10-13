package collectorcontrol

import (
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestHeartbeatProtocolRangePreservesV1AndRejectsUnknownRanges(t *testing.T) {
	now := time.Now().UTC()
	report := Heartbeat{CollectorID: "collector-1", Version: "test", ReportedAt: now, Capabilities: []CapabilityReport{{Name: string(domain.QueryGPUXID), Version: "1"}}}
	for _, test := range []struct {
		minimum, maximum int
		valid            bool
	}{{0, 0, true}, {1, 1, true}, {1, 2, true}, {2, 2, true}, {0, 2, false}, {1, 0, false}, {2, 1, false}, {1, 3, false}, {-1, 2, false}} {
		report.ProtocolMin, report.ProtocolMax = test.minimum, test.maximum
		if err := ValidateHeartbeat(report, now); (err == nil) != test.valid {
			t.Fatalf("range %d-%d validity %t: %v", test.minimum, test.maximum, test.valid, err)
		}
	}
	report.ProtocolMin, report.ProtocolMax = 0, 0
	if min, max := report.ProtocolRange(); min != 1 || max != 1 {
		t.Fatalf("legacy range=%d-%d", min, max)
	}
}
