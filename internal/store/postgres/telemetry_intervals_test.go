package postgres

import (
	"errors"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func TestTelemetryIntervalsPreserveHolesAndUint64(t *testing.T) {
	sources := []telemetry.SourceGrant{{SourceID: "source-a"}, {SourceID: "source-b"}}
	all := []telemetryInterval{{kind: "RECEIVED", from: 2, through: 3}}
	if telemetryCovered(all, sources, 3) {
		t.Fatal("highest sequence filled missing first sequence")
	}
	all = append(all, telemetryInterval{kind: "LOST", source: "source-a", from: 1, through: 1})
	if telemetryCovered(all, sources, 3) {
		t.Fatal("one source loss filled another source gap")
	}
	all = append(all, telemetryInterval{kind: "LOST", source: "source-b", from: 1, through: 1})
	if !telemetryCovered(all, sources, 3) {
		t.Fatal("complete explicit received/lost coverage not recognized")
	}
	maximum := ^uint64(0)
	merged, err := mergeTelemetryInterval([]telemetryInterval{{kind: "RECEIVED", from: maximum, through: maximum}}, telemetryInterval{kind: "RECEIVED", from: 1, through: 1})
	if err != nil || len(merged) != 2 {
		t.Fatal("uint64 overflow merged disjoint endpoints", err)
	}
	if value, err := telemetryU64("18446744073709551615"); err != nil || value != maximum {
		t.Fatal("exact uint64 rejected")
	}
	for _, invalid := range []string{"01", "18446744073709551616", "-1", "1.0"} {
		if _, err := telemetryU64(invalid); !errors.Is(err, telemetry.ErrInvalid) {
			t.Fatal("invalid decimal accepted")
		}
	}
}
func TestTelemetryIntervalFragmentationBackpressure(t *testing.T) {
	var all []telemetryInterval
	for i := uint64(0); i < 256; i++ {
		all = append(all, telemetryInterval{kind: "RECEIVED", from: i*2 + 1, through: i*2 + 1})
	}
	if _, err := mergeTelemetryInterval(all, telemetryInterval{kind: "RECEIVED", from: 1024, through: 1024}); !errors.Is(err, telemetry.ErrBackpressure) {
		t.Fatal("fragmentation cap not enforced")
	}
	merged, err := mergeTelemetryInterval(all, telemetryInterval{kind: "RECEIVED", from: 2, through: 510})
	if err != nil || len(merged) != 1 || merged[0].through != 511 {
		t.Fatal("hole fills cannot compact bounded ledger", err)
	}
}
