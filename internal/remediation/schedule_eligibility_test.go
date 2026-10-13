package remediation

import (
	"testing"
	"time"
)

func TestScheduleRepairRequiresDemonstrableGap(t *testing.T) {
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	base := ScheduleFacts{Now: now, Active: true, Interval: time.Minute, NextRun: now.Add(time.Hour), SourceAvailable: true, SourceCheckedAt: now, CollectorAvailable: true, CollectorHeartbeat: now, InventoryCount: 1, LastRunSucceeded: true, LastRunComplete: true, ExpectedSeries: 1, ReturnedSeries: 1, LastSample: now.Add(-4 * time.Minute), LastCompleted: now.Add(-4 * time.Minute)}
	cases := []struct {
		name  string
		alter func(*ScheduleFacts)
		want  ScheduleEligibility
	}{
		{"gap", func(*ScheduleFacts) {}, ScheduleEligible},
		{"disabled", func(f *ScheduleFacts) { f.Active = false }, ScheduleDisabled},
		{"leased", func(f *ScheduleFacts) { f.LeaseUntil = now.Add(time.Second) }, ScheduleBusy},
		{"queued", func(f *ScheduleFacts) { f.ActiveWork = true }, ScheduleBusy},
		{"source", func(f *ScheduleFacts) { f.SourceAvailable = false }, ScheduleSourceUnavailable},
		{"collector", func(f *ScheduleFacts) { f.CollectorHeartbeat = now.Add(-3 * time.Minute) }, ScheduleCollectorUnavailable},
		{"future health", func(f *ScheduleFacts) { f.SourceCheckedAt = now.Add(time.Second) }, ScheduleSourceUnavailable},
		{"inventory", func(f *ScheduleFacts) { f.InventoryCount = 0 }, ScheduleInventoryMissing},
		{"failed", func(f *ScheduleFacts) { f.LastRunSucceeded = false }, ScheduleCollectionFailed},
		{"incomplete", func(f *ScheduleFacts) { f.LastRunComplete = false }, ScheduleCoverageIncomplete},
		{"missing series", func(f *ScheduleFacts) { f.ReturnedSeries = 0 }, ScheduleCoverageIncomplete},
		{"unknown coverage", func(f *ScheduleFacts) { f.ExpectedSeries = 0 }, ScheduleCoverageIncomplete},
		{"future completion", func(f *ScheduleFacts) { f.LastCompleted = now.Add(time.Second) }, ScheduleUnknown},
		{"future sample", func(f *ScheduleFacts) { f.LastSample = now.Add(time.Second) }, ScheduleUnknown},
		{"fresh boundary", func(f *ScheduleFacts) { f.LastSample = now.Add(-3 * time.Minute); f.LastCompleted = now }, ScheduleFresh},
		{"normally due", func(f *ScheduleFacts) { f.NextRun = now.Add(-time.Hour) }, ScheduleNormallyDue},
		{"cadence boundary", func(f *ScheduleFacts) { f.NextRun = now.Add(time.Minute) }, ScheduleNormallyDue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := base
			tc.alter(&f)
			if got := EvaluateScheduleRepair(f); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}
