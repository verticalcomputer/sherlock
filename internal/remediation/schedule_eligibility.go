package remediation

import "time"

// ScheduleFacts describes one authoritative job snapshot. Unknown facts remain
// ineligible; source availability alone is not proof of working collection.
type ScheduleFacts struct {
	Now                time.Time
	Active             bool
	Interval           time.Duration
	NextRun            time.Time
	LeaseUntil         time.Time
	ActiveWork         bool
	SourceAvailable    bool
	SourceCheckedAt    time.Time
	CollectorAvailable bool
	CollectorHeartbeat time.Time
	InventoryCount     int
	LastRunSucceeded   bool
	LastRunComplete    bool
	ExpectedSeries     int
	ReturnedSeries     int
	LastSample         time.Time
	LastCompleted      time.Time
}

type ScheduleEligibility string

const (
	ScheduleEligible             ScheduleEligibility = "SCHEDULE_DISPATCH_GAP"
	ScheduleUnknown              ScheduleEligibility = "SCHEDULE_FACTS_UNKNOWN"
	ScheduleDisabled             ScheduleEligibility = "STREAM_DISABLED"
	ScheduleBusy                 ScheduleEligibility = "COLLECTION_ACTIVE"
	ScheduleSourceUnavailable    ScheduleEligibility = "SOURCE_UNAVAILABLE"
	ScheduleCollectorUnavailable ScheduleEligibility = "COLLECTOR_UNAVAILABLE"
	ScheduleInventoryMissing     ScheduleEligibility = "INVENTORY_MISSING"
	ScheduleCoverageIncomplete   ScheduleEligibility = "COVERAGE_INCOMPLETE"
	ScheduleCollectionFailed     ScheduleEligibility = "COLLECTION_FAILED"
	ScheduleFresh                ScheduleEligibility = "STREAM_FRESH"
	ScheduleNormallyDue          ScheduleEligibility = "NORMAL_SCHEDULER_DUE"
)

// EvaluateScheduleRepair deliberately admits only a demonstrable future
// scheduling gap: a previously complete stream is stale by three cadences,
// yet its next run is more than one cadence away. An ordinarily due job is left
// to its scheduler; a failed source is never relabeled as a scheduling defect.
func EvaluateScheduleRepair(f ScheduleFacts) ScheduleEligibility {
	if f.Now.IsZero() || f.Interval < time.Second || f.Interval > 24*time.Hour || f.NextRun.IsZero() {
		return ScheduleUnknown
	}
	if !f.Active {
		return ScheduleDisabled
	}
	if f.LeaseUntil.After(f.Now) || f.ActiveWork {
		return ScheduleBusy
	}
	if !recentScheduleFact(f.SourceCheckedAt, f.Now) || !f.SourceAvailable {
		return ScheduleSourceUnavailable
	}
	if !recentScheduleFact(f.CollectorHeartbeat, f.Now) || !f.CollectorAvailable {
		return ScheduleCollectorUnavailable
	}
	if f.InventoryCount <= 0 {
		return ScheduleInventoryMissing
	}
	if !f.LastRunSucceeded {
		return ScheduleCollectionFailed
	}
	if !f.LastRunComplete || f.ExpectedSeries <= 0 || f.ReturnedSeries != f.ExpectedSeries {
		return ScheduleCoverageIncomplete
	}
	if f.LastSample.IsZero() || f.LastCompleted.Before(f.LastSample) || f.LastCompleted.After(f.Now) {
		return ScheduleUnknown
	}
	if f.Now.Sub(f.LastSample) <= 3*f.Interval {
		return ScheduleFresh
	}
	if !f.NextRun.After(f.Now.Add(f.Interval)) {
		return ScheduleNormallyDue
	}
	return ScheduleEligible
}

func recentScheduleFact(observed, now time.Time) bool {
	return !observed.IsZero() && !observed.After(now) && now.Sub(observed) <= 2*time.Minute
}
