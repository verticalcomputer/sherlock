package domain

import (
	"fmt"
	"time"
)

// MaxDurableSchedulerSnapshotKeys bounds explicit durable schedule enrollment
// for snapshot views. The policy is explicit enrollment with a hard cap: there
// is no overflow bucket, and snapshot data must never register additional
// labels.
const MaxDurableSchedulerSnapshotKeys = 64

// DurableSchedulerSnapshotRow is one schedule's durable state at the snapshot
// observation time. NextDue is the stored next-due timestamp,
// CoalescedIntervals is the durable cumulative coalesced-interval count and
// DroppedIntervals counts admitted periodic occurrences that terminated
// before their first claim, projected from retained occurrence/work records.
type DurableSchedulerSnapshotRow struct {
	Key                ScheduleKey
	NextDue            time.Time
	CoalescedIntervals int64
	DroppedIntervals   int64
}

// DurableSchedulerSnapshot is a complete replacement view of durable schedule
// state. Rows absent from a later snapshot stop being exported.
type DurableSchedulerSnapshot struct {
	ObservedAt time.Time
	Rows       []DurableSchedulerSnapshotRow
}

// ValidateDurableSchedulerSnapshotKeys checks an explicit schedule enrollment
// before any database read. Empty enrollment is valid. Keys must be complete,
// reference reviewed operations and contain no duplicates.
func ValidateDurableSchedulerSnapshotKeys(keys []ScheduleKey) error {
	if len(keys) > MaxDurableSchedulerSnapshotKeys {
		return fmt.Errorf("durable scheduler snapshot allow-list exceeds %d schedule keys", MaxDurableSchedulerSnapshotKeys)
	}
	seen := make(map[ScheduleKey]struct{}, len(keys))
	for _, key := range keys {
		if key.ClusterID == "" || key.SourceID == "" || key.Operation == "" {
			return fmt.Errorf("durable scheduler snapshot schedule identity is incomplete")
		}
		if _, ok := ReviewedCollectionOperation(key.Operation); !ok {
			return fmt.Errorf("durable scheduler snapshot operation %q is not reviewed", key.Operation)
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate durable scheduler snapshot schedule identity")
		}
		seen[key] = struct{}{}
	}
	return nil
}
