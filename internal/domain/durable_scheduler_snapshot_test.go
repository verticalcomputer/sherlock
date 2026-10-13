package domain

import (
	"strings"
	"testing"
)

func TestValidateDurableSchedulerSnapshotKeys(t *testing.T) {
	valid := ScheduleKey{ClusterID: "c1", SourceID: "s1", Operation: OperationPrometheusGPUUtilization}
	if err := ValidateDurableSchedulerSnapshotKeys(nil); err != nil {
		t.Fatalf("empty enrollment rejected: %v", err)
	}
	if err := ValidateDurableSchedulerSnapshotKeys([]ScheduleKey{valid}); err != nil {
		t.Fatalf("valid enrollment rejected: %v", err)
	}
	cases := map[string][]ScheduleKey{
		"duplicate keys":    {valid, valid},
		"empty cluster":     {{SourceID: "s1", Operation: OperationPrometheusGPUUtilization}},
		"empty source":      {{ClusterID: "c1", Operation: OperationPrometheusGPUUtilization}},
		"empty operation":   {{ClusterID: "c1", SourceID: "s1"}},
		"unknown operation": {{ClusterID: "c1", SourceID: "s1", Operation: "example.unreviewed.v9"}},
	}
	for name, keys := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateDurableSchedulerSnapshotKeys(keys); err == nil {
				t.Fatal("expected enrollment rejection")
			}
		})
	}
}

func TestValidateDurableSchedulerSnapshotKeysRejectsOverLimit(t *testing.T) {
	keys := make([]ScheduleKey, 0, MaxDurableSchedulerSnapshotKeys+1)
	for i := 0; i <= MaxDurableSchedulerSnapshotKeys; i++ {
		keys = append(keys, ScheduleKey{
			ClusterID: ClusterID(strings.Repeat("c", i+1)),
			SourceID:  "s1",
			Operation: OperationPrometheusGPUUtilization,
		})
	}
	if err := ValidateDurableSchedulerSnapshotKeys(keys); err == nil {
		t.Fatal("expected over-limit enrollment rejection")
	}
	if err := ValidateDurableSchedulerSnapshotKeys(keys[:MaxDurableSchedulerSnapshotKeys]); err != nil {
		t.Fatalf("boundary enrollment rejected: %v", err)
	}
}
