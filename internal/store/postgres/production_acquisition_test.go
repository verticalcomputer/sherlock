package postgres

import (
	"testing"
	"time"
)

func TestProductionReceiptAdmissionClock(t *testing.T) {
	checkpoint := time.Unix(1700000000, 0).UTC()
	received := checkpoint.Add(12 * time.Second)
	polled := checkpoint.Add(30 * time.Second)
	for _, tc := range []struct {
		name                             string
		checkpoint, received, completed  time.Time
		receiptWriter, observationWriter string
		correction                       bool
		want                             time.Time
	}{
		{"original atomic report", checkpoint, received, checkpoint, "123", "123", false, received},
		{"new row behind checkpoint", checkpoint, checkpoint.Add(-time.Second), checkpoint.Add(-time.Minute), "123", "123", false, polled},
		{"receipt at checkpoint", checkpoint, checkpoint, checkpoint, "123", "123", false, polled},
		{"receipt from later transaction", checkpoint, received, checkpoint, "", "123", false, polled},
		{"observation from later transaction", checkpoint, received, checkpoint, "123", "124", false, polled},
		{"changed already-admitted sample", checkpoint, received, checkpoint, "123", "123", true, polled},
		{"receipt before completion", checkpoint, received, received.Add(time.Second), "123", "123", false, polled},
		{"no proven lower bound", time.Time{}, received, checkpoint, "123", "123", false, polled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempt := assessmentAttempt{received: tc.received, completed: tc.completed, uploadWriter: tc.receiptWriter}
			got := productionSampleAdmission(attempt, tc.observationWriter, tc.correction, tc.checkpoint, polled)
			if !got.Equal(tc.want) {
				t.Fatalf("admission = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestProductionCoolingAcquisitionPhases(t *testing.T) {
	start := time.Unix(1800000000, 0).UTC()
	const assets = 8
	for rank := 0; rank < assets; rank++ {
		if !productionAcquisitionDue(start, nil, rank, assets) {
			t.Fatal("unclaimed asset skipped")
		}
		last := start.Add(-time.Second)
		claims := 0
		for second := 0; second < 60; second++ {
			now := start.Add(time.Duration(second) * time.Second)
			if productionAcquisitionDue(now, &last, rank, assets) {
				if second%30 != rank*30/assets {
					t.Fatalf("rank %d claimed at %s", rank, now)
				}
				last = now
				claims++
				if productionAcquisitionDue(now, &last, rank, assets) {
					t.Fatal("duplicate claim in same phase")
				}
			}
		}
		if claims != 2 {
			t.Fatalf("rank %d claimed %d times", rank, claims)
		}
	}
}
