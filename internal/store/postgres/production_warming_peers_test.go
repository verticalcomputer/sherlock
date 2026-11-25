package postgres

import (
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
)

func peerTarget(seconds, temp, watts float64) [4]*float64 {
	return [4]*float64{&seconds, &temp, &watts, nil}
}

func TestComparablePeersNearestPairedReading(t *testing.T) {
	at := time.Unix(1200, 0).UTC()
	context := cooling.WarmingContext{Rows: [][4]*float64{peerTarget(-121, 74, 600), peerTarget(-15, 76, 650), peerTarget(2, 74, 600)}}
	offset := func(s int) time.Time { return at.Add(time.Duration(s) * time.Second) }
	readings := []peerReading{
		{"a", offset(-16), 58, 625}, {"a", offset(-20), 55, 640},
		{"b", offset(-17), 65, 675}, {"b", offset(-13), 63, 675},
		{"c", offset(-15), 60, 600}, {"c", offset(-18), 60, 640},
		{"d", offset(-31), 90, 650}, {"e", offset(1), 150, 650},
	}
	got := summarizeSuspectedPeers(at, context, readings)
	if got.Status != "available" || got.DistinctPeers != 2 || len(got.Rows) != 1 {
		t.Fatalf("peer scope: %+v", got)
	}
	row := got.Rows[0]
	if row.Peers != 2 || row.MedianC != 61.5 || row.MaxC != 65 || row.TargetC != 76 || row.SecondsBeforeOpen != 15 {
		t.Fatalf("wrong peer aggregation: %+v", row)
	}
}
