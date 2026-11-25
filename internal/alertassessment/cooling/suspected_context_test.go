package cooling

import (
	"testing"
	"time"
)

func TestSuspectedReviewBelowThresholdAndReceiptFence(t *testing.T) {
	anchor := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	var samples []WarmingSample
	for n := -600; n <= 0; n += 15 {
		at := anchor.Add(time.Duration(n) * time.Second)
		temp := 55.
		if n == -300 {
			temp = 45
		}
		samples = append(samples, WarmingSample{Temperature, temp, at, at}, WarmingSample{Power, 575, at, at})
	}
	// A conflicting receipt arrives after the original decision.
	samples = append(samples, WarmingSample{Power, 100, anchor, anchor.Add(time.Minute)})
	c, ok := SuspectedWarmingContext(samples, nil, anchor, anchor, time.Time{})
	if !ok || c.EndpointC != 55 || c.ComparableLoad == nil || c.ComparableLoad.MedianC != 55 || c.ReviewPowerW == nil || *c.ReviewPowerW != 575 || c.Rows[len(c.Rows)-1][3] != nil {
		t.Fatalf("incorrect initial review: %+v", c)
	}
	if _, ok := SuspectedWarmingContext(samples, nil, anchor, anchor, c.EndpointAt); ok {
		t.Fatal("duplicate review")
	}
	if _, ok := SuspectedWarmingContext(samples, nil, anchor, anchor.Add(time.Minute), time.Time{}); ok {
		t.Fatal("stale endpoint")
	}
	if _, ok := SuspectedWarmingContext(samples, []WarmingNegative{{Metric: Temperature, From: anchor, Through: anchor, AvailableAt: anchor}}, anchor, anchor, time.Time{}); ok {
		t.Fatal("reviewed invalid latest reading")
	}
}

func TestSuspectedReviewAfterLoadStep(t *testing.T) {
	anchor := time.Now().UTC()
	var samples []WarmingSample
	for n := -600; n <= 0; n += 15 {
		w, temp := 140., 55.
		if n >= -90 {
			w, temp = 650, 77
		}
		at := anchor.Add(time.Duration(n) * time.Second)
		samples = append(samples, WarmingSample{Temperature, temp, at, at}, WarmingSample{Power, w, at, at})
	}
	c, ok := SuspectedWarmingContext(samples, nil, anchor, anchor, time.Time{})
	if !ok || c.ComparableLoad != nil || c.ReviewPowerW == nil || *c.ReviewPowerW != 650 {
		t.Fatalf("idle measurements used as loaded reference: %+v", c)
	}
}

func TestSuspectedLateCorrectionWithdrawsOpenComparison(t *testing.T) {
	a := time.Now().UTC()
	var entry []WarmingSample
	for n := -150; n <= 0; n += 15 {
		at := a.Add(time.Duration(n) * time.Second)
		w := 500.
		if n == 0 {
			w = 650
		}
		entry = append(entry, WarmingSample{Temperature, 65, at, at}, WarmingSample{Power, w, at, at})
	}
	live := append(append([]WarmingSample(nil), entry...), WarmingSample{Power, 500, a, a.Add(time.Second)})
	c, ok := SuspectedWarmingContextFromEvidence(entry, nil, live, nil, a, a.Add(2*time.Second), time.Time{})
	if !ok || c.ReviewPowerW != nil || c.ComparableLoad != nil {
		t.Fatal("contradicted OPEN power should withdraw historical band")
	}
	if len(c.OpenPeerRows) == 0 {
		t.Fatal("missing unaffected peer target rows")
	}
	for _, r := range c.OpenPeerRows {
		if *r[0] == 0 {
			t.Fatal("contradicted target still in peer comparison")
		}
	}
}
