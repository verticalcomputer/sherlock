package cooling

import (
	"math"
	"time"
)

// SuspectedWarmingContext reviews an already-qualified category decision. The
// local load reference is anchored to information available at the OPEN.
func SuspectedWarmingContext(samples []WarmingSample, negatives []WarmingNegative, anchor, asOf, last time.Time) (WarmingContext, bool) {
	return SuspectedWarmingContextFromEvidence(samples, negatives, samples, negatives, anchor, asOf, last)
}

// SuspectedWarmingContextFromEvidence never uses newly discovered rows to train
// the original load comparison. Later conflicts can withdraw its evidence.
func SuspectedWarmingContextFromEvidence(entry []WarmingSample, entryNegatives []WarmingNegative, samples []WarmingSample, negatives []WarmingNegative, anchor, asOf, last time.Time) (WarmingContext, bool) {
	c := WarmingContext{ReviewKind: "cooling_suspected"}
	if anchor.IsZero() || asOf.Before(anchor) || asOf.Sub(anchor) > 10*time.Minute+45*time.Second {
		return c, false
	}
	c.Now = asOf.Sub(anchor).Seconds()
	start := anchor.Add(-15 * time.Minute)
	by, times, gaps := warmingMeasurements(samples, negatives, start, asOf)
	for col, metric := range []string{"", Temperature, Power, Utilization} {
		for _, g := range gaps[col] {
			c.UnknownIntervals = append(c.UnknownIntervals, WarmingUnknownInterval{metric, g.from.Sub(anchor).Seconds(), g.through.Sub(anchor).Seconds()})
		}
	}
	for _, t := range times {
		row := by[t]
		for i, v := range row {
			if v != nil && (math.IsNaN(*v) || gaps[i].intersects(t, t)) {
				row[i] = nil
			}
		}
		sec := t.Sub(anchor).Seconds()
		row[0] = &sec
		c.Rows = append(c.Rows, row)
		if row[1] != nil {
			c.EndpointC = *row[1]
			c.EndpointAt = t
		}
	}
	c.QualifiedSinceAt = anchor
	if c.EndpointAt.IsZero() || asOf.Sub(c.EndpointAt) > 45*time.Second || gaps[1].intersects(c.EndpointAt, asOf) || (!last.IsZero() && c.EndpointAt.Sub(last) < time.Minute) {
		return c, false
	}

	openRows, openTimes, openGaps := warmingMeasurements(entry, entryNegatives, start, anchor)
	// Match only time-aligned measurements; an idle interval does not supply
	// a loaded reference. Exclude the recent two minutes containing the OPEN.
	for i := len(openTimes) - 1; i >= 0; i-- {
		at := openTimes[i]
		if anchor.Sub(at) > 45*time.Second {
			break
		}
		r := openRows[at]
		if r[1] != nil && r[2] != nil && !openGaps[1].intersects(at, at) && !openGaps[2].intersects(at, at) && *r[2] > 0 && *r[2] <= 2000 {
			if !gaps[2].intersects(at, at) && !gaps[1].intersects(at, at) {
				w := *r[2]
				c.ReviewPowerW = &w
			}
			break
		}
	}
	for _, at := range openTimes {
		if anchor.Sub(at) > 2*time.Minute {
			continue
		}
		row := openRows[at]
		if row[1] == nil || row[2] == nil || gaps[1].intersects(at, at) || gaps[2].intersects(at, at) || openGaps[1].intersects(at, at) || openGaps[2].intersects(at, at) {
			continue
		}
		sec := at.Sub(anchor).Seconds()
		row[0] = &sec
		c.OpenPeerRows = append(c.OpenPeerRows, row)
	}
	if c.ReviewPowerW != nil {
		var matched []point
		for _, at := range openTimes {
			if anchor.Sub(at) < 2*time.Minute {
				break
			}
			row := openRows[at]
			if row[1] == nil || row[2] == nil || math.IsNaN(*row[1]) || math.IsNaN(*row[2]) || gaps[1].intersects(at, at) || gaps[2].intersects(at, at) || math.Abs(*row[2]-*c.ReviewPowerW) > comparablePowerBandW {
				continue
			}
			matched = append(matched, point{at: at, value: *row[1]})
		}
		if len(matched) >= 5 && matched[len(matched)-1].at.Sub(matched[0].at) >= time.Minute {
			c.ReferenceC = median(matched)
			from := matched[0].at.Sub(anchor).Seconds()
			to := matched[len(matched)-1].at.Sub(anchor).Seconds()
			c.ComparableLoad = &WarmingReference{Start: from, Through: to, MedianC: c.ReferenceC, PowerW: *c.ReviewPowerW, Samples: len(matched)}
			c.ReferenceTime = (from + to) / 2
		}
	}
	c.JointPowerUtil = warmingPlateaus(c.Rows, times, gaps, []int{2, 3}, []float64{25, 5}, 60)
	c.PowerOnly = warmingPlateaus(c.Rows, times, gaps, []int{2}, []float64{25}, 60)
	c.TemperaturePlateaus = warmingPlateaus(c.Rows, times, gaps, []int{1}, []float64{1}, 45)
	return c, true
}
