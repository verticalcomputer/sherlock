package cooling

import (
	"math"
	"sort"
	"time"
)

const comparablePowerBandW = 25

// WarmingReference describes the observed load band and temperature of the
// same GPU before its dip, or before entry for an undipped sustained rise.
// The time bounds describe contributing observations, relative to entry.
type WarmingReference struct {
	Start   float64 `json:"start"`
	Through float64 `json:"through"`
	MedianC float64 `json:"median_c"`
	PowerW  float64 `json:"power_w"`
	Samples int     `json:"samples"`
}

// ConfirmedComparableWarming checks all nonurgent warming branches against
// the same load. Reference selection can only use facts already available at
// entry; a late invalidation may veto the reference, never train a new one.
// When a comparable reference exists but confirmation fails, the returned
// context can be used for audit, never to request inference.
func ConfirmedComparableWarming(samples []WarmingSample, anchor, asOf, lastCall time.Time, negatives ...WarmingNegative) (WarmingContext, bool) {
	return ConfirmedComparableWarmingFromEvidence(samples, negatives, samples, anchor, anchor, asOf, lastCall, negatives...)
}

// ConfirmedComparableWarmingFromEvidence uses the entry record to reproduce
// the original baseline even after the live working set rotates. All currently
// visible facts (including entry facts) can invalidate that frozen reference.
func ConfirmedComparableWarmingFromEvidence(entry []WarmingSample, entryNegatives []WarmingNegative, samples []WarmingSample, anchor, entryKnownAt, asOf, lastCall time.Time, negatives ...WarmingNegative) (WarmingContext, bool) {
	if anchor.IsZero() || entryKnownAt.Before(anchor) || entryKnownAt.After(asOf) {
		return WarmingContext{}, false
	}
	ref, at, ok := preWarmingLoad(entry, anchor, entryKnownAt, entryNegatives)
	if !ok {
		return WarmingContext{}, false
	}
	return confirmWarming(samples, at, ref.MedianC, anchor, asOf, lastCall, &ref, negatives)
}

func preWarmingLoad(samples []WarmingSample, anchor, entryKnownAt time.Time, negatives []WarmingNegative) (WarmingReference, time.Time, bool) {
	byTime, times, unknown := warmingMeasurements(samples, negatives, anchor.Add(-15*time.Minute), entryKnownAt)
	var powers, temps []point
	for _, t := range times {
		row := byTime[t]
		if !t.Before(anchor) || row[1] == nil || row[2] == nil || unknown[1].intersects(t, t) || unknown[2].intersects(t, t) {
			continue
		}
		powers = append(powers, point{at: t, value: *row[2]})
		temps = append(temps, point{at: t, value: *row[1]})
	}
	// Locate the start of a large drop against the preceding two minutes of
	// loaded operation. Successive low samples are part of the same dip.
	var dip, restored, previousRestore time.Time
	var loadedW float64
	for i, p := range powers {
		j := sort.Search(i, func(j int) bool { return !powers[j].at.Before(p.at.Add(-2 * time.Minute)) })
		if !dip.IsZero() && restored.IsZero() {
			if p.value >= loadedW-comparablePowerBandW {
				restored = p.at
			} else {
				continue
			}
		}
		if i-j >= 6 {
			center := median(powers[j:i])
			if p.value < 0.5*center {
				previousRestore = restored
				dip, loadedW, restored = p.at, center, time.Time{}
			}
		}
	}
	end := anchor
	// Once a full reference window follows restoration, use the more recent load.
	if !dip.IsZero() && (restored.IsZero() || anchor.Sub(restored) < 5*time.Minute) {
		end = dip
	}
	start := end.Add(-5 * time.Minute)
	if end.Equal(dip) && previousRestore.After(start) {
		start = previousRestore
	}
	first := sort.Search(len(powers), func(i int) bool { return !powers[i].at.Before(start) })
	last := sort.Search(len(powers), func(i int) bool { return !powers[i].at.Before(end) })
	if last-first < 5 {
		return WarmingReference{}, time.Time{}, false
	}
	center := median(powers[first:last])
	var matched []point
	for i := first; i < last; i++ {
		if math.Abs(powers[i].value-center) <= comparablePowerBandW {
			matched = append(matched, temps[i])
		}
	}
	if len(matched) < 5 {
		return WarmingReference{}, time.Time{}, false
	}
	from, through := matched[0].at, matched[len(matched)-1].at
	if through.Sub(from) < time.Minute || end.Sub(through) > time.Minute {
		return WarmingReference{}, time.Time{}, false
	}
	at := from.Add(through.Sub(from) / 2)
	return WarmingReference{Start: from.Sub(anchor).Seconds(), Through: through.Sub(anchor).Seconds(), MedianC: median(matched), PowerW: center, Samples: len(matched)}, at, true
}
