package cooling

import (
	"math"
	"slices"
	"time"
)

// WarmingSample is one measurement for the candidate GPU. AvailableAt is when
// Sherlock could first use it, which may be later than the sensor timestamp.
type WarmingSample struct {
	Metric                string
	Value                 float64
	SourceAt, AvailableAt time.Time
}

type WarmingPlateau struct {
	Start   float64   `json:"start"`
	Through float64   `json:"through"`
	Median  []float64 `json:"median"`
}

// WarmingContext contains only relative times and numeric measurements.
// Rows are [seconds since the initial crossing, degrees C, watts, percent];
// missing measurements remain JSON null, including unavailable utilization.
type WarmingContext struct {
	EndpointC           float64          `json:"-"`
	EndpointAt          time.Time        `json:"-"`
	Now                 float64          `json:"now"`
	ReferenceTime       float64          `json:"reference_time"`
	ReferenceC          float64          `json:"reference_c"`
	Rows                [][4]*float64    `json:"rows"`
	JointPowerUtil      []WarmingPlateau `json:"joint_power_util_plateaus"`
	PowerOnly           []WarmingPlateau `json:"power_only_plateaus"`
	TemperaturePlateaus []WarmingPlateau `json:"temperature_plateaus"`
}

// ConfirmedWarming checks the latest source endpoint. The caller fixes the
// reference and anchor for the episode and persists EndpointAt for each call.
// A broken crossing must independently qualify again. Repeated polls cannot
// turn old measurements into confirmation.
func ConfirmedWarming(samples []WarmingSample, referenceAt time.Time, referenceC float64, anchor, asOf, lastCall time.Time) (WarmingContext, bool) {
	if referenceAt.IsZero() || anchor.IsZero() || referenceAt.After(anchor) || anchor.After(asOf) || !validSampleValue(Temperature, referenceC) {
		return WarmingContext{}, false
	}
	start := referenceAt.Add(-225 * time.Second)
	byTime := map[time.Time][4]*float64{}
	for _, s := range samples {
		t := s.SourceAt.UTC()
		if t.Before(start) || t.After(asOf) || s.AvailableAt.IsZero() || s.AvailableAt.After(asOf) {
			continue
		}
		var col int
		switch s.Metric {
		case Temperature:
			col = 1
		case Power:
			col = 2
		case Utilization:
			col = 3
		default:
			continue
		}
		value := s.Value
		row := byTime[t]
		if !validSampleValue(s.Metric, value) || (col == 3 && (value < 0 || value > 100)) || (row[col] != nil && *row[col] != value) {
			// Keep a conflicting or invalid measurement unknown regardless of input order.
			value = math.NaN()
		}
		row[col] = &value
		byTime[t] = row
	}
	times := make([]time.Time, 0, len(byTime))
	for t := range byTime {
		times = append(times, t)
	}
	slices.SortFunc(times, time.Time.Compare)
	c := WarmingContext{Now: asOf.Sub(anchor).Seconds(), ReferenceTime: referenceAt.Sub(anchor).Seconds(), ReferenceC: referenceC}
	var since, last time.Time
	var temps []point
	for _, t := range times {
		row := byTime[t]
		hasTemp := row[1] != nil
		for i, v := range row {
			if v != nil && math.IsNaN(*v) {
				row[i] = nil
			}
		}
		relative := t.Sub(anchor).Seconds()
		row[0] = &relative
		c.Rows = append(c.Rows, row)
		if !hasTemp {
			continue
		}
		if t.Sub(last) > 16*time.Second || row[1] == nil {
			temps = nil
			since = time.Time{}
		}
		last = t
		if row[1] == nil {
			continue
		}
		for len(temps) > 0 && t.Sub(temps[0].at) >= 30*time.Second {
			temps = temps[1:]
		}
		temps = append(temps, point{at: t, value: *row[1]})
		if t.Before(anchor) || len(temps) < 2 {
			continue
		}
		endpoint := median(temps)
		c.EndpointC = endpoint
		if endpoint <= 65 || endpoint-referenceC <= 5 {
			since = time.Time{}
			continue
		}
		if since.IsZero() {
			since = t
		}
	}
	if since.IsZero() || last.Sub(since) < 30*time.Second || asOf.Sub(last) > 45*time.Second || last.Sub(anchor) > 10*time.Minute || (!lastCall.IsZero() && (!last.After(lastCall) || (!lastCall.Before(since) && last.Sub(lastCall) < time.Minute))) {
		return WarmingContext{}, false
	}
	c.EndpointAt = last
	c.JointPowerUtil = warmingPlateaus(c.Rows, []int{2, 3}, []float64{25, 5}, 60)
	c.PowerOnly = warmingPlateaus(c.Rows, []int{2}, []float64{25}, 60)
	c.TemperaturePlateaus = warmingPlateaus(c.Rows, []int{1}, []float64{1}, 45)
	return c, true
}

func warmingPlateaus(rows [][4]*float64, columns []int, tolerances []float64, minimumSeconds float64) []WarmingPlateau {
	result := []WarmingPlateau{}
	var group [][4]*float64
	flush := func() {
		if len(group) > 0 && *group[len(group)-1][0]-*group[0][0] >= minimumSeconds {
			p := WarmingPlateau{Start: *group[0][0], Through: *group[len(group)-1][0]}
			for _, col := range columns {
				values := make([]point, len(group))
				for i, row := range group {
					values[i].value = *row[col]
				}
				p.Median = append(p.Median, median(values))
			}
			result = append(result, p)
		}
		group = nil
	}
	lows := make([]float64, len(columns))
	highs := make([]float64, len(columns))
	for _, row := range rows {
		missing := false
		split := len(group) > 0 && *row[0]-*group[len(group)-1][0] > 20
		for i, col := range columns {
			if row[col] == nil {
				missing = true
				break
			}
			if len(group) > 0 && max(highs[i], *row[col])-min(lows[i], *row[col]) > tolerances[i] {
				split = true
			}
		}
		if missing || split {
			flush()
		}
		if missing {
			continue
		}
		for i, col := range columns {
			if len(group) == 0 {
				lows[i], highs[i] = *row[col], *row[col]
			} else {
				lows[i] = min(lows[i], *row[col])
				highs[i] = max(highs[i], *row[col])
			}
		}
		group = append(group, row)
	}
	flush()
	return result
}
