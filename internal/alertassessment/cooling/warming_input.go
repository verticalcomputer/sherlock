package cooling

import (
	"encoding/json"
	"slices"
	"sort"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

// WarmingNegative is an inclusive source interval of unusable evidence.
type WarmingNegative struct {
	Metric                     string
	From, Through, AvailableAt time.Time
}

func WarmingInputsFromFacts(facts []a.Fact, asset string) ([]WarmingSample, []WarmingNegative, error) {
	var samples []WarmingSample
	var negatives []WarmingNegative
	seen := make(map[string]struct{})
	for _, f := range facts {
		if f.Asset != asset {
			continue
		}
		if _, ok := seen[f.ID]; f.ID != "" && ok {
			continue
		}
		seen[f.ID] = struct{}{}
		switch f.Kind {
		case "SAMPLE":
			var s a.Sample
			if err := json.Unmarshal(f.Body, &s); err != nil {
				return nil, nil, err
			}
			samples = append(samples, WarmingSample{s.Metric, s.Value, s.SourceAt, f.AvailableAt})
		case "COVERAGE":
			var c a.Coverage
			if err := json.Unmarshal(f.Body, &c); err != nil {
				return nil, nil, err
			}
			negatives = append(negatives, WarmingNegative{c.Metric, c.From, c.Through, f.AvailableAt})
		case "CONFLICT":
			var c a.Conflict
			if err := json.Unmarshal(f.Body, &c); err != nil {
				return nil, nil, err
			}
			negatives = append(negatives, WarmingNegative{c.Metric, c.SourceAt, c.SourceAt, f.AvailableAt})
		}
	}
	return samples, negatives, nil
}

func warmingColumn(metric string) int {
	switch metric {
	case Temperature:
		return 1
	case Power:
		return 2
	case Utilization:
		return 3
	}
	return 0
}

type warmingInterval struct{ from, through time.Time }
type warmingIntervals []warmingInterval

func (v warmingIntervals) merged() warmingIntervals {
	slices.SortFunc(v, func(a, b warmingInterval) int { return a.from.Compare(b.from) })
	var ranges warmingIntervals
	for _, x := range v {
		i := len(ranges) - 1
		if i < 0 || x.from.After(ranges[i].through) {
			ranges = append(ranges, x)
			continue
		}
		ranges[i].through = later(ranges[i].through, x.through)
	}
	return ranges
}

func (v warmingIntervals) intersects(from, through time.Time) bool {
	i := sort.Search(len(v), func(i int) bool { return !v[i].through.Before(from) })
	return i < len(v) && !v[i].from.After(through)
}

type WarmingUnknownInterval struct {
	Metric  string  `json:"metric"`
	Start   float64 `json:"start"`
	Through float64 `json:"through"`
}
