package cooling

import (
	"encoding/json"
	"slices"
	"testing"
	"time"
)

var warmingAnchor = time.Unix(10_000, 0).UTC()

func warmingSamples(metric string, start int, values ...float64) []WarmingSample {
	var samples []WarmingSample
	for i, v := range values {
		t := warmingAnchor.Add(time.Duration(start+15*i) * time.Second)
		samples = append(samples, WarmingSample{Metric: metric, Value: v, SourceAt: t, AvailableAt: t})
	}
	return samples
}
func warmingCheck(samples []WarmingSample, ref float64, offset int, last time.Time) (WarmingContext, bool) {
	return ConfirmedWarming(samples, warmingAnchor.Add(-10*time.Minute), ref, warmingAnchor, warmingAnchor.Add(time.Duration(offset)*time.Second), last)
}

func TestWarmingConfirmationBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		temp, ref float64
		offset    int
		want      bool
	}{
		{"rise exactly five", 70, 65, 30, false}, {"temperature exactly 65", 65, 55, 30, false},
		{"both strictly above", 66, 60, 30, true}, {"one fresh endpoint", 66, 60, 0, false},
		{"second fresh endpoint", 66, 60, 15, false}, {"stale endpoint", 66, 60, 76, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := warmingSamples(Temperature, -15, tt.temp, tt.temp, tt.temp, tt.temp)
			_, got := warmingCheck(rows, tt.ref, tt.offset, time.Time{})
			if got != tt.want {
				t.Fatalf("eligible=%t", got)
			}
		})
	}
}
func TestWarmingConfirmationRecrossAndDuplicates(t *testing.T) {
	first := warmingSamples(Temperature, -15, 68, 68, 68, 68)
	second := warmingSamples(Temperature, 45, 50, 68, 68, 68, 68)
	rows := append(first, second...)
	c, ok := warmingCheck(rows, 55, 30, time.Time{})
	if !ok {
		t.Fatal("first crossing missing")
	}
	if _, ok := warmingCheck(rows, 55, 30, c.EndpointAt); ok {
		t.Fatal("repeat poll called again")
	}
	if _, ok := warmingCheck(rows, 55, 90, c.EndpointAt); ok {
		t.Fatal("second crossing did not wait")
	}
	if _, ok := warmingCheck(rows, 55, 105, c.EndpointAt); !ok {
		t.Fatal("independent crossing missing")
	}
	// Missing temperature, conflicting duplicates, or late delivery must not
	// supply a fresh two-sample endpoint.
	gap := append(slices.Clone(first[:2]), first[3])
	if _, ok := warmingCheck(gap, 55, 30, time.Time{}); ok {
		t.Fatal("gap confirmed")
	}
	conflict := first[2]
	conflict.Value = 66
	if _, ok := warmingCheck(append(first, conflict), 55, 30, time.Time{}); ok {
		t.Fatal("conflict confirmed")
	}
	late := slices.Clone(first)
	late[2].AvailableAt = warmingAnchor.Add(time.Minute)
	if _, ok := warmingCheck(late, 55, 30, time.Time{}); ok {
		t.Fatal("future arrival confirmed")
	}
}

func TestWarmingConfirmationReevaluationAndPlateaus(t *testing.T) {
	var rows []WarmingSample
	for _, field := range []struct {
		metric string
		value  float64
	}{{Temperature, 68}, {Power, 550}, {Utilization, 90}} {
		rows = append(rows, warmingSamples(field.metric, -30, field.value, field.value, field.value, field.value, field.value, field.value, field.value, field.value, field.value)...)
	}
	first, ok := warmingCheck(rows, 59, 30, time.Time{})
	if !ok {
		t.Fatal("missing first confirmation")
	}
	if len(first.Rows) != 5 || len(first.JointPowerUtil) != 1 || len(first.PowerOnly) != 1 || len(first.TemperaturePlateaus) != 1 {
		t.Fatalf("unexpected model context %+v", first)
	}
	j := first.JointPowerUtil[0]
	if j.Start != -30 || j.Through != 30 || !slices.Equal(j.Median, []float64{550, 90}) {
		t.Fatalf("unexpected load phase: %+v", j)
	}
	if _, ok := warmingCheck(rows, 59, 75, first.EndpointAt); ok {
		t.Fatal("WATCH rechecked early")
	}
	if _, ok := warmingCheck(rows, 59, 90, first.EndpointAt); !ok {
		t.Fatal("WATCH recheck missing")
	}
	without := slices.DeleteFunc(slices.Clone(rows), func(s WarmingSample) bool { return s.Metric == Utilization })
	withheld, ok := warmingCheck(without, 59, 30, time.Time{})
	if !ok || len(withheld.JointPowerUtil) != 0 || withheld.Rows[0][3] != nil {
		t.Fatalf("unexpected absent utilization %+v", withheld)
	}
	if _, err := json.Marshal(withheld); err != nil {
		t.Fatal(err)
	}
}

func TestWarmingConfirmationRequiresMedian(t *testing.T) {
	if _, ok := warmingCheck(warmingSamples(Temperature, -15, 50, 68, 68, 68), 58, 30, time.Time{}); ok {
		t.Fatal("raw high samples bypassed endpoint median")
	}
}

func TestWarmingNegativeIntervals(t *testing.T) {
	at := func(offset int) time.Time { return warmingAnchor.Add(time.Duration(offset) * time.Second) }
	ref := at(-600)
	var rows []WarmingSample
	for i := -120; i <= 180; i += 15 {
		rows = append(rows, WarmingSample{Temperature, 68, at(i), at(i)}, WarmingSample{Power, 500, at(i), at(i)}, WarmingSample{Utilization, 90, at(i), at(i)})
	}
	check := func(now int, ns ...WarmingNegative) (WarmingContext, bool) {
		return ConfirmedWarming(rows, ref, 59, warmingAnchor, at(now), time.Time{}, ns...)
	}
	for _, metric := range []string{Power, Utilization, Temperature} {
		gap := WarmingNegative{metric, at(-60), at(-55), at(0)}
		ctx, ok := check(45, gap)
		if !ok {
			t.Fatalf("old %s negative blocked fresh temperature", metric)
		}
		for _, row := range ctx.Rows {
			if *row[0] == -60 && row[warmingColumn(metric)] != nil {
				t.Fatalf("%s sample in negative interval", metric)
			}
		}
		var groups []WarmingPlateau
		switch metric {
		case Temperature:
			groups = ctx.TemperaturePlateaus
		case Power:
			groups = append(ctx.PowerOnly, ctx.JointPowerUtil...)
		case Utilization:
			groups = ctx.JointPowerUtil
		}
		for _, p := range groups {
			if p.Start <= -60 && p.Through >= -55 {
				t.Fatalf("%s plateau spans known gap: %+v", metric, p)
			}
		}
	}
	gap := WarmingNegative{Temperature, at(5), at(8), at(45)}
	if _, ok := check(30, gap); !ok {
		t.Fatal("future coverage vetoed confirmation")
	}
	if _, ok := check(45, gap); ok {
		t.Fatal("newly arrived negative inside rolling endpoint did not break confirmation")
	}
	if _, ok := check(75, gap); !ok {
		t.Fatal("confirmation did not rearm after fresh coverage")
	}
	if _, ok := check(75, WarmingNegative{Temperature, ref.Add(-25 * time.Second), ref.Add(-25 * time.Second), at(60)}); ok {
		t.Fatal("late conflict in reference endpoint was ignored")
	}
	if _, ok := check(75, WarmingNegative{Power, ref, ref, at(60)}); !ok {
		t.Fatal("power conflict invalidated temperature reference")
	}
}

func TestAsynchronousWarmingPlateaus(t *testing.T) {
	at := func(offset int) time.Time { return warmingAnchor.Add(time.Duration(offset) * time.Second) }
	var rows []WarmingSample
	for i := -120; i <= 60; i += 15 {
		rows = append(rows, WarmingSample{Temperature, 68, at(i), at(i)}, WarmingSample{Power, 500, at(i + 2), at(i + 2)}, WarmingSample{Utilization, 90, at(i + 2), at(i + 2)})
	}
	ctx, ok := ConfirmedWarming(rows, at(-600), 59, warmingAnchor, at(60), time.Time{}, WarmingNegative{Power, at(-60), at(-60), at(0)})
	if !ok || len(ctx.TemperaturePlateaus) != 1 || len(ctx.PowerOnly) != 1 || len(ctx.JointPowerUtil) != 1 {
		t.Fatalf("missing independent plateaus %+v", ctx)
	}
	if ctx.TemperaturePlateaus[0].Start != -120 || ctx.TemperaturePlateaus[0].Through != 60 || ctx.PowerOnly[0].Start != -58 || ctx.PowerOnly[0].Through != 47 || ctx.JointPowerUtil[0].Start != -58 {
		t.Fatalf("invalid asynchronous plateau boundaries %+v", ctx)
	}
}
