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
