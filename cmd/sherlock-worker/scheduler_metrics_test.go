package main

import (
	"errors"
	prom "github.com/prometheus/client_golang/prometheus"
	"testing"
	"time"
)

func TestSchedulerMetricOutcomesAreClosed(t *testing.T) {
	reg := prom.NewRegistry()
	m := newSchedulerMetrics(reg, nil)
	m.recordClaim(time.Millisecond, false, nil)
	m.recordClaim(time.Millisecond, true, nil)
	m.recordClaim(time.Millisecond, false, errors.New("private-marker"))
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				v := label.GetValue()
				if v != "idle" && v != "claimed" && v != "error" {
					t.Fatalf("unbounded label %q", v)
				}
			}
		}
	}
}
