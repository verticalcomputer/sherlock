package domain

import (
	"math"
	"testing"
)

func TestGPUHealthSensorExactSemantics(t *testing.T) {
	for _, query := range ExpandedDCGMQueries() {
		for _, field := range DCGMFields(query) {
			definition, ok := GPUHealthSensor(field.Name)
			if !ok || definition.Kind != field.Kind || definition.Unit != field.Unit || definition.Category == "" || field.Kind == "counter" && definition.CounterEpoch != field.Reset {
				t.Fatalf("reviewed field lost explicit health semantics: %s %+v", field.Name, definition)
			}
		}
	}
	for _, metric := range []string{"application_POWER_USAGE", "DCGM_FI_DEV_MEMORY_BANDWIDTH", "custom_ECC_COUNT", "GPU_TEMP_FAKE"} {
		if _, ok := GPUHealthSensor(metric); ok {
			t.Fatalf("substring adopted sensor contract: %s", metric)
		}
	}
	for _, metric := range []string{"DCGM_FI_DEV_CLOCKS_EVENT_REASONS", "DCGM_FI_DEV_CLOCK_THROTTLE_REASONS", "DCGM_FI_DEV_THERMAL_VIOLATION", "DCGM_FI_DEV_POWER_VIOLATION"} {
		definition, ok := GPUHealthSensor(metric)
		if !ok || definition.Category != "" || definition.Kind == "gauge" {
			t.Fatalf("bitmap/duration became a temperature or power gauge: %+v", definition)
		}
	}
	gpu, _ := GPUHealthSensor("DCGM_FI_DEV_GPU_TEMP")
	memory, _ := GPUHealthSensor("DCGM_FI_DEV_MEMORY_TEMP")
	if gpu.Sensor == memory.Sensor {
		t.Fatal("GPU die and memory temperature sensors were merged")
	}
}

func TestGPUHealthObservationRejectsInvalidSensorEvidence(t *testing.T) {
	for _, observation := range []Observation{
		{Metric: "DCGM_FI_DEV_POWER_USAGE", Value: 95, Unit: "percent"},
		{Metric: "DCGM_FI_DEV_ROW_REMAP_FAILURE", Value: 2, Unit: "boolean"},
		{Metric: "DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS", Value: 1.5, Unit: "count"},
		{Metric: "DCGM_FI_DEV_ECC_DBE_VOL_TOTAL", Value: -1, Unit: "count"},
		{Metric: "DCGM_FI_DEV_GPU_TEMP", Value: math.NaN(), Unit: "celsius"},
		{Metric: "DCGM_FI_DEV_GPU_TEMP", Value: math.Inf(1), Unit: "celsius"},
		{Metric: "DCGM_FI_DEV_POWER_USAGE", Value: 140737488355330, Unit: "watts"},
		{Metric: "DCGM_FI_DEV_GPU_UTIL", Value: 101, Unit: "percent"},
		{Metric: "DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS", Value: 1, Unit: "count", Semantics: &MetricSemantics{Kind: "gauge"}},
	} {
		if ValidGPUHealthObservation(observation) {
			t.Fatalf("invalid sensor evidence accepted: %+v", observation)
		}
	}
	for _, observation := range []Observation{
		{Metric: "DCGM_FI_DEV_GPU_TEMP", Value: -1, Unit: "celsius"},
		{Metric: "DCGM_FI_DEV_FB_USED", Value: 4, Unit: "MiB"},
		{Metric: "DCGM_FI_DEV_ROW_REMAP_FAILURE", Value: 1, Unit: "boolean"},
		{Metric: "DCGM_FI_DEV_UNCORRECTABLE_REMAPPED_ROWS", Value: 2, Unit: "count", Semantics: &MetricSemantics{Kind: "counter", ResetObserved: true}},
	} {
		if !ValidGPUHealthObservation(observation) {
			t.Fatalf("valid sensor evidence rejected: %+v", observation)
		}
	}
}
