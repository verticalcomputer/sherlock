package domain

import "math"

// GPUSensorDefinition is interpretation metadata, not source enrollment or
// hardware support. Names are exact; a substring is never a sensor contract.
type GPUSensorDefinition struct {
	Sensor           string
	Category         HealthSignalType
	Kind             string
	Unit             string
	PositiveSeverity HealthSeverity
	CounterEpoch     string
}

func GPUHealthSensor(metric string) (GPUSensorDefinition, bool) {
	var d GPUSensorDefinition
	switch metric {
	case "DCGM_FI_DEV_GPU_TEMP":
		d = GPUSensorDefinition{Sensor: "gpu_temperature", Category: HealthSignalThermal, Kind: "gauge", Unit: "celsius"}
	case "DCGM_FI_DEV_MEMORY_TEMP":
		d = GPUSensorDefinition{Sensor: "memory_temperature", Category: HealthSignalThermal, Kind: "gauge", Unit: "celsius"}
	case "DCGM_FI_DEV_POWER_USAGE":
		d = GPUSensorDefinition{Sensor: "power_draw", Category: HealthSignalPower, Kind: "gauge", Unit: "watts"}
	case "DCGM_FI_DEV_POWER_MGMT_LIMIT":
		d = GPUSensorDefinition{Sensor: "power_limit", Category: HealthSignalPower, Kind: "gauge", Unit: "watts"}
	case "DCGM_FI_DEV_FB_USED", "DCGM_FI_DEV_FB_FREE", "DCGM_FI_DEV_FB_TOTAL", "DCGM_FI_DEV_FB_RESERVED":
		d = GPUSensorDefinition{Sensor: map[string]string{"DCGM_FI_DEV_FB_USED": "memory_used", "DCGM_FI_DEV_FB_FREE": "memory_free", "DCGM_FI_DEV_FB_TOTAL": "memory_total", "DCGM_FI_DEV_FB_RESERVED": "memory_reserved"}[metric], Category: HealthSignalMemory, Kind: "gauge", Unit: "mebibytes"}
	case "DCGM_FI_DEV_ECC_SBE_VOL_TOTAL", "DCGM_FI_DEV_ECC_SBE_AGG_TOTAL":
		d = GPUSensorDefinition{Sensor: "correctable_ecc_count", Category: HealthSignalECC, Kind: "counter", Unit: "count", PositiveSeverity: HealthSeverityWarning}
	case "DCGM_FI_DEV_ECC_DBE_VOL_TOTAL", "DCGM_FI_DEV_ECC_DBE_AGG_TOTAL":
		d = GPUSensorDefinition{Sensor: "uncorrectable_ecc_count", Category: HealthSignalECC, Kind: "counter", Unit: "count", PositiveSeverity: HealthSeverityCritical}
	case "DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS":
		d = GPUSensorDefinition{Sensor: "correctable_remapped_rows", Category: HealthSignalECC, Kind: "counter", Unit: "count", PositiveSeverity: HealthSeverityWarning}
	case "DCGM_FI_DEV_UNCORRECTABLE_REMAPPED_ROWS":
		d = GPUSensorDefinition{Sensor: "uncorrectable_remapped_rows", Category: HealthSignalECC, Kind: "counter", Unit: "count", PositiveSeverity: HealthSeverityCritical}
	case "DCGM_FI_DEV_ROW_REMAP_FAILURE", "DCGM_FI_DEV_ROW_REMAP_FAILED":
		d = GPUSensorDefinition{Sensor: "row_remap_failure", Category: HealthSignalECC, Kind: "gauge", Unit: "boolean", PositiveSeverity: HealthSeverityCritical}
	case "DCGM_FI_DEV_XID_ERRORS":
		d = GPUSensorDefinition{Sensor: "last_xid_code", Category: HealthSignalXID, Kind: "gauge", Unit: "count", PositiveSeverity: HealthSeverityCritical}
	case "DCGM_FI_DEV_GPU_UTIL":
		d = GPUSensorDefinition{Sensor: "gpu_utilization", Category: HealthSignalUtilization, Kind: "gauge", Unit: "percent"}
	case "DCGM_FI_DEV_CLOCKS_EVENT_REASONS", "DCGM_FI_DEV_CLOCK_THROTTLE_REASONS":
		// A reason bitmap is neither a temperature nor a power percentage. Some
		// bits mean idle/application clocks; advanced bit-specific rules are separate.
		d = GPUSensorDefinition{Sensor: "clock_event_reasons", Kind: "bitmask", Unit: "bitmask"}
	case "DCGM_FI_DEV_THERMAL_VIOLATION", "DCGM_FI_DEV_POWER_VIOLATION":
		// Accumulated duration requires a qualified epoch and interval for rates.
		d = GPUSensorDefinition{Sensor: map[string]string{"DCGM_FI_DEV_THERMAL_VIOLATION": "thermal_violation_duration", "DCGM_FI_DEV_POWER_VIOLATION": "power_violation_duration"}[metric], Kind: "counter", Unit: "nanoseconds"}
	default:
		return GPUSensorDefinition{}, false
	}
	if d.Kind == "counter" {
		d.CounterEpoch = "epoch_unknown"
		for _, field := range DCGMFields(QueryGPUECC) {
			if field.Name == metric {
				d.CounterEpoch = field.Reset
				break
			}
		}
	}
	return d, true
}

// ValidGPUHealthObservation rejects blank values and incompatible units/kinds.
// It does not claim support, establish an epoch or calculate counter deltas.
func ValidGPUHealthObservation(o Observation) bool {
	d, ok := GPUHealthSensor(o.Metric)
	if !ok || math.IsNaN(o.Value) || math.IsInf(o.Value, 0) || o.Value >= 140737488355328 {
		return false
	}
	if o.Value < 0 && d.Unit != "celsius" {
		return false
	}
	if d.Unit == "count" || d.Unit == "boolean" || d.Kind == "bitmask" || d.Unit == "nanoseconds" {
		if math.Trunc(o.Value) != o.Value {
			return false
		}
	}
	if d.Unit == "boolean" && o.Value != 0 && o.Value != 1 {
		return false
	}
	if d.Unit == "percent" && o.Value > 100 {
		return false
	}
	if o.Semantics != nil && o.Semantics.Kind != d.Kind {
		return false
	}
	switch d.Unit {
	case "count":
		if d.Sensor == "last_xid_code" {
			return o.Unit == "count" || o.Unit == "xid_code"
		}
		return o.Unit == "count"
	case "mebibytes":
		return o.Unit == "mebibytes" || o.Unit == "MiB"
	case "celsius":
		return o.Unit == "celsius" || o.Unit == "C"
	case "watts":
		return o.Unit == "watts" || o.Unit == "W"
	case "percent":
		return o.Unit == "percent" || o.Unit == "%"
	default:
		return o.Unit == d.Unit
	}
}
