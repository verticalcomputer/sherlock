package domain

import (
	"math"
	"strings"
	"time"
)

// DCGMFieldEvidence is a per-run assessment, never execution authority or a
// permanent hardware-support claim. Absence always remains UNKNOWN.
type DCGMFieldEvidence struct {
	NodeID StableNodeID    `json:"node_id"`
	GPU    PhysicalGPUUUID `json:"gpu_uuid"`
	Metric string          `json:"metric"`
	State  string          `json:"state"`
	Reason string          `json:"reason"`
}

type MetricSemantics struct {
	Kind          string `json:"kind"`
	Reset         string `json:"reset"`
	ResetObserved bool   `json:"reset_observed,omitempty"`
}

type DCGMField struct {
	Name, Unit, Kind, Reset string
	// Only fields declared double by DCGM may use its exact FP64 sentinel.
	Double bool
	// Boolean fields accept only the documented 0/1 values. Other integral
	// values remain UNKNOWN rather than being presented as a valid state.
	Boolean bool
}

const DCGMFreshFor = 2 * time.Minute

// The existing operation capability predates field-local freshness filtering.
// This provenance marker is emitted only by the reviewed new executor contract.
func DCGMSourceReference(q QueryKind) string { return "prometheus:dcgm-fields-v1:" + string(q) }

func ExpandedDCGMQueries() []QueryKind {
	return []QueryKind{QueryGPUTemperature, QueryGPUPower, QueryGPUMemory, QueryGPUECC}
}

// Existing reviewed metric names are pinned; these are not exporter discovery
// selectors supplied by a caller. See docs/GP06A_DCGM_METRICS.md.
func DCGMFields(q QueryKind) []DCGMField {
	switch q {
	case QueryGPUTemperature:
		return []DCGMField{{Name: "DCGM_FI_DEV_GPU_TEMP", Unit: "celsius", Kind: "gauge", Reset: "not_applicable"}, {Name: "DCGM_FI_DEV_MEMORY_TEMP", Unit: "celsius", Kind: "gauge", Reset: "not_applicable"}}
	case QueryGPUPower:
		return []DCGMField{{Name: "DCGM_FI_DEV_POWER_USAGE", Unit: "watts", Kind: "gauge", Reset: "not_applicable", Double: true}, {Name: "DCGM_FI_DEV_POWER_MGMT_LIMIT", Unit: "watts", Kind: "gauge", Reset: "not_applicable", Double: true}}
	case QueryGPUMemory:
		return []DCGMField{{Name: "DCGM_FI_DEV_FB_USED", Unit: "mebibytes", Kind: "gauge", Reset: "not_applicable"}, {Name: "DCGM_FI_DEV_FB_FREE", Unit: "mebibytes", Kind: "gauge", Reset: "not_applicable"}, {Name: "DCGM_FI_DEV_FB_RESERVED", Unit: "mebibytes", Kind: "gauge", Reset: "not_applicable"}}
	case QueryGPUECC:
		return []DCGMField{
			{Name: "DCGM_FI_DEV_ECC_SBE_VOL_TOTAL", Unit: "count", Kind: "counter", Reset: "driver_reload_or_explicit_clear;epoch_unknown"},
			{Name: "DCGM_FI_DEV_ECC_DBE_VOL_TOTAL", Unit: "count", Kind: "counter", Reset: "driver_reload_or_explicit_clear;epoch_unknown"},
			{Name: "DCGM_FI_DEV_ECC_SBE_AGG_TOTAL", Unit: "count", Kind: "counter", Reset: "persistent_until_explicit_clear;epoch_unknown"},
			{Name: "DCGM_FI_DEV_ECC_DBE_AGG_TOTAL", Unit: "count", Kind: "counter", Reset: "persistent_until_explicit_clear;epoch_unknown"},
			{Name: "DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS", Unit: "count", Kind: "counter", Reset: "source_or_device_reset;epoch_unknown"},
			{Name: "DCGM_FI_DEV_UNCORRECTABLE_REMAPPED_ROWS", Unit: "count", Kind: "counter", Reset: "source_or_device_reset;epoch_unknown"},
			{Name: "DCGM_FI_DEV_ROW_REMAP_FAILURE", Unit: "boolean", Kind: "gauge", Reset: "not_applicable", Boolean: true},
		}
	}
	return nil
}

// NormalizeDCGMCollection binds expanded instant samples to an authoritative,
// same-source expected inventory. Returned cell assessments cover each field,
// including fields never returned. Caller-provided assessments are ignored.
func NormalizeDCGMCollection(r CollectionResult, entities []EntityIdentity) CollectionResult {
	fields := DCGMFields(r.Task.Query)
	if len(fields) == 0 {
		return r
	}
	if r.Task.Range != nil {
		// This packet discovers instant support. Keep the established range
		// evidence path without assigning instant support/semantics to it.
		r.Coverage.MetricFields = nil
		for i := range r.Observations {
			r.Observations[i].Semantics = nil
		}
		return r
	}
	if len(entities) > 1024 {
		entities = nil
	}
	if len(r.Observations) > r.Task.MaxSeries || r.Coverage.SeriesReturned > r.Task.MaxSeries || r.Coverage.BytesRead > r.Task.MaxBytes {
		r.Status = ResultFailed
		r.Coverage.Complete = false
		r.Observations = nil
		r.Failures = []CollectionFailure{{Code: FailureResultLimit, Message: "DCGM response exceeds assigned limits"}}
	}
	if r.Status == ResultFailed {
		for i := range r.Failures {
			r.Failures[i].Target = ""
			r.Failures[i].Message = "DCGM collection failed"
		}
	}
	r.Coverage.MetricFields = nil
	r.Coverage.ExpectedTargets = nil
	r.Coverage.SeriesExpected = nil
	definitions := map[string]DCGMField{}
	for _, f := range fields {
		definitions[f.Name] = f
	}
	type key struct{ node, gpu, metric string }
	cells := map[key]int{}
	uuidNodes := map[string]string{}
	ambiguous := map[string]bool{}
	for _, e := range entities {
		if e.ClusterID != r.Task.ClusterID {
			continue
		}
		if e.Kind == EntityMIG {
			ambiguous[string(e.PhysicalGPUUUID)] = true
		}
		if e.Kind != EntityGPU {
			continue
		}
		if prior, ok := uuidNodes[string(e.PhysicalGPUUUID)]; ok && prior != string(e.NodeID) {
			ambiguous[string(e.PhysicalGPUUUID)] = true
		}
		uuidNodes[string(e.PhysicalGPUUUID)] = string(e.NodeID)
	}
	seenTargets := map[EvidenceTarget]bool{}
	for _, e := range entities {
		if e.ClusterID != r.Task.ClusterID || e.Kind != EntityGPU || (r.Task.Node != "" && string(e.NodeID) != r.Task.Node) {
			continue
		}
		for _, f := range fields {
			k := key{string(e.NodeID), string(e.PhysicalGPUUUID), f.Name}
			if _, ok := cells[k]; ok {
				continue
			}
			cells[k] = len(r.Coverage.MetricFields)
			r.Coverage.MetricFields = append(r.Coverage.MetricFields, DCGMFieldEvidence{e.NodeID, e.PhysicalGPUUUID, f.Name, "UNKNOWN", "missing_or_unavailable"})
		}
		for _, t := range []EvidenceTarget{{Kind: EvidenceTargetNode, ID: EvidenceTargetID(e.NodeID)}, {Kind: EvidenceTargetGPU, ID: EvidenceTargetID(e.PhysicalGPUUUID)}} {
			if !seenTargets[t] {
				seenTargets[t] = true
				r.Coverage.ExpectedTargets = append(r.Coverage.ExpectedTargets, t)
			}
		}
	}
	if len(cells) > 0 {
		n := len(cells)
		r.Coverage.SeriesExpected = &n
	}
	observations := make([]Observation, 0, len(r.Observations))
	seen := map[key]bool{}
	bad := false
	for _, o := range r.Observations {
		node, gpu, valid := DCGMIdentity(o.Labels, r.Task)
		k := key{node, gpu, o.Metric}
		i, exists := cells[k]
		if !valid || !exists || ambiguous[gpu] || o.ClusterID != r.Task.ClusterID || o.SourceID != r.Task.SourceID {
			bad = true
			continue
		}
		cell := &r.Coverage.MetricFields[i]
		if seen[k] {
			cell.State = "UNKNOWN"
			cell.Reason = "ambiguous_series"
			bad = true
			continue
		}
		seen[k] = true
		if o.SourceReference != DCGMSourceReference(r.Task.Query) {
			cell.Reason = "unverified_execution_contract"
			bad = true
			continue
		}
		if r.Status == ResultFailed || o.ObservedAt.Before(r.Task.ScheduledFor.Add(-DCGMFreshFor)) || o.ObservedAt.Before(r.CompletedAt.Add(-DCGMFreshFor)) || o.ObservedAt.After(r.Task.ScheduledFor.Add(time.Second)) || o.ObservedAt.After(r.CompletedAt.Add(time.Second)) {
			cell.Reason = "stale_or_invalid_time"
			bad = true
			continue
		}
		f := definitions[o.Metric]
		if f.Double && o.Value == 140737488355330 {
			cell.State = "NOT_SUPPORTED"
			cell.Reason = "dcgm_fp64_not_supported"
			continue
		}
		if math.IsNaN(o.Value) || math.IsInf(o.Value, 0) || (o.Value < 0 && r.Task.Query != QueryGPUTemperature) || o.Value >= 140737488355328 || (!f.Double && math.Trunc(o.Value) != o.Value) || (f.Boolean && o.Value != 0 && o.Value != 1) {
			cell.Reason = "invalid_or_blank_value"
			bad = true
			continue
		}
		cell.State = "SUPPORTED"
		cell.Reason = "fresh_sample"
		o.EntityKey = (EntityIdentity{ClusterID: r.Task.ClusterID, Kind: EntityGPU, NodeID: StableNodeID(node), PhysicalGPUUUID: PhysicalGPUUUID(gpu)}).Key()
		o.Labels = []Label{{Name: "Hostname", Value: node}, {Name: "UUID", Value: gpu}}
		o.Unit = f.Unit
		o.Semantics = &MetricSemantics{Kind: f.Kind, Reset: f.Reset}
		o.Kind = map[QueryKind]string{QueryGPUTemperature: "gpu_temperature", QueryGPUPower: "gpu_power", QueryGPUMemory: "gpu_memory", QueryGPUECC: "gpu_ecc"}[r.Task.Query]
		o.SourceReference = DCGMSourceReference(r.Task.Query)
		o.SchemaVersion = 1
		observations = append(observations, o)
	}
	r.Observations = nil
	for _, o := range observations {
		node, gpu, _ := DCGMIdentity(o.Labels, r.Task)
		if r.Coverage.MetricFields[cells[key{node, gpu, o.Metric}]].State == "SUPPORTED" {
			r.Observations = append(r.Observations, o)
		}
	}
	complete := r.Coverage.Complete && len(cells) > 0 && !bad
	for _, cell := range r.Coverage.MetricFields {
		if cell.State != "SUPPORTED" {
			complete = false
		}
	}
	r.Coverage.Complete = complete
	if !complete && r.Status != ResultFailed {
		r.Status = ResultPartial
		r.Failures = []CollectionFailure{{Code: FailurePartialData, Message: "DCGM field availability or stable mapping is incomplete"}}
	}
	return r
}

// DCGMIdentity deliberately has no instance/index/device fallback. Ambiguous
// MIG, node aliases, and conflicting labels remain gaps. Free-form exporter
// labels such as "cluster"/"cluster_id" are deployment metadata, not
// identity, and are ignored here: scope and foreignness are decided
// separately by the exact-cluster/source expected inventory in
// NormalizeDCGMCollection, which already provides the GP-02 foreign-identity
// guarantee (a UUID or node not present in the revision is never mapped).
func DCGMIdentity(labels []Label, task CollectionTask) (string, string, bool) {
	var node, gpu string
	for _, l := range labels {
		switch l.Name {
		case "Hostname", "hostname":
			if node != "" && node != l.Value {
				return "", "", false
			}
			node = l.Value
		case "UUID", "uuid":
			if gpu != "" && gpu != l.Value {
				return "", "", false
			}
			gpu = l.Value
		case "GPU_I_ID", "GPU_I_PROFILE", "GPU_CI_ID", "gpu_instance_id", "compute_instance_id", "MIG_UUID":
			return "", "", false
		}
	}
	return node, gpu, validDCGMIdentityToken(node) && validDCGMIdentityToken(gpu) && strings.HasPrefix(gpu, "GPU-") && (task.Node == "" || task.Node == node)
}

func validDCGMIdentityToken(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':') {
			return false
		}
	}
	return true
}
