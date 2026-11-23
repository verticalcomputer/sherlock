package cooling

import (
	"context"
	"encoding/json"
	"math"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

const CategoryID = "gpu_cooling"
const Temperature = "DCGM_FI_DEV_GPU_TEMP"
const Power = "DCGM_FI_DEV_POWER_USAGE"
const Utilization = "DCGM_FI_DEV_GPU_UTIL"

type Policy struct {
	Profile                  string  `json:"profile"`
	CadenceSeconds           int64   `json:"cadence_seconds"`
	HistorySeconds           int64   `json:"history_seconds"`
	FreshSeconds             int64   `json:"fresh_seconds"`
	EdgeToleranceSeconds     int64   `json:"edge_tolerance_seconds"`
	GapSeconds               int64   `json:"gap_seconds"`
	CoverageRatio            float64 `json:"coverage_ratio"`
	EndpointSeconds          int64   `json:"endpoint_seconds"`
	EndpointMinSamples       int64   `json:"endpoint_min_samples"`
	AlignmentSeconds         int64   `json:"alignment_seconds"`
	RapidSeconds             int64   `json:"rapid_seconds"`
	RapidDeltaC              float64 `json:"rapid_delta_c"`
	SlowSeconds              int64   `json:"slow_seconds"`
	SlowDeltaC               float64 `json:"slow_delta_c"`
	PersistentEntrySeconds   int64   `json:"persistent_entry_seconds"`
	PersistentEntrySamples   int64   `json:"persistent_entry_samples"`
	PersistentC              float64 `json:"persistent_c"`
	PowerPrefixSeconds       int64   `json:"power_prefix_seconds"`
	StableWatts              float64 `json:"stable_watts"`
	StableRatio              float64 `json:"stable_ratio"`
	PersistenceSeconds       int64   `json:"persistence_seconds"`
	PersistenceSamples       int64   `json:"persistence_samples"`
	PersistenceDropC         float64 `json:"persistence_drop_c"`
	PersistentConfirmSeconds int64   `json:"persistent_confirm_seconds"`
	TransitionSeconds        int64   `json:"transition_seconds"`
	TransitionWatts          float64 `json:"transition_watts"`
	TransitionRatio          float64 `json:"transition_ratio"`
	SettlingSeconds          int64   `json:"settling_seconds"`
	SettlingSamples          int64   `json:"settling_samples"`
	ReferenceToleranceC      float64 `json:"reference_tolerance_c"`
	RearmSeconds             int64   `json:"rearm_seconds"`
	PersistentRecoveryC      float64 `json:"persistent_recovery_c"`
	UpdateDeltaC             float64 `json:"update_delta_c"`
}

func DefaultPolicy() Policy {
	var p Policy
	_ = json.Unmarshal([]byte(`{"profile":"cooling-experiment-v1","cadence_seconds":15,"history_seconds":900,"fresh_seconds":45,"edge_tolerance_seconds":15,"gap_seconds":30,"coverage_ratio":0.8,"endpoint_seconds":30,"endpoint_min_samples":2,"alignment_seconds":15,"rapid_seconds":300,"rapid_delta_c":10,"slow_seconds":600,"slow_delta_c":5,"persistent_entry_seconds":30,"persistent_entry_samples":3,"persistent_c":75,"power_prefix_seconds":120,"stable_watts":10,"stable_ratio":0.05,"persistence_seconds":30,"persistence_samples":3,"persistence_drop_c":1,"persistent_confirm_seconds":60,"transition_seconds":30,"transition_watts":50,"transition_ratio":0.2,"settling_seconds":45,"settling_samples":3,"reference_tolerance_c":2,"rearm_seconds":300,"persistent_recovery_c":70,"update_delta_c":5}`), &p)
	return p
}

func (p Policy) Validate() error {
	if p.Profile != "cooling-experiment-v1" || p.HistorySeconds < 1 || p.HistorySeconds > 900 {
		return a.ErrInvalid
	}
	for _, v := range []int64{p.CadenceSeconds, p.HistorySeconds, p.FreshSeconds, p.EdgeToleranceSeconds, p.GapSeconds, p.EndpointSeconds, p.AlignmentSeconds, p.RapidSeconds, p.SlowSeconds, p.PersistentEntrySeconds, p.PowerPrefixSeconds, p.PersistenceSeconds, p.PersistentConfirmSeconds, p.TransitionSeconds, p.SettlingSeconds, p.RearmSeconds} {
		if v < 1 || v > p.HistorySeconds {
			return a.ErrInvalid
		}
	}
	for _, v := range []int64{p.EndpointMinSamples, p.PersistentEntrySamples, p.PersistenceSamples, p.SettlingSamples} {
		if v < 2 || v > 768 {
			return a.ErrInvalid
		}
	}
	for _, v := range []float64{p.CoverageRatio, p.StableRatio, p.TransitionRatio} {
		if math.IsNaN(v) || v <= 0 || v > 1 {
			return a.ErrInvalid
		}
	}
	for _, v := range []float64{p.RapidDeltaC, p.SlowDeltaC, p.PersistentC, p.StableWatts, p.PersistenceDropC, p.TransitionWatts, p.ReferenceToleranceC, p.PersistentRecoveryC, p.UpdateDeltaC} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
			return a.ErrInvalid
		}
	}
	if p.RapidSeconds >= p.SlowSeconds || p.SlowSeconds+p.PowerPrefixSeconds > p.HistorySeconds || p.SlowSeconds+p.EndpointSeconds > p.HistorySeconds || p.PersistentRecoveryC >= p.PersistentC || p.GapSeconds < p.CadenceSeconds || p.EdgeToleranceSeconds > p.GapSeconds || p.EndpointSeconds > p.RapidSeconds || p.RearmSeconds > p.HistorySeconds || p.PersistentConfirmSeconds < p.PersistentEntrySeconds {
		return a.ErrInvalid
	}
	return nil
}

type Rebound struct {
	DropAt    time.Time    `json:"drop_at"`
	RiseAt    time.Time    `json:"rise_at"`
	Reference a.FeatureRef `json:"reference"`
	PrePowerW float64      `json:"pre_power_w"`
	BundleID  string       `json:"bundle_id"`
	Support   []string     `json:"support"`
}
type TrackerState struct {
	Schema            int64          `json:"schema"`
	Active            bool           `json:"active"`
	Branches          []string       `json:"branches"`
	EntryEndpoint     *a.FeatureRef  `json:"entry_endpoint,omitempty"`
	Reference         *a.FeatureRef  `json:"reference,omitempty"`
	Rebound           *Rebound       `json:"rebound,omitempty"`
	UrgentOccurrences []a.Occurrence `json:"urgent_occurrences"`
	RearmSince        *time.Time     `json:"rearm_since,omitempty"`
	LastEndpointAt    *time.Time     `json:"last_endpoint_at,omitempty"`
}
type State struct {
	Schema         int64         `json:"schema"`
	Branches       []string      `json:"branches"`
	EntryEndpoint  *a.FeatureRef `json:"entry_endpoint,omitempty"`
	Reference      *a.FeatureRef `json:"reference,omitempty"`
	Rebound        *Rebound      `json:"rebound,omitempty"`
	LastEndpointAt *time.Time    `json:"last_endpoint_at,omitempty"`
}
type Details struct {
	Schema        int64         `json:"schema"`
	Temperature   *a.FeatureRef `json:"temperature,omitempty"`
	SignedChangeC *float64      `json:"signed_change_c,omitempty"`
	PowerMedianW  *float64      `json:"power_median_w,omitempty"`
	PowerRangeW   *float64      `json:"power_range_w,omitempty"`
	Branches      []string      `json:"branches"`
	Rebound       *Rebound      `json:"rebound,omitempty"`
	Coverage      string        `json:"coverage"`
	Support       []string      `json:"support"`
}
type Category struct{}

// Cooling reacts to new evidence and to evidence leaving its rolling
// windows. With no fresh temperature, removing older samples cannot re-arm
// or worsen an active occurrence. Qualified events and deadlines remain
// independent of sample freshness.
func (Category) ReplaysVisibleInputOnly() bool { return true }

func (Category) ReplaySampleWindows(ctx context.Context, policy a.Payload) (time.Duration, time.Duration) {
	p, err := decodePolicy(ctx, policy)
	if err != nil {
		return 0, 0
	}
	return seconds(p.HistorySeconds + p.FreshSeconds), seconds(p.FreshSeconds)
}

var _ a.VisibleInputReplay = Category{}

func (Category) Describe() a.Descriptor {
	outcomes := []a.Outcome{}
	for _, p := range []string{"DISCOVER", "ASSESS"} {
		if p == "DISCOVER" {
			outcomes = append(outcomes, a.Outcome{Code: CategoryID + "/NO_CANDIDATE", Purpose: p, Phase: "NO_CANDIDATE", Action: "NONE", EvidenceClass: "NONTERMINAL"})
		}
		outcomes = append(outcomes, a.Outcome{Code: CategoryID + "/OBSERVING", Purpose: p, Phase: "OBSERVING", Action: "NONE", EvidenceClass: "NONTERMINAL"}, a.Outcome{Code: CategoryID + "/URGENT_BYPASS", Purpose: p, Phase: "FINAL", Action: "URGENT", EvidenceClass: "SUPPORTED_CONCERN"})
	}
	for _, o := range []a.Outcome{{Code: "COOLING_SUSPECTED", Action: "INVESTIGATE", EvidenceClass: "SUPPORTED_CONCERN"}, {Code: "TRANSIENT_SUPPORTED", Action: "NONE", EvidenceClass: "BENIGN"}, {Code: "UNRESOLVED_WARMING", Action: "INVESTIGATE", EvidenceClass: "UNRESOLVED"}} {
		o.Code = CategoryID + "/" + o.Code
		o.Purpose = "ASSESS"
		o.Phase = "FINAL"
		outcomes = append(outcomes, o)
	}
	return a.Descriptor{Category: CategoryID, Contract: 1, Implementation: 1, PolicySchema: 1, TrackerSchema: 1, CandidateSchema: 1, DetailsSchema: 1, Modes: []string{"replay", "shadow"}, Metrics: []a.Metric{{Metric: Temperature, Unit: "celsius", Required: true, HistorySeconds: 900}, {Metric: Power, Unit: "watts", Required: true, HistorySeconds: 900}, {Metric: Utilization, Unit: "percent", Required: false, HistorySeconds: 900}}, Outcomes: outcomes, Reasons: []string{"deadline", "insufficient_evidence", "persistent", "rapid", "rebound", "settled", "slow", "stable_power", "urgent"}, Updates: []a.Update{{Code: "urgent", Action: "URGENT", EvidenceClass: "SUPPORTED_CONCERN"}, {Code: "higher_temperature", Action: "INVESTIGATE", EvidenceClass: "UNRESOLVED"}}, PayloadLimits: a.PayloadLimits{Policy: 16384, Tracker: 16384, Candidate: 16384, Details: 4096}}
}
func (Category) NormalizePolicy(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var p Policy
	if err := a.DecodeStrict(raw, &p, stateLimit); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return a.Canonical(p)
}

func (Category) ValidatePolicy(ctx context.Context, p a.Payload) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	policy, err := decodePolicy(ctx, p)
	if err != nil {
		return err
	}
	return policy.Validate()
}
