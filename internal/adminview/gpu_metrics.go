package adminview

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// GP-06a admin projection. Every model here separates "observed value" from
// "no evidence": a field that was never returned, was assessed unsupported, or
// whose newest projection is older than the operation's own freshness window
// carries an explicit state and a nil value. A caller can therefore never
// render absence as zero or as health. See docs/GP06A_DCGM_METRICS.md.

// GPUMetricState is the per-GPU, per-field evidence state.
type GPUMetricState string

const (
	// GPUMetricSupported is the only state that carries a numeric value.
	GPUMetricSupported GPUMetricState = "SUPPORTED"
	// GPUMetricNotSupported is the committed run's exact not-supported marker.
	GPUMetricNotSupported GPUMetricState = "NOT_SUPPORTED"
	// GPUMetricUnknown covers missing, ambiguous, or unassessed cells.
	GPUMetricUnknown GPUMetricState = "UNKNOWN"
	// GPUMetricStale is a projection older than the operation freshness window.
	GPUMetricStale GPUMetricState = "STALE"
	// GPUMetricNoData means no committed run assessed this cell at all.
	GPUMetricNoData GPUMetricState = "NO_DATA"
	// GPUMetricAmbiguousMIG marks an expected MIG entity. A MIG identity is not
	// a physical GPU identity, so no reviewed field value can be attributed to
	// it; the row exists so a MIG entity is never counted as covered.
	GPUMetricAmbiguousMIG GPUMetricState = "AMBIGUOUS_MIG"
)

// GPUMetricsFreshness describes an operation's newest committed run.
type GPUMetricsFreshness string

const (
	GPUMetricsFresh        GPUMetricsFreshness = "FRESH"
	GPUMetricsFreshnessOld GPUMetricsFreshness = "STALE"
	GPUMetricsNoData       GPUMetricsFreshness = "NO_DATA"
	// GPUMetricsFailing is the newest committed run in a status that produces
	// no usable evidence. A failing run must never read as fresh evidence.
	GPUMetricsFailing GPUMetricsFreshness = "FAILING"
	// GPUMetricsClockSkewed marks a completion instant meaningfully ahead of the
	// evaluation instant. Freshness is then unknowable, not fresh.
	GPUMetricsClockSkewed GPUMetricsFreshness = "CLOCK_SKEW"
)

// GPUMetricsObservedState is the per-row target-cache state. The observed
// target cache is never pruned, so presence alone is not evidence that the
// target is still being scraped; the age of the observation decides.
type GPUMetricsObservedState string

const (
	GPUMetricsObserved        GPUMetricsObservedState = "OBSERVED"
	GPUMetricsObservedStale   GPUMetricsObservedState = "OBSERVED_STALE"
	GPUMetricsObservedUnknown GPUMetricsObservedState = "OBSERVED_UNKNOWN"
	GPUMetricsNotObserved     GPUMetricsObservedState = "NOT_OBSERVED"
)

const (
	// GPUMetricsRowLimit bounds the projected GPU table and every inventory list.
	GPUMetricsRowLimit = 1024
	// GPUMetricsDefaultFreshFor is the freshness window used when an operation
	// has no desired schedule, so an unenrolled operation cannot look fresh by
	// inheriting an interval it does not have.
	GPUMetricsDefaultFreshFor = 5 * time.Minute
	// GPUMetricsSourceLimit bounds the Prometheus sources projected per cluster.
	GPUMetricsSourceLimit = 32
	// GPUMetricsClockSkewTolerance is the only slack allowed for a recorded
	// instant ahead of the evaluation instant. Beyond it the record and the
	// reader disagree about time, and no freshness claim can be made.
	GPUMetricsClockSkewTolerance = 2 * time.Minute
)

// GPUMetricsQuery is the bounded admin request. It is always scoped to one
// cluster; there is no cross-cluster or unscoped form.
type GPUMetricsQuery struct {
	ClusterID string
	Now       time.Time
}

type GPUMetricsSnapshot struct {
	ClusterID    string                  `json:"cluster_id"`
	GeneratedAt  time.Time               `json:"generated_at"`
	Sources      []GPUMetricsSource      `json:"sources"`
	GPUs         []GPUMetricsRow         `json:"gpus"`
	Inventory    GPUMetricsInventory     `json:"inventory"`
	Fields       []GPUMetricsFieldRef    `json:"fields"`
	OtherSources []GPUMetricsOtherSource `json:"other_sources"`
	Truncated    bool                    `json:"truncated"`
	// SourcesTruncated states that the cluster has more Prometheus sources than
	// the projection bound, so the page is not a complete source list.
	SourcesTruncated bool `json:"sources_truncated"`
}

// GPUMetricsFieldRef is the ordered reviewed field list backing the GPU table
// columns. It is fixed domain metadata, not exporter discovery.
type GPUMetricsFieldRef struct {
	Name      string `json:"name"`
	Unit      string `json:"unit"`
	Semantics string `json:"semantics"`
	Operation string `json:"operation"`
}

// GPUMetricsOtherSource names a Prometheus source that the governing expected
// revision does not cover. Its observed targets are stated so the bounded GPU
// table cannot be mistaken for the whole cluster.
type GPUMetricsOtherSource struct {
	SourceID      string `json:"source_id"`
	DisplayName   string `json:"display_name,omitempty"`
	ObservedNodes int    `json:"observed_nodes"`
	ObservedGPUs  int    `json:"observed_gpus"`
}

type GPUMetricsSource struct {
	SourceID    string                `json:"source_id"`
	DisplayName string                `json:"display_name"`
	Primary     bool                  `json:"primary"`
	Operations  []GPUMetricsOperation `json:"operations"`
}

// GPUMetricsOperation projects one expanded DCGM operation for one source.
// Enrollment, the newest committed run, and field assessment are independent
// facts: an enabled schedule with no fresh run is not evidence of support.
type GPUMetricsOperation struct {
	OperationID        string                   `json:"operation_id"`
	QueryKind          string                   `json:"query_kind"`
	Enrolled           bool                     `json:"enrolled"`
	Enabled            bool                     `json:"enabled"`
	Mode               string                   `json:"mode,omitempty"`
	IntervalSeconds    int64                    `json:"interval_seconds"`
	Revision           int64                    `json:"revision"`
	LastRun            *GPUMetricsRun           `json:"last_run,omitempty"`
	Freshness          GPUMetricsFreshness      `json:"freshness"`
	FreshWindowSeconds int64                    `json:"fresh_window_seconds"`
	Fields             []GPUMetricsFieldColumn  `json:"fields"`
	FieldSummaries     []GPUMetricsFieldSummary `json:"field_summaries"`
}

type GPUMetricsRun struct {
	RunID            string    `json:"run_id"`
	Status           string    `json:"status"`
	ScheduledFor     time.Time `json:"scheduled_for"`
	CompletedAt      time.Time `json:"completed_at"`
	CoverageComplete bool      `json:"coverage_complete"`
}

// GPUMetricsFieldColumn is the reviewed field metadata carried by the domain,
// not a value. Unit and semantics are fixed server-side constants.
type GPUMetricsFieldColumn struct {
	Name      string `json:"name"`
	Unit      string `json:"unit"`
	Semantics string `json:"semantics"`
}

// GPUMetricsFieldSummary counts the newest committed run's assessments over
// its expected targets. Dominant never resolves a tie towards SUPPORTED, and
// the counts carry their own denominator: an expected GPU the run never
// assessed is counted UNKNOWN rather than silently dropped.
type GPUMetricsFieldSummary struct {
	Field        string `json:"field"`
	Supported    int    `json:"supported"`
	NotSupported int    `json:"not_supported"`
	Unknown      int    `json:"unknown"`
	// Assessed is the number of distinct targets the newest run assessed.
	Assessed int `json:"assessed"`
	// Expected is the governing revision's expected physical GPU count.
	Expected int `json:"expected"`
	// UnassessedExpected is the part of Unknown contributed by expected GPUs
	// the newest run never assessed.
	UnassessedExpected int            `json:"unassessed_expected"`
	Dominant           GPUMetricState `json:"dominant"`
}

// GPUMetricsRow is one physical GPU known from the expected inventory
// revision, the observed target cache, or both. A row with a MIG identity is
// an expected MIG entity, which carries no physical field evidence.
type GPUMetricsRow struct {
	SourceID      string                    `json:"source_id"`
	NodeID        string                    `json:"node_id"`
	GPUUUID       string                    `json:"gpu_uuid"`
	MIGIdentity   string                    `json:"mig_identity,omitempty"`
	Expected      bool                      `json:"expected"`
	Observed      bool                      `json:"observed"`
	ObservedAt    *time.Time                `json:"observed_at,omitempty"`
	ObservedState GPUMetricsObservedState   `json:"observed_state"`
	Values        map[string]GPUMetricValue `json:"values"`
	// Conditions are the same scoped projection consumed by the public GPU
	// API. Field support and transport coverage remain separate facts.
	Conditions []domain.HealthSignal `json:"conditions,omitempty"`
}

// GPUMetricValue carries a number only in the SUPPORTED state. Value is nil in
// every other state so absence can never be formatted as zero.
type GPUMetricValue struct {
	State         GPUMetricState `json:"state"`
	Value         *float64       `json:"value,omitempty"`
	Unit          string         `json:"unit,omitempty"`
	Semantics     string         `json:"semantics,omitempty"`
	ObservedAt    *time.Time     `json:"observed_at,omitempty"`
	ResetObserved bool           `json:"reset_observed,omitempty"`
}

// GPUMetricsEntityRef names one inventory gap. A node-only reference has an
// empty GPU UUID. Stale marks an entity that is present in the never-pruned
// target cache but whose newest observation is older than the window, which is
// a coverage gap exactly like an entity that was never observed.
type GPUMetricsEntityRef struct {
	NodeID     string     `json:"node_id"`
	GPUUUID    string     `json:"gpu_uuid,omitempty"`
	Stale      bool       `json:"stale,omitempty"`
	Unknown    bool       `json:"unknown,omitempty"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
}

// GPUMetricsObservation is one repository-supplied raw fact about an expected
// or observed entity. It is the input to the service's time-relative coverage
// derivation and never crosses the API boundary, so no consumer can read a
// presence-only observation as coverage.
type GPUMetricsObservation struct {
	NodeID     string
	GPUUUID    string
	Expected   bool
	ObservedAt *time.Time
}

// GPUMetricsInventory compares the operator-seeded expected revision for the
// primary Prometheus source with the observed target cache. A missing revision
// is stated, never assumed complete.
type GPUMetricsInventory struct {
	SourceID            string     `json:"source_id,omitempty"`
	HasExpectedRevision bool       `json:"has_expected_revision"`
	RevisionID          string     `json:"revision_id,omitempty"`
	EffectiveAt         *time.Time `json:"effective_at,omitempty"`
	SourceAt            *time.Time `json:"source_at,omitempty"`
	ObservedAt          *time.Time `json:"observed_at,omitempty"`
	ExpectedNodes       int        `json:"expected_nodes"`
	ExpectedGPUs        int        `json:"expected_gpus"`
	MIGCount            int        `json:"mig_count"`
	ObservedNodes       int        `json:"observed_nodes"`
	ObservedGPUs        int        `json:"observed_gpus"`
	// FreshObserved* and StaleObservedGPUs split the never-pruned target cache
	// into what is still being scraped and what merely remains on record.
	FreshObservedNodes int `json:"fresh_observed_nodes"`
	FreshObservedGPUs  int `json:"fresh_observed_gpus"`
	StaleObservedGPUs  int `json:"stale_observed_gpus"`
	// CoveredNodes and CoveredGPUs count only expected entities with a fresh
	// observation. Coverage is never asserted from presence alone.
	CoveredNodes int `json:"covered_nodes"`
	CoveredGPUs  int `json:"covered_gpus"`
	// CoverageComplete is true only with an expected revision, an untruncated
	// comparison, and no expected entity missing or stale.
	CoverageComplete         bool                  `json:"coverage_complete"`
	ObservationWindowSeconds int64                 `json:"observation_window_seconds"`
	ExpectedNotObserved      []GPUMetricsEntityRef `json:"expected_not_observed"`
	ObservedNotExpected      []GPUMetricsEntityRef `json:"observed_not_expected"`
	Truncated                bool                  `json:"truncated"`
	// Observations is the repository's raw presence-and-instant input. It is
	// consumed by DeriveGPUMetricsStates and deliberately not serialized.
	Observations []GPUMetricsObservation `json:"-"`
}

// GPUMetricsRepository is the narrow persistence boundary. It returns the
// committed facts; time-relative states are derived by the service so a fixed
// evaluation instant can be supplied in tests and by the API clock.
type GPUMetricsRepository interface {
	LoadGPUMetrics(context.Context, string) (GPUMetricsSnapshot, error)
}

type gpuHealthRepository interface {
	LoadGPUHealthSummaries(context.Context, string, time.Time, time.Duration) ([]application.GPUSummaryProjection, error)
}

type gpuMetricsSnapshotRepository interface {
	LoadGPUMetricsWithHealth(context.Context, string, time.Time, time.Duration) (GPUMetricsSnapshot, error)
}

// GPUMetrics returns the persisted expanded-DCGM evidence for one cluster.
func (service *Service) GPUMetrics(ctx context.Context, query GPUMetricsQuery) (GPUMetricsSnapshot, error) {
	repository, ok := service.repository.(GPUMetricsRepository)
	if !ok {
		return GPUMetricsSnapshot{}, fmt.Errorf("admin view repository does not project GPU metrics")
	}
	if !validClusterID(query.ClusterID) {
		return GPUMetricsSnapshot{}, fmt.Errorf("admin view cluster ID is invalid")
	}
	if query.Now.IsZero() {
		query.Now = service.now()
	}
	now := query.Now.UTC()
	var snapshot GPUMetricsSnapshot
	var err error
	_, combined := service.repository.(gpuMetricsSnapshotRepository)
	if combined {
		snapshot, err = service.repository.(gpuMetricsSnapshotRepository).LoadGPUMetricsWithHealth(ctx, query.ClusterID, now, service.gpuHealthFreshFor)
	} else {
		snapshot, err = repository.LoadGPUMetrics(ctx, query.ClusterID)
	}
	if err != nil {
		return GPUMetricsSnapshot{}, fmt.Errorf("load GPU metrics projection: %w", err)
	}
	snapshot.ClusterID = query.ClusterID
	snapshot.GeneratedAt = now
	DeriveGPUMetricsStates(&snapshot, now)
	if healthRepository, ok := service.repository.(gpuHealthRepository); ok && !combined {
		summaries, err := healthRepository.LoadGPUHealthSummaries(ctx, query.ClusterID, now, service.gpuHealthFreshFor)
		if err != nil {
			return GPUMetricsSnapshot{}, fmt.Errorf("load shared GPU health projection: %w", err)
		}
		attachGPUMetricsConditions(&snapshot, summaries)
	}
	return snapshot, nil
}

func attachGPUMetricsConditions(snapshot *GPUMetricsSnapshot, summaries []application.GPUSummaryProjection) {
	byIdentity := make(map[string][]domain.HealthSignal, len(summaries))
	for _, summary := range summaries {
		byIdentity[string(summary.SourceID)+"\x00"+summary.EntityKey] = summary.Signals
	}
	for index := range snapshot.GPUs {
		row := &snapshot.GPUs[index]
		if row.MIGIdentity != "" {
			continue
		}
		identity, err := domain.CreateEntityIdentity(domain.EntityIdentity{ClusterID: domain.ClusterID(snapshot.ClusterID), Kind: domain.EntityGPU,
			NodeID: domain.StableNodeID(row.NodeID), PhysicalGPUUUID: domain.PhysicalGPUUUID(row.GPUUUID)})
		if err != nil {
			continue
		}
		row.Conditions = byIdentity[row.SourceID+"\x00"+identity.Key()]
	}
}

// attachGPUMetricsValues consumes the same per-device admission and assessments
// as conditions. A newer node-only attempt must not replace its sibling's run;
// a missing latest field must not borrow a historical current projection.
func attachGPUMetricsValues(snapshot *GPUMetricsSnapshot, summaries []application.GPUSummaryProjection, support map[string][]domain.DCGMFieldEvidence) {
	byIdentity := make(map[string]application.GPUSummaryProjection, len(summaries))
	for _, summary := range summaries {
		byIdentity[string(summary.SourceID)+"\x00"+summary.EntityKey] = summary
	}
	for index := range snapshot.GPUs {
		row := &snapshot.GPUs[index]
		if row.MIGIdentity != "" {
			continue
		}
		entity, err := domain.CreateEntityIdentity(domain.EntityIdentity{ClusterID: domain.ClusterID(snapshot.ClusterID), Kind: domain.EntityGPU,
			NodeID: domain.StableNodeID(row.NodeID), PhysicalGPUUUID: domain.PhysicalGPUUUID(row.GPUUUID)})
		if err != nil {
			continue
		}
		key := row.SourceID + "\x00" + entity.Key()
		if row.Values == nil {
			row.Values = map[string]GPUMetricValue{}
		}
		assessments := map[string]string{}
		for _, field := range support[key] {
			assessments[field.Metric] = field.State
		}
		observations := map[string][]domain.Observation{}
		for _, observation := range byIdentity[key].Observations {
			observations[observation.Metric] = append(observations[observation.Metric], observation)
		}
		for _, field := range snapshot.Fields {
			value := GPUMetricValue{State: GPUMetricNoData, Unit: field.Unit, Semantics: field.Semantics}
			state, assessed := assessments[field.Name]
			if assessed {
				value.State = GPUMetricUnknown
			}
			if state == string(GPUMetricNotSupported) {
				value.State = GPUMetricNotSupported
			}
			if state == string(GPUMetricSupported) && len(observations[field.Name]) > 0 {
				samples := observations[field.Name]
				latest := samples[0]
				for _, candidate := range samples[1:] {
					if candidate.ObservedAt.After(latest.ObservedAt) {
						latest = candidate
					}
				}
				valid := domain.ValidGPUHealthObservation(latest)
				var explicit *domain.MetricSemantics
				for _, candidate := range samples {
					if candidate.ObservedAt.Equal(latest.ObservedAt) && (!domain.ValidGPUHealthObservation(candidate) || candidate.Value != latest.Value) {
						valid = false
					}
					if candidate.ObservedAt.Equal(latest.ObservedAt) && candidate.Semantics != nil {
						if explicit != nil && *explicit != *candidate.Semantics {
							valid = false
						}
						explicit = candidate.Semantics
					}
				}
				if valid {
					number, observed := latest.Value, latest.ObservedAt.UTC()
					value.State, value.Value, value.ObservedAt, value.Unit = GPUMetricSupported, &number, &observed, latest.Unit
					if explicit != nil {
						value.Semantics, value.ResetObserved = explicit.Kind, explicit.ResetObserved
					}
				}
			}
			row.Values[field.Name] = value
		}
	}
}

// DeriveGPUMetricsStates applies every time-relative rule in this projection:
// run freshness against the operation window, value staleness, observed-target
// staleness, and the coverage comparison that follows from it. It is the only
// place an instant is compared with a committed record.
func DeriveGPUMetricsStates(snapshot *GPUMetricsSnapshot, now time.Time) {
	now = now.UTC()
	windows := make(map[string]map[string]time.Duration, len(snapshot.Sources))
	observationWindows := make(map[string]time.Duration, len(snapshot.Sources))
	for sourceIndex := range snapshot.Sources {
		source := &snapshot.Sources[sourceIndex]
		if windows[source.SourceID] == nil {
			windows[source.SourceID] = make(map[string]time.Duration)
		}
		for operationIndex := range source.Operations {
			operation := &source.Operations[operationIndex]
			window := gpuMetricsWindow(operation)
			operation.FreshWindowSeconds = int64(window / time.Second)
			operation.Freshness = gpuMetricsRunFreshness(operation.LastRun, now, window)
			for _, field := range operation.Fields {
				windows[source.SourceID][field.Name] = window
			}
			if window > observationWindows[source.SourceID] {
				observationWindows[source.SourceID] = window
			}
		}
	}
	deriveGPUMetricsValues(snapshot, now, windows)
	deriveGPUMetricsObservedStates(snapshot, now, observationWindows)
	deriveGPUMetricsCoverage(snapshot, now, gpuMetricsObservationWindow(observationWindows, snapshot.Inventory.SourceID))
	deriveGPUMetricsFieldDenominators(snapshot)
}

// gpuMetricsRunFreshness never reports FRESH for a run that produced no usable
// evidence: a failing run is a collection problem, not current evidence.
func gpuMetricsRunFreshness(run *GPUMetricsRun, now time.Time, window time.Duration) GPUMetricsFreshness {
	if run == nil || run.CompletedAt.IsZero() {
		return GPUMetricsNoData
	}
	if !gpuMetricsRunYieldsEvidence(run.Status) {
		return GPUMetricsFailing
	}
	age := now.Sub(run.CompletedAt.UTC())
	switch {
	case age < -GPUMetricsClockSkewTolerance:
		return GPUMetricsClockSkewed
	case age > window:
		return GPUMetricsFreshnessOld
	default:
		return GPUMetricsFresh
	}
}

// gpuMetricsRunYieldsEvidence lists the only committed statuses whose field
// assessments are meaningful. Everything else, including FAILED, TIMEOUT and
// an unrecognized status, yields no support claim.
func gpuMetricsRunYieldsEvidence(status string) bool {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "SUCCEEDED", "PARTIAL":
		return true
	default:
		return false
	}
}

func deriveGPUMetricsValues(snapshot *GPUMetricsSnapshot, now time.Time, windows map[string]map[string]time.Duration) {
	for rowIndex := range snapshot.GPUs {
		row := &snapshot.GPUs[rowIndex]
		for name, value := range row.Values {
			window, ok := windows[row.SourceID][name]
			if !ok {
				window = GPUMetricsDefaultFreshFor
			}
			if value.State == GPUMetricSupported {
				value.State = gpuMetricsSupportedState(value, now, window)
			}
			if value.State != GPUMetricSupported {
				// A non-supported cell must never carry a renderable number.
				value.Value = nil
			}
			row.Values[name] = value
		}
	}
}

// gpuMetricsSupportedState downgrades a supported cell that cannot honestly be
// rendered as a number: a non-finite sample and a sample from a clock that
// disagrees with the reader are both UNKNOWN, never a value and never zero.
func gpuMetricsSupportedState(value GPUMetricValue, now time.Time, window time.Duration) GPUMetricState {
	if value.Value == nil || math.IsNaN(*value.Value) || math.IsInf(*value.Value, 0) {
		return GPUMetricUnknown
	}
	if value.ObservedAt == nil {
		return GPUMetricStale
	}
	age := now.Sub(value.ObservedAt.UTC())
	switch {
	case age < -GPUMetricsClockSkewTolerance:
		return GPUMetricUnknown
	case age > window:
		return GPUMetricStale
	default:
		return GPUMetricSupported
	}
}

func deriveGPUMetricsObservedStates(snapshot *GPUMetricsSnapshot, now time.Time, windows map[string]time.Duration) {
	for rowIndex := range snapshot.GPUs {
		row := &snapshot.GPUs[rowIndex]
		observed := row.ObservedAt
		if !row.Observed {
			observed = nil
		}
		row.ObservedState = gpuMetricsObservedStateFor(observed, now, gpuMetricsObservationWindow(windows, row.SourceID))
	}
}

func gpuMetricsObservationWindow(windows map[string]time.Duration, sourceID string) time.Duration {
	if window, ok := windows[sourceID]; ok && window > 0 {
		return window
	}
	return GPUMetricsDefaultFreshFor
}

// gpuMetricsObservedStateFor decides whether a never-pruned target record is
// still evidence of collection. Presence with an old instant is OBSERVED_STALE,
// which is a gap, not health.
func gpuMetricsObservedStateFor(observedAt *time.Time, now time.Time, window time.Duration) GPUMetricsObservedState {
	if observedAt == nil || observedAt.IsZero() {
		return GPUMetricsNotObserved
	}
	if now.Sub(observedAt.UTC()) < -GPUMetricsClockSkewTolerance {
		return GPUMetricsObservedUnknown
	}
	if now.Sub(observedAt.UTC()) > window {
		return GPUMetricsObservedStale
	}
	return GPUMetricsObserved
}

// deriveGPUMetricsCoverage rebuilds the inventory comparison from the raw
// observations. An expected entity counts as covered only with a fresh
// observation; a stale one is listed as a gap and marked Stale.
func deriveGPUMetricsCoverage(snapshot *GPUMetricsSnapshot, now time.Time, window time.Duration) {
	inventory := &snapshot.Inventory
	inventory.ObservationWindowSeconds = int64(window / time.Second)
	if inventory.ExpectedNotObserved == nil {
		inventory.ExpectedNotObserved = []GPUMetricsEntityRef{}
	}
	if inventory.ObservedNotExpected == nil {
		inventory.ObservedNotExpected = []GPUMetricsEntityRef{}
	}
	if len(inventory.Observations) == 0 {
		inventory.CoverageComplete = inventory.HasExpectedRevision &&
			len(inventory.ExpectedNotObserved) == 0 && !inventory.Truncated
		return
	}
	expectedNodes, expectedGPUs := 0, 0
	for _, observation := range inventory.Observations {
		if !observation.Expected {
			continue
		}
		if observation.GPUUUID == "" {
			expectedNodes++
			continue
		}
		expectedGPUs++
	}
	missing, extra := []GPUMetricsEntityRef{}, []GPUMetricsEntityRef{}
	inventory.ExpectedNodes, inventory.ExpectedGPUs = expectedNodes, expectedGPUs
	inventory.ObservedNodes, inventory.ObservedGPUs = 0, 0
	inventory.FreshObservedNodes, inventory.FreshObservedGPUs, inventory.StaleObservedGPUs = 0, 0, 0
	inventory.CoveredNodes, inventory.CoveredGPUs = 0, 0
	for _, observation := range inventory.Observations {
		state := gpuMetricsObservedStateFor(observation.ObservedAt, now, window)
		isGPU := observation.GPUUUID != ""
		ref := GPUMetricsEntityRef{
			NodeID: observation.NodeID, GPUUUID: observation.GPUUUID,
			Stale: state == GPUMetricsObservedStale, Unknown: state == GPUMetricsObservedUnknown, ObservedAt: observation.ObservedAt,
		}
		if observation.Expected {
			switch {
			case state == GPUMetricsObserved && isGPU:
				inventory.CoveredGPUs++
			case state == GPUMetricsObserved:
				inventory.CoveredNodes++
			default:
				missing = append(missing, ref)
			}
		}
		if state == GPUMetricsNotObserved {
			continue
		}
		if isGPU {
			inventory.ObservedGPUs++
			if state == GPUMetricsObservedStale {
				inventory.StaleObservedGPUs++
			} else if state == GPUMetricsObserved {
				inventory.FreshObservedGPUs++
			}
		} else {
			inventory.ObservedNodes++
			if state == GPUMetricsObserved {
				inventory.FreshObservedNodes++
			}
		}
		if observation.Expected {
			continue
		}
		if (isGPU && expectedGPUs > 0) || (!isGPU && expectedNodes > 0) {
			extra = append(extra, ref)
		}
	}
	var missingTruncated, extraTruncated bool
	inventory.ExpectedNotObserved, missingTruncated = boundGPUMetricsRefs(missing)
	inventory.ObservedNotExpected, extraTruncated = boundGPUMetricsRefs(extra)
	inventory.Truncated = inventory.Truncated || missingTruncated || extraTruncated
	inventory.CoverageComplete = inventory.HasExpectedRevision && len(missing) == 0 && !inventory.Truncated
}

// boundGPUMetricsRefs orders and caps an inventory list and states whether the
// cap dropped entries, so a bounded list is never read as a complete one.
func boundGPUMetricsRefs(refs []GPUMetricsEntityRef) ([]GPUMetricsEntityRef, bool) {
	sort.Slice(refs, func(a, b int) bool {
		if refs[a].NodeID != refs[b].NodeID {
			return refs[a].NodeID < refs[b].NodeID
		}
		return refs[a].GPUUUID < refs[b].GPUUUID
	})
	if len(refs) > GPUMetricsRowLimit {
		return refs[:GPUMetricsRowLimit], true
	}
	return refs, false
}

// deriveGPUMetricsFieldDenominators gives every field summary its denominator.
// An expected GPU the newest run never assessed is UNKNOWN, so a run that
// assessed one GPU out of a hundred cannot read as fleet-wide support.
func deriveGPUMetricsFieldDenominators(snapshot *GPUMetricsSnapshot) {
	for sourceIndex := range snapshot.Sources {
		source := &snapshot.Sources[sourceIndex]
		expected := 0
		if source.Primary && source.SourceID == snapshot.Inventory.SourceID {
			expected = snapshot.Inventory.ExpectedGPUs
		}
		for operationIndex := range source.Operations {
			operation := &source.Operations[operationIndex]
			for index := range operation.FieldSummaries {
				summary := &operation.FieldSummaries[index]
				summary.Unknown -= summary.UnassessedExpected
				if summary.Unknown < 0 {
					summary.Unknown = 0
				}
				if assessed := summary.Supported + summary.NotSupported + summary.Unknown; summary.Assessed < assessed {
					summary.Assessed = assessed
				}
				summary.Expected = expected
				summary.UnassessedExpected = 0
				if gap := expected - summary.Assessed; gap > 0 {
					summary.UnassessedExpected = gap
				}
				summary.Unknown += summary.UnassessedExpected
				summary.Dominant = DominantFieldState(*summary)
			}
		}
	}
}

func gpuMetricsWindow(operation *GPUMetricsOperation) time.Duration {
	if operation.Enrolled && operation.IntervalSeconds > 0 {
		return 2 * time.Duration(operation.IntervalSeconds) * time.Second
	}
	return GPUMetricsDefaultFreshFor
}

// DominantFieldState resolves the summary badge. Ties and empty assessments
// never resolve to SUPPORTED.
func DominantFieldState(summary GPUMetricsFieldSummary) GPUMetricState {
	if summary.Supported+summary.NotSupported+summary.Unknown == 0 {
		return GPUMetricUnknown
	}
	switch {
	case summary.Unknown >= summary.Supported && summary.Unknown >= summary.NotSupported:
		return GPUMetricUnknown
	case summary.NotSupported >= summary.Supported:
		return GPUMetricNotSupported
	default:
		return GPUMetricSupported
	}
}
