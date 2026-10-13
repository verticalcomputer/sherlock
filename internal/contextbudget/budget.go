// Package contextbudget performs deterministic pre-provider input accounting.
package contextbudget

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/modelprovider"
)

var ErrAllowanceExceeded = errors.New("provider input exceeds preflight allowance")
var ErrEstimatorUnderrun = errors.New("TOKEN_ESTIMATOR_UNDERRUN")
var ErrRequiredContextExceeded = errors.New("REQUIRED_CONTEXT_EXCEEDS_ALLOWANCE")

// ErrProspectiveRunBudget retains the precise admission failure used by safe
// operational logs while also classifying the failure as an investigation
// budget exhaustion for the durable terminal state.
var ErrProspectiveRunBudget error = prospectiveRunBudgetError{}

type prospectiveRunBudgetError struct{}

func (prospectiveRunBudgetError) Error() string { return "PROSPECTIVE_RUN_BUDGET_EXCEEDED" }
func (prospectiveRunBudgetError) Unwrap() error { return domain.ErrInvestigationBudgetExceeded }

type Estimator interface {
	Estimate([]byte) int64
	Version() string
}

// JSONHeuristicEstimator is deterministic and intentionally rounded upward.
// Provider-reported usage remains the authoritative post-call measurement.
type JSONHeuristicEstimator struct{}

func (JSONHeuristicEstimator) Estimate(value []byte) int64 { return int64((len(value) + 3) / 4) }
func (JSONHeuristicEstimator) Version() string             { return "json-bytes-ceil-div4-v1" }

type Config struct {
	MaximumInputTokens       int64
	MaximumMemoryTokens      int64
	MaximumMemoryEntries     int
	ProviderOverheadTokens   int64
	MaximumOutputTokens      int64
	FixedMarginTokens        int64
	FallbackFactorMillionths int64
	InputMicrosPerMillion    int64
	OutputMicrosPerMillion   int64
}

func DefaultConfig() Config {
	// FallbackFactorMillionths is the multiplier applied until enough calibration
	// samples exist, and it must stay low because the two failure modes are not
	// symmetric. Under-estimating spends budget faster than planned; the run
	// still progresses. Over-estimating is fatal: PreparePlanning cannot shrink
	// required context, so it returns REQUIRED_CONTEXT_EXCEEDS_ALLOWANCE and the
	// investigation ends before any model call.
	//
	// The true factor is a property of payload composition, not of the provider.
	// Measured live: identifier-dense pilot payloads carrying 44 GPU UUIDs needed
	// 2.105 to 2.369, while four-entity payloads of the same schema needed 0.95
	// to 1.21, because the estimator's four-characters-per-token rule fits prose
	// and structure but not high-entropy identifiers. A single constant cannot
	// serve both, and raising this to 2.5 to cover the dense case converted
	// runs that fitted comfortably into hard failures. Until the estimator
	// itself accounts for content, keep the conservative-but-survivable value
	// and let recorded calibration samples supersede it.
	return Config{MaximumInputTokens: 20_000, MaximumMemoryTokens: 1_000, MaximumMemoryEntries: 12, ProviderOverheadTokens: 0, MaximumOutputTokens: 4_096, FixedMarginTokens: 256, FallbackFactorMillionths: 1_600_000}
}

type Manifest struct {
	ID                          string
	ClusterID                   domain.ClusterID
	InvestigationID             domain.InvestigationID
	CallKey                     string
	CallKind                    application.ModelCallKind
	EstimatorVersion            string
	PromptSchemaVersion         string
	ToolSchemaVersion           string
	AllowanceTokens             int64
	EstimatedInputTokens        int64
	RawEstimatedInputTokens     int64
	CalibrationFactorMillionths int64
	CalibrationSampleCount      int
	FixedMarginTokens           int64
	MaximumOutputTokens         int64
	MemoryAllowanceTokens       int64
	MemoryCandidateCount        int
	SelectedMemoryIDs           []string
	SelectedEvidenceIDs         []string
	ExclusionReasons            map[string]int
	SectionTokens               map[string]int64
	RetrievalLatency            time.Duration
	IndexVersion                string
	FallbackState               string
	ShadowOnly                  bool
	CreatedAt                   time.Time
	ActualInputTokens           int64
	EstimatorUnderrun           bool
	ContextMode                 string
	CheckpointDigest            string
	DeltaFromVersion            int
}

type Sink interface {
	RecordContextManifest(context.Context, Manifest) error
}

type ProviderDocumenter interface {
	PlanningInputDocument(modelprovider.PlanningRequest) ([]byte, error)
	SynthesisInputDocument(modelprovider.SynthesisRequest) ([]byte, error)
}

type CalibrationKey struct{ Provider, Model, ConfigurationID, PromptSchemaVersion, ToolSchemaVersion, EstimatorVersion string }
type CalibrationStore interface {
	LoadCalibrationRatios(context.Context, CalibrationKey, int) ([]int64, error)
	RecordCalibrationSample(context.Context, CalibrationKey, Manifest, int64) error
}
type ActualUsageSink interface {
	RecordActualContextUsage(context.Context, Manifest, int64, bool) error
}

type Selection struct {
	CandidateCount   int
	RetrievalLatency time.Duration
	IndexVersion     string
	FallbackState    string
	ShadowOnly       bool
	ExclusionReasons map[string]int
}

type Manager struct {
	config         Config
	estimator      Estimator
	sink           Sink
	now            func() time.Time
	documenter     ProviderDocumenter
	calibration    CalibrationStore
	calibrationKey CalibrationKey
}

func (manager *Manager) ConfigureCalibration(store CalibrationStore, key CalibrationKey) error {
	if manager == nil || store == nil || key.Provider == "" || key.Model == "" || key.ConfigurationID == "" {
		return fmt.Errorf("token calibration configuration is invalid")
	}
	key.EstimatorVersion = manager.estimator.Version()
	manager.calibration, manager.calibrationKey = store, key
	return nil
}

func (manager *Manager) ConfigureProviderDocumenter(documenter ProviderDocumenter) error {
	if manager == nil || documenter == nil {
		return fmt.Errorf("provider input documenter is required")
	}
	manager.documenter = documenter
	return nil
}

func New(config Config, estimator Estimator, sink Sink) (*Manager, error) {
	if config.FallbackFactorMillionths == 0 {
		config.FallbackFactorMillionths = 1_000_000
	}
	if config.MaximumInputTokens < 1024 || config.MaximumInputTokens > 1_000_000 || config.MaximumMemoryTokens < 0 || config.MaximumMemoryTokens > config.MaximumInputTokens || config.MaximumMemoryEntries < 0 || config.MaximumMemoryEntries > 12 || config.ProviderOverheadTokens < 0 || config.MaximumOutputTokens < 0 || config.FixedMarginTokens < 0 || config.FallbackFactorMillionths < 1_000_000 || config.FallbackFactorMillionths > 3_000_000 || estimator == nil || sink == nil {
		return nil, fmt.Errorf("context budget configuration is invalid")
	}
	return &Manager{config: config, estimator: estimator, sink: sink, now: time.Now}, nil
}

func (manager *Manager) PreparePlanning(ctx context.Context, snapshot application.InvestigationSnapshot, callKey string, request modelprovider.PlanningRequest, selection Selection) (modelprovider.PlanningRequest, Manifest, error) {
	manifest := manager.base(snapshot, callKey, application.ModelCallPlanning, selection)
	if len(request.PriorActions) > 256 {
		manifest.ExclusionReasons["prior_action_item_limit"] += len(request.PriorActions) - 256
		request.PriorActions = slices.Clone(request.PriorActions[len(request.PriorActions)-256:])
	}
	if len(request.Memory) > manager.config.MaximumMemoryEntries {
		manifest.ExclusionReasons["memory_entry_limit"] += len(request.Memory) - manager.config.MaximumMemoryEntries
		request.Memory = request.Memory[:manager.config.MaximumMemoryEntries]
	}
	for estimateValue(manager.estimator, request.Memory) > manager.config.MaximumMemoryTokens && len(request.Memory) > 0 {
		request.Memory = request.Memory[:len(request.Memory)-1]
		manifest.ExclusionReasons["memory_token_limit"]++
	}
	// Prior actions are ordered durably. Retain the newest suffix when the full
	// provider request would exceed its allowance; failures and exact scope stay
	// inside each retained action and are never summarized into free text.
	for !manager.fitsFallback(request) && len(request.PriorActions) > 0 {
		index := optionalPriorAction(request.PriorActions)
		if index < 0 {
			return modelprovider.PlanningRequest{}, Manifest{}, ErrRequiredContextExceeded
		}
		request.PriorActions = slices.Delete(request.PriorActions, index, index+1)
		manifest.ExclusionReasons["prior_action_compaction"]++
	}
	if err := manager.finishWithoutWrite(ctx, request, &manifest); err != nil {
		return modelprovider.PlanningRequest{}, Manifest{}, err
	}
	for _, entry := range request.Memory {
		manifest.SelectedMemoryIDs = append(manifest.SelectedMemoryIDs, entry.MemoryID)
	}
	if err := manager.prospective(snapshot, manifest); err != nil {
		return modelprovider.PlanningRequest{}, Manifest{}, err
	}
	// Re-record after selected IDs are known. The sink is idempotent by call key.
	if err := manager.sink.RecordContextManifest(ctx, manifest); err != nil {
		return modelprovider.PlanningRequest{}, Manifest{}, fmt.Errorf("persist context manifest: %w", err)
	}
	return request, manifest, nil
}

func (manager *Manager) fitsFallback(value any) bool {
	raw := manager.total(value)
	return conservativeEstimate(raw, manager.config.FallbackFactorMillionths, manager.config.FixedMarginTokens) <= manager.config.MaximumInputTokens
}

func optionalPriorAction(values []modelprovider.PriorAction) int {
	protected := map[string]int{}
	for index, action := range values {
		switch action.Outcome {
		case "NO_EVIDENCE", "FAILED", "REJECTED", "OUTCOME_UNKNOWN":
			protected[action.Outcome+"\x00"+action.ToolID] = index
		}
	}
	for index, action := range values {
		switch action.Outcome {
		case "NO_EVIDENCE", "FAILED", "REJECTED", "OUTCOME_UNKNOWN":
			if protected[action.Outcome+"\x00"+action.ToolID] == index {
				continue
			}
		}
		return index
	}
	return -1
}

func (manager *Manager) PrepareSynthesis(ctx context.Context, snapshot application.InvestigationSnapshot, callKey string, request modelprovider.SynthesisRequest) (modelprovider.SynthesisRequest, Manifest, error) {
	manifest := manager.base(snapshot, callKey, application.ModelCallSynthesis, Selection{FallbackState: "REQUIRED_CONTEXT_ONLY", ShadowOnly: true})
	if err := manager.finishWithoutWrite(ctx, request, &manifest); err != nil {
		return modelprovider.SynthesisRequest{}, Manifest{}, err
	}
	if err := manager.prospective(snapshot, manifest); err != nil {
		return modelprovider.SynthesisRequest{}, Manifest{}, err
	}
	if err := manager.sink.RecordContextManifest(ctx, manifest); err != nil {
		return modelprovider.SynthesisRequest{}, Manifest{}, fmt.Errorf("persist context manifest: %w", err)
	}
	return request, manifest, nil
}

func (manager *Manager) base(snapshot application.InvestigationSnapshot, callKey string, kind application.ModelCallKind, selection Selection) Manifest {
	request := snapshot.Investigation.Request()
	digest := domain.ChecksumSHA256([]byte(string(request.ID) + "\x00" + callKey))
	exclusions := map[string]int{}
	for key, value := range selection.ExclusionReasons {
		exclusions[key] = value
	}
	fallback := selection.FallbackState
	if fallback == "" {
		fallback = "NONE"
	}
	return Manifest{ID: "manifest-" + hex.EncodeToString(digest[:12]), ClusterID: request.ClusterID, InvestigationID: request.ID, CallKey: callKey, CallKind: kind, EstimatorVersion: manager.estimator.Version(), AllowanceTokens: manager.config.MaximumInputTokens, MemoryAllowanceTokens: manager.config.MaximumMemoryTokens, MemoryCandidateCount: selection.CandidateCount, SelectedMemoryIDs: []string{}, SelectedEvidenceIDs: []string{}, ExclusionReasons: exclusions, RetrievalLatency: selection.RetrievalLatency, IndexVersion: selection.IndexVersion, FallbackState: fallback, ShadowOnly: selection.ShadowOnly, CreatedAt: manager.now().UTC(), MaximumOutputTokens: manager.config.MaximumOutputTokens, FixedMarginTokens: manager.config.FixedMarginTokens, ContextMode: "STATELESS"}
}

func (manager *Manager) finishWithoutWrite(ctx context.Context, request any, manifest *Manifest) error {
	manifest.RawEstimatedInputTokens = manager.total(request)
	switch value := request.(type) {
	case modelprovider.PlanningRequest:
		manifest.PromptSchemaVersion, manifest.ToolSchemaVersion = value.PromptVersion, value.ToolSchemaVersion
		manifest.CheckpointDigest, manifest.DeltaFromVersion = value.CheckpointDigest, value.DeltaFromVersion
		if value.ContextMode != "" {
			manifest.ContextMode = value.ContextMode
		}
		for _, evidence := range value.Evidence {
			manifest.SelectedEvidenceIDs = append(manifest.SelectedEvidenceIDs, evidence.EvidenceID)
		}
	case modelprovider.SynthesisRequest:
		manifest.PromptSchemaVersion = value.PromptVersion
		manifest.CheckpointDigest, manifest.DeltaFromVersion = value.CheckpointDigest, value.DeltaFromVersion
		if value.ContextMode != "" {
			manifest.ContextMode = value.ContextMode
		}
		for _, evidence := range value.Evidence {
			manifest.SelectedEvidenceIDs = append(manifest.SelectedEvidenceIDs, evidence.EvidenceID)
		}
	}
	factor, count, err := manager.factor(ctx, *manifest)
	if err != nil {
		return fmt.Errorf("load token calibration: %w", err)
	}
	manifest.CalibrationFactorMillionths, manifest.CalibrationSampleCount = factor, count
	manifest.EstimatedInputTokens = conservativeEstimate(manifest.RawEstimatedInputTokens, factor, manager.config.FixedMarginTokens)
	manifest.SectionTokens = sectionEstimates(manager.estimator, request)
	if manifest.EstimatedInputTokens > manifest.AllowanceTokens {
		return fmt.Errorf("%w: estimated=%d allowance=%d", ErrAllowanceExceeded, manifest.EstimatedInputTokens, manifest.AllowanceTokens)
	}
	return nil
}

func conservativeEstimate(raw, factor, margin int64) int64 {
	if raw < 0 || factor < 1 || margin < 0 || raw > (math.MaxInt64-margin-999_999)/factor {
		return math.MaxInt64
	}
	return (raw*factor+999_999)/1_000_000 + margin
}

func (manager *Manager) factor(ctx context.Context, manifest Manifest) (int64, int, error) {
	if manager.calibration == nil {
		return manager.config.FallbackFactorMillionths, 0, nil
	}
	key := manager.calibrationKey
	key.PromptSchemaVersion, key.ToolSchemaVersion = manifest.PromptSchemaVersion, manifest.ToolSchemaVersion
	ratios, err := manager.calibration.LoadCalibrationRatios(ctx, key, 200)
	if err != nil {
		return 0, 0, err
	}
	return CalibrationFactor(ratios, manager.config.FallbackFactorMillionths), len(ratios), nil
}

func CalibrationFactor(ratios []int64, fallback int64) int64 {
	if len(ratios) < 20 {
		factor := fallback
		for _, ratio := range ratios {
			candidate := (ratio*105 + 99) / 100
			if candidate > factor {
				factor = candidate
			}
		}
		return min(int64(3_000_000), max(int64(1_000_000), factor))
	}
	values := slices.Clone(ratios)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	rank := (95*len(values)+99)/100 - 1
	factor := (values[rank]*105 + 99) / 100
	return min(int64(3_000_000), max(int64(1_000_000), factor))
}

func (manager *Manager) prospective(snapshot application.InvestigationSnapshot, manifest Manifest) error {
	remaining := snapshot.Investigation.Request().Budget
	usage := snapshot.Investigation.Usage()
	if manager.config.MaximumOutputTokens > 0 && remaining.MaxModelTokens-usage.ModelTokens < manifest.EstimatedInputTokens+manager.config.MaximumOutputTokens {
		return ErrProspectiveRunBudget
	}
	if manager.config.InputMicrosPerMillion > 0 && manager.config.OutputMicrosPerMillion > 0 {
		cost := (manifest.EstimatedInputTokens*manager.config.InputMicrosPerMillion+999_999)/1_000_000 + (manager.config.MaximumOutputTokens*manager.config.OutputMicrosPerMillion+999_999)/1_000_000
		if remaining.MaxCostMicros-usage.CostMicros < cost {
			return ErrProspectiveRunBudget
		}
	}
	return nil
}

func (manager *Manager) Observe(ctx context.Context, manifest Manifest, actualInputTokens int64) error {
	if actualInputTokens <= 0 {
		return fmt.Errorf("actual provider input tokens must be positive")
	}
	underrun := actualInputTokens > manifest.EstimatedInputTokens
	if manager.calibration != nil {
		key := manager.calibrationKey
		key.PromptSchemaVersion, key.ToolSchemaVersion = manifest.PromptSchemaVersion, manifest.ToolSchemaVersion
		if err := manager.calibration.RecordCalibrationSample(ctx, key, manifest, actualInputTokens); err != nil {
			return err
		}
	}
	if sink, ok := manager.sink.(ActualUsageSink); ok {
		if err := sink.RecordActualContextUsage(ctx, manifest, actualInputTokens, underrun); err != nil {
			return err
		}
	}
	if underrun {
		return ErrEstimatorUnderrun
	}
	return nil
}

func (manager *Manager) total(value any) int64 {
	var encoded []byte
	if manager.documenter != nil {
		switch request := value.(type) {
		case modelprovider.PlanningRequest:
			var err error
			encoded, err = manager.documenter.PlanningInputDocument(request)
			if err != nil {
				return math.MaxInt64
			}
		case modelprovider.SynthesisRequest:
			var err error
			encoded, err = manager.documenter.SynthesisInputDocument(request)
			if err != nil {
				return math.MaxInt64
			}
		}
	}
	if encoded == nil {
		encoded, _ = json.Marshal(value)
	}
	return manager.estimator.Estimate(encoded) + manager.config.ProviderOverheadTokens
}
func estimateValue(estimator Estimator, value any) int64 {
	encoded, _ := json.Marshal(value)
	return estimator.Estimate(encoded)
}

func sectionEstimates(estimator Estimator, value any) map[string]int64 {
	encoded, _ := json.Marshal(value)
	var sections map[string]json.RawMessage
	_ = json.Unmarshal(encoded, &sections)
	result := map[string]int64{}
	for key, section := range sections {
		result[key] = estimator.Estimate(section)
	}
	return result
}
