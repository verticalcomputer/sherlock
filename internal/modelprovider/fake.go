package modelprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
)

var (
	ErrNoPlanningResult  = errors.New("fake model provider has no planning result")
	ErrNoSynthesisResult = errors.New("fake model provider has no synthesis result")
)

type PlanningStep struct {
	Result PlanningResult
	Err    error
}

type SynthesisStep struct {
	Result SynthesisResult
	Err    error
}

// FakeProvider returns queued results in a deterministic order and records
// defensive copies of every valid request. It is safe for concurrent tests.
type FakeProvider struct {
	mu             sync.Mutex
	planning       []PlanningStep
	synthesis      []SynthesisStep
	planningIndex  int
	synthesisIndex int
	planningCalls  []PlanningRequest
	synthesisCalls []SynthesisRequest
}

func NewFakeProvider(planning []PlanningStep, synthesis []SynthesisStep) (*FakeProvider, error) {
	for _, step := range planning {
		if step.Err != nil && !reflect.DeepEqual(step.Result, PlanningResult{}) {
			return nil, fmt.Errorf("planning step cannot contain both result and error")
		}
	}
	for _, step := range synthesis {
		if step.Err != nil && !reflect.DeepEqual(step.Result, SynthesisResult{}) {
			return nil, fmt.Errorf("synthesis step cannot contain both result and error")
		}
	}
	planningCopy := make([]PlanningStep, len(planning))
	for index, step := range planning {
		planningCopy[index] = PlanningStep{Result: cloneJSON(step.Result), Err: step.Err}
	}
	synthesisCopy := make([]SynthesisStep, len(synthesis))
	for index, step := range synthesis {
		synthesisCopy[index] = SynthesisStep{Result: cloneJSON(step.Result), Err: step.Err}
	}
	return &FakeProvider{planning: planningCopy, synthesis: synthesisCopy}, nil
}

func (provider *FakeProvider) Plan(ctx context.Context, request PlanningRequest) (PlanningResult, error) {
	if err := ctx.Err(); err != nil {
		return PlanningResult{}, err
	}
	if err := request.Validate(); err != nil {
		return PlanningResult{}, fmt.Errorf("validate planning request: %w", err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.planningCalls = append(provider.planningCalls, cloneJSON(request))
	if provider.planningIndex >= len(provider.planning) {
		return PlanningResult{}, ErrNoPlanningResult
	}
	step := provider.planning[provider.planningIndex]
	provider.planningIndex++
	if step.Err != nil {
		return PlanningResult{}, step.Err
	}
	if err := step.Result.ValidateFor(request); err != nil {
		return PlanningResult{}, fmt.Errorf("validate planning result: %w", err)
	}
	return cloneJSON(step.Result), nil
}

func (provider *FakeProvider) Synthesize(ctx context.Context, request SynthesisRequest) (SynthesisResult, error) {
	if err := ctx.Err(); err != nil {
		return SynthesisResult{}, err
	}
	if err := request.Validate(); err != nil {
		return SynthesisResult{}, fmt.Errorf("validate synthesis request: %w", err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.synthesisCalls = append(provider.synthesisCalls, cloneJSON(request))
	if provider.synthesisIndex >= len(provider.synthesis) {
		return SynthesisResult{}, ErrNoSynthesisResult
	}
	step := provider.synthesis[provider.synthesisIndex]
	provider.synthesisIndex++
	if step.Err != nil {
		return SynthesisResult{}, step.Err
	}
	if err := step.Result.ValidateFor(request); err != nil {
		return SynthesisResult{}, fmt.Errorf("validate synthesis result: %w", err)
	}
	return cloneJSON(step.Result), nil
}

func (provider *FakeProvider) PlanningCalls() []PlanningRequest {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return cloneJSON(provider.planningCalls)
}

func (provider *FakeProvider) SynthesisCalls() []SynthesisRequest {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return cloneJSON(provider.synthesisCalls)
}

type PlanningCall struct {
	Request PlanningRequest
	Result  PlanningResult
	Failed  bool
}

type SynthesisCall struct {
	Request SynthesisRequest
	Result  SynthesisResult
	Failed  bool
}

// RecordingProvider decorates a provider for controller and audit tests. It
// records structured values and a failure bit, never an unrestricted provider
// error body.
type RecordingProvider struct {
	provider  Provider
	mu        sync.Mutex
	planning  []PlanningCall
	synthesis []SynthesisCall
}

func NewRecordingProvider(provider Provider) (*RecordingProvider, error) {
	if provider == nil {
		return nil, fmt.Errorf("model provider is required")
	}
	return &RecordingProvider{provider: provider}, nil
}

func (provider *RecordingProvider) Plan(ctx context.Context, request PlanningRequest) (PlanningResult, error) {
	result, err := provider.provider.Plan(ctx, request)
	provider.mu.Lock()
	provider.planning = append(provider.planning, PlanningCall{Request: cloneJSON(request), Result: cloneJSON(result), Failed: err != nil})
	provider.mu.Unlock()
	return result, err
}

func (provider *RecordingProvider) Synthesize(ctx context.Context, request SynthesisRequest) (SynthesisResult, error) {
	result, err := provider.provider.Synthesize(ctx, request)
	provider.mu.Lock()
	provider.synthesis = append(provider.synthesis, SynthesisCall{Request: cloneJSON(request), Result: cloneJSON(result), Failed: err != nil})
	provider.mu.Unlock()
	return result, err
}

func (provider *RecordingProvider) PlanningCalls() []PlanningCall {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return cloneJSON(provider.planning)
}
func (provider *RecordingProvider) SynthesisCalls() []SynthesisCall {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return cloneJSON(provider.synthesis)
}

func cloneJSON[T any](value T) T {
	// Every boundary type consists only of JSON-compatible values. Marshal can
	// fail only after a programmer change, in which case returning zero makes a
	// test fail without introducing a runtime panic at the model boundary.
	encoded, err := json.Marshal(value)
	if err != nil {
		var zero T
		return zero
	}
	var result T
	if json.Unmarshal(encoded, &result) != nil {
		var zero T
		return zero
	}
	return result
}
