// Package azureopenai implements Sherlock's Azure OpenAI Responses API
// boundary without allowing provider transport values to cross into the
// modelprovider contract.
package azureopenai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/modelprovider"
)

const (
	defaultTimeout          = 30 * time.Second
	defaultRetryBackoff     = 200 * time.Millisecond
	defaultMaxResponseBytes = 1 << 20
	defaultMaxOutputTokens  = 4096
)

type ErrorCode string
type ErrorStage string

const (
	ErrorInvalidArgument  ErrorCode = "INVALID_ARGUMENT"
	ErrorUnauthorized     ErrorCode = "UNAUTHORIZED"
	ErrorRateLimited      ErrorCode = "RATE_LIMITED"
	ErrorUnavailable      ErrorCode = "UNAVAILABLE"
	ErrorDeadlineExceeded ErrorCode = "DEADLINE_EXCEEDED"
	ErrorInvalidResponse  ErrorCode = "INVALID_RESPONSE"
	ErrorRefused          ErrorCode = "REFUSED"
	ErrorBudgetExceeded   ErrorCode = "BUDGET_EXCEEDED"
)

const (
	StageRequestBuild       ErrorStage = "REQUEST_BUILD"
	StageTransport          ErrorStage = "TRANSPORT"
	StageHTTPStatus         ErrorStage = "HTTP_STATUS"
	StageResponseRead       ErrorStage = "RESPONSE_READ"
	StageResponseSize       ErrorStage = "RESPONSE_SIZE"
	StageResponseEnvelope   ErrorStage = "RESPONSE_ENVELOPE"
	StageOutputIncomplete   ErrorStage = "OUTPUT_INCOMPLETE"
	StageStructuredDecode   ErrorStage = "STRUCTURED_DECODE"
	StageSemanticValidation ErrorStage = "SEMANTIC_VALIDATION"
	StageCostAccounting     ErrorStage = "COST_ACCOUNTING"
)

// Error deliberately contains no upstream response text, URL, request body,
// response ID, or credential-bearing configuration.
type Error struct {
	Code       ErrorCode
	Stage      ErrorStage
	Retryable  bool
	StatusCode int
	metadata   *modelprovider.CallMetadata
	trace      modelprovider.CallTrace
}

// SafeReasonCode contains only fixed enums and is suitable for durable audit
// metadata. It never includes an endpoint, response body, prompt, or secret.
func (err *Error) SafeReasonCode() string {
	if err == nil || err.Code == "" {
		return "PROVIDER_ERROR"
	}
	if err.Stage == "" {
		return string(err.Code)
	}
	return string(err.Code) + "_" + string(err.Stage)
}

func (err *Error) Error() string {
	if err == nil {
		return "Azure OpenAI request failed"
	}
	return fmt.Sprintf("Azure OpenAI request failed (%s)", err.Code)
}

func (err *Error) ModelCallMetadata() (modelprovider.CallMetadata, bool) {
	if err == nil || err.metadata == nil {
		return modelprovider.CallMetadata{}, false
	}
	return *err.metadata, true
}

func (err *Error) ModelCallTrace() modelprovider.CallTrace {
	if err == nil {
		return modelprovider.CallTrace{}
	}
	return modelprovider.CallTrace{Input: bytes.Clone(err.trace.Input), Output: bytes.Clone(err.trace.Output)}
}

type Config struct {
	Endpoint                    string
	APIKey                      string
	Deployment                  string
	ConfigurationID             string
	Timeout                     time.Duration
	MaxRetries                  int
	RetryBackoff                time.Duration
	MaxResponseBytes            int64
	MaxOutputTokens             int
	HTTPClient                  *http.Client
	InputTokenMicrosPerMillion  int64
	OutputTokenMicrosPerMillion int64
}

type Provider struct {
	endpoint                    *url.URL
	apiKey                      string
	deployment                  string
	configurationID             string
	timeout                     time.Duration
	maxRetries                  int
	retryBackoff                time.Duration
	maxResponseBytes            int64
	maxOutputTokens             int
	client                      *http.Client
	inputTokenMicrosPerMillion  int64
	outputTokenMicrosPerMillion int64
	sleep                       func(context.Context, time.Duration) error
}

func NewProvider(config Config) (*Provider, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.User != nil {
		return nil, &Error{Code: ErrorInvalidArgument}
	}
	host := strings.ToLower(endpoint.Hostname())
	if endpoint.Scheme != "https" && !isLoopback(host) || !isLoopback(host) && !isAzureOpenAIHost(host) {
		return nil, &Error{Code: ErrorInvalidArgument}
	}
	if endpoint.Path != "/openai/v1" && endpoint.Path != "/openai/v1/" {
		return nil, &Error{Code: ErrorInvalidArgument}
	}
	endpoint.Path = "/openai/v1/"
	if !validToken(config.Deployment) || !validToken(config.ConfigurationID) || strings.TrimSpace(config.APIKey) == "" {
		return nil, &Error{Code: ErrorInvalidArgument}
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if config.RetryBackoff == 0 {
		config.RetryBackoff = defaultRetryBackoff
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultMaxResponseBytes
	}
	if config.MaxOutputTokens == 0 {
		config.MaxOutputTokens = defaultMaxOutputTokens
	}
	if config.Timeout <= 0 || config.Timeout > 2*time.Minute || config.MaxRetries < 0 || config.MaxRetries > 2 || config.RetryBackoff <= 0 || config.RetryBackoff > 5*time.Second || config.MaxResponseBytes < 1024 || config.MaxResponseBytes > 4<<20 || config.MaxOutputTokens < 128 || config.MaxOutputTokens > 32768 || config.InputTokenMicrosPerMillion <= 0 || config.OutputTokenMicrosPerMillion <= 0 || config.InputTokenMicrosPerMillion > 1_000_000_000_000 || config.OutputTokenMicrosPerMillion > 1_000_000_000_000 {
		return nil, &Error{Code: ErrorInvalidArgument}
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	clientCopy := *client
	clientCopy.CheckRedirect = rejectRedirect
	return &Provider{
		endpoint: endpoint, apiKey: config.APIKey, deployment: config.Deployment,
		configurationID: config.ConfigurationID, timeout: config.Timeout,
		maxRetries: config.MaxRetries, retryBackoff: config.RetryBackoff,
		maxResponseBytes: config.MaxResponseBytes, maxOutputTokens: config.MaxOutputTokens,
		client: &clientCopy, sleep: sleepContext,
		inputTokenMicrosPerMillion:  config.InputTokenMicrosPerMillion,
		outputTokenMicrosPerMillion: config.OutputTokenMicrosPerMillion,
	}, nil
}

// Authenticated provider calls never follow redirects. Besides preventing an
// API key from crossing origins, this keeps the configured Azure deployment
// endpoint as the sole network authority for a model call.
func rejectRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func (provider *Provider) Plan(ctx context.Context, request modelprovider.PlanningRequest) (modelprovider.PlanningResult, error) {
	if err := request.Validate(); err != nil {
		return modelprovider.PlanningResult{}, &Error{Code: ErrorInvalidArgument, Stage: StageRequestBuild}
	}
	if request.RemainingBudget.ModelTokens > 0 && request.RemainingBudget.ModelTokens < 128 {
		return modelprovider.PlanningResult{}, &Error{Code: ErrorBudgetExceeded, Stage: StageRequestBuild}
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return modelprovider.PlanningResult{}, &Error{Code: ErrorInvalidArgument, Stage: StageRequestBuild}
	}
	schema, err := planningSchemaFor(request)
	if err != nil {
		return modelprovider.PlanningResult{}, &Error{Code: ErrorInvalidArgument, Stage: StageRequestBuild}
	}
	started := time.Now()
	response, err := provider.respond(ctx, "planning", planningInstructions, payload, schema, outputLimit(provider.maxOutputTokens, request.RemainingBudget.ModelTokens))
	if err != nil {
		return modelprovider.PlanningResult{}, err
	}
	metadata, err := provider.metadata(response, time.Since(started))
	if err != nil {
		return modelprovider.PlanningResult{}, attachCallFailure(err, modelprovider.CallTrace{Input: response.input, Output: response.output}, modelprovider.CallMetadata{})
	}
	trace := modelprovider.CallTrace{Input: bytes.Clone(response.input), Output: bytes.Clone(response.output)}
	if response.refused {
		metadata.Outcome = modelprovider.OutcomeRefused
		fallback := modelprovider.PlanningResponse{SchemaVersion: modelprovider.PlanningSchemaVersion, StateSummary: "The model declined to produce a planning decision.", Stop: true, StopReason: stopReason(modelprovider.StopNoUsefulAction)}
		return modelprovider.PlanningResult{Response: fallback, Metadata: metadata, Trace: trace}, nil
	}
	value, err := modelprovider.DecodePlanningResponse(response.output, request)
	if err != nil {
		return modelprovider.PlanningResult{}, attachCallFailure(structuredOutputError(err), trace, metadata)
	}
	return modelprovider.PlanningResult{Response: value, Metadata: metadata, Trace: trace}, nil
}

func (provider *Provider) PlanningInputDocument(request modelprovider.PlanningRequest) ([]byte, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	schema, err := planningSchemaFor(request)
	if err != nil {
		return nil, err
	}
	return provider.requestDocument("planning", planningInstructions, payload, schema, outputLimit(provider.maxOutputTokens, request.RemainingBudget.ModelTokens))
}

func (provider *Provider) SynthesisInputDocument(request modelprovider.SynthesisRequest) ([]byte, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	schema, err := synthesisSchemaFor(request)
	if err != nil {
		return nil, err
	}
	return provider.requestDocument("synthesis", synthesisInstructions, payload, schema, provider.maxOutputTokens)
}

func (provider *Provider) Synthesize(ctx context.Context, request modelprovider.SynthesisRequest) (modelprovider.SynthesisResult, error) {
	if err := request.Validate(); err != nil {
		return modelprovider.SynthesisResult{}, &Error{Code: ErrorInvalidArgument, Stage: StageRequestBuild}
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return modelprovider.SynthesisResult{}, &Error{Code: ErrorInvalidArgument, Stage: StageRequestBuild}
	}
	schema, err := synthesisSchemaFor(request)
	if err != nil {
		return modelprovider.SynthesisResult{}, &Error{Code: ErrorInvalidArgument, Stage: StageRequestBuild}
	}
	started := time.Now()
	response, err := provider.respond(ctx, "synthesis", synthesisInstructions, payload, schema, provider.maxOutputTokens)
	if err != nil {
		return modelprovider.SynthesisResult{}, err
	}
	metadata, err := provider.metadata(response, time.Since(started))
	if err != nil {
		return modelprovider.SynthesisResult{}, attachCallFailure(err, modelprovider.CallTrace{Input: response.input, Output: response.output}, modelprovider.CallMetadata{})
	}
	trace := modelprovider.CallTrace{Input: bytes.Clone(response.input), Output: bytes.Clone(response.output)}
	if response.refused {
		metadata.Outcome = modelprovider.OutcomeRefused
		fallback := modelprovider.SynthesisResponse{SchemaVersion: modelprovider.SynthesisSchemaVersion}
		return modelprovider.SynthesisResult{Response: fallback, Metadata: metadata, Trace: trace}, nil
	}
	value, err := modelprovider.DecodeSynthesisResponse(response.output, request)
	if err != nil {
		return modelprovider.SynthesisResult{}, attachCallFailure(structuredOutputError(err), trace, metadata)
	}
	return modelprovider.SynthesisResult{Response: value, Metadata: metadata, Trace: trace}, nil
}

type Health struct {
	Healthy         bool
	Provider        string
	Deployment      string
	ConfigurationID string
	Latency         time.Duration
}

// CheckHealth verifies that the configured deployment accepts a strict
// Responses API request. It never returns model text or provider error bodies.
func (provider *Provider) CheckHealth(ctx context.Context) (Health, error) {
	started := time.Now()
	response, err := provider.respond(ctx, "health", healthInstructions, []byte(`{"probe":"health"}`), healthSchema, 64)
	latency := time.Since(started)
	health := Health{Provider: "azure-openai", Deployment: provider.deployment, ConfigurationID: provider.configurationID, Latency: latency}
	if err != nil {
		return health, err
	}
	var value struct {
		OK bool `json:"ok"`
	}
	if response.refused || json.Unmarshal(response.output, &value) != nil || !value.OK {
		return health, &Error{Code: ErrorInvalidResponse, Stage: StageSemanticValidation}
	}
	health.Healthy = true
	return health, nil
}

type responseRequest struct {
	Model           string         `json:"model"`
	Instructions    string         `json:"instructions"`
	Input           []inputMessage `json:"input"`
	Text            textConfig     `json:"text"`
	MaxOutputTokens int            `json:"max_output_tokens"`
	Store           bool           `json:"store"`
}

type inputMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type textConfig struct {
	Format schemaFormat `json:"format"`
}
type schemaFormat struct {
	Type   string          `json:"type"`
	Name   string          `json:"name"`
	Schema json.RawMessage `json:"schema"`
	Strict bool            `json:"strict"`
}

type wireResponse struct {
	Model             string `json:"model"`
	Status            string `json:"status"`
	IncompleteDetails *struct {
		Reason string `json:"reason"`
	} `json:"incomplete_details"`
	Output []struct {
		Type    string `json:"type"`
		Content []struct {
			Type    string `json:"type"`
			Text    string `json:"text"`
			Refusal string `json:"refusal"`
		} `json:"content"`
	} `json:"output"`
	Usage struct {
		InputTokens  int64 `json:"input_tokens"`
		OutputTokens int64 `json:"output_tokens"`
	} `json:"usage"`
}

type providerResponse struct {
	model        string
	input        []byte
	output       []byte
	inputTokens  int64
	outputTokens int64
	refused      bool
}

func (provider *Provider) respond(ctx context.Context, name, instructions string, input []byte, schema json.RawMessage, maxOutputTokens int) (providerResponse, error) {
	requestBody, err := provider.requestDocument(name, instructions, input, schema, maxOutputTokens)
	if err != nil {
		return providerResponse{}, &Error{Code: ErrorInvalidArgument, Stage: StageRequestBuild}
	}
	digest := sha256.Sum256(requestBody)

	for attempt := 0; attempt <= provider.maxRetries; attempt++ {
		result, retry, callErr := provider.attempt(ctx, requestBody, "sherlock-"+hex.EncodeToString(digest[:16]))
		if callErr == nil {
			result.input = bytes.Clone(requestBody)
			return result, nil
		}
		if !retry || attempt == provider.maxRetries {
			return providerResponse{}, attachCallFailure(callErr, modelprovider.CallTrace{Input: requestBody}, modelprovider.CallMetadata{})
		}
		jittered := provider.retryBackoff*time.Duration(1<<attempt) + time.Duration(rand.Int64N(int64(provider.retryBackoff/2)+1))
		if err := provider.sleep(ctx, jittered); err != nil {
			return providerResponse{}, classifyContext(err)
		}
	}
	return providerResponse{}, &Error{Code: ErrorUnavailable, Stage: StageTransport, Retryable: true}
}

func (provider *Provider) requestDocument(name, instructions string, input []byte, schema json.RawMessage, maxOutputTokens int) ([]byte, error) {
	return json.Marshal(responseRequest{
		Model: provider.deployment, Instructions: instructions,
		Input:           []inputMessage{{Role: "user", Content: string(input)}},
		Text:            textConfig{Format: schemaFormat{Type: "json_schema", Name: "sherlock_" + name + "_v1", Schema: schema, Strict: true}},
		MaxOutputTokens: maxOutputTokens, Store: false,
	})
}

func (provider *Provider) attempt(ctx context.Context, body []byte, idempotencyKey string) (providerResponse, bool, error) {
	callCtx, cancel := context.WithTimeout(ctx, provider.timeout)
	defer cancel()
	endpoint := provider.endpoint.ResolveReference(&url.URL{Path: "responses"})
	request, err := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return providerResponse{}, false, &Error{Code: ErrorInvalidArgument, Stage: StageRequestBuild}
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("api-key", provider.apiKey)
	request.Header.Set("Idempotency-Key", idempotencyKey)
	response, err := provider.client.Do(request)
	if err != nil {
		if callCtx.Err() != nil {
			return providerResponse{}, false, classifyContext(callCtx.Err())
		}
		var netErr net.Error
		retryable := errors.As(err, &netErr)
		return providerResponse{}, retryable, &Error{Code: ErrorUnavailable, Stage: StageTransport, Retryable: retryable}
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, provider.maxResponseBytes+1)
	encoded, readErr := io.ReadAll(limited)
	if readErr != nil {
		return providerResponse{}, false, &Error{Code: ErrorInvalidResponse, Stage: StageResponseRead}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		code, retryable := classifyStatus(response.StatusCode)
		return providerResponse{}, retryable, &Error{Code: code, Stage: StageHTTPStatus, Retryable: retryable, StatusCode: response.StatusCode}
	}
	if int64(len(encoded)) > provider.maxResponseBytes {
		return providerResponse{}, false, &Error{Code: ErrorInvalidResponse, Stage: StageResponseSize}
	}
	result, parseErr := decodeResponse(encoded)
	if parseErr != nil {
		return providerResponse{}, false, parseErr
	}
	return result, false, nil
}

func decodeResponse(encoded []byte) (providerResponse, error) {
	var wire wireResponse
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := decoder.Decode(&wire); err != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.Usage.InputTokens < 0 || wire.Usage.OutputTokens < 0 {
		return providerResponse{}, &Error{Code: ErrorInvalidResponse, Stage: StageResponseEnvelope}
	}
	if wire.Status != "completed" || wire.IncompleteDetails != nil {
		return providerResponse{}, &Error{Code: ErrorInvalidResponse, Stage: StageOutputIncomplete}
	}
	result := providerResponse{model: wire.Model, inputTokens: wire.Usage.InputTokens, outputTokens: wire.Usage.OutputTokens}
	for _, item := range wire.Output {
		if item.Type != "message" {
			continue
		}
		for _, content := range item.Content {
			switch content.Type {
			case "output_text":
				if len(result.output) != 0 || content.Text == "" {
					return providerResponse{}, &Error{Code: ErrorInvalidResponse, Stage: StageResponseEnvelope}
				}
				result.output = []byte(content.Text)
			case "refusal":
				result.refused = true
			}
		}
	}
	if result.refused {
		if len(result.output) != 0 {
			return providerResponse{}, &Error{Code: ErrorInvalidResponse, Stage: StageResponseEnvelope}
		}
		return result, nil
	}
	if len(result.output) == 0 {
		return providerResponse{}, &Error{Code: ErrorInvalidResponse, Stage: StageResponseEnvelope}
	}
	return result, nil
}

func (provider *Provider) metadata(response providerResponse, latency time.Duration) (modelprovider.CallMetadata, error) {
	inputCost, ok := tokenCost(response.inputTokens, provider.inputTokenMicrosPerMillion)
	if !ok {
		return modelprovider.CallMetadata{}, &Error{Code: ErrorInvalidResponse, Stage: StageCostAccounting}
	}
	outputCost, ok := tokenCost(response.outputTokens, provider.outputTokenMicrosPerMillion)
	if !ok || inputCost > math.MaxInt64-outputCost {
		return modelprovider.CallMetadata{}, &Error{Code: ErrorInvalidResponse, Stage: StageCostAccounting}
	}
	return modelprovider.CallMetadata{Provider: "azure-openai", Model: provider.deployment, ConfigurationID: provider.configurationID, InputTokens: response.inputTokens, OutputTokens: response.outputTokens, CostMicros: inputCost + outputCost, Latency: latency, Outcome: modelprovider.OutcomeSucceeded}, nil
}

func tokenCost(tokens, microsPerMillion int64) (int64, bool) {
	if tokens < 0 || microsPerMillion <= 0 {
		return 0, false
	}
	whole := tokens / 1_000_000
	remainder := tokens % 1_000_000
	if whole != 0 && microsPerMillion > math.MaxInt64/whole {
		return 0, false
	}
	cost := whole * microsPerMillion
	if remainder != 0 && microsPerMillion > math.MaxInt64/remainder {
		return 0, false
	}
	fraction := remainder * microsPerMillion
	fraction = fraction/1_000_000 + boolInt(fraction%1_000_000 != 0)
	if cost > math.MaxInt64-fraction {
		return 0, false
	}
	return cost + fraction, true
}

func boolInt(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func structuredOutputError(err error) *Error {
	var validation *modelprovider.ResponseValidationError
	if errors.As(err, &validation) && validation.Stage == modelprovider.ResponseStructuredDecode {
		return &Error{Code: ErrorInvalidResponse, Stage: StageStructuredDecode}
	}
	return &Error{Code: ErrorInvalidResponse, Stage: StageSemanticValidation}
}

func attachCallFailure(err error, trace modelprovider.CallTrace, metadata modelprovider.CallMetadata) error {
	var providerError *Error
	if !errors.As(err, &providerError) {
		return err
	}
	providerError.trace = modelprovider.CallTrace{Input: bytes.Clone(trace.Input), Output: bytes.Clone(trace.Output)}
	if metadata.Provider != "" {
		copy := metadata
		providerError.metadata = &copy
	}
	return providerError
}

func classifyStatus(status int) (ErrorCode, bool) {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrorUnauthorized, false
	case http.StatusTooManyRequests:
		return ErrorRateLimited, true
	case http.StatusRequestTimeout, http.StatusConflict, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return ErrorUnavailable, true
	case http.StatusBadRequest, http.StatusNotFound, http.StatusUnprocessableEntity:
		return ErrorInvalidArgument, false
	default:
		return ErrorUnavailable, status >= 500
	}
}

func classifyContext(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return &Error{Code: ErrorDeadlineExceeded, Stage: StageTransport}
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	return &Error{Code: ErrorUnavailable, Stage: StageTransport}
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func outputLimit(configured int, remaining int64) int {
	if remaining > 0 && remaining < int64(configured) {
		return max(128, int(remaining))
	}
	return configured
}

func isLoopback(host string) bool {
	return host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

func isAzureOpenAIHost(host string) bool {
	for _, suffix := range []string{".openai.azure.com", ".services.ai.azure.com"} {
		if len(host) > len(suffix) && strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func validToken(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("-_.", character) {
			continue
		}
		return false
	}
	return true
}

func stopReason(value modelprovider.PlanningStopReason) *modelprovider.PlanningStopReason {
	return &value
}

var _ modelprovider.Provider = (*Provider)(nil)
