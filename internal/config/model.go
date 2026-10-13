package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// RuntimeSecret prevents accidental fmt or JSON disclosure while keeping the
// credential available for adapter construction. It is never persisted.
type RuntimeSecret struct{ value string }

func (secret RuntimeSecret) Reveal() string   { return secret.value }
func (secret RuntimeSecret) Configured() bool { return secret.value != "" }
func (secret RuntimeSecret) String() string   { return "[REDACTED]" }
func (secret RuntimeSecret) GoString() string { return "[REDACTED]" }

// Model contains only hosted-model runtime configuration. Unlike API, it can
// be loaded by a health probe without requiring database or public API secrets.
type Model struct {
	Provider              string
	AzureOpenAIEndpoint   string
	AzureOpenAIAPIKey     RuntimeSecret
	AzureOpenAIDeployment string
	ConfigurationID       string
	Timeout               time.Duration
	MaxRetries            int
	// MaxOutputTokens caps a single structured response. It was never plumbed
	// through, so the provider silently used its own 4096 default while the
	// budget reserved the same figure. A synthesis report over eight actions
	// measured 3,060 output tokens, close enough to that cap that a larger
	// investigation truncates mid-JSON and degrades to the deterministic
	// fallback instead of returning the model's report.
	MaxOutputTokens              int
	InputMicrosPerMillionTokens  int64
	OutputMicrosPerMillionTokens int64
}

func int64Env(name string, fallback int64) (int64, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", name, err)
	}
	return parsed, nil
}

func LoadModel() (Model, error) {
	if err := loadLocalEnv(); err != nil {
		return Model{}, err
	}
	cfg := Model{
		Provider:              os.Getenv("SHERLOCK_MODEL_PROVIDER"),
		AzureOpenAIEndpoint:   os.Getenv("SHERLOCK_AZURE_OPENAI_ENDPOINT"),
		AzureOpenAIAPIKey:     RuntimeSecret{value: os.Getenv("SHERLOCK_AZURE_OPENAI_API_KEY")},
		AzureOpenAIDeployment: os.Getenv("SHERLOCK_AZURE_OPENAI_DEPLOYMENT"),
		ConfigurationID:       os.Getenv("SHERLOCK_MODEL_CONFIGURATION_ID"),
		Timeout:               60 * time.Second,
		MaxRetries:            2,
		MaxOutputTokens:       16384,
	}
	var err error
	if cfg.Timeout, err = durationEnv("SHERLOCK_MODEL_TIMEOUT", cfg.Timeout); err != nil {
		return Model{}, err
	}
	if cfg.MaxOutputTokens, err = intEnv("SHERLOCK_MODEL_MAX_OUTPUT_TOKENS", cfg.MaxOutputTokens); err != nil {
		return Model{}, err
	}
	if cfg.MaxRetries, err = intEnv("SHERLOCK_MODEL_MAX_RETRIES", cfg.MaxRetries); err != nil {
		return Model{}, err
	}
	if cfg.InputMicrosPerMillionTokens, err = int64Env("SHERLOCK_MODEL_INPUT_MICROS_PER_MILLION_TOKENS", 0); err != nil {
		return Model{}, err
	}
	if cfg.OutputMicrosPerMillionTokens, err = int64Env("SHERLOCK_MODEL_OUTPUT_MICROS_PER_MILLION_TOKENS", 0); err != nil {
		return Model{}, err
	}
	values := []bool{cfg.Provider != "", cfg.AzureOpenAIEndpoint != "", cfg.AzureOpenAIAPIKey.Configured(), cfg.AzureOpenAIDeployment != "", cfg.ConfigurationID != "", cfg.InputMicrosPerMillionTokens > 0, cfg.OutputMicrosPerMillionTokens > 0}
	configured := 0
	for _, value := range values {
		if value {
			configured++
		}
	}
	if configured != 0 && configured != len(values) {
		return Model{}, fmt.Errorf("model provider, Azure endpoint, API key, deployment, configuration ID, and token rates must be configured together")
	}
	if cfg.Provider != "" && cfg.Provider != "azure-openai" {
		return Model{}, fmt.Errorf("SHERLOCK_MODEL_PROVIDER must be azure-openai when configured")
	}
	// The bound mirrors the provider's own accepted range so a misconfiguration
	// fails at startup rather than at the first truncated report.
	if cfg.MaxOutputTokens < 128 || cfg.MaxOutputTokens > 32768 {
		return Model{}, fmt.Errorf("SHERLOCK_MODEL_MAX_OUTPUT_TOKENS must be between 128 and 32768")
	}
	if cfg.Timeout <= 0 || cfg.Timeout > 2*time.Minute || cfg.MaxRetries < 0 || cfg.MaxRetries > 2 || cfg.InputMicrosPerMillionTokens < 0 || cfg.OutputMicrosPerMillionTokens < 0 || cfg.InputMicrosPerMillionTokens > 1_000_000_000_000 || cfg.OutputMicrosPerMillionTokens > 1_000_000_000_000 {
		return Model{}, fmt.Errorf("model timeout, retry limit, or token rate is outside safety bounds")
	}
	return cfg, nil
}
