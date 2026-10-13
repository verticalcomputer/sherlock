package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestLoadModelDoesNotRequireAPIOrClusterConfiguration(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "")
	t.Setenv("SHERLOCK_API_KEY_HASH_KEY", "")
	t.Setenv("SHERLOCK_MODEL_ALLOWED_CLUSTERS", "")
	t.Setenv("SHERLOCK_MODEL_PROVIDER", "azure-openai")
	t.Setenv("SHERLOCK_AZURE_OPENAI_ENDPOINT", "https://fixture.services.ai.azure.com/openai/v1")
	t.Setenv("SHERLOCK_AZURE_OPENAI_API_KEY", "model-secret")
	t.Setenv("SHERLOCK_AZURE_OPENAI_DEPLOYMENT", "gpt-5.6-sol")
	t.Setenv("SHERLOCK_MODEL_CONFIGURATION_ID", "config-v1")
	t.Setenv("SHERLOCK_MODEL_INPUT_MICROS_PER_MILLION_TOKENS", "5000000")
	t.Setenv("SHERLOCK_MODEL_OUTPUT_MICROS_PER_MILLION_TOKENS", "30000000")
	cfg, err := LoadModel()
	if err != nil || cfg.AzureOpenAIDeployment != "gpt-5.6-sol" {
		t.Fatalf("config=%+v error=%v", cfg, err)
	}
	if value := fmt.Sprintf("%+v", cfg.AzureOpenAIAPIKey); strings.Contains(value, "model-secret") {
		t.Fatalf("secret rendered as %q", value)
	}
}

// The cap was never plumbed to the provider, which silently used its own 4096
// default while a synthesis report measured 3,060 output tokens against it.
func TestModelMaxOutputTokensIsConfigurableAndBounded(t *testing.T) {
	t.Setenv("SHERLOCK_MODEL_PROVIDER", "azure-openai")
	t.Setenv("SHERLOCK_AZURE_OPENAI_ENDPOINT", "https://example.invalid")
	t.Setenv("SHERLOCK_AZURE_OPENAI_API_KEY", "key")
	t.Setenv("SHERLOCK_AZURE_OPENAI_DEPLOYMENT", "deployment")
	t.Setenv("SHERLOCK_MODEL_CONFIGURATION_ID", "config-v1")
	t.Setenv("SHERLOCK_MODEL_INPUT_MICROS_PER_MILLION_TOKENS", "100")
	t.Setenv("SHERLOCK_MODEL_OUTPUT_MICROS_PER_MILLION_TOKENS", "100")

	cfg, err := LoadModel()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxOutputTokens != 16384 {
		t.Fatalf("default max output tokens = %d", cfg.MaxOutputTokens)
	}
	t.Setenv("SHERLOCK_MODEL_MAX_OUTPUT_TOKENS", "8192")
	if cfg, err = LoadModel(); err != nil || cfg.MaxOutputTokens != 8192 {
		t.Fatalf("configured max output tokens = %d err=%v", cfg.MaxOutputTokens, err)
	}
	// Outside the provider's accepted range must fail at startup.
	for _, value := range []string{"127", "32769"} {
		t.Setenv("SHERLOCK_MODEL_MAX_OUTPUT_TOKENS", value)
		if _, err := LoadModel(); err == nil {
			t.Fatalf("max output tokens %s was accepted", value)
		}
	}
}
