package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/verticalcomputer/sherlock/internal/adapters/azureopenai"
	"github.com/verticalcomputer/sherlock/internal/config"
)

type healthReport struct {
	Healthy         bool   `json:"healthy"`
	Provider        string `json:"provider"`
	Deployment      string `json:"deployment"`
	ConfigurationID string `json:"configuration_id"`
	LatencyMS       int64  `json:"latency_ms"`
	ErrorCode       string `json:"error_code,omitempty"`
	Retryable       bool   `json:"retryable,omitempty"`
	HTTPStatus      int    `json:"http_status,omitempty"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Sherlock model health check failed")
		os.Exit(1)
	}
}

func run(ctx context.Context, output io.Writer) error {
	cfg, err := config.LoadModel()
	if err != nil {
		_ = json.NewEncoder(output).Encode(healthReport{ErrorCode: "CONFIGURATION_INVALID"})
		return err
	}
	if cfg.Provider == "" {
		_ = json.NewEncoder(output).Encode(healthReport{ErrorCode: "MODEL_NOT_CONFIGURED"})
		return errors.New("model provider is not configured")
	}
	provider, err := azureopenai.NewProvider(azureopenai.Config{
		Endpoint: cfg.AzureOpenAIEndpoint, APIKey: cfg.AzureOpenAIAPIKey.Reveal(),
		Deployment: cfg.AzureOpenAIDeployment, ConfigurationID: cfg.ConfigurationID,
		Timeout: cfg.Timeout, MaxRetries: cfg.MaxRetries,
		InputTokenMicrosPerMillion:  cfg.InputMicrosPerMillionTokens,
		OutputTokenMicrosPerMillion: cfg.OutputMicrosPerMillionTokens,
	})
	if err != nil {
		report := healthReport{Provider: cfg.Provider, Deployment: cfg.AzureOpenAIDeployment, ConfigurationID: cfg.ConfigurationID, ErrorCode: "CONFIGURATION_INVALID"}
		var providerError *azureopenai.Error
		if errors.As(err, &providerError) {
			report.ErrorCode = string(providerError.Code)
		}
		_ = json.NewEncoder(output).Encode(report)
		return err
	}
	health, err := provider.CheckHealth(ctx)
	if err != nil {
		report := healthReport{Provider: health.Provider, Deployment: health.Deployment, ConfigurationID: health.ConfigurationID, LatencyMS: health.Latency.Milliseconds()}
		var providerError *azureopenai.Error
		if errors.As(err, &providerError) {
			report.ErrorCode = string(providerError.Code)
			report.Retryable = providerError.Retryable
			report.HTTPStatus = providerError.StatusCode
		} else {
			report.ErrorCode = "MODEL_UNAVAILABLE"
		}
		if encodeErr := json.NewEncoder(output).Encode(report); encodeErr != nil {
			return encodeErr
		}
		return err
	}
	return json.NewEncoder(output).Encode(healthReport{Healthy: health.Healthy, Provider: health.Provider, Deployment: health.Deployment, ConfigurationID: health.ConfigurationID, LatencyMS: health.Latency.Milliseconds()})
}
