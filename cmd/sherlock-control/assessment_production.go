package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adapters/azureopenai"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
	"github.com/verticalcomputer/sherlock/internal/config"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// runProductionAssessment starts no listeners, collectors, investigation,
// diagnostics or workload control loops. Acquisition and delivery have their
// own explicit enrollment and process authority.
func runProductionAssessment(ctx context.Context, logger *slog.Logger) error {
	cfg, err := config.LoadAssessmentProduction()
	if err != nil {
		return err
	}
	registry, err := a.NewRegistry(cooling.Category{}, cooling.ProductionCategory{})
	if err != nil {
		return err
	}
	initCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	enrollment, err := cfg.Read(initCtx, registry)
	if err != nil {
		return err
	}
	pc, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return errors.New("invalid production database configuration")
	}
	pc.MaxConns = 2
	pc.MinConns = 0
	pc.ConnConfig.ConnectTimeout = 3 * time.Second
	pc.ConnConfig.RuntimeParams["application_name"] = "sherlock-assessment-production"
	pool, err := pgxpool.NewWithConfig(initCtx, pc)
	if err != nil {
		return errors.New("production database unavailable")
	}
	defer pool.Close()
	if err = pool.Ping(initCtx); err != nil {
		return errors.New("production database unavailable")
	}
	if err = storepg.CheckProductionAssessmentRole(initCtx, pool); err != nil {
		return errors.New("production database privileges rejected")
	}
	store, err := storepg.NewProductionAssessmentStore(initCtx, pool, registry, enrollment)
	if err != nil {
		return errors.New("production assessment admission rejected")
	}
	var model *azureopenai.Provider
	if enrollment.AzureWarmingTriage {
		model, err = warmingTriageModel()
		if err != nil {
			return err
		}
	}
	if err = store.Start(initCtx); err != nil {
		return errors.New("production assessment startup rejected")
	}
	if model != nil {
		workerCtx, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			runWarmingTriage(workerCtx, store, model.TriageWarming, logger)
		}()
		defer func() { stop(); <-done }()
	}
	logger.Info("control.production_assessment_started", "notifications_enabled", enrollment.NotificationsEnabled)
	refreshTick := time.NewTicker(time.Second)
	defer refreshTick.Stop()
	cleanupTick := time.NewTicker(time.Minute)
	defer cleanupTick.Stop()
	runProductionAssessmentLoops(ctx, store, logger, refreshTick.C, cleanupTick.C, a.ShadowRefreshBudget, 250*time.Millisecond)
	return ctx.Err()
}

// Retention has its own bounded opportunity, even when acquisition fails or
// consumes its full deadline. Both loops share the same two-connection pool.
// Cleanup runs once at startup and then once per minute; it cannot extend a
// GPU's 250ms limit or the two-second refresh budget.
func runProductionAssessmentLoops(ctx context.Context, store assessmentRefresher, logger *slog.Logger, refreshTick, cleanupTick <-chan time.Time, refreshBudget, cleanupBudget time.Duration) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			bounded, cancel := context.WithTimeout(ctx, refreshBudget)
			started := time.Now()
			err := store.Refresh(bounded)
			cancel()
			if err != nil && ctx.Err() == nil {
				fields := append(storepg.AssessmentDiagnosticFields(err), "refresh_elapsed_ms", time.Since(started).Milliseconds())
				logger.Warn("control.production_assessment_refresh_failed", fields...)
			}
			select {
			case <-ctx.Done():
				return
			case <-refreshTick:
			}
		}
	}()
	defer func() { <-done }()
	for ctx.Err() == nil {
		bounded, cancel := context.WithTimeout(ctx, cleanupBudget)
		started := time.Now()
		_, err := store.Cleanup(bounded)
		cancel()
		if err != nil && ctx.Err() == nil {
			fields := append(storepg.AssessmentDiagnosticFields(err), "cleanup_elapsed_ms", time.Since(started).Milliseconds())
			logger.Warn("control.production_assessment_cleanup_failed", fields...)
		}
		select {
		case <-ctx.Done():
			return
		case <-cleanupTick:
		}
	}
}

func warmingTriageModel() (*azureopenai.Provider, error) {
	cfg, err := config.LoadModel()
	if err != nil || cfg.Provider != "azure-openai" {
		return nil, errors.New("warming triage requires configured Azure inference")
	}
	return azureopenai.NewProvider(azureopenai.Config{
		Endpoint:                    cfg.AzureOpenAIEndpoint,
		APIKey:                      cfg.AzureOpenAIAPIKey.Reveal(),
		Deployment:                  cfg.AzureOpenAIDeployment,
		ConfigurationID:             cfg.ConfigurationID,
		Timeout:                     min(cfg.Timeout, 30*time.Second),
		MaxOutputTokens:             min(1200, cfg.MaxOutputTokens),
		InputTokenMicrosPerMillion:  cfg.InputMicrosPerMillionTokens,
		OutputTokenMicrosPerMillion: cfg.OutputMicrosPerMillionTokens,
	})
}

type warmingTriageStore interface {
	ProcessWarmingTriage(context.Context, func(context.Context, json.RawMessage) (string, string, error)) error
}

// Inference runs independently of the per-GPU and refresh deadlines. A single
// in-flight request per process bounds model traffic during a correlated event.
func runWarmingTriage(ctx context.Context, store warmingTriageStore, infer func(context.Context, json.RawMessage) (string, string, error), logger *slog.Logger) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for ctx.Err() == nil {
		pass, cancel := context.WithTimeout(ctx, 40*time.Second)
		err := store.ProcessWarmingTriage(pass, infer)
		cancel()
		if err != nil && ctx.Err() == nil {
			logger.Warn("control.warming_triage_failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
