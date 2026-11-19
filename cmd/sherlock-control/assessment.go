package main

import (
	"context"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
	"github.com/verticalcomputer/sherlock/internal/config"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

type assessmentRefresher interface {
	Refresh(context.Context) error
	Cleanup(context.Context) (int, error)
}

func startAssessment(parent context.Context, cfg config.Assessment, logger *slog.Logger) func() {
	noop := func() {}
	if cfg.Mode == "" || cfg.Mode == "disabled" {
		return noop
	}
	if cfg.Invalid || cfg.Mode != "shadow" {
		logger.Warn("control.assessment_disabled", "reason", "invalid optional configuration")
		return noop
	}
	initCtx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	registry, err := a.NewRegistry(cooling.Category{})
	if err != nil {
		logger.Warn("control.assessment_disabled", "reason", "category registration failed")
		return noop
	}
	enrollment, err := cfg.Read(initCtx, registry)
	if err != nil {
		logger.Warn("control.assessment_disabled", "reason", "invalid assessment file")
		return noop
	}
	poolConfig, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		logger.Warn("control.assessment_disabled", "reason", "invalid dedicated database configuration")
		return noop
	}
	poolConfig.MaxConns = 2
	poolConfig.MinConns = 0
	poolConfig.ConnConfig.ConnectTimeout = 3 * time.Second
	poolConfig.ConnConfig.RuntimeParams["application_name"] = "sherlock-assessment"
	pool, err := pgxpool.NewWithConfig(initCtx, poolConfig)
	if err != nil {
		logger.Warn("control.assessment_disabled", "reason", "dedicated database unavailable")
		return noop
	}
	fail := func(reason string) func() {
		pool.Close()
		logger.Warn("control.assessment_disabled", "reason", reason)
		return noop
	}
	if err = pool.Ping(initCtx); err != nil {
		return fail("dedicated database unavailable")
	}
	buildID := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		buildID = info.String()
	}
	store, err := storepg.NewAssessmentStore(initCtx, pool, registry, enrollment, buildID)
	if err != nil {
		return fail("dedicated database admission rejected")
	}
	if err = store.Start(initCtx); err != nil {
		return fail("run admission rejected")
	}
	ctx, stop := context.WithCancel(parent)
	done := make(chan struct{})
	go func() { defer close(done); defer pool.Close(); runAssessmentRefresh(ctx, store, logger) }()
	logger.Info("control.assessment_started", "mode", "shadow")
	return func() { stop(); <-done }
}
func runAssessmentRefresh(ctx context.Context, store assessmentRefresher, logger *slog.Logger) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		bounded, cancel := context.WithTimeout(ctx, a.ShadowRefreshBudget)
		err := store.Refresh(bounded)
		if err == nil && bounded.Err() == nil {
			_, err = store.Cleanup(bounded)
		}
		cancel()
		if err != nil && ctx.Err() == nil {
			logger.Warn("control.assessment_refresh_failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
