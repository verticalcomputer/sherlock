package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/controlplane"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func runPrometheusUpload(ctx context.Context, logger *slog.Logger) error {
	cfg, err := config.LoadPrometheusUploadControl()
	if err != nil {
		logger.Error("control.configuration_invalid", "error", err.Error())
		return err
	}
	scope, err := config.LoadPrometheusUploadScope()
	if err != nil {
		logger.Error("control.prometheus_upload_scope_invalid")
		return err
	}
	tlsConfig, err := controlplane.LoadPrometheusUploadTLSConfig(cfg)
	if err != nil {
		return err
	}
	if cfg.CollectorAuthMode == config.CollectorAuthDirectMTLS {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	ca, err := os.ReadFile(cfg.CollectorCA)
	if err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return err
	}
	identity, err := storepg.NewCollectorControlStore(pool)
	if err != nil {
		return err
	}
	store, err := storepg.NewCollectionStore(pool)
	if err != nil {
		return err
	}
	clock := platform.SystemClock{}
	auth, err := configureRequestAuthentication(ctx, cfg, clock, logger, ca, identity)
	if err != nil {
		return err
	}
	var handler http.Handler
	if len(scope.Bindings) > 0 {
		bindings := make([]collectorcontrol.PrometheusUploadBinding, 0, len(scope.Bindings))
		for _, binding := range scope.Bindings {
			bindings = append(bindings, collectorcontrol.PrometheusUploadBinding{
				CollectorID: domain.CollectorID(binding.CollectorID), SourceID: domain.SourceID(binding.SourceID),
			})
		}
		handler, err = collectorcontrol.NewSharedPrometheusUploadHandler(identity, auth, store, clock, bindings)
	} else {
		handler, err = collectorcontrol.NewPrometheusUploadHandler(identity, auth, store, clock,
			domain.CollectorID(scope.CollectorID), domain.ClusterID(scope.ClusterID), domain.SourceID(scope.SourceID))
	}
	if err != nil {
		return err
	}
	server, err := controlplane.NewHTTPServer(cfg, handler, tlsConfig)
	if err != nil {
		return err
	}
	fail := make(chan error, 1)
	go func() { fail <- server.ListenAndServeTLS("", "") }()
	logger.Info("control.prometheus_upload_listening", "address", cfg.ListenAddress)
	select {
	case <-ctx.Done():
		bounded, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		return server.Shutdown(bounded)
	case err := <-fail:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
