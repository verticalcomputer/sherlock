package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

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
	collector := domain.CollectorID(strings.TrimSpace(os.Getenv("SHERLOCK_COLLECTOR_ID")))
	cluster := domain.ClusterID(strings.TrimSpace(os.Getenv("SHERLOCK_CLUSTER_ID")))
	source := domain.SourceID(strings.TrimSpace(os.Getenv("SHERLOCK_SOURCE_ID")))
	if collector == "" || cluster == "" || source == "" {
		logger.Error("control.prometheus_upload_scope_missing")
		return fmt.Errorf("scheduled Prometheus intake requires an explicit scope")
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
	handler, err := collectorcontrol.NewPrometheusUploadHandler(identity, auth, store, clock, collector, cluster, source)
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
