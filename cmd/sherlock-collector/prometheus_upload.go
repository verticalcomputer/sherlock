package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	adapter "github.com/verticalcomputer/sherlock/internal/adapters/prometheus"
	execution "github.com/verticalcomputer/sherlock/internal/collectorexecution/prometheus"
	"github.com/verticalcomputer/sherlock/internal/collectorruntime"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
)

func runPrometheusUpload(ctx context.Context, logger *slog.Logger, probe bool) error {
	cfg, err := config.LoadCollector()
	if err != nil {
		return err
	}
	spool := os.Getenv("SHERLOCK_PROMETHEUS_UPLOAD_SPOOL")
	if cfg.ClusterID == "" || !filepath.IsAbs(spool) || cfg.BCMAccessTest.Enabled || cfg.GPUProcessObservation.Enabled {
		return fmt.Errorf("scheduled Prometheus upload requires a cluster, an absolute private spool, and disabled diagnostic sources")
	}
	local, err := url.Parse(cfg.PrometheusURL)
	if err != nil || local.User != nil || local.RawQuery != "" || local.Fragment != "" ||
		(local.Path != "" && local.Path != "/") || !net.ParseIP(local.Hostname()).IsLoopback() {
		return fmt.Errorf("scheduled Prometheus requires a loopback IP origin")
	}
	source, err := adapter.NewClient(adapter.Config{
		BaseURL: cfg.PrometheusURL, Timeout: 8 * time.Second, MaxBytes: domain.PrometheusUploadMaxBytes,
		MaxSeries: domain.PrometheusUploadMaxSeries, DenyRedirects: true,
		Auth: adapter.Auth{BearerToken: cfg.PrometheusBearer, Username: cfg.PrometheusUser, Password: cfg.PrometheusPassword},
	})
	if err != nil {
		return err
	}
	executor, err := execution.NewUpload(source, platform.SystemClock{}, platform.RandomIDGenerator{})
	if err != nil {
		return err
	}
	client, err := prometheusUploadHTTPClient(cfg, probe)
	if err != nil {
		return err
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	control, err := collectorruntime.NewHTTPClient(cfg.ControlURL, client, time.Minute)
	if err != nil {
		return err
	}
	if probe {
		if err := control.ProbePrometheusUpload(ctx); err != nil {
			return err
		}
		logger.Info("collector.prometheus_upload_ready", "scope", "authenticated upload route")
		return nil
	}
	return collectorruntime.RunPrometheusUpload(ctx, executor, control, logger, spool, domain.ClusterID(cfg.ClusterID), domain.SourceID(cfg.SourceID))
}
