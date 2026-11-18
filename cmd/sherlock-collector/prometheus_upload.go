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
	"strings"
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
		_, hash, _, err := loadLocalCoolingUpload(cfg, spool)
		if err != nil {
			return err
		}
		if hash != "" {
			if err := control.ProbeCoolingUpload(ctx); err != nil {
				return err
			}
			logger.Info("collector.cooling_upload_ready", "scope", "authenticated cooling upload route")
		}
		logger.Info("collector.prometheus_upload_ready", "scope", "authenticated upload route")
		return nil
	}
	stopCooling := startCoolingUpload(ctx, executor, control, logger, spool, cfg)
	defer stopCooling()
	return collectorruntime.RunPrometheusUpload(ctx, executor, control, logger, spool, domain.ClusterID(cfg.ClusterID), domain.SourceID(cfg.SourceID))
}

func startCoolingUpload(ctx context.Context, executor *execution.Executor, control *collectorruntime.HTTPClient, logger *slog.Logger,
	minuteSpool string, cfg config.Collector) func() {
	profile, hash, spool, err := loadLocalCoolingUpload(cfg, minuteSpool)
	if err != nil {
		logger.Warn("collector.cooling_upload_disabled", "reason", err)
	}
	if err != nil || hash == "" {
		return func() {}
	}
	coolingCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := collectorruntime.RunCoolingUpload(coolingCtx, executor, control, logger, spool, profile, hash); err != nil && coolingCtx.Err() == nil {
			logger.Warn("collector.cooling_upload_disabled", "reason", "local cooling runtime or spool failed")
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func loadLocalCoolingUpload(cfg config.Collector, minuteSpool string) (domain.CoolingUploadProfile, string, string, error) {
	profile, hash, err := config.LoadCoolingUploadProfile()
	if err != nil {
		return domain.CoolingUploadProfile{}, "", "", fmt.Errorf("invalid local cooling upload profile")
	}
	if hash == "" {
		return profile, "", "", nil
	}
	if profile.CollectorID != domain.CollectorID(cfg.CollectorID) || profile.ClusterID != domain.ClusterID(cfg.ClusterID) ||
		profile.SourceID != domain.SourceID(cfg.SourceID) {
		return domain.CoolingUploadProfile{}, "", "", fmt.Errorf("cooling upload profile does not match collector scope")
	}
	spool := os.Getenv("SHERLOCK_PROMETHEUS_COOLING_SPOOL")
	info, err := os.Lstat(spool)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || !separateUploadSpools(minuteSpool, spool) {
		return domain.CoolingUploadProfile{}, "", "", fmt.Errorf("cooling upload requires a separate private spool")
	}
	return profile, hash, spool, nil
}

func separateUploadSpools(minute, cooling string) bool {
	if !filepath.IsAbs(minute) || !filepath.IsAbs(cooling) {
		return false
	}
	resolvedMinute, err := filepath.EvalSymlinks(minute)
	if err != nil {
		return false
	}
	resolvedCooling, err := filepath.EvalSymlinks(cooling)
	if err != nil {
		return false
	}
	for _, pair := range [][2]string{{resolvedMinute, resolvedCooling}, {resolvedCooling, resolvedMinute}} {
		relative, err := filepath.Rel(pair[0], pair[1])
		if err != nil || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
			return false
		}
	}
	return true
}
