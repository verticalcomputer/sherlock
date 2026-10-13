// sherlock-remediator runs the default-off SIMULATED or single-stream LIVE supervisor.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediation"
	"github.com/verticalcomputer/sherlock/internal/remediationops"
	"github.com/verticalcomputer/sherlock/internal/remediationruntime"
	"github.com/verticalcomputer/sherlock/internal/store/postgres"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	var err error
	if len(os.Args) >= 2 && os.Args[1] == "healthcheck" {
		path := "/health/ready"
		if len(os.Args) == 3 && os.Args[2] == "live" {
			path = "/health/live"
		} else if len(os.Args) != 2 {
			path = ""
		}
		err = checkHealth(context.Background(), path)
	} else if len(os.Args) == 4 && os.Args[1] == "control" {
		err = runConfigured(logger, os.Args[2], os.Args[3])
	} else if len(os.Args) == 1 {
		err = run(logger)
	} else {
		err = fmt.Errorf("invalid remediation command")
	}
	if err != nil {
		logger.Error("remediation.stopped", "code", "REMEDIATION_STOPPED")
		os.Exit(1)
	}
}
func run(logger *slog.Logger) error { return runConfigured(logger, "", "") }

func runConfigured(logger *slog.Logger, operation, runID string) error {
	if operation != "" && (operation != "cancel" && operation != "rollback" && operation != "reconcile" || !domain.ValidRemediationToken(runID)) {
		return fmt.Errorf("invalid remediation control")
	}
	raw := os.Getenv("SHERLOCK_REMEDIATION_ENABLED")
	if operation == "" && (raw == "" || raw == "false") {
		logger.Info("remediation.disabled")
		return nil
	}
	if operation == "" && raw != "true" {
		return fmt.Errorf("invalid remediation enablement")
	}
	executorMode := os.Getenv("SHERLOCK_REMEDIATION_EXECUTOR")
	if executorMode != "SIMULATED" && executorMode != "LIVE" {
		return fmt.Errorf("remediation requires SIMULATED or LIVE executor")
	}
	if operation != "" && executorMode != "LIVE" {
		return fmt.Errorf("remediation control requires LIVE configuration")
	}
	var roots []remediation.RecipeTrustRoot
	var release remediation.SignedRecipeRelease
	if err := readJSON(os.Getenv("SHERLOCK_REMEDIATION_TRUST_ROOTS"), &roots); err != nil {
		return err
	}
	if err := readJSON(os.Getenv("SHERLOCK_REMEDIATION_RELEASE"), &release); err != nil {
		return err
	}
	trust, err := remediation.NewRecipeTrustStore(roots)
	if err != nil {
		return err
	}
	catalog, err := trust.Verify(release, time.Now().UTC())
	if err != nil {
		return err
	}
	batch, err := strconv.Atoi(os.Getenv("SHERLOCK_REMEDIATION_BATCH"))
	if err != nil {
		return fmt.Errorf("invalid remediation batch")
	}
	interval, err := time.ParseDuration(os.Getenv("SHERLOCK_REMEDIATION_POLL_INTERVAL"))
	if err != nil {
		return fmt.Errorf("invalid remediation interval")
	}
	cfg := remediationruntime.Config{Enabled: true, Live: executorMode == "LIVE", ClusterID: domain.ClusterID(os.Getenv("SHERLOCK_CLUSTER_ID")), Owner: os.Getenv("SHERLOCK_REMEDIATION_WORKER_ID"), Batch: batch, PollInterval: interval, Lease: time.Minute}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pool, err := openPool(ctx, cfg.Live, cfg.ClusterID)
	if err != nil {
		return fmt.Errorf("invalid remediation database configuration")
	}
	defer pool.Close()
	store, err := postgres.NewRemediationStore(pool)
	if err != nil {
		return fmt.Errorf("invalid remediation store configuration")
	}
	observer, err := remediationops.New(store, string(cfg.ClusterID), prometheus.NewRegistry())
	if err != nil {
		return fmt.Errorf("invalid remediation metrics configuration")
	}
	cfg.Observer = observer
	rt, err := remediationruntime.New(pool, catalog, cfg, logger)
	if err != nil {
		return err
	}
	if operation != "" {
		if err := rt.Control(ctx, operation, domain.RemediationRunID(runID)); err != nil {
			return fmt.Errorf("remediation control refused")
		}
		logger.Info("remediation.control_completed", "operation", operation)
		return nil
	}
	address, err := metricsAddress(os.Getenv("SHERLOCK_REMEDIATION_METRICS_ADDRESS"))
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("remediation metrics listener unavailable")
	}
	server := &http.Server{Handler: observer.Handler(), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener); stop() }()
	runErr := rt.Run(ctx)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
	}
	serveErr := <-serveDone
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return fmt.Errorf("remediation metrics server stopped")
	}
	if errors.Is(runErr, context.Canceled) {
		return nil
	}
	if runErr != nil {
		return fmt.Errorf("remediation runtime stopped")
	}
	return nil
}

func openPool(ctx context.Context, live bool, cluster domain.ClusterID) (*pgxpool.Pool, error) {
	if live {
		raw := os.Getenv("SHERLOCK_REMEDIATION_DATABASE_URL")
		if raw == "" {
			return nil, fmt.Errorf("restricted remediation database configuration required")
		}
		return postgres.NewRestrictedRemediationPool(ctx, raw, cluster)
	}
	pool, err := pgxpool.New(ctx, os.Getenv("SHERLOCK_DATABASE_URL"))
	if err != nil {
		return nil, fmt.Errorf("invalid remediation database configuration")
	}
	return pool, nil
}

func metricsAddress(raw string) (string, error) {
	if raw == "" {
		raw = "127.0.0.1:9095"
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", fmt.Errorf("invalid remediation metrics address")
	}
	ip := net.ParseIP(host)
	n, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("remediation metrics must bind a loopback address")
	}
	return raw, nil
}

func healthcheck(ctx context.Context) error { return checkHealth(ctx, "/health/ready") }

func checkHealth(ctx context.Context, path string) error {
	if path != "/health/ready" && path != "/health/live" {
		return fmt.Errorf("invalid remediation health check")
	}
	address, err := metricsAddress(os.Getenv("SHERLOCK_REMEDIATION_METRICS_ADDRESS"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+path, nil)
	if err != nil {
		return fmt.Errorf("remediation not ready")
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("remediation not ready")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("remediation not ready")
	}
	return nil
}
func readJSON(path string, out any) error {
	if path == "" {
		return fmt.Errorf("remediation trust and release files are required")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot open remediation configuration")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err = d.Decode(out); err != nil {
		return fmt.Errorf("invalid remediation configuration")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fmt.Errorf("trailing remediation configuration")
	}
	return nil
}
