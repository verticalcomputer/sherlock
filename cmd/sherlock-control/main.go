package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adapters/investigationapi"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/controlplane"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := config.LoadControl()
	if err != nil {
		logger.Error("control.configuration_invalid", "error", err.Error())
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, logger); err != nil && !errors.Is(err, context.Canceled) {
		// Startup/runtime errors are deliberately not expanded here: PostgreSQL
		// driver errors can include connection configuration.
		logger.Error("control.stopped", "reason", "startup or runtime failure")
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config.Control, logger *slog.Logger) error {
	tlsConfig, err := controlplane.LoadTLSConfig(cfg)
	if err != nil {
		return err
	}
	caCertificate, err := os.ReadFile(cfg.CollectorCA)
	if err != nil {
		return fmt.Errorf("read collector CA: %w", err)
	}
	caPrivateKey, err := controlplane.ReadProtectedPrivateKey(cfg.CollectorCAPrivateKey)
	if err != nil {
		return err
	}
	issuer, err := collectorcontrol.NewCAIssuer(caCertificate, caPrivateKey, rand.Reader)
	if err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("configure PostgreSQL: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	store, err := storepg.NewCollectorControlStore(pool)
	if err != nil {
		return err
	}
	clock := platform.SystemClock{}
	identity, err := collectorcontrol.NewIdentityService(store, issuer, clock, platform.RandomIDGenerator{}, rand.Reader, cfg.IdentityTTL)
	if err != nil {
		return err
	}
	requestAuth, err := configureRequestAuthentication(ctx, cfg, clock, logger, caCertificate, store)
	if err != nil {
		return err
	}
	transport, err := collectorcontrol.NewTransportWithRequestAuthenticator(identity, store, store, store, store, clock, rand.Reader, requestAuth)
	if err != nil {
		return err
	}
	if err := transport.ConfigureTypedCollection(store); err != nil {
		return err
	}
	telemetryStore := storepg.NewTelemetryStore(pool)
	if err := transport.ConfigureTelemetry(telemetryStore); err != nil {
		return err
	}
	if err := configureNodeIdentity(cfg, transport, telemetryStore); err != nil {
		return err
	}
	networkStore := storepg.NewNetworkMonitorStore(pool)
	transport.ConfigureNetworkMonitoring(networkStore)
	networkCtx, networkCancel := context.WithCancel(ctx)
	networkDone := make(chan struct{})
	go func() {
		defer close(networkDone)
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			bounded, cancel := context.WithTimeout(networkCtx, 10*time.Second)
			err := networkStore.Refresh(bounded)
			cancel()
			if err != nil && networkCtx.Err() == nil {
				logger.Warn("control.network_refresh_failed")
			}
			select {
			case <-networkCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() { networkCancel(); <-networkDone }()
	// Enrolled GPU/source policies advance on database time even when collection
	// is silent. This independent loop shares no ownership with network rules
	// and must stop before the database pool is closed.
	monitoringStore := storepg.NewMonitoringStore(pool)
	monitoringCtx, monitoringCancel := context.WithCancel(ctx)
	monitoringDone := make(chan struct{})
	go func() {
		defer close(monitoringDone)
		_ = runMonitoringRefresh(monitoringCtx, monitoringStore, logger, time.Second, 5*time.Second)
	}()
	defer func() { monitoringCancel(); <-monitoringDone }()
	// Execution is opt-in per collector. With no allow-list the diagnostic
	// endpoints are never registered, so a control plane that grants nobody
	// execution exposes no execution surface -- not an authenticated one that
	// answers 403.
	if len(cfg.DiagnosticExecutionCollectors) > 0 {
		if err := configureDiagnosticExecution(cfg, pool, transport, clock); err != nil {
			return err
		}
		logger.Info("control.diagnostic_execution_enabled", "collectors", len(cfg.DiagnosticExecutionCollectors))
	}
	// Credential delivery is opt-in with the external keyring. Without it the
	// control plane mounts no credential-test route at all.
	if cfg.CredentialKeyring.ActiveVersion != "" {
		if err := configureCredentialAccessTests(cfg, pool, transport); err != nil {
			return err
		}
		logger.Info("control.credential_access_tests_enabled")
	}
	server, err := controlplane.NewHTTPServer(cfg, transport, tlsConfig)
	if err != nil {
		return err
	}
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.ListenAndServeTLS("", "") }()
	logger.Info("control.listening", "address", cfg.ListenAddress, "tls_minimum", "1.3", "collector_auth_mode", cfg.CollectorAuthMode)
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shut down control server: %w", err)
		}
		return ctx.Err()
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve collector control API: %w", err)
	}
}

type authEventLogger struct {
	logger *slog.Logger
	mu     sync.Mutex
	counts map[string]uint64
}

func (o *authEventLogger) Rejected(reason string) {
	o.mu.Lock()
	o.counts[reason]++
	count := o.counts[reason]
	o.mu.Unlock()
	o.logger.Warn("control.collector_authentication_rejected", "reason", reason, "count", count)
}
func (o *authEventLogger) JWKSRefresh(succeeded bool, age time.Duration) {
	reason := "jwks_refresh_failure"
	if succeeded {
		reason = "jwks_refresh_success"
	}
	o.mu.Lock()
	o.counts[reason]++
	count := o.counts[reason]
	o.mu.Unlock()
	o.logger.Info("control.cloudflare_jwks_refresh", "succeeded", succeeded, "count", count, "last_success_age_seconds", int64(age.Seconds()))
}

func configureRequestAuthentication(ctx context.Context, cfg config.Control, clock platform.SystemClock, logger *slog.Logger, collectorCAPEM []byte, replayStore collectorcontrol.RequestReplayStore) (collectorcontrol.RequestAuthenticator, error) {
	if cfg.CollectorAuthMode == config.CollectorAuthDirectMTLS {
		return collectorcontrol.DirectMTLSAuthenticator{}, nil
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(collectorCAPEM) {
		return nil, fmt.Errorf("collector CA file contains no certificates")
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   1,
	}}
	return collectorcontrol.NewCloudflareAccessServiceTokenPoPAuthenticator(ctx, collectorcontrol.CloudflareAccessServiceTokenPoPConfig{
		Issuer: cfg.CloudflareTeamDomain, Audience: cfg.CloudflareAudience,
		TrustedProxies: cfg.TrustedProxyPrefixes, CollectorHostname: cfg.CollectorHostname,
		EnrollmentHostname: cfg.EnrollmentHostname, CollectorRoots: roots,
		ReplayStore: replayStore, HTTPClient: client, Clock: clock,
		Observer: &authEventLogger{logger: logger, counts: map[string]uint64{}},
	})
}

// configureDiagnosticExecution mounts the pull side of reviewed remote
// execution: the durable M5 queue behind the collector protocol, gated by an
// operator-maintained allow-list. A collector authenticated to poll metrics is
// not thereby authorized to run commands, which is why the authority is a
// separate decision from identity.
func configureDiagnosticExecution(cfg config.Control, pool *pgxpool.Pool, transport *collectorcontrol.Transport, clock platform.SystemClock) error {
	store, err := storepg.NewDiagnosticStore(pool)
	if err != nil {
		return err
	}
	worker, err := application.NewDiagnosticWorker(store, clock, platform.RandomIDGenerator{})
	if err != nil {
		return err
	}
	authority, err := investigationapi.NewAllowedCollectors(cfg.DiagnosticExecutionCollectors)
	if err != nil {
		return err
	}
	operations, err := investigationapi.NewDiagnosticWorkTransport(worker, authority)
	if err != nil {
		return err
	}
	return transport.ConfigureDiagnosticWork(operations)
}
