package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/verticalcomputer/sherlock/internal/bcmaccess"
	"github.com/verticalcomputer/sherlock/internal/collectorruntime"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if len(os.Args) > 2 {
		logger.Error("collector.mode_invalid")
		os.Exit(2)
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "readiness":
			cfg, err := config.LoadCollector()
			if err == nil {
				err = writeCollectionReadiness(os.Stdout, cfg, nil)
			}
			if err != nil {
				logger.Error("collector.readiness_failed", "reason", "local collection configuration is unavailable or incompatible")
				os.Exit(2)
			}
			return
		case "enroll":
			if err := enroll(context.Background()); err != nil {
				logger.Error("collector.enrollment_failed", "error", err.Error())
				os.Exit(1)
			}
			logger.Info("collector.enrolled")
			return
		case "diagnostics":
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if err := runDiagnostics(ctx, logger); !errors.Is(err, context.Canceled) {
				logger.Error("collector.diagnostics_stopped", "error", err.Error())
				os.Exit(1)
			}
			logger.Info("collector.diagnostics_stopped")
			return
		case "network-readiness":
			if err := qualifyNetworkMonitor(context.Background(), os.Stdout); err != nil {
				logger.Error("collector.network_readiness_failed")
				os.Exit(1)
			}
			return
		case "network-monitor":
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if err := runNetworkMonitor(ctx, logger); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("collector.network_monitor_stopped", "reason", "configuration or transport unavailable")
				os.Exit(1)
			}
			return
		case "bcm-access-test":
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if err := runBCMAccessTest(ctx, logger); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("collector.bcm_access_test_stopped", "error", err.Error())
				os.Exit(1)
			}
			logger.Info("collector.bcm_access_test_stopped")
			return
		case "renew":
			if err := renew(context.Background()); err != nil {
				logger.Error("collector.renewal_failed", "error", err.Error())
				os.Exit(1)
			}
			logger.Info("collector.identity_renewed")
			return
		case "journal-check-legacy":
			if err := runJournalCheckLegacy(logger); err != nil {
				logger.Error("collector.journal_check_failed", "error", err.Error())
				os.Exit(1)
			}
			return
		case "journal-migrate":
			if err := runJournalMigrate(logger); err != nil {
				logger.Error("collector.journal_migration_failed", "error", err.Error())
				os.Exit(1)
			}
			return
		case "journal-status":
			path, err := config.LoadCollectorJournalPath()
			if err == nil {
				err = writeJournalStatus(os.Stdout, path, time.Now().UTC())
			}
			if err != nil {
				logger.Error("collector.journal_status_failed", "error", err.Error())
				os.Exit(1)
			}
			return
		case "journal-export-rollback":
			if err := runJournalExportRollback(logger); err != nil {
				logger.Error("collector.journal_export_failed", "error", err.Error())
				os.Exit(1)
			}
			return
		default:
			logger.Error("collector.mode_invalid")
			os.Exit(2)
		}
	}
	cfg, err := config.LoadCollector()
	if err != nil {
		logger.Error("collector.configuration_invalid", "error", err.Error())
		os.Exit(2)
	}
	registry := prometheus.NewRegistry()
	metrics := newJournalMetrics(registry, func() time.Time { return time.Now().UTC() })
	runtime, journal, credentialWorker, err := buildRuntime(cfg, metrics, logger)
	if err != nil {
		logger.Error("collector.start_failed", "error", err.Error())
		os.Exit(1)
	}
	logJournalPreparation(logger, journal.MigrationReport())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := serve(ctx, logger, cfg, runtime, journal, credentialWorker, metrics, registry)
	stop()
	os.Exit(code)
}

// serve runs collection with journal maintenance and the optional loopback
// metrics listener, and closes the journal only after both have stopped.
func serve(ctx context.Context, logger *slog.Logger, cfg config.Collector, runtime *collectorruntime.Runtime, journal *collectorruntime.Journal, credentialWorker *collectorruntime.CredentialTestWorker, metrics *journalMetrics, registry *prometheus.Registry) int {
	serviceContext, cancel := context.WithCancel(ctx)
	var background sync.WaitGroup
	if credentialWorker != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			if err := credentialWorker.Run(serviceContext); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("collector.credential_test_worker_stopped", "error", err.Error())
			}
		}()
		logger.Info("collector.credential_test_worker_started", "expected_host", cfg.BCMAccessTest.ExpectedHost)
	}
	defer func() {
		cancel()
		background.Wait()
		if err := journal.Close(); err != nil {
			logger.Error("collector.journal_close_failed", "error", err.Error())
		}
	}()
	background.Add(1)
	go func() {
		defer background.Done()
		_ = collectorruntime.RunJournalMaintenance(serviceContext, journal, journalMaintenanceInterval, journalMaintenanceObserver(logger, metrics))
	}()
	if cfg.MetricsAddress != "" {
		listener, err := net.Listen("tcp", cfg.MetricsAddress)
		if err != nil {
			logger.Error("collector.metrics_listen_failed", "error", err.Error())
			return 1
		}
		server := &http.Server{Handler: promhttp.HandlerFor(registry, promhttp.HandlerOpts{}), ReadHeaderTimeout: 3 * time.Second}
		background.Add(2)
		go func() {
			defer background.Done()
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("collector.metrics_server_failed", "error", err.Error())
			}
		}()
		go func() {
			defer background.Done()
			<-serviceContext.Done()
			shutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelShutdown()
			_ = server.Shutdown(shutdown)
		}()
		logger.Info("collector.metrics_listening", "address", cfg.MetricsAddress)
	}
	logger.Info("collector.started", "collector_id", cfg.CollectorID)
	if err := runtime.Run(serviceContext); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("collector.stopped", "error", err.Error())
		return 1
	}
	return 0
}

func enroll(ctx context.Context) error {
	cfg, err := config.LoadCollectorIdentity()
	if err != nil {
		return err
	}
	var token *collectorruntime.BootstrapToken
	if cfg.BootstrapTokenFile != "" {
		token, err = collectorruntime.ReadBootstrapTokenFile(cfg.BootstrapTokenFile)
	} else {
		token, err = collectorruntime.ReadTokenFromStdin(os.Stdin, os.Stderr)
	}
	if err != nil {
		return err
	}
	defer token.Clear()
	privateKey, csr, err := collectorruntime.GenerateIdentityRequest()
	if err != nil {
		return err
	}
	defer clear(privateKey)
	httpClient, err := bootstrapHTTPClient(cfg, 15*time.Second)
	if err != nil {
		return err
	}
	client, err := collectorruntime.NewHTTPClient(cfg.ControlURL, httpClient, time.Minute)
	if err != nil {
		return err
	}
	identity, err := client.Enroll(ctx, token, csr, collectorruntime.DefaultCollectorMetadata(cfg.DisplayName, cfg.Version, cfg.BuildCommit))
	if err != nil {
		return err
	}
	return collectorruntime.PersistIdentity(cfg.IdentityDir, identity, privateKey, "", time.Now().UTC())
}

func renew(ctx context.Context) error {
	cfg, err := config.LoadCollector()
	if err != nil {
		return err
	}
	if cfg.IdentityDir == "" {
		return fmt.Errorf("SHERLOCK_COLLECTOR_IDENTITY_DIR is required for atomic identity renewal")
	}
	privateKey, csr, err := collectorruntime.GenerateIdentityRequest()
	if err != nil {
		return err
	}
	defer clear(privateKey)
	httpClient, err := controlHTTPClient(cfg.Transport())
	if err != nil {
		return err
	}
	client, err := collectorruntime.NewHTTPClient(cfg.ControlURL, httpClient, time.Minute)
	if err != nil {
		return err
	}
	identity, err := client.RenewIdentity(ctx, csr)
	if err != nil {
		return err
	}
	return collectorruntime.PersistIdentity(cfg.IdentityDir, identity, privateKey, cfg.CollectorID, time.Now().UTC())
}

func buildRuntime(cfg config.Collector, observer collectorruntime.JournalObserver, logger *slog.Logger) (*collectorruntime.Runtime, *collectorruntime.Journal, *collectorruntime.CredentialTestWorker, error) {
	httpClient, err := controlHTTPClient(cfg.Transport())
	if err != nil {
		return nil, nil, nil, err
	}
	control, err := collectorruntime.NewHTTPClient(cfg.ControlURL, httpClient, 2*time.Minute)
	if err != nil {
		return nil, nil, nil, err
	}
	clock := platform.SystemClock{}
	executor, typed, err := buildCollectionExecutors(cfg, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	journal, err := collectorruntime.OpenJournal(cfg.JournalPath, clock, collectorruntime.WithJournalObserver(observer))
	if err != nil {
		return nil, nil, nil, err
	}
	credentialWorker, err := buildBCMCredentialWorker(cfg, control, clock, logger)
	if err != nil {
		_ = journal.Close()
		return nil, nil, nil, err
	}
	additional := bcmAccessTestCapabilities(cfg)
	runtime, err := collectorruntime.NewRuntimeWithTyped(collectorruntime.RuntimeConfig{
		CollectorID: domain.CollectorID(cfg.CollectorID), SourceID: domain.SourceID(cfg.SourceID), Version: cfg.Version, BuildCommit: cfg.BuildCommit,
		Capabilities: cfg.Capabilities, HeartbeatInterval: cfg.HeartbeatInterval, ClaimWait: cfg.ClaimWait,
		RenewInterval: cfg.RenewInterval, BackoffMinimum: cfg.BackoffMinimum, BackoffMaximum: cfg.BackoffMaximum,
		ExecutionRetries: cfg.ExecutionRetries, ExecutionBackoff: cfg.ExecutionBackoff, AdditionalCapabilities: additional,
	}, control, executor, typed, journal, clock)
	if err != nil {
		_ = journal.Close()
		return nil, nil, nil, err
	}
	return runtime, journal, credentialWorker, nil
}

func bcmAccessTestCapabilities(cfg config.Collector) []string {
	if cfg.BCMAccessTest.Enabled || cfg.BCMAccessTest.ExternalWorker {
		// Both reviewed operations of the family run the same fixed head
		// command through the same checker, so a head configured for one is
		// configured for both. An operator binding, not this advertisement,
		// is still what entitles any claim.
		return domain.CredentialAccessOperations()
	}
	return nil
}

// buildBCMCredentialWorker is kept separate from the ordinary runtime so the
// external claimant configuration cannot accidentally create a second worker.
func buildBCMCredentialWorker(cfg config.Collector, control collectorruntime.CredentialTestControlClient, clock collectorruntime.Clock, logger *slog.Logger) (*collectorruntime.CredentialTestWorker, error) {
	if !cfg.BCMAccessTest.Enabled {
		return nil, nil
	}
	checker, err := bcmaccess.New(bcmaccess.Config{SudoPath: cfg.BCMAccessTest.SudoPath, CmshPath: cfg.BCMAccessTest.CmshPath, ReleaseFile: cfg.BCMAccessTest.ReleaseFile, ExpectedHost: cfg.BCMAccessTest.ExpectedHost})
	if err != nil {
		return nil, err
	}
	return collectorruntime.NewCredentialTestWorker(collectorruntime.CredentialTestWorkerConfig{
		CollectorID: domain.CollectorID(cfg.CollectorID), ClaimWait: cfg.ClaimWait, RenewInterval: cfg.RenewInterval,
		BackoffMinimum: cfg.BackoffMinimum, BackoffMaximum: cfg.BackoffMaximum, Logger: logger,
	}, control, checker, clock)
}

// runBCMAccessTest owns the only credential-delivery claimant in a split BCM
// deployment. It intentionally does not create a collection runtime or emit a
// heartbeat: the ordinary collector retains the one approved identity and
// advertises the capability only when its configuration names this role.
func runBCMAccessTest(ctx context.Context, logger *slog.Logger) error {
	cfg, err := config.LoadCollector()
	if err != nil {
		return err
	}
	if !cfg.BCMAccessTest.Enabled || cfg.BCMAccessTest.ExternalWorker {
		return fmt.Errorf("BCM access test role requires SHERLOCK_BCM_ACCESS_TEST_ENABLED=true and SHERLOCK_BCM_ACCESS_TEST_EXTERNAL_WORKER=false")
	}
	if err := requireNoNewPrivilegesDisabled(runtime.GOOS, os.ReadFile); err != nil {
		return err
	}
	httpClient, err := controlHTTPClient(cfg.Transport())
	if err != nil {
		return err
	}
	control, err := collectorruntime.NewHTTPClient(cfg.ControlURL, httpClient, 2*time.Minute)
	if err != nil {
		return err
	}
	worker, err := buildBCMCredentialWorker(cfg, control, platform.SystemClock{}, logger)
	if err != nil || worker == nil {
		if err == nil {
			err = fmt.Errorf("BCM access test role did not create a credential worker")
		}
		return err
	}
	logger.Info("collector.bcm_access_test_started", "collector_id", cfg.CollectorID, "expected_host", cfg.BCMAccessTest.ExpectedHost)
	return worker.Run(ctx)
}

// requireNoNewPrivilegesDisabled is deliberately BCM-role-only. sudo cannot
// gain the reviewed privilege when the kernel's irreversible no-new-privileges
// bit is set, so fail before a claim or credential delivery instead of turning
// a service sandbox error into a misleading authentication result.
func requireNoNewPrivilegesDisabled(goos string, readFile func(string) ([]byte, error)) error {
	if goos != "linux" {
		return fmt.Errorf("BCM access test role requires Linux to verify NoNewPrivileges")
	}
	status, err := readFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("inspect BCM access test NoNewPrivileges state: %w", err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		key, value, found := strings.Cut(line, ":")
		if found && key == "NoNewPrivs" {
			switch strings.TrimSpace(value) {
			case "0":
				return nil
			case "1":
				return fmt.Errorf("BCM access test role has NoNewPrivileges=1; start sherlock-collector-bcm-access-test.service with NoNewPrivileges=false and no sandbox setting that implies it")
			default:
				return fmt.Errorf("BCM access test role has an invalid NoNewPrivileges status")
			}
		}
	}
	return fmt.Errorf("BCM access test role could not determine NoNewPrivileges status")
}

func controlHTTPClient(cfg config.CollectorTransport) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	keyInfo, err := os.Stat(cfg.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("inspect collector private key: %w", err)
	}
	if keyInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("collector private key must not be accessible by group or other users")
	}
	certificatePEM, err := os.ReadFile(cfg.CertificateFile)
	if err != nil {
		return nil, fmt.Errorf("read collector certificate: %w", err)
	}
	privateKeyPEM, err := os.ReadFile(cfg.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read collector private key: %w", err)
	}
	defer clear(privateKeyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load collector identity: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read collector control CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("collector control CA file contains no certificates")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	var roundTripper http.RoundTripper = transport
	switch cfg.AuthMode {
	case config.CollectorTransportDirectMTLS:
		if cfg.IdentityDir != "" {
			identityChain, err := os.ReadFile(cfg.IdentityDir + "/current/ca.pem")
			if err != nil {
				return nil, fmt.Errorf("read collector identity CA chain: %w", err)
			}
			certificatePEM = append(append(certificatePEM, '\n'), identityChain...)
			certificate, err = tls.X509KeyPair(certificatePEM, privateKeyPEM)
			if err != nil {
				return nil, fmt.Errorf("load collector mTLS identity chain: %w", err)
			}
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	case config.CollectorTransportCloudflareAccessServiceTokenPoP:
		token, err := collectorruntime.ReadAccessServiceToken(cfg.AccessServiceTokenFile)
		if err != nil {
			return nil, err
		}
		roundTripper, err = collectorruntime.NewAccessServiceTokenPoPRoundTripper(transport, token, certificate)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported collector transport authentication mode")
	}
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Transport: roundTripper, Timeout: cfg.RequestTimeout}, nil
}

func bootstrapHTTPClient(cfg config.CollectorIdentity, timeout time.Duration) (*http.Client, error) {
	caPEM, err := os.ReadFile(cfg.BootstrapCAFile)
	if err != nil {
		return nil, fmt.Errorf("read collector bootstrap CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("collector bootstrap CA file contains no certificates")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	var roundTripper http.RoundTripper = transport
	if cfg.TransportAuthMode == config.CollectorTransportCloudflareAccessServiceTokenPoP {
		token, err := collectorruntime.ReadAccessServiceToken(cfg.AccessServiceTokenFile)
		if err != nil {
			return nil, err
		}
		roundTripper, err = collectorruntime.NewAccessServiceTokenRoundTripper(transport, token)
		if err != nil {
			return nil, err
		}
	}
	return &http.Client{Transport: roundTripper, Timeout: timeout}, nil
}
