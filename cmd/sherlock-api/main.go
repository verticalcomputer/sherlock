package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"
	investigationapi "github.com/verticalcomputer/sherlock/internal/adapters/investigationapi"
	"github.com/verticalcomputer/sherlock/internal/adminapi"
	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/adminview"
	publicapi "github.com/verticalcomputer/sherlock/internal/api"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/artifacts"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/diagnosticpolicy"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/events"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := config.LoadAPI()
	if err != nil {
		logger.Error("api.configuration_invalid", "error", err.Error())
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, logger); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("api.stopped", "reason", "startup or runtime failure")
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config.API, logger *slog.Logger) error {
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("configure PostgreSQL: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	authStore, err := auth.NewPostgreSQLStore(pool)
	if err != nil {
		return err
	}
	clock := platform.SystemClock{}
	authService, err := auth.NewService(authStore, clock, rand.Reader, cfg.APIKeyHashKey)
	for index := range cfg.APIKeyHashKey {
		cfg.APIKeyHashKey[index] = 0
	}
	if err != nil {
		return err
	}
	defer authService.Close()
	queryStore, err := storepg.NewPublicQueryStore(pool)
	if err != nil {
		return err
	}
	queries, err := application.NewPublicQueries(queryStore, clock, cfg.FreshFor)
	if err != nil {
		return err
	}
	eventStore, err := events.NewStore(pool)
	if err != nil {
		return err
	}
	investigationStore, err := storepg.NewInvestigationStore(pool)
	if err != nil {
		return err
	}
	artifactStore, err := configureArtifactStore(ctx, cfg.ArtifactStorage, cfg.ModelAuditArtifactMaxBytes)
	if err != nil {
		return err
	}
	investigationController, err := investigationapi.NewFailClosedController(investigationStore, clock, platform.RandomIDGenerator{})
	if err != nil {
		return err
	}
	investigations, err := investigationapi.NewService(pool, investigationController, clock)
	if err != nil {
		return err
	}
	var diagnostics *application.DiagnosticService
	var diagnosticQueries *application.DiagnosticQueries
	if cfg.CommandPackFile != "" {
		var diagnosticErr error
		diagnostics, diagnosticQueries, diagnosticErr = configureDiagnostics(cfg, pool, authStore, clock)
		if diagnosticErr != nil {
			return diagnosticErr
		}
	}
	handler, err := publicapi.NewConfiguredServer(publicapi.ServerOptions{
		Authenticator: authService, Queries: queries, Events: eventStore,
		Diagnostics: diagnostics, DiagnosticRuns: diagnosticQueries, Investigations: investigations,
		Clock: clock, FreshFor: cfg.FreshFor, AllowedOrigins: cfg.AllowedOrigins,
	})
	if err != nil {
		return err
	}
	server, err := publicapi.NewHTTPServer(cfg.ListenAddress, handler, cfg.ReadHeaderTimeout, cfg.ReadTimeout, cfg.IdleTimeout)
	if err != nil {
		return err
	}
	adminServer, err := configureAdminAPIServer(cfg, pool, artifactStore, investigations)
	if err != nil {
		return err
	}
	serverErrors := make(chan error, 1)
	go func() {
		if cfg.TLSCertificate != "" {
			serverErrors <- server.ListenAndServeTLS(cfg.TLSCertificate, cfg.TLSPrivateKey)
			return
		}
		serverErrors <- server.ListenAndServe()
	}()
	var adminServerErrors <-chan error
	if adminServer != nil {
		errorsChannel := make(chan error, 1)
		adminServerErrors = errorsChannel
		go func() {
			if cfg.AdminAPITLSCertificate != "" {
				errorsChannel <- adminServer.ListenAndServeTLS(cfg.AdminAPITLSCertificate, cfg.AdminAPITLSPrivateKey)
				return
			}
			errorsChannel <- adminServer.ListenAndServe()
		}()
		logger.Info("admin_api.listening", "address", cfg.AdminAPIListenAddress, "tls", cfg.AdminAPITLSCertificate != "")
	}
	logger.Info("api.listening", "address", cfg.ListenAddress, "tls", cfg.TLSCertificate != "")
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := shutdownAPIServers(shutdownCtx, server, adminServer); err != nil {
			return err
		}
		return ctx.Err()
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve public API: %w", err)
	case err := <-adminServerErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve private admin API: %w", err)
	}
}

type adminInvestigationService interface {
	adminapi.InvestigationStarter
	adminapi.InvestigationCanceller
}

func configureAdminAPIServer(cfg config.API, pool *pgxpool.Pool, artifactStore artifacts.Store, investigationServices ...adminInvestigationService) (*http.Server, error) {
	if !cfg.AdminAPIEnabled {
		return nil, nil
	}
	store, err := adminview.NewPostgresStore(pool)
	if err != nil {
		return nil, err
	}
	// Private GPU conditions and public GPU queries use one freshness policy.
	views, err := adminview.NewService(store, adminview.WithGPUHealthFreshness(cfg.FreshFor))
	if err != nil {
		return nil, err
	}
	auditor, err := storepg.NewAdminAuditStore(pool)
	if err != nil {
		return nil, err
	}
	var managementOptions []adminmanage.PostgresOption
	if cfg.CredentialKeyring.ActiveVersion != "" {
		ring, err := adminmanage.NewCredentialKeyring(cfg.CredentialKeyring.ActiveVersion, cfg.CredentialKeyring.Keys)
		if err != nil {
			return nil, fmt.Errorf("configure credential keyring: %w", err)
		}
		defer ring.Destroy()
		for _, key := range cfg.CredentialKeyring.Keys {
			for i := range key {
				key[i] = 0
			}
		}
		managementOptions = append(managementOptions, adminmanage.WithCredentialKeyring(ring))
	}
	if artifactStore != nil {
		evidenceStore, err := storepg.NewEvidenceStore(pool)
		if err != nil {
			return nil, err
		}
		payloadReader, err := adminmanage.NewEvidencePayloadReader(evidenceStore, artifactStore)
		if err != nil {
			return nil, err
		}
		managementOptions = append(managementOptions, adminmanage.WithModelPayloadReader(payloadReader))
	}
	// Expected-inventory import writes only through the canonical GP-02
	// goodput store, so the admin management store is given that writer
	// rather than a second path into the inventory tables.
	goodputStore, err := storepg.NewGoodputStore(pool)
	if err != nil {
		return nil, err
	}
	progressService, err := application.NewProgressService(goodputStore)
	if err != nil {
		return nil, err
	}
	managementOptions = append(managementOptions, adminmanage.WithGoodputStore(goodputStore))
	management, err := adminmanage.NewPostgresStore(pool, managementOptions...)
	if err != nil {
		return nil, err
	}
	serviceToken := []byte(cfg.AdminAPIServiceToken.Reveal())
	options := adminapi.Options{Provider: views, GPUMetrics: views, Progress: progressService, Management: management, Auditor: auditor, ServiceToken: serviceToken, RequireHumanSession: cfg.AdminHumanSessionRequired, HumanAuthorization: management, RequireHumanAuthorization: cfg.AdminHumanAuthorizationRequired}
	if cfg.CredentialKeyring.ActiveVersion != "" {
		options.Credentials = management
		options.AccessTests = management
		options.ExpectedInventory = management
	}
	if len(investigationServices) > 0 && investigationServices[0] != nil {
		options.Investigations = investigationServices[0]
		options.Cancellations = investigationServices[0]
	}
	handler, err := adminapi.New(options)
	clearBytes(serviceToken)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr: cfg.AdminAPIListenAddress, Handler: handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout, ReadTimeout: cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout, IdleTimeout: cfg.IdleTimeout,
		MaxHeaderBytes: 64 << 10,
	}, nil
}

func shutdownAPIServers(ctx context.Context, servers ...*http.Server) error {
	var shutdownErrors []error
	for _, server := range servers {
		if server == nil {
			continue
		}
		if err := server.Shutdown(ctx); err != nil {
			shutdownErrors = append(shutdownErrors, err)
		}
	}
	if err := errors.Join(shutdownErrors...); err != nil {
		return fmt.Errorf("shut down API listeners: %w", err)
	}
	return nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func configureArtifactStore(ctx context.Context, storage config.ArtifactStorage, maxBytes int64) (artifacts.Store, error) {
	if !storage.Configured() {
		return nil, nil
	}
	store, err := artifacts.NewStore(ctx, artifacts.Options{
		Backend: storage.Backend, LocalRoot: storage.LocalRoot,
		Endpoint: storage.R2Endpoint, Bucket: storage.R2Bucket,
		AccessKeyID: storage.R2AccessKeyID.Reveal(), SecretAccessKey: storage.R2SecretAccessKey.Reveal(),
		Prefix: storage.R2Prefix, MaxBytes: maxBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("configure artifact store: %w", err)
	}
	return store, nil
}

func configureDiagnostics(cfg config.API, pool *pgxpool.Pool, keyReader diagnosticpolicy.KeyReader, clock platform.SystemClock) (*application.DiagnosticService, *application.DiagnosticQueries, error) {
	verified, err := commandpack.LoadVerifiedCatalog(cfg.CommandPackFile, cfg.TrustRootsFile, cfg.RunnerVersion, clock.Now())
	if err != nil {
		return nil, nil, err
	}
	rawInventory, err := commandpack.LoadTargetRoles(cfg.DiagnosticInventoryFile)
	if err != nil {
		return nil, nil, err
	}
	inventory := make(map[domain.ClusterID]map[domain.DiagnosticTarget]commandpack.TargetRole, len(rawInventory))
	for clusterID, targets := range rawInventory {
		inventory[domain.ClusterID(clusterID)] = make(map[domain.DiagnosticTarget]commandpack.TargetRole, len(targets))
		for target, role := range targets {
			inventory[domain.ClusterID(clusterID)][domain.DiagnosticTarget(target)] = role
		}
	}
	// The operator-maintained inventory remains the source until derivation is
	// wired to live Slurm, coverage, and Redfish observations. Switching this
	// call to NewCatalog with a hostroles.Resolver is the only change needed.
	policy, err := diagnosticpolicy.NewCatalogWithStaticInventory(verified, inventory)
	if err != nil {
		return nil, nil, err
	}
	authorizer, err := diagnosticpolicy.NewAuthorizer(keyReader, clock)
	if err != nil {
		return nil, nil, err
	}
	store, err := storepg.NewDiagnosticStore(pool)
	if err != nil {
		return nil, nil, err
	}
	service, err := application.NewDiagnosticService(store, policy, authorizer, store, clock, platform.RandomIDGenerator{})
	if err != nil {
		return nil, nil, err
	}
	queryStore, err := storepg.NewDiagnosticQueryStore(pool)
	if err != nil {
		return nil, nil, err
	}
	diagnosticQueries, err := application.NewDiagnosticQueries(queryStore)
	if err != nil {
		return nil, nil, err
	}
	return service, diagnosticQueries, nil
}
