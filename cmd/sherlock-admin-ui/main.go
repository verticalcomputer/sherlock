package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/verticalcomputer/sherlock/internal/adminclient"
	"github.com/verticalcomputer/sherlock/internal/adminui"
	"github.com/verticalcomputer/sherlock/internal/config"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, slog.New(slog.NewJSONHandler(os.Stderr, nil))); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "admin dashboard stopped")
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	cfg, err := config.LoadAdmin()
	if err != nil {
		return fmt.Errorf("load admin configuration: %w", err)
	}
	if !cfg.Enabled {
		logger.Info("admin.disabled")
		return nil
	}

	serviceToken := []byte(cfg.APIToken.Reveal())
	client, err := adminclient.New(cfg.APIURL, serviceToken, &http.Client{Timeout: cfg.APIClientTimeout})
	clear(serviceToken)
	if err != nil {
		return fmt.Errorf("configure private admin API client: %w", err)
	}
	accessVerifier, err := adminui.NewCloudflareAccessVerifier(ctx, adminui.CloudflareAccessConfig{
		Issuer: cfg.AccessTeamDomain, Audience: cfg.AccessAudience,
		HTTPClient: &http.Client{Timeout: cfg.APIClientTimeout},
	})
	if err != nil {
		return fmt.Errorf("configure Cloudflare Access verification: %w", err)
	}
	handler, err := adminui.New(adminui.Options{
		Provider: client, AccessVerifier: accessVerifier, RequireHumanAuthorization: cfg.HumanAuthorizationRequired,
		Auditor: client, ErrorReporter: safeAuditReporter{logger: logger},
	})
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr: cfg.ListenAddress, Handler: handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout, ReadTimeout: cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout, IdleTimeout: cfg.IdleTimeout,
	}
	serverErrors := make(chan error, 1)
	go func() {
		if cfg.TLSCertificate != "" {
			serverErrors <- server.ListenAndServeTLS(cfg.TLSCertificate, cfg.TLSPrivateKey)
			return
		}
		serverErrors <- server.ListenAndServe()
	}()
	logger.Info("admin.listening", "address", cfg.ListenAddress, "tls", cfg.TLSCertificate != "", "data_source", "private-admin-api")
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shut down admin dashboard: %w", err)
		}
		return ctx.Err()
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve admin dashboard: %w", err)
	}
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

type safeAuditReporter struct{ logger *slog.Logger }

func (reporter safeAuditReporter) ReportAdminError(_ context.Context, failure adminui.AuditDeliveryError) {
	reporter.logger.Error("admin.audit_delivery_failed", "kind", failure.Kind, "outcome", failure.Outcome)
}
