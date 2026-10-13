package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDisabledRemediationNeedsNoDependencies(t *testing.T) {
	t.Setenv("SHERLOCK_REMEDIATION_ENABLED", "")
	if err := run(slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
}
func TestRemediationConfigurationFailsClosed(t *testing.T) {
	for _, test := range []struct{ name, enabled, executor string }{{"invalid enablement", "yes", "SIMULATED"}, {"live executor", "true", "LIVE"}, {"missing roots", "true", "SIMULATED"}} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("SHERLOCK_REMEDIATION_ENABLED", test.enabled)
			t.Setenv("SHERLOCK_REMEDIATION_EXECUTOR", test.executor)
			t.Setenv("SHERLOCK_REMEDIATION_TRUST_ROOTS", "")
			if err := run(slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestLiveDatabaseRequiresDedicatedIdentity(t *testing.T) {
	t.Setenv("SHERLOCK_REMEDIATION_DATABASE_URL", "")
	t.Setenv("SHERLOCK_DATABASE_URL", "not-a-real-general-pool")
	if pool, err := openPool(context.Background(), true, "cluster-test"); err == nil || pool != nil {
		t.Fatal("LIVE accepted general database fallback")
	}
}
func TestMetricsAddressIsPrivate(t *testing.T) {
	for _, value := range []string{"0.0.0.0:9095", ":9095", "localhost:9095", "192.0.2.1:9095", "127.0.0.1:0", "http://secret@127.0.0.1:9095"} {
		if _, err := metricsAddress(value); err == nil || strings.Contains(err.Error(), value) {
			t.Fatalf("unsafe address handling")
		}
	}
	for _, value := range []string{"", "127.0.0.1:9095", "[::1]:9095"} {
		if _, err := metricsAddress(value); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHealthCheckIsBoundedAndRedacted(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable, http.StatusFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Location", "http://invalid.example/private-marker")
				w.WriteHeader(status)
				_, _ = w.Write([]byte("private-marker"))
			}))
			defer server.Close()
			t.Setenv("SHERLOCK_REMEDIATION_METRICS_ADDRESS", strings.TrimPrefix(server.URL, "http://"))
			err := healthcheck(context.Background())
			if status == http.StatusOK && err != nil {
				t.Fatal(err)
			}
			if status != http.StatusOK && (err == nil || strings.Contains(err.Error(), "private-marker")) {
				t.Fatal("unsafe health error")
			}
			if calls != 1 {
				t.Fatalf("health check followed redirect: calls=%d", calls)
			}
		})
	}
}
func TestControlRefusesInvalidOperationWithoutDependencies(t *testing.T) {
	for _, operation := range []string{"dispatch", "shell", "enable"} {
		if err := runConfigured(slog.New(slog.NewTextHandler(io.Discard, nil)), operation, "run-test"); err == nil {
			t.Fatal("unsafe control operation accepted")
		}
	}
}
