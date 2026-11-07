package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/gpussh"
)

func TestPrometheusOnlyCollectorHasNoTypedOrSSHExecutor(t *testing.T) {
	// Synthetic paths and identity. Readiness must work without opening
	// credentials, command packs, the collection journal or the network.
	for key, value := range map[string]string{
		"SHERLOCK_CLUSTER_ID":                           "fixture-cluster",
		"SHERLOCK_SOURCE_ID":                            "fixture-prometheus",
		"SHERLOCK_COLLECTOR_ID":                         "fixture-collector",
		"SHERLOCK_COLLECTOR_IDENTITY_DIR":               "",
		"SHERLOCK_COLLECTOR_CERT_FILE":                  "/synthetic/cert.pem",
		"SHERLOCK_COLLECTOR_KEY_FILE":                   "/synthetic/key.pem",
		"SHERLOCK_COLLECTOR_JOURNAL":                    "/synthetic/journal",
		"SHERLOCK_CONTROL_URL":                          "https://collector.example.test",
		"SHERLOCK_CONTROL_CA_FILE":                      "/synthetic/ca.pem",
		"SHERLOCK_COLLECTOR_TRANSPORT_AUTH_MODE":        "cloudflare_access_service_token_pop",
		"SHERLOCK_CLOUDFLARE_ACCESS_SERVICE_TOKEN_FILE": "/synthetic/access-token.json",
		"SHERLOCK_PROMETHEUS_URL":                       "http://127.0.0.1:9090",
		"SHERLOCK_COLLECTOR_CAPABILITIES":               "",
		"SHERLOCK_BCM_ACCESS_TEST_ENABLED":              "false",
		"SHERLOCK_BCM_ACCESS_TEST_EXTERNAL_WORKER":      "false",
		"SHERLOCK_GPU_PROCESS_OBSERVATIONS_ENABLED":     "false",
		"SHERLOCK_GPU_PROCESS_COMMAND_PACK_FILE":        "/synthetic/unused-gpu-pack.json",
		"SHERLOCK_COMMAND_PACK_FILE":                    "/synthetic/unused-diagnostic-pack.json",
		gpussh.PolicyEnvironment:                        "deny",
		gpussh.Environment:                              "",
		"SHERLOCK_GPU_SSH_DISPATCH_APPROVAL_FILE":       "",
	} {
		t.Setenv(key, value)
	}
	operations := []string{
		"prometheus.source_health.v1", "prometheus.gpu_identity.v1",
		"prometheus.gpu_utilization.v1", "prometheus.gpu_xid.v1",
		"prometheus.gpu_temperature.v1", "prometheus.gpu_power.v1",
		"prometheus.gpu_memory.v1", "prometheus.gpu_ecc.v1",
	}
	t.Setenv("SHERLOCK_COLLECTION_OPERATIONS", strings.Join(operations, ","))

	cfg, err := config.LoadCollector()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Operations) != len(operations) || cfg.GPUProcessObservation.Enabled || cfg.BCMAccessTest.Enabled || cfg.BCMAccessTest.ExternalWorker {
		t.Fatal("Prometheus-only collector enabled an unexpected role")
	}
	for _, op := range cfg.Operations {
		if !strings.HasPrefix(string(op), "prometheus.") {
			t.Fatalf("unexpected operation %q", op)
		}
	}
	legacy, typed, err := buildCollectionExecutors(cfg, nil)
	if err != nil || legacy == nil || typed != nil {
		t.Fatalf("expected only a Prometheus executor: %v", err)
	}
	if !gpussh.ExplicitDenyProfile() {
		t.Fatal("missing explicit deny profile")
	}
	for _, role := range []string{"gpu-process", "diagnostics", "network-monitor", "network-readiness", "network-probe"} {
		if !errors.Is(gpussh.Require(role, cfg.ClusterID), gpussh.ErrBlocked) {
			t.Fatalf("Prometheus-only collector authorized SSH role %s", role)
		}
	}
	var out bytes.Buffer
	if err := writeCollectionReadiness(&out, cfg, nil); err != nil || !strings.Contains(out.String(), `"ready":true`) {
		t.Fatalf("offline Prometheus readiness failed: %v", err)
	}
}
