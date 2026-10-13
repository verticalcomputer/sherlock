package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestLoadCollectorDefaults(t *testing.T) {
	t.Setenv("SHERLOCK_CONTROL_URL", "https://control.test")
	t.Setenv("SHERLOCK_COLLECTOR_ID", "collector-1")
	t.Setenv("SHERLOCK_PROMETHEUS_URL", "http://prometheus.test")
	t.Setenv("SHERLOCK_COLLECTOR_CERT_FILE", "collector.crt")
	t.Setenv("SHERLOCK_COLLECTOR_KEY_FILE", "collector.key")
	t.Setenv("SHERLOCK_CONTROL_CA_FILE", "ca.crt")
	cfg, err := LoadCollector()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClaimWait != 25*time.Second || cfg.RequestTimeout < cfg.ClaimWait || cfg.JournalPath == "" || cfg.ExecutionRetries != 2 {
		t.Fatalf("unsafe defaults: %+v", cfg)
	}
	wantCapabilities := []string{"prometheus_source_health", "dcgm_gpu_identity", "dcgm_gpu_utilization", "dcgm_gpu_xid"}
	if !slices.Equal(cfg.Capabilities, wantCapabilities) {
		t.Fatalf("default capabilities = %v, want %v", cfg.Capabilities, wantCapabilities)
	}
	if slices.Contains(cfg.Operations, domain.OperationSlurmSnapshot) {
		t.Fatal("Slurm snapshot was enabled by default")
	}
}

func TestLoadCollectorSlurmSnapshotRequiresExplicitLocalAuthority(t *testing.T) {
	t.Setenv("SHERLOCK_CONTROL_URL", "https://control.test")
	t.Setenv("SHERLOCK_COLLECTOR_ID", "collector-1")
	t.Setenv("SHERLOCK_COLLECTOR_CERT_FILE", "collector.crt")
	t.Setenv("SHERLOCK_COLLECTOR_KEY_FILE", "collector.key")
	t.Setenv("SHERLOCK_CONTROL_CA_FILE", "ca.crt")
	t.Setenv("SHERLOCK_COLLECTION_OPERATIONS", "slurm.snapshot.v1")
	t.Setenv("SHERLOCK_CLUSTER_ID", "cluster-1")
	t.Setenv("SHERLOCK_SLURM_NODE_MAP", "node-1=comp007")
	if _, err := LoadCollector(); err == nil {
		t.Fatal("snapshot accepted without scheduler namespace and cluster")
	}
	t.Setenv("SHERLOCK_SLURM_SCHEDULER_NAMESPACE", "slurm/cluster-a")
	t.Setenv("SHERLOCK_SLURM_SCHEDULER_CLUSTER", "cluster-a")
	t.Setenv("SHERLOCK_SLURM_CURRENT_JOBS_COMPLETE", "true")
	t.Setenv("SHERLOCK_SLURM_ACCOUNTING_COMPLETE", "true")
	cfg, err := LoadCollector()
	if err != nil || !slices.Equal(cfg.Operations, []domain.CollectionOperationID{domain.OperationSlurmSnapshot}) || !cfg.SlurmCurrentJobsComplete || !cfg.SlurmAccountingComplete || cfg.SlurmAccountingOverlap != 5*time.Minute {
		t.Fatalf("snapshot config=%+v err=%v", cfg, err)
	}
	t.Setenv("SHERLOCK_SLURM_ACCOUNTING_OVERLAP", "0s")
	if _, err := LoadCollector(); err == nil {
		t.Fatal("unbounded accounting overlap accepted")
	}
}

func TestLoadCollectorUsesExplicitCapabilities(t *testing.T) {
	t.Setenv("SHERLOCK_CONTROL_URL", "https://control.test")
	t.Setenv("SHERLOCK_COLLECTOR_ID", "collector-1")
	t.Setenv("SHERLOCK_PROMETHEUS_URL", "http://prometheus.test")
	t.Setenv("SHERLOCK_COLLECTOR_CERT_FILE", "collector.crt")
	t.Setenv("SHERLOCK_COLLECTOR_KEY_FILE", "collector.key")
	t.Setenv("SHERLOCK_CONTROL_CA_FILE", "ca.crt")
	t.Setenv("SHERLOCK_COLLECTOR_CAPABILITIES", "prometheus_source_health, dcgm_gpu_xid")
	cfg, err := LoadCollector()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"prometheus_source_health", "dcgm_gpu_xid"}
	if !slices.Equal(cfg.Capabilities, want) {
		t.Fatalf("explicit capabilities = %v, want %v", cfg.Capabilities, want)
	}
}

func TestLoadCollectorSlurmInventoryIsExplicitAndDoesNotRequirePrometheus(t *testing.T) {
	t.Setenv("SHERLOCK_CONTROL_URL", "https://control.test")
	t.Setenv("SHERLOCK_COLLECTOR_ID", "collector-1")
	t.Setenv("SHERLOCK_COLLECTOR_CERT_FILE", "collector.crt")
	t.Setenv("SHERLOCK_COLLECTOR_KEY_FILE", "collector.key")
	t.Setenv("SHERLOCK_CONTROL_CA_FILE", "ca.crt")
	t.Setenv("SHERLOCK_PROMETHEUS_URL", "")
	t.Setenv("SHERLOCK_COLLECTOR_CAPABILITIES", "")
	t.Setenv("SHERLOCK_COLLECTION_OPERATIONS", "slurm.inventory.v1")
	t.Setenv("SHERLOCK_CLUSTER_ID", "cluster-1")
	t.Setenv("SHERLOCK_SLURM_NODE_MAP", "node-1=comp007,node-2=comp008")
	cfg, err := LoadCollector()
	if err != nil || len(cfg.Capabilities) != 0 || len(cfg.SlurmNodes) != 2 || cfg.SlurmSourceID != "local-slurm" {
		t.Fatalf("typed configuration: %+v %v", cfg, err)
	}
	for _, mapping := range []string{"", "node-1", "node-1=comp007,node-1=comp008", "node-1=comp007,node-2=comp007"} {
		t.Setenv("SHERLOCK_SLURM_NODE_MAP", mapping)
		if _, err := LoadCollector(); err == nil {
			t.Fatalf("invalid mapping accepted: %s", mapping)
		}
	}
	t.Setenv("SHERLOCK_SLURM_NODE_MAP", "node-1=comp007")
	for _, operation := range []string{"slurm.events.v1", "slurm.allocation.v1", "slurm.inventory.v1,slurm.inventory.v1"} {
		t.Setenv("SHERLOCK_COLLECTION_OPERATIONS", operation)
		if _, err := LoadCollector(); err == nil {
			t.Fatalf("unsupported operation accepted: %s", operation)
		}
	}
}

func TestLoadCollectorUsesReviewedOperationConfigurationAndDerivesV1Capabilities(t *testing.T) {
	t.Setenv("SHERLOCK_CONTROL_URL", "https://control.test")
	t.Setenv("SHERLOCK_COLLECTOR_ID", "collector-1")
	t.Setenv("SHERLOCK_PROMETHEUS_URL", "http://prometheus.test")
	t.Setenv("SHERLOCK_COLLECTOR_CERT_FILE", "collector.crt")
	t.Setenv("SHERLOCK_COLLECTOR_KEY_FILE", "collector.key")
	t.Setenv("SHERLOCK_CONTROL_CA_FILE", "ca.crt")
	t.Setenv("SHERLOCK_COLLECTION_OPERATIONS", "prometheus.gpu_utilization.v1,prometheus.gpu_xid.v1")
	cfg, err := LoadCollector()
	if err != nil {
		t.Fatal(err)
	}
	wantOperations := []domain.CollectionOperationID{domain.OperationPrometheusGPUUtilization, domain.OperationPrometheusGPUXID}
	if !slices.Equal(cfg.Operations, wantOperations) {
		t.Fatalf("operations = %v, want %v", cfg.Operations, wantOperations)
	}
	wantCapabilities := []string{"dcgm_gpu_utilization", "dcgm_gpu_xid"}
	if !slices.Equal(cfg.Capabilities, wantCapabilities) {
		t.Fatalf("v1 capabilities = %v, want %v", cfg.Capabilities, wantCapabilities)
	}
}

func TestLoadCollectorRejectsUnreviewedOrAmbiguousOperationConfiguration(t *testing.T) {
	base := func(t *testing.T) {
		t.Helper()
		t.Setenv("SHERLOCK_CONTROL_URL", "https://control.test")
		t.Setenv("SHERLOCK_COLLECTOR_ID", "collector-1")
		t.Setenv("SHERLOCK_PROMETHEUS_URL", "http://prometheus.test")
		t.Setenv("SHERLOCK_COLLECTOR_CERT_FILE", "collector.crt")
		t.Setenv("SHERLOCK_COLLECTOR_KEY_FILE", "collector.key")
		t.Setenv("SHERLOCK_CONTROL_CA_FILE", "ca.crt")
	}
	t.Run("unknown operation", func(t *testing.T) {
		base(t)
		t.Setenv("SHERLOCK_COLLECTION_OPERATIONS", "prometheus.shell.v1")
		if _, err := LoadCollector(); err == nil {
			t.Fatal("unreviewed operation was accepted")
		}
	})
	t.Run("ambiguous old and new settings", func(t *testing.T) {
		base(t)
		t.Setenv("SHERLOCK_COLLECTION_OPERATIONS", "prometheus.gpu_xid.v1")
		t.Setenv("SHERLOCK_COLLECTOR_CAPABILITIES", "dcgm_gpu_xid")
		if _, err := LoadCollector(); err == nil {
			t.Fatal("ambiguous operation configuration was accepted")
		}
	})
}

func TestLoadCollectorUsesManagedIdentityWithoutConflatingServerCA(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "current"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "current", "collector_id"), []byte("collector-managed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHERLOCK_CONTROL_URL", "https://control.test")
	t.Setenv("SHERLOCK_COLLECTOR_IDENTITY_DIR", directory)
	t.Setenv("SHERLOCK_CONTROL_CA_FILE", "/trust/server-ca.pem")
	t.Setenv("SHERLOCK_PROMETHEUS_URL", "http://prometheus.test")
	cfg, err := LoadCollector()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CollectorID != "collector-managed" || cfg.CAFile != "/trust/server-ca.pem" || cfg.CertificateFile != filepath.Join(directory, "current", "cert.pem") {
		t.Fatalf("managed identity config = %+v", cfg)
	}
}

func TestLoadCollectorRequiresMTLSFilesForHTTPS(t *testing.T) {
	t.Setenv("SHERLOCK_CONTROL_URL", "https://control.test")
	t.Setenv("SHERLOCK_COLLECTOR_ID", "collector-1")
	t.Setenv("SHERLOCK_PROMETHEUS_URL", "http://prometheus.test")
	if _, err := LoadCollector(); err == nil {
		t.Fatal("LoadCollector accepted HTTPS without an mTLS identity")
	}
}

func TestLoadCollectorRequiresServiceTokenFileInPoPMode(t *testing.T) {
	t.Setenv("SHERLOCK_CONTROL_URL", "https://control.test")
	t.Setenv("SHERLOCK_COLLECTOR_ID", "collector-1")
	t.Setenv("SHERLOCK_PROMETHEUS_URL", "http://prometheus.test")
	t.Setenv("SHERLOCK_COLLECTOR_CERT_FILE", "collector.crt")
	t.Setenv("SHERLOCK_COLLECTOR_KEY_FILE", "collector.key")
	t.Setenv("SHERLOCK_CONTROL_CA_FILE", "ca.crt")
	t.Setenv("SHERLOCK_COLLECTOR_TRANSPORT_AUTH_MODE", "cloudflare_access_service_token_pop")
	if _, err := LoadCollector(); err == nil {
		t.Fatal("LoadCollector accepted proof-of-possession mode without an Access Service Token file")
	}
	t.Setenv("SHERLOCK_CLOUDFLARE_ACCESS_SERVICE_TOKEN_FILE", "/run/sherlock/access-token.json")
	cfg, err := LoadCollector()
	if err != nil || cfg.TransportAuthMode != CollectorTransportCloudflareAccessServiceTokenPoP {
		t.Fatalf("proof-of-possession config = %+v err=%v", cfg, err)
	}
}

func TestLoadCollectorMetricsAddressMustBeLoopback(t *testing.T) {
	t.Setenv("SHERLOCK_CONTROL_URL", "https://control.test")
	t.Setenv("SHERLOCK_COLLECTOR_ID", "collector-1")
	t.Setenv("SHERLOCK_PROMETHEUS_URL", "http://prometheus.test")
	t.Setenv("SHERLOCK_COLLECTOR_CERT_FILE", "collector.crt")
	t.Setenv("SHERLOCK_COLLECTOR_KEY_FILE", "collector.key")
	t.Setenv("SHERLOCK_CONTROL_CA_FILE", "ca.crt")
	cfg, err := LoadCollector()
	if err != nil || cfg.MetricsAddress != "" {
		t.Fatalf("metrics listener must be disabled by default: %q %v", cfg.MetricsAddress, err)
	}
	t.Setenv("SHERLOCK_COLLECTOR_METRICS_ADDRESS", "0.0.0.0:9464")
	if _, err := LoadCollector(); err == nil {
		t.Fatal("LoadCollector accepted a non-loopback metrics listener")
	}
	t.Setenv("SHERLOCK_COLLECTOR_METRICS_ADDRESS", "127.0.0.1:9464")
	if cfg, err := LoadCollector(); err != nil || cfg.MetricsAddress != "127.0.0.1:9464" {
		t.Fatalf("loopback metrics listener = %q %v", cfg.MetricsAddress, err)
	}
}

func TestLoadCollectorRejectsUnboundedBackoff(t *testing.T) {
	t.Setenv("SHERLOCK_CONTROL_URL", "https://control.test")
	t.Setenv("SHERLOCK_COLLECTOR_ID", "collector-1")
	t.Setenv("SHERLOCK_PROMETHEUS_URL", "http://prometheus.test")
	t.Setenv("SHERLOCK_COLLECTOR_CERT_FILE", "collector.crt")
	t.Setenv("SHERLOCK_COLLECTOR_KEY_FILE", "collector.key")
	t.Setenv("SHERLOCK_CONTROL_CA_FILE", "ca.crt")
	t.Setenv("SHERLOCK_BACKOFF_MINIMUM", "2s")
	t.Setenv("SHERLOCK_BACKOFF_MAXIMUM", "1s")
	if _, err := LoadCollector(); err == nil {
		t.Fatal("LoadCollector accepted a maximum backoff below its minimum")
	}
}
