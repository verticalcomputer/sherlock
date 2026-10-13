package config

import (
	"encoding/json"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"strings"
	"testing"
	"time"
)

func TestDurableAdmissionConfigurationFailsClosed(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://fixture")
	t.Setenv("SHERLOCK_COLLECTION_EXECUTOR", "remote")
	t.Setenv("SHERLOCK_DURABLE_ADMISSION_ENABLED", "")
	t.Setenv("SHERLOCK_DURABLE_EXECUTIONS", "")
	cfg, err := LoadWorker()
	if err != nil || cfg.DurableAdmissionEnabled {
		t.Fatalf("default off: %v %v", cfg.DurableAdmissionEnabled, err)
	}
	g := domain.DurableExecution{ScheduleKey: domain.ScheduleKey{ClusterID: "cluster", SourceID: "source", Operation: domain.OperationSlurmInventory}, Revision: 1, CollectorID: "collector", Nodes: []domain.StableNodeID{"node"}}
	encoded, _ := json.Marshal([]domain.DurableExecution{g})
	for _, raw := range []string{string(encoded) + " {}", string(encoded) + " garbage", `[{"unknown":true}]`} {
		t.Setenv("SHERLOCK_DURABLE_EXECUTIONS", raw)
		if _, err = LoadWorker(); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	encoded, _ = json.Marshal([]domain.DurableExecution{g, g})
	t.Setenv("SHERLOCK_DURABLE_EXECUTIONS", string(encoded))
	if _, err = LoadWorker(); err == nil {
		t.Fatal("duplicate grant")
	}
	encoded, _ = json.Marshal([]domain.DurableExecution{g})
	t.Setenv("SHERLOCK_DURABLE_EXECUTIONS", string(encoded))
	t.Setenv("SHERLOCK_DURABLE_ADMISSION_ENABLED", "true")
	if cfg, err = LoadWorker(); err != nil || !cfg.DurableAdmissionEnabled || len(cfg.DurableExecutions) != 1 {
		t.Fatalf("valid configuration: %v", err)
	}
	t.Setenv("SHERLOCK_COLLECTION_EXECUTOR", "inprocess")
	t.Setenv("SHERLOCK_PROMETHEUS_URL", "http://fixture")
	if _, err = LoadWorker(); err == nil {
		t.Fatal("inprocess admission")
	}
}

func TestDurableMetricsSchedulesConfiguration(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://fixture")
	t.Setenv("SHERLOCK_COLLECTION_EXECUTOR", "remote")
	t.Setenv("SHERLOCK_DURABLE_METRICS_SCHEDULES", "")
	cfg, err := LoadWorker()
	if err != nil || len(cfg.DurableMetricsSchedules) != 0 {
		t.Fatalf("default enrollment: %v %+v", cfg.DurableMetricsSchedules, err)
	}
	key := domain.ScheduleKey{ClusterID: "cluster", SourceID: "source", Operation: domain.OperationPrometheusGPUUtilization}
	encoded, _ := json.Marshal([]domain.ScheduleKey{key})
	t.Setenv("SHERLOCK_DURABLE_METRICS_SCHEDULES", string(encoded))
	if cfg, err = LoadWorker(); err != nil || len(cfg.DurableMetricsSchedules) != 1 || cfg.DurableMetricsSchedules[0] != key {
		t.Fatalf("valid enrollment: %+v %v", cfg.DurableMetricsSchedules, err)
	}
	for _, raw := range []string{
		string(encoded) + " []",
		string(encoded) + " garbage",
		`[{"ClusterID":"c","SourceID":"s","Operation":"prometheus.gpu_utilization.v1","extra":true}]`,
		`{"ClusterID":"c","SourceID":"s","Operation":"prometheus.gpu_utilization.v1"}`,
		`null`,
		`5`,
		`[{"ClusterID":"c","SourceID":"","Operation":"prometheus.gpu_utilization.v1"}]`,
		`[{"ClusterID":"c","SourceID":"s","Operation":"example.unreviewed.v9"}]`,
	} {
		t.Setenv("SHERLOCK_DURABLE_METRICS_SCHEDULES", raw)
		if _, err = LoadWorker(); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	duplicates, _ := json.Marshal([]domain.ScheduleKey{key, key})
	t.Setenv("SHERLOCK_DURABLE_METRICS_SCHEDULES", string(duplicates))
	if _, err = LoadWorker(); err == nil {
		t.Fatal("duplicate schedule keys accepted")
	}
	enrolled := make([]domain.ScheduleKey, 0, domain.MaxDurableSchedulerSnapshotKeys+1)
	for i := 0; i <= domain.MaxDurableSchedulerSnapshotKeys; i++ {
		enrolled = append(enrolled, domain.ScheduleKey{ClusterID: domain.ClusterID("cluster-" + string(rune('a'+i/26)) + string(rune('a'+i%26))), SourceID: "source", Operation: domain.OperationPrometheusGPUUtilization})
	}
	encoded, _ = json.Marshal(enrolled[:domain.MaxDurableSchedulerSnapshotKeys])
	t.Setenv("SHERLOCK_DURABLE_METRICS_SCHEDULES", string(encoded))
	if cfg, err = LoadWorker(); err != nil || len(cfg.DurableMetricsSchedules) != domain.MaxDurableSchedulerSnapshotKeys {
		t.Fatalf("64-key boundary: %v %v", len(cfg.DurableMetricsSchedules), err)
	}
	encoded, _ = json.Marshal(enrolled)
	t.Setenv("SHERLOCK_DURABLE_METRICS_SCHEDULES", string(encoded))
	if _, err = LoadWorker(); err == nil {
		t.Fatal("65 schedule keys accepted")
	}
	t.Setenv("SHERLOCK_DURABLE_METRICS_SCHEDULES", strings.Repeat("a", 65<<10))
	if _, err = LoadWorker(); err == nil {
		t.Fatal("oversized schedule configuration accepted")
	}
}

func TestWorkerSchedulingModeAndPrecision(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://fixture")
	t.Setenv("SHERLOCK_COLLECTION_EXECUTOR", "remote")
	t.Setenv("SHERLOCK_SCHEDULING_MODE", "")
	cfg, err := LoadWorker()
	if err != nil || cfg.SchedulingMode != "legacy" {
		t.Fatalf("default mode: %q, %v", cfg.SchedulingMode, err)
	}
	t.Setenv("SHERLOCK_SCHEDULING_MODE", "durable")
	if cfg, err = LoadWorker(); err != nil || cfg.SchedulingMode != "durable" {
		t.Fatalf("durable mode: %q, %v", cfg.SchedulingMode, err)
	}
	t.Setenv("SHERLOCK_SCHEDULING_MODE", "both")
	if _, err = LoadWorker(); err == nil {
		t.Fatal("accepted multiple owners")
	}
	t.Setenv("SHERLOCK_SCHEDULING_MODE", "legacy")
	t.Setenv("SHERLOCK_COLLECTION_INTERVAL", "30.5s")
	if _, err = LoadWorker(); err == nil {
		t.Fatal("accepted fractional interval")
	}
}

func TestLoadWorkerDefaultsAndRejectsUnsafeBounds(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://fixture")
	t.Setenv("SHERLOCK_COLLECTION_EXECUTOR", "inprocess")
	t.Setenv("SHERLOCK_PROMETHEUS_URL", "http://prometheus.test")
	cfg, err := LoadWorker()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxRetries != 2 || cfg.MaxSeries != 10_000 || cfg.MaxBytes != 10<<20 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	t.Setenv("SHERLOCK_MAX_SERIES", "10001")
	if _, err := LoadWorker(); err == nil {
		t.Fatal("LoadWorker accepted a series limit above the M1 bound")
	}
}

func TestLoadWorkerAutomaticInvestigationIsDefaultOffAndBounded(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://example")
	t.Setenv("SHERLOCK_COLLECTION_EXECUTOR", "remote")
	cfg, err := LoadWorker()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AutoInvestigationEnabled || len(cfg.AutoInvestigationRules) != 1 || cfg.AutoInvestigationRules[0] != "dcgm.xid.nonzero.v1" || cfg.AutoMaxDecisions != 64 || cfg.AutoMaxToolCalls != 64 || cfg.AutoMaxDiagnosticCalls != 0 || cfg.AutoMaxFanOut != 64 || cfg.AutoMaxModelTokens != 200_000 || cfg.AutoDailyTokenBudget != 200_000 || cfg.AutoMaxCostBudget != 5_000_000 || cfg.AutoMaxCostBudget > cfg.AutoDailyCostBudget || cfg.AutoMaxModelTokens > cfg.AutoDailyTokenBudget {
		t.Fatalf("unsafe automatic investigation defaults: %+v", cfg)
	}
	t.Setenv("SHERLOCK_AUTO_INVESTIGATION_ENABLED", "true")
	t.Setenv("SHERLOCK_AUTO_INVESTIGATION_MAX_MODEL_TOKENS", "101")
	t.Setenv("SHERLOCK_AUTO_INVESTIGATION_DAILY_TOKEN_BUDGET", "100")
	if _, err := LoadWorker(); err == nil {
		t.Fatal("expected per-run token budget above daily ceiling to fail")
	}
	t.Setenv("SHERLOCK_AUTO_INVESTIGATION_MAX_MODEL_TOKENS", "100")
	t.Setenv("SHERLOCK_AUTO_INVESTIGATION_MAX_FAN_OUT", "257")
	if _, err := LoadWorker(); err == nil {
		t.Fatal("expected fan-out batch above the scope ceiling to fail")
	}
	t.Setenv("SHERLOCK_AUTO_INVESTIGATION_MAX_FAN_OUT", "64")
	t.Setenv("SHERLOCK_AUTO_INVESTIGATION_MAX_TOOL_CALLS", "1001")
	if _, err := LoadWorker(); err == nil {
		t.Fatal("expected excessive automatic tool-call limit to fail")
	}
	t.Setenv("SHERLOCK_AUTO_INVESTIGATION_MAX_TOOL_CALLS", "64")
	t.Setenv("SHERLOCK_AUTO_INVESTIGATION_MAX_DIAGNOSTIC_CALLS", "1001")
	if _, err := LoadWorker(); err == nil {
		t.Fatal("expected excessive automatic diagnostic-call limit to fail")
	}
}

func TestLoadWorkerAutomaticDiagnosticCallsRequireExplicitGrant(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://example")
	t.Setenv("SHERLOCK_COLLECTION_EXECUTOR", "remote")
	t.Setenv("SHERLOCK_AUTO_INVESTIGATION_MAX_DIAGNOSTIC_CALLS", "1")
	cfg, err := LoadWorker()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AutoMaxDiagnosticCalls != 1 {
		t.Fatalf("automatic diagnostic-call grant=%d, want 1", cfg.AutoMaxDiagnosticCalls)
	}
}

func TestLoadWorkerArtifactReconciliationBounds(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://fixture")
	t.Setenv("SHERLOCK_ARTIFACT_ROOT", "/var/lib/sherlock/artifacts")
	t.Setenv("SHERLOCK_ARTIFACT_RECONCILE_MIN_AGE", "10m")
	t.Setenv("SHERLOCK_ARTIFACT_RECONCILE_BATCH_SIZE", "250")
	cfg, err := LoadWorker()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ArtifactRoot != "/var/lib/sherlock/artifacts" || cfg.ReconcileMinAge != 10*time.Minute || cfg.ReconcileBatchSize != 250 {
		t.Fatalf("unexpected artifact configuration: %+v", cfg)
	}
	t.Setenv("SHERLOCK_ARTIFACT_ROOT", "relative")
	if _, err := LoadWorker(); err == nil {
		t.Fatal("relative artifact root was accepted")
	}
}

func TestLoadWorkerAcceptsSharedR2ReconciliationBackend(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://fixture")
	t.Setenv("SHERLOCK_ARTIFACT_ROOT", "")
	t.Setenv("SHERLOCK_ARTIFACT_BACKEND", "r2")
	t.Setenv("SHERLOCK_R2_ENDPOINT", "https://account.r2.cloudflarestorage.com")
	t.Setenv("SHERLOCK_R2_BUCKET", "sherlock-audit")
	t.Setenv("SHERLOCK_R2_ACCESS_KEY_ID", "access-id")
	t.Setenv("SHERLOCK_R2_SECRET_ACCESS_KEY", "secret")
	t.Setenv("SHERLOCK_R2_PREFIX", "sherlock/model-audit")
	cfg, err := LoadWorker()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ArtifactStorage.Backend != ArtifactBackendR2 || cfg.ArtifactStorage.LocalRoot != "" {
		t.Fatalf("worker R2 configuration=%+v", cfg.ArtifactStorage)
	}
}

func TestLoadWorkerRejectsMixedAuthentication(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://fixture")
	t.Setenv("SHERLOCK_COLLECTION_EXECUTOR", "inprocess")
	t.Setenv("SHERLOCK_PROMETHEUS_URL", "http://prometheus.test")
	t.Setenv("SHERLOCK_PROMETHEUS_BEARER_TOKEN", "fixture-token")
	t.Setenv("SHERLOCK_PROMETHEUS_USERNAME", "fixture-user")
	t.Setenv("SHERLOCK_PROMETHEUS_PASSWORD", "fixture-password")
	if _, err := LoadWorker(); err == nil {
		t.Fatal("LoadWorker accepted mixed authentication")
	}
}

func TestLoadWorkerRemoteModeRejectsClusterCredentials(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://fixture")
	cfg, err := LoadWorker()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CollectionExecutor != "remote" {
		t.Fatalf("executor=%q", cfg.CollectionExecutor)
	}
	t.Setenv("SHERLOCK_PROMETHEUS_URL", "http://must-stay-cluster-local.test")
	if _, err := LoadWorker(); err == nil {
		t.Fatal("remote worker accepted a cluster-local Prometheus endpoint")
	}
}
