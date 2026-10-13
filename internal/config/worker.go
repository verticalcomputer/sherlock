package config

import (
	"encoding/json"
	"fmt"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

type Worker struct {
	DatabaseURL                  string
	CollectionExecutor           string
	SchedulingMode               string
	DurableAdmissionEnabled      bool
	DurableGlobalLimit           int
	DurableClusterLimit          int
	DurableExecutions            []domain.DurableExecution
	DurableMetricsSchedules      []domain.ScheduleKey
	CollectionReservationEnabled bool
	CollectionDispatchFloor      int
	CollectionDispatchPeriod     int
	PrometheusURL                string
	PrometheusBearer             string
	PrometheusUser               string
	PrometheusPassword           string
	ClusterID                    string
	ClusterName                  string
	SourceID                     string
	SourceName                   string
	WorkerID                     string
	MetricsAddress               string
	CollectionInterval           time.Duration
	QueryTimeout                 time.Duration
	MaxRetries                   int
	MaxSeries                    int
	MaxBytes                     int64
	ObservationRetention         time.Duration
	RunRetention                 time.Duration
	MaintenanceInterval          time.Duration
	RemotePollInterval           time.Duration
	ArtifactRoot                 string
	ArtifactStorage              ArtifactStorage
	ArtifactMaxBytes             int64
	ReconcileMinAge              time.Duration
	ReconcileBatchSize           int
	AutoInvestigationEnabled     bool
	AutoInvestigationRules       []string
	AutoMinimumSeverity          string
	AutoMaximumEvidenceAge       time.Duration
	AutoAllowPartialCoverage     bool
	AutoCooldown                 time.Duration
	AutoMaxConcurrent            int
	AutoMaxDecisions             int
	AutoMaxToolCalls             int
	AutoMaxDiagnosticCalls       int
	AutoDailyTokenBudget         int64
	AutoDailyCostBudget          int64
	AutoMaxFanOut                int
	AutoMaxModelTokens           int64
	AutoMaxCostBudget            int64
	AutoInvestigationTTL         time.Duration
	AutoServiceActor             string
}

func LoadWorker() (Worker, error) {
	if err := loadLocalEnv(); err != nil {
		return Worker{}, err
	}
	cfg := Worker{
		DatabaseURL:              os.Getenv("SHERLOCK_DATABASE_URL"),
		CollectionExecutor:       valueOrDefault("SHERLOCK_COLLECTION_EXECUTOR", "remote"),
		SchedulingMode:           valueOrDefault("SHERLOCK_SCHEDULING_MODE", "legacy"),
		DurableGlobalLimit:       16,
		DurableClusterLimit:      4,
		CollectionDispatchFloor:  1,
		CollectionDispatchPeriod: 2,
		PrometheusURL:            os.Getenv("SHERLOCK_PROMETHEUS_URL"),
		PrometheusBearer:         os.Getenv("SHERLOCK_PROMETHEUS_BEARER_TOKEN"),
		PrometheusUser:           os.Getenv("SHERLOCK_PROMETHEUS_USERNAME"),
		PrometheusPassword:       os.Getenv("SHERLOCK_PROMETHEUS_PASSWORD"),
		ClusterID:                valueOrDefault("SHERLOCK_CLUSTER_ID", "local-cluster"),
		ClusterName:              valueOrDefault("SHERLOCK_CLUSTER_NAME", "Local cluster"),
		SourceID:                 valueOrDefault("SHERLOCK_SOURCE_ID", "local-prometheus"),
		SourceName:               valueOrDefault("SHERLOCK_SOURCE_NAME", "Local Prometheus"),
		WorkerID:                 valueOrDefault("SHERLOCK_WORKER_ID", "worker-local"),
		MetricsAddress:           valueOrDefault("SHERLOCK_METRICS_ADDRESS", "127.0.0.1:9091"),
		CollectionInterval:       30 * time.Second,
		QueryTimeout:             10 * time.Second,
		MaxRetries:               2,
		MaxSeries:                10_000,
		MaxBytes:                 10 << 20,
		ObservationRetention:     7 * 24 * time.Hour,
		RunRetention:             30 * 24 * time.Hour,
		MaintenanceInterval:      6 * time.Hour,
		RemotePollInterval:       100 * time.Millisecond,
		ArtifactRoot:             os.Getenv("SHERLOCK_ARTIFACT_ROOT"),
		ArtifactMaxBytes:         100 << 20,
		ReconcileMinAge:          5 * time.Minute,
		ReconcileBatchSize:       1000,
		AutoInvestigationRules:   []string{"dcgm.xid.nonzero.v1"},
		AutoMinimumSeverity:      "HIGH", AutoMaximumEvidenceAge: 5 * time.Minute,
		AutoCooldown: time.Hour, AutoMaxConcurrent: 1,
		AutoMaxDecisions: 64, AutoMaxToolCalls: 64, AutoMaxDiagnosticCalls: 0,
		AutoDailyTokenBudget: 200_000, AutoDailyCostBudget: 10_000_000,
		AutoMaxFanOut: 64, AutoMaxModelTokens: 200_000, AutoMaxCostBudget: 5_000_000,
		AutoInvestigationTTL: 30 * time.Minute, AutoServiceActor: "sherlock-auto-investigator",
	}
	if cfg.DatabaseURL == "" {
		return Worker{}, fmt.Errorf("SHERLOCK_DATABASE_URL is required")
	}
	var err error
	if cfg.DurableAdmissionEnabled, err = boolEnv("SHERLOCK_DURABLE_ADMISSION_ENABLED", false); err != nil {
		return Worker{}, err
	}
	if cfg.DurableGlobalLimit, err = intEnv("SHERLOCK_DURABLE_GLOBAL_LIMIT", cfg.DurableGlobalLimit); err != nil {
		return Worker{}, err
	}
	if cfg.DurableClusterLimit, err = intEnv("SHERLOCK_DURABLE_CLUSTER_LIMIT", cfg.DurableClusterLimit); err != nil {
		return Worker{}, err
	}
	if err = (domain.DurableAdmissionPolicy{GlobalLimit: cfg.DurableGlobalLimit, ClusterLimit: cfg.DurableClusterLimit}).Validate(); err != nil {
		return Worker{}, err
	}
	if raw := os.Getenv("SHERLOCK_DURABLE_EXECUTIONS"); raw != "" {
		if len(raw) > 1<<20 {
			return Worker{}, fmt.Errorf("durable execution configuration exceeds one MiB")
		}
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&cfg.DurableExecutions); err != nil {
			return Worker{}, fmt.Errorf("invalid SHERLOCK_DURABLE_EXECUTIONS: %w", err)
		}
		if err = decoder.Decode(new(any)); err != io.EOF {
			return Worker{}, fmt.Errorf("durable execution configuration requires exactly one JSON array")
		}
		if len(cfg.DurableExecutions) > 1000 {
			return Worker{}, fmt.Errorf("durable execution configuration exceeds 1000 entries")
		}
		seen := map[domain.ScheduleKey]bool{}
		for _, execution := range cfg.DurableExecutions {
			if seen[execution.ScheduleKey] {
				return Worker{}, fmt.Errorf("duplicate durable execution schedule")
			}
			seen[execution.ScheduleKey] = true
			if err = execution.Validate(); err != nil {
				return Worker{}, err
			}
		}
	}
	if cfg.DurableAdmissionEnabled && cfg.CollectionExecutor != "remote" {
		return Worker{}, fmt.Errorf("durable admission requires remote collection executor")
	}
	if cfg.CollectionReservationEnabled, err = boolEnv("SHERLOCK_COLLECTION_RESERVATION_ENABLED", false); err != nil {
		return Worker{}, err
	}
	if cfg.CollectionDispatchFloor, err = intEnv("SHERLOCK_COLLECTION_DISPATCH_FLOOR", cfg.CollectionDispatchFloor); err != nil {
		return Worker{}, err
	}
	if cfg.CollectionDispatchPeriod, err = intEnv("SHERLOCK_COLLECTION_DISPATCH_PERIOD", cfg.CollectionDispatchPeriod); err != nil {
		return Worker{}, err
	}
	if err = (domain.CollectionDispatchPolicy{Floor: cfg.CollectionDispatchFloor, Period: cfg.CollectionDispatchPeriod}).Validate(); err != nil {
		return Worker{}, err
	}
	if cfg.CollectionReservationEnabled && (cfg.CollectionExecutor != "remote" || len(cfg.DurableExecutions) == 0) {
		return Worker{}, fmt.Errorf("collection reservation requires remote executor and explicit durable execution collectors")
	}
	// Durable metrics enrollment is read-only and independent of admission:
	// operators may observe existing durable schedules while admission stays
	// off. Keys name cluster/source/operation identities explicitly; nothing
	// is derived from execution grants or discovered from the database.
	if raw := os.Getenv("SHERLOCK_DURABLE_METRICS_SCHEDULES"); raw != "" {
		if len(raw) > 64<<10 {
			return Worker{}, fmt.Errorf("durable metrics schedule configuration exceeds 64 KiB")
		}
		if strings.TrimSpace(raw) == "null" {
			return Worker{}, fmt.Errorf("durable metrics schedules must be a JSON array")
		}
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.DisallowUnknownFields()
		var schedules []domain.ScheduleKey
		if err = decoder.Decode(&schedules); err != nil {
			return Worker{}, fmt.Errorf("invalid SHERLOCK_DURABLE_METRICS_SCHEDULES: %w", err)
		}
		if err = decoder.Decode(new(any)); err != io.EOF {
			return Worker{}, fmt.Errorf("durable metrics schedule configuration requires exactly one JSON array")
		}
		if err = domain.ValidateDurableSchedulerSnapshotKeys(schedules); err != nil {
			return Worker{}, err
		}
		cfg.DurableMetricsSchedules = schedules
	}
	if cfg.CollectionInterval, err = durationEnv("SHERLOCK_COLLECTION_INTERVAL", cfg.CollectionInterval); err != nil {
		return Worker{}, err
	}
	if cfg.QueryTimeout, err = durationEnv("SHERLOCK_QUERY_TIMEOUT", cfg.QueryTimeout); err != nil {
		return Worker{}, err
	}
	if cfg.MaxRetries, err = intEnv("SHERLOCK_MAX_RETRIES", cfg.MaxRetries); err != nil {
		return Worker{}, err
	}
	if cfg.MaxSeries, err = intEnv("SHERLOCK_MAX_SERIES", cfg.MaxSeries); err != nil {
		return Worker{}, err
	}
	if bytes, parseErr := intEnv("SHERLOCK_MAX_BYTES", int(cfg.MaxBytes)); parseErr != nil {
		return Worker{}, parseErr
	} else {
		cfg.MaxBytes = int64(bytes)
	}
	if cfg.ObservationRetention, err = durationEnv("SHERLOCK_OBSERVATION_RETENTION", cfg.ObservationRetention); err != nil {
		return Worker{}, err
	}
	if cfg.RunRetention, err = durationEnv("SHERLOCK_RUN_RETENTION", cfg.RunRetention); err != nil {
		return Worker{}, err
	}
	if cfg.MaintenanceInterval, err = durationEnv("SHERLOCK_MAINTENANCE_INTERVAL", cfg.MaintenanceInterval); err != nil {
		return Worker{}, err
	}
	if cfg.RemotePollInterval, err = durationEnv("SHERLOCK_REMOTE_POLL_INTERVAL", cfg.RemotePollInterval); err != nil {
		return Worker{}, err
	}
	if bytes, parseErr := intEnv("SHERLOCK_ARTIFACT_MAX_BYTES", int(cfg.ArtifactMaxBytes)); parseErr != nil {
		return Worker{}, parseErr
	} else {
		cfg.ArtifactMaxBytes = int64(bytes)
	}
	if cfg.ReconcileMinAge, err = durationEnv("SHERLOCK_ARTIFACT_RECONCILE_MIN_AGE", cfg.ReconcileMinAge); err != nil {
		return Worker{}, err
	}
	if cfg.ReconcileBatchSize, err = intEnv("SHERLOCK_ARTIFACT_RECONCILE_BATCH_SIZE", cfg.ReconcileBatchSize); err != nil {
		return Worker{}, err
	}
	if cfg.AutoInvestigationEnabled, err = boolEnv("SHERLOCK_AUTO_INVESTIGATION_ENABLED", false); err != nil {
		return Worker{}, err
	}
	if cfg.AutoAllowPartialCoverage, err = boolEnv("SHERLOCK_AUTO_INVESTIGATION_ALLOW_PARTIAL_COVERAGE", false); err != nil {
		return Worker{}, err
	}
	if raw := os.Getenv("SHERLOCK_AUTO_INVESTIGATION_RULES"); raw != "" {
		cfg.AutoInvestigationRules = splitNonEmpty(raw)
	}
	cfg.AutoMinimumSeverity = valueOrDefault("SHERLOCK_AUTO_INVESTIGATION_MINIMUM_SEVERITY", cfg.AutoMinimumSeverity)
	cfg.AutoServiceActor = valueOrDefault("SHERLOCK_AUTO_INVESTIGATION_SERVICE_ACTOR", cfg.AutoServiceActor)
	if cfg.AutoMaximumEvidenceAge, err = durationEnv("SHERLOCK_AUTO_INVESTIGATION_MAX_EVIDENCE_AGE", cfg.AutoMaximumEvidenceAge); err != nil {
		return Worker{}, err
	}
	if cfg.AutoCooldown, err = durationEnv("SHERLOCK_AUTO_INVESTIGATION_COOLDOWN", cfg.AutoCooldown); err != nil {
		return Worker{}, err
	}
	if cfg.AutoInvestigationTTL, err = durationEnv("SHERLOCK_AUTO_INVESTIGATION_TTL", cfg.AutoInvestigationTTL); err != nil {
		return Worker{}, err
	}
	if cfg.AutoMaxConcurrent, err = intEnv("SHERLOCK_AUTO_INVESTIGATION_MAX_CONCURRENT", cfg.AutoMaxConcurrent); err != nil {
		return Worker{}, err
	}
	if cfg.AutoMaxDecisions, err = intEnv("SHERLOCK_AUTO_INVESTIGATION_MAX_DECISIONS", cfg.AutoMaxDecisions); err != nil {
		return Worker{}, err
	}
	if cfg.AutoMaxToolCalls, err = intEnv("SHERLOCK_AUTO_INVESTIGATION_MAX_TOOL_CALLS", cfg.AutoMaxToolCalls); err != nil {
		return Worker{}, err
	}
	if cfg.AutoMaxDiagnosticCalls, err = intEnv("SHERLOCK_AUTO_INVESTIGATION_MAX_DIAGNOSTIC_CALLS", cfg.AutoMaxDiagnosticCalls); err != nil {
		return Worker{}, err
	}
	if cfg.AutoMaxFanOut, err = intEnv("SHERLOCK_AUTO_INVESTIGATION_MAX_FAN_OUT", cfg.AutoMaxFanOut); err != nil {
		return Worker{}, err
	}
	if value, parseErr := int64Env("SHERLOCK_AUTO_INVESTIGATION_DAILY_TOKEN_BUDGET", cfg.AutoDailyTokenBudget); parseErr != nil {
		return Worker{}, parseErr
	} else {
		cfg.AutoDailyTokenBudget = value
	}
	if value, parseErr := int64Env("SHERLOCK_AUTO_INVESTIGATION_DAILY_COST_MICROS", cfg.AutoDailyCostBudget); parseErr != nil {
		return Worker{}, parseErr
	} else {
		cfg.AutoDailyCostBudget = value
	}
	if value, parseErr := int64Env("SHERLOCK_AUTO_INVESTIGATION_MAX_MODEL_TOKENS", cfg.AutoMaxModelTokens); parseErr != nil {
		return Worker{}, parseErr
	} else {
		cfg.AutoMaxModelTokens = value
	}
	if value, parseErr := int64Env("SHERLOCK_AUTO_INVESTIGATION_MAX_COST_MICROS", cfg.AutoMaxCostBudget); parseErr != nil {
		return Worker{}, parseErr
	} else {
		cfg.AutoMaxCostBudget = value
	}
	if cfg.SchedulingMode != "legacy" && cfg.SchedulingMode != "durable" {
		return Worker{}, fmt.Errorf("SHERLOCK_SCHEDULING_MODE must be legacy or durable")
	}
	if cfg.CollectionInterval <= 0 || cfg.CollectionInterval%time.Second != 0 || cfg.CollectionInterval/time.Second > 2147483647 || cfg.QueryTimeout <= 0 || cfg.QueryTimeout%time.Millisecond != 0 || cfg.QueryTimeout > cfg.CollectionInterval {
		return Worker{}, fmt.Errorf("collection interval must be positive and at least the query timeout")
	}
	if cfg.MaxRetries < 0 || cfg.MaxRetries > 2 || cfg.MaxSeries < 1 || cfg.MaxSeries > 10_000 || cfg.MaxBytes < 1 || cfg.MaxBytes > 10<<20 {
		return Worker{}, fmt.Errorf("worker retry or result limits exceed the M1 safety bounds")
	}
	if cfg.ObservationRetention <= 0 || cfg.RunRetention < cfg.ObservationRetention || cfg.MaintenanceInterval <= 0 {
		return Worker{}, fmt.Errorf("retention durations must be positive and run retention cannot be shorter than observation retention")
	}
	if cfg.CollectionExecutor != "remote" && cfg.CollectionExecutor != "inprocess" {
		return Worker{}, fmt.Errorf("SHERLOCK_COLLECTION_EXECUTOR must be remote or inprocess")
	}
	if cfg.CollectionExecutor == "inprocess" && cfg.PrometheusURL == "" {
		return Worker{}, fmt.Errorf("SHERLOCK_PROMETHEUS_URL is required for the in-process executor")
	}
	if cfg.PrometheusBearer != "" && (cfg.PrometheusUser != "" || cfg.PrometheusPassword != "") {
		return Worker{}, fmt.Errorf("prometheus bearer and basic authentication are mutually exclusive")
	}
	if cfg.CollectionExecutor == "remote" && (cfg.PrometheusURL != "" || cfg.PrometheusBearer != "" || cfg.PrometheusUser != "" || cfg.PrometheusPassword != "") {
		return Worker{}, fmt.Errorf("remote workers must not receive Prometheus endpoints or credentials")
	}
	if cfg.RemotePollInterval < 10*time.Millisecond || cfg.RemotePollInterval > time.Second {
		return Worker{}, fmt.Errorf("remote poll interval must be between 10 milliseconds and one second")
	}
	cfg.ArtifactStorage, err = loadArtifactStorage(cfg.ArtifactRoot)
	if err != nil {
		return Worker{}, err
	}
	if cfg.ArtifactMaxBytes < 1 || cfg.ArtifactMaxBytes > 100<<20 || cfg.ReconcileMinAge < 0 || cfg.ReconcileBatchSize < 1 || cfg.ReconcileBatchSize > 10_000 {
		return Worker{}, fmt.Errorf("artifact reconciliation bounds are invalid")
	}
	if len(cfg.AutoInvestigationRules) == 0 || cfg.AutoMaximumEvidenceAge <= 0 || cfg.AutoCooldown <= 0 || cfg.AutoInvestigationTTL <= 0 || cfg.AutoInvestigationTTL > 24*time.Hour || cfg.AutoMaxConcurrent < 1 || cfg.AutoMaxDecisions < 1 || cfg.AutoMaxDecisions > 100 || cfg.AutoMaxToolCalls < 1 || cfg.AutoMaxToolCalls > 1000 || cfg.AutoMaxDiagnosticCalls < 0 || cfg.AutoMaxDiagnosticCalls > 1000 || cfg.AutoMaxFanOut < 1 || cfg.AutoMaxFanOut > 256 || cfg.AutoDailyTokenBudget < 0 || cfg.AutoDailyCostBudget < 0 || cfg.AutoMaxModelTokens < 0 || cfg.AutoMaxCostBudget < 0 || cfg.AutoMaxModelTokens > cfg.AutoDailyTokenBudget || cfg.AutoMaxCostBudget > cfg.AutoDailyCostBudget {
		return Worker{}, fmt.Errorf("automatic investigation policy bounds are invalid")
	}
	if cfg.AutoMinimumSeverity != "INFO" && cfg.AutoMinimumSeverity != "LOW" && cfg.AutoMinimumSeverity != "MEDIUM" && cfg.AutoMinimumSeverity != "HIGH" && cfg.AutoMinimumSeverity != "CRITICAL" {
		return Worker{}, fmt.Errorf("automatic investigation minimum severity is invalid")
	}
	return cfg, nil
}

func valueOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func durationEnv(name string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration: %w", name, err)
	}
	return parsed, nil
}

func intEnv(name string, fallback int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", name, err)
	}
	return parsed, nil
}

func boolEnv(name string, fallback bool) (bool, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", name, err)
	}
	return parsed, nil
}

func splitNonEmpty(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}
