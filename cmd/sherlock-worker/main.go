package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	clientprom "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/verticalcomputer/sherlock/internal/adapters/investigationapi"
	adapter "github.com/verticalcomputer/sherlock/internal/adapters/prometheus"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/artifacts"
	prometheusexecution "github.com/verticalcomputer/sherlock/internal/collectorexecution/prometheus"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

type runtime struct {
	cfg            config.Worker
	clock          platform.SystemClock
	ids            platform.RandomIDGenerator
	store          *storepg.CollectionStore
	collector      *application.Collector
	logger         *slog.Logger
	runs           *clientprom.CounterVec
	duration       *clientprom.HistogramVec
	retention      *clientprom.CounterVec
	reconciler     artifactReconciliationRunner
	reconciled     *clientprom.CounterVec
	anomalies      anomalyBridgeRunner
	repairs        repairCollectionRunner
	scheduler      *schedulerMetrics
	maintenance    *maintenanceMetrics
	retentionStore retentionMaintenanceStore
}

type artifactReconciliationRunner interface {
	Run(context.Context, time.Time) (application.ArtifactReconciliationResult, error)
}

type anomalyBridgeRunner interface {
	RunOnce(context.Context) (bool, error)
}

type repairCollectionRunner interface {
	RunOnce(context.Context) (bool, error)
}

type safeSummary struct {
	RunID              domain.RunID         `json:"run_id"`
	Status             domain.ResultStatus  `json:"status"`
	Query              domain.QueryKind     `json:"query"`
	Attempts           int                  `json:"attempts"`
	PreviouslyRecorded bool                 `json:"previously_recorded"`
	SeriesReturned     int                  `json:"series_returned"`
	BytesRead          int64                `json:"bytes_read"`
	CoverageComplete   bool                 `json:"coverage_complete"`
	Availability       string               `json:"source_availability"`
	Freshness          domain.Freshness     `json:"freshness"`
	FailureCodes       []domain.FailureCode `json:"failure_codes,omitempty"`
	StartedAt          time.Time            `json:"started_at"`
	CompletedAt        time.Time            `json:"completed_at"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := config.LoadWorker()
	if err != nil {
		logger.Error("configuration.invalid", "error", err.Error())
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rt, cleanup, err := buildRuntime(ctx, cfg, logger)
	if err != nil {
		logger.Error("worker.start_failed", "error", err.Error())
		os.Exit(1)
	}
	defer cleanup()
	mode := "scheduled"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "discover-dcgm":
		if err := rt.discoverDCGM(ctx); err != nil {
			logger.Error("dcgm.discovery_failed", "error", err.Error())
			os.Exit(1)
		}
	case "collect-once":
		query := domain.QueryGPUUtilization
		if len(os.Args) > 2 {
			query = domain.QueryKind(os.Args[2])
		}
		summary, err := rt.collectOnce(ctx, query)
		if err != nil {
			logger.Error("collection.once_failed", "error", err.Error())
			os.Exit(1)
		}
		if err := json.NewEncoder(os.Stdout).Encode(summary); err != nil {
			logger.Error("collection.summary_failed", "error", err.Error())
			os.Exit(1)
		}
		if summary.Status == domain.ResultFailed {
			os.Exit(3)
		}
	case "scheduled":
		if err := rt.runScheduled(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("worker.stopped", "error", err.Error())
			os.Exit(1)
		}
	default:
		logger.Error("mode.invalid", "mode", mode)
		os.Exit(2)
	}
}

func buildRuntime(ctx context.Context, cfg config.Worker, logger *slog.Logger) (*runtime, func(), error) {
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, func() {}, fmt.Errorf("configure PostgreSQL: %w", err)
	}
	cleanup := func() { pool.Close() }
	if err := pool.Ping(ctx); err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	store, _ := storepg.NewCollectionStore(pool)
	if err := store.EnsureSource(ctx, domain.ClusterID(cfg.ClusterID), cfg.ClusterName, domain.SourceID(cfg.SourceID), cfg.SourceName); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	clock := platform.SystemClock{}
	ids := platform.RandomIDGenerator{}
	var executor application.CollectionExecutor
	if cfg.CollectionExecutor == "remote" {
		controlStore, controlErr := storepg.NewCollectorControlStore(pool)
		if controlErr != nil {
			cleanup()
			return nil, func() {}, controlErr
		}
		executor, err = application.NewRemoteCollectionExecutor(controlStore, clock, cfg.RemotePollInterval)
	} else {
		var client *adapter.Client
		client, err = adapter.NewClient(adapter.Config{
			// Task bounds come from persisted schedules; these are the unchanged
			// global safety ceilings, not a second copy of startup defaults.
			BaseURL: cfg.PrometheusURL, Timeout: cfg.QueryTimeout, MaxBytes: 10 << 20, MaxSeries: 10000,
			Auth: adapter.Auth{BearerToken: cfg.PrometheusBearer, Username: cfg.PrometheusUser, Password: cfg.PrometheusPassword},
		})
		if err == nil {
			executor, err = prometheusexecution.NewScheduled(client, clock, ids)
		}
	}
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	collector, _ := application.NewCollector(executor, store, clock, cfg.MaxRetries, 200*time.Millisecond)
	var repairs repairCollectionRunner
	if cfg.CollectionExecutor == "remote" {
		remediationStore, remediationErr := storepg.NewRemediationStore(pool)
		if remediationErr != nil {
			cleanup()
			return nil, func() {}, remediationErr
		}
		repairs, remediationErr = application.NewRepairCollectionWorker(remediationStore, collector, domain.ClusterID(cfg.ClusterID), domain.SourceID(cfg.SourceID), cfg.WorkerID, 2*cfg.QueryTimeout)
		if remediationErr != nil {
			cleanup()
			return nil, func() {}, remediationErr
		}
	}
	runs := clientprom.NewCounterVec(clientprom.CounterOpts{Name: "sherlock_collection_runs_total", Help: "Collection runs by query and final status."}, []string{"query", "status"})
	duration := clientprom.NewHistogramVec(clientprom.HistogramOpts{Name: "sherlock_collection_duration_seconds", Help: "Collection run duration.", Buckets: clientprom.DefBuckets}, []string{"query"})
	retention := clientprom.NewCounterVec(clientprom.CounterOpts{Name: "sherlock_retention_deleted_total", Help: "Rows deleted by retention class."}, []string{"class"})
	reconciled := clientprom.NewCounterVec(clientprom.CounterOpts{Name: "sherlock_artifact_reconciliation_total", Help: "Artifact reconciliation checks by safe availability condition."}, []string{"condition"})
	clientprom.MustRegister(runs, duration, retention, reconciled)
	scheduler := newSchedulerMetrics(clientprom.DefaultRegisterer, pool)
	maintenance := newMaintenanceMetrics(clientprom.DefaultRegisterer)
	var reconciler artifactReconciliationRunner
	if cfg.ArtifactStorage.Configured() {
		artifactStore, artifactErr := artifacts.NewStore(ctx, artifacts.Options{
			Backend: cfg.ArtifactStorage.Backend, LocalRoot: cfg.ArtifactStorage.LocalRoot,
			Endpoint: cfg.ArtifactStorage.R2Endpoint, Bucket: cfg.ArtifactStorage.R2Bucket,
			AccessKeyID: cfg.ArtifactStorage.R2AccessKeyID.Reveal(), SecretAccessKey: cfg.ArtifactStorage.R2SecretAccessKey.Reveal(),
			Prefix: cfg.ArtifactStorage.R2Prefix, MaxBytes: cfg.ArtifactMaxBytes,
		})
		if artifactErr != nil {
			cleanup()
			return nil, func() {}, artifactErr
		}
		evidenceStore, evidenceErr := storepg.NewEvidenceStore(pool)
		if evidenceErr != nil {
			cleanup()
			return nil, func() {}, evidenceErr
		}
		configuredReconciler, reconcileErr := application.NewArtifactReconciler(evidenceStore, artifactStore, cfg.ReconcileMinAge, cfg.ReconcileBatchSize)
		err = reconcileErr
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		reconciler = configuredReconciler
	}
	anomalyStore, err := storepg.NewAnomalyBridgeStore(pool)
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	investigationStore, err := storepg.NewInvestigationStore(pool)
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	starter, err := investigationapi.NewFailClosedController(investigationStore, clock, ids)
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	rules := make(map[string]bool, len(cfg.AutoInvestigationRules))
	for _, rule := range cfg.AutoInvestigationRules {
		rules[rule] = true
	}
	bridge, err := application.NewAnomalyBridge(anomalyStore, starter, clock, "sherlock-worker-anomaly-v1", domain.ClusterID(cfg.ClusterID), application.AutomaticInvestigationPolicy{
		Enabled: cfg.AutoInvestigationEnabled, EnabledRules: rules, MinimumSeverity: cfg.AutoMinimumSeverity,
		MaximumEvidenceAge: cfg.AutoMaximumEvidenceAge, AllowPartialCoverage: cfg.AutoAllowPartialCoverage,
		Cooldown: cfg.AutoCooldown, MaxConcurrent: cfg.AutoMaxConcurrent,
		DailyTokenBudget: cfg.AutoDailyTokenBudget, DailyCostBudget: cfg.AutoDailyCostBudget,
		InvestigationBudget: domain.InvestigationBudget{MaxDecisions: cfg.AutoMaxDecisions, MaxToolCalls: cfg.AutoMaxToolCalls, MaxDiagnosticCalls: cfg.AutoMaxDiagnosticCalls, MaxPrivilegedCalls: 0, MaxFanOut: cfg.AutoMaxFanOut, MaxModelTokens: cfg.AutoMaxModelTokens, MaxCostMicros: cfg.AutoMaxCostBudget},
		InvestigationTTL:    cfg.AutoInvestigationTTL, ServiceActor: cfg.AutoServiceActor,
	})
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	return &runtime{cfg: cfg, clock: clock, ids: ids, store: store, collector: collector, logger: logger, runs: runs, duration: duration, retention: retention, reconciler: reconciler, reconciled: reconciled, anomalies: bridge, repairs: repairs, scheduler: scheduler, maintenance: maintenance, retentionStore: store}, func() { cleanup() }, nil
}

func (r *runtime) collectOnce(ctx context.Context, query domain.QueryKind) (safeSummary, error) {
	now := r.clock.Now()
	runID, err := r.ids.NewID()
	if err != nil {
		return safeSummary{}, err
	}
	task := domain.CollectionTask{
		RunID: domain.RunID(runID), ClusterID: domain.ClusterID(r.cfg.ClusterID), SourceID: domain.SourceID(r.cfg.SourceID),
		Query: query, ScheduledFor: now, Deadline: now.Add(r.cfg.QueryTimeout), MaxSeries: r.cfg.MaxSeries,
		MaxBytes: r.cfg.MaxBytes, IdempotencyKey: "manual/" + runID,
	}
	return r.collect(ctx, task)
}

func (r *runtime) collect(ctx context.Context, task domain.CollectionTask) (safeSummary, error) {
	outcome, err := r.collector.Collect(ctx, task)
	if err != nil {
		return safeSummary{}, err
	}
	result := outcome.Result
	if len(domain.DCGMFields(task.Query)) > 0 {
		result.Status, result.Coverage, err = r.store.DCGMCollectionState(ctx, task.ClusterID, task.SourceID, task.RunID)
		if err != nil {
			return safeSummary{}, err
		}
		if result.Status == domain.ResultPartial && len(result.Failures) == 0 {
			result.Failures = []domain.CollectionFailure{{Code: domain.FailurePartialData}}
		}
	}
	r.runs.WithLabelValues(string(task.Query), string(result.Status)).Inc()
	r.duration.WithLabelValues(string(task.Query)).Observe(result.CompletedAt.Sub(result.StartedAt).Seconds())
	state, err := r.store.SourceState(ctx, task.SourceID, r.clock.Now(), 2*r.cfg.CollectionInterval)
	if err != nil {
		return safeSummary{}, err
	}
	summary := safeSummary{
		RunID: task.RunID, Status: result.Status, Query: task.Query, Attempts: outcome.Attempts,
		PreviouslyRecorded: outcome.PreviouslyRecorded, SeriesReturned: result.Coverage.SeriesReturned,
		BytesRead: result.Coverage.BytesRead, CoverageComplete: result.Coverage.Complete,
		Availability: state.Availability, Freshness: state.Freshness, StartedAt: result.StartedAt, CompletedAt: result.CompletedAt,
	}
	for _, failure := range result.Failures {
		summary.FailureCodes = append(summary.FailureCodes, failure.Code)
	}
	r.logger.Info("collection.completed", "run_id", task.RunID, "query", task.Query, "status", result.Status, "series", result.Coverage.SeriesReturned, "attempts", outcome.Attempts)
	_ = r.reconcileAnomalies(ctx)
	return summary, nil
}

func (r *runtime) runScheduled(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if r.repairs != nil {
		done := make(chan struct{})
		go func() {
			defer close(done)
			tick := time.NewTicker(time.Second)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					if _, err := r.repairs.RunOnce(ctx); err != nil && ctx.Err() == nil {
						r.logger.Error("repair_collection.failed", "code", "REPAIR_COLLECTION_FAILED")
					}
				}
			}
		}()
		defer func() { cancel(); <-done }()
	}

	first := r.clock.Now()
	seeds := application.LegacyPrometheusSchedules(domain.ClusterID(r.cfg.ClusterID), domain.SourceID(r.cfg.SourceID), domain.SchedulingMode(r.cfg.SchedulingMode), r.cfg.CollectionInterval, r.cfg.QueryTimeout, r.cfg.MaxSeries, r.cfg.MaxBytes)
	if err := r.store.ImportLegacyPrometheusSchedules(ctx, seeds, first); err != nil {
		return err
	}
	if r.cfg.DurableAdmissionEnabled || r.cfg.CollectionReservationEnabled {
		for _, execution := range r.cfg.DurableExecutions {
			if err := r.store.ConfigureDurableExecution(ctx, execution); err != nil {
				return err
			}
			if r.cfg.CollectionReservationEnabled {
				if err := r.store.ConfigureCollectionDispatch(ctx, execution.ClusterID, execution.CollectorID, domain.CollectionDispatchPolicy{Floor: r.cfg.CollectionDispatchFloor, Period: r.cfg.CollectionDispatchPeriod}); err != nil {
					return err
				}
			}
		}
	}
	// Durable metrics enrollment is read-only and independent of admission:
	// the publisher observes existing schedules on its own goroutine while
	// admission stays default off. Scrapes serve only its cached snapshot.
	if durableMetricsPublishingEnabled(r.cfg.DurableMetricsSchedules) {
		publisher, err := newDurableSchedulerPublisher(clientprom.DefaultRegisterer, r.store, r.cfg.DurableMetricsSchedules, durableSchedulerRefreshInterval, durableSchedulerReadTimeout, r.logger)
		if err != nil {
			return err
		}
		metricsDone := make(chan struct{})
		go func() {
			defer close(metricsDone)
			publisher.run(ctx)
		}()
		defer func() { cancel(); <-metricsDone }()
	}
	if r.cfg.DurableAdmissionEnabled {
		var rejections *durableRejectionMetrics
		if durableMetricsPublishingEnabled(r.cfg.DurableMetricsSchedules) {
			var err error
			rejections, err = newDurableRejectionMetrics(clientprom.DefaultRegisterer, r.cfg.DurableMetricsSchedules)
			if err != nil {
				return err
			}
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			runDurableAdmission(ctx, r.store, domain.DurableAdmissionPolicy{GlobalLimit: r.cfg.DurableGlobalLimit, ClusterLimit: r.cfg.DurableClusterLimit}, rejections, r.logger, time.Second, 2*time.Second)
		}()
		defer func() { cancel(); <-done }()
	}
	// Maintenance may need to delete many expired rows. Keep it off the
	// one-second claim loop so a long pass cannot skip collection intervals.
	policy := defaultMaintenancePolicy(r.cfg.MaintenanceInterval)
	maintenanceDone := startPeriodicMaintenance(ctx, policy, "retention", r.maintenance, r.logger, r.applyRetention)
	defer func() { cancel(); <-maintenanceDone }()
	if r.reconciler != nil {
		reconciliationDone := startPeriodicMaintenance(ctx, policy, "artifact_reconciliation", r.maintenance, r.logger, r.reconcileArtifacts)
		defer func() { cancel(); <-reconciliationDone }()
	}
	for index := 0; index < 32; index++ {
		progressed, err := r.reconcileAnomaliesOnce(ctx)
		if err != nil || !progressed {
			break
		}
	}
	server := &http.Server{Addr: r.cfg.MetricsAddress, Handler: promhttp.Handler(), ReadHeaderTimeout: 3 * time.Second}
	serverErrors := make(chan error, 1)
	go func() {
		r.logger.Info("metrics.listening", "address", r.cfg.MetricsAddress)
		serverErrors <- server.ListenAndServe()
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	return runScheduledLoop(ctx, ticker.C, serverErrors, r.collectDueJob)
}

// Only collection/startup and metrics-server failures can stop this loop.
// Maintenance has its own bounded supervisor and never supplies a fatal event.
func runScheduledLoop(ctx context.Context, ticks <-chan time.Time, serverErrors <-chan error, collectDue func(context.Context) error) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-serverErrors:
			if !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("metrics server: %w", err)
			}
		case <-ticks:
			if err := collectDue(ctx); err != nil {
				return err
			}
		}
	}
}

func (r *runtime) collectDueJob(ctx context.Context) error {
	_ = r.reconcileAnomalies(ctx)
	claimStarted := time.Now()
	job, found, err := r.store.ClaimDueClusterSourceJob(ctx, r.cfg.WorkerID, 2*r.cfg.QueryTimeout, domain.ClusterID(r.cfg.ClusterID), domain.SourceID(r.cfg.SourceID))
	if r.scheduler != nil {
		r.scheduler.recordClaim(time.Since(claimStarted), found, err)
	}
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	runID, err := r.ids.NewID()
	if err != nil {
		return err
	}
	task := scheduledCollectionTask(job, r.cfg, domain.RunID(runID), r.clock.Now())
	completed, err := processScheduledJob(ctx, r.store, job, r.cfg.WorkerID, task, func(ctx context.Context, task domain.CollectionTask) error {
		_, err := r.collect(ctx, task)
		if err != nil {
			r.logger.Error("collection.job_failed", "job_id", job.JobID, "error", err.Error())
		}
		return err
	})
	if err != nil {
		if r.scheduler != nil {
			r.scheduler.completions.WithLabelValues("error").Inc()
		}
		return err
	}
	if r.scheduler != nil && completed {
		r.scheduler.completions.WithLabelValues("completed").Inc()
	}
	return nil
}

type scheduledJobStore interface {
	BindCollectionJob(context.Context, storepg.ClaimedJob, string, domain.RunID) (domain.RunID, error)
	CompleteJob(context.Context, storepg.ClaimedJob, string) error
}

// processScheduledJob treats only a known superseded claim as ordinary
// scheduling progress. Database/operational failures still stop the worker.
func processScheduledJob(ctx context.Context, store scheduledJobStore, job storepg.ClaimedJob, owner string, task domain.CollectionTask, collect func(context.Context, domain.CollectionTask) error) (bool, error) {
	canonical, err := store.BindCollectionJob(ctx, job, owner, task.RunID)
	if errors.Is(err, storepg.ErrCollectionClaimSuperseded) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	task.RunID = canonical
	if err := collect(ctx, task); err != nil {
		return false, nil
	}
	if err := store.CompleteJob(ctx, job, owner); err != nil {
		if errors.Is(err, storepg.ErrCollectionClaimSuperseded) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (r *runtime) reconcileAnomalies(ctx context.Context) error {
	_, err := r.reconcileAnomaliesOnce(ctx)
	return err
}

func (r *runtime) reconcileAnomaliesOnce(ctx context.Context) (bool, error) {
	if r.anomalies == nil {
		return false, nil
	}
	progressed, err := r.anomalies.RunOnce(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return progressed, ctx.Err()
		}
		// Collection and the public API do not depend on automatic response.
		r.logger.Error("anomaly_bridge.failed", "error_code", "ANOMALY_BRIDGE_FAILED")
		return progressed, nil
	}
	return progressed, nil
}

func scheduledCollectionTask(job storepg.ClaimedJob, cfg config.Worker, runID domain.RunID, now time.Time) domain.CollectionTask {
	timeout, maxTargets, maxBytes := cfg.QueryTimeout, cfg.MaxSeries, cfg.MaxBytes
	if job.DesiredRevision > 0 {
		timeout, maxTargets, maxBytes = job.Timeout, job.MaxTargets, job.MaxBytes
	}
	return domain.CollectionTask{
		RunID: runID, ClusterID: job.ClusterID, SourceID: job.SourceID, Query: job.Query, Node: job.Node,
		ScheduledFor: job.ScheduledFor, Deadline: now.Add(timeout), MaxSeries: maxTargets, MaxBytes: maxBytes,
		IdempotencyKey: fmt.Sprintf("%s/%s/config/%d", job.JobID, job.ScheduledFor.UTC().Format(time.RFC3339Nano), job.ConfigurationRevision),
	}
}

func scheduledJobID(sourceID domain.SourceID, query domain.QueryKind) string {
	return "m1/" + string(sourceID) + "/" + string(query)
}

func scheduledQueries() []domain.QueryKind {
	// Identity runs first by job ID and establish the durable GPU inventory
	// snapshot used to prove coverage for the remaining DCGM operations.
	return []domain.QueryKind{domain.QuerySourceHealth, domain.QueryGPUIdentity, domain.QueryGPUUtilization, domain.QueryGPUXID}
}

func (r *runtime) reconcileArtifacts(ctx context.Context) error {
	if r.reconciler == nil {
		return nil
	}
	result, err := r.reconciler.Run(ctx, r.clock.Now())
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	r.reconciled.WithLabelValues("AVAILABLE").Add(float64(result.Available))
	r.reconciled.WithLabelValues("UNAVAILABLE").Add(float64(result.Unavailable))
	r.reconciled.WithLabelValues("CORRUPT").Add(float64(result.Corrupt))
	r.reconciled.WithLabelValues("FAILED").Add(float64(result.Failures))
	if err != nil {
		// Backend errors can contain paths or artifact identity. Keep the log to
		// bounded aggregate fields and retry on the next maintenance cycle.
		r.logger.Error("artifact_reconciliation.failed", "checked", result.Checked, "changed", result.Changed, "available", result.Available, "unavailable", result.Unavailable, "corrupt", result.Corrupt, "failed", result.Failures)
		return errArtifactReconciliation
	}
	r.logger.Info("artifact_reconciliation.completed", "checked", result.Checked, "changed", result.Changed, "available", result.Available, "unavailable", result.Unavailable, "corrupt", result.Corrupt, "failed", result.Failures)
	return nil
}

func (r *runtime) applyRetention(ctx context.Context) error {
	started := time.Now()
	result, err := r.retentionStore.ApplyRetention(ctx, r.clock.Now(), r.cfg.ObservationRetention, r.cfg.RunRetention)
	r.retention.WithLabelValues("observations").Add(float64(result.ObservationsDeleted))
	r.retention.WithLabelValues("runs").Add(float64(result.RunsDeleted))
	r.retention.WithLabelValues("events").Add(float64(result.EventsDeleted))
	event := "retention.completed"
	if err != nil {
		event = "retention.partial_progress"
	}
	r.logger.Info(event, "observations_deleted", result.ObservationsDeleted, "runs_deleted", result.RunsDeleted, "events_deleted", result.EventsDeleted, "batches", result.Batches, "duration_seconds", time.Since(started).Seconds())
	// Observe even when cleanup failed: committed progress and remaining work
	// are separate facts. This short budget cannot extend the maintenance pass.
	r.observeRetentionBacklog(ctx)
	return err
}
