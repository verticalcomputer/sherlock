package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adapters/azureopenai"
	investigationapi "github.com/verticalcomputer/sherlock/internal/adapters/investigationapi"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/artifacts"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/clustermemory"
	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/contextbudget"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigation"
	"github.com/verticalcomputer/sherlock/internal/investigationcontext"
	"github.com/verticalcomputer/sherlock/internal/investigationtools"
	investigatorrun "github.com/verticalcomputer/sherlock/internal/investigator"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := config.LoadInvestigator()
	if err != nil {
		logger.Error("investigator.configuration_invalid", "error", err.Error())
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, logger); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("investigator.stopped", "reason", "startup or runtime failure")
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config.Investigator, logger *slog.Logger) error {
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("configure PostgreSQL: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	artifactStore, err := artifacts.NewStore(ctx, artifacts.Options{Backend: cfg.ArtifactStorage.Backend, LocalRoot: cfg.ArtifactStorage.LocalRoot, Endpoint: cfg.ArtifactStorage.R2Endpoint, Bucket: cfg.ArtifactStorage.R2Bucket, AccessKeyID: cfg.ArtifactStorage.R2AccessKeyID.Reveal(), SecretAccessKey: cfg.ArtifactStorage.R2SecretAccessKey.Reveal(), Prefix: cfg.ArtifactStorage.R2Prefix, MaxBytes: cfg.ArtifactMaxBytes})
	if err != nil {
		return fmt.Errorf("configure artifact store: %w", err)
	}
	memoryStore, err := clustermemory.NewPostgres(pool)
	if err != nil {
		return err
	}
	controller, err := configureController(cfg, pool, artifactStore, memoryStore)
	if err != nil {
		return err
	}
	leases, err := storepg.NewInvestigationLeaseStore(pool)
	if err != nil {
		return err
	}
	runner, err := investigatorrun.New(leases, controller, platform.SystemClock{}, investigatorrun.Config{WorkerID: cfg.WorkerID, PollInterval: cfg.PollInterval, LeaseDuration: cfg.LeaseDuration, MaxConcurrent: cfg.MaxConcurrent, MaxGlobal: cfg.MaxGlobal, MaxPerCluster: cfg.MaxPerCluster}, logger)
	if err != nil {
		return err
	}
	if err := runner.ConfigureMemoryProjection(memoryStore); err != nil {
		return err
	}
	logger.Info("investigator.running", "worker_id", cfg.WorkerID, "max_concurrent", cfg.MaxConcurrent)
	return runner.Run(ctx)
}

func configureController(cfg config.Investigator, pool *pgxpool.Pool, artifactStore artifacts.Store, memoryStore *clustermemory.Postgres) (*application.InvestigationController, error) {
	clock, ids := platform.SystemClock{}, platform.RandomIDGenerator{}
	store, err := storepg.NewInvestigationStore(pool)
	if err != nil {
		return nil, err
	}
	provider, err := azureopenai.NewProvider(azureopenai.Config{Endpoint: cfg.Model.AzureOpenAIEndpoint, APIKey: cfg.Model.AzureOpenAIAPIKey.Reveal(), Deployment: cfg.Model.AzureOpenAIDeployment, ConfigurationID: cfg.Model.ConfigurationID, Timeout: cfg.Model.Timeout, MaxRetries: cfg.Model.MaxRetries, MaxOutputTokens: cfg.Model.MaxOutputTokens, InputTokenMicrosPerMillion: cfg.Model.InputMicrosPerMillionTokens, OutputTokenMicrosPerMillion: cfg.Model.OutputMicrosPerMillionTokens})
	if err != nil {
		return nil, fmt.Errorf("configure hosted model provider: %w", err)
	}
	clusters := make([]domain.ClusterID, len(cfg.AllowedClusters))
	for i, value := range cfg.AllowedClusters {
		clusters[i] = domain.ClusterID(value)
	}
	diagnosticClusters := make([]domain.ClusterID, len(cfg.DiagnosticClusters))
	for i, value := range cfg.DiagnosticClusters {
		diagnosticClusters[i] = domain.ClusterID(value)
	}
	catalog, err := investigationtools.NewCatalog(append(toolDefinitions(clusters), diagnosticToolDefinitions(diagnosticClusters)...))
	if err != nil {
		return nil, err
	}
	lookups, err := investigationapi.NewEvidenceExecutor(store, clusters)
	if err != nil {
		return nil, err
	}
	executor, err := investigationExecutor(cfg, pool, store, lookups, diagnosticClusters, clock, ids)
	if err != nil {
		return nil, err
	}
	builder, err := investigationcontext.NewBuilder(investigationcontext.DefaultLimits())
	if err != nil {
		return nil, err
	}
	audits, err := storepg.NewModelCallAuditStore(pool)
	if err != nil {
		return nil, err
	}
	evidenceStore, err := storepg.NewEvidenceStore(pool)
	if err != nil {
		return nil, err
	}
	evidenceRecorder, err := application.NewEvidenceRecorder(evidenceStore, artifactStore, cfg.ArtifactMaxBytes)
	if err != nil {
		return nil, err
	}
	payloadRecorder, err := application.NewModelPayloadRecorder(audits, evidenceRecorder, cfg.ArtifactMaxBytes)
	if err != nil {
		return nil, err
	}
	planner, err := investigation.NewOrchestrator(provider, catalog, investigation.StaticAuthority{Actor: []auth.Capability{auth.CapabilityInvestigationsRun}, Cluster: investigatorClusterCapabilities()}, store, investigation.LedgerContextSource{Loader: store}, builder, audits, clock, ids, investigation.Config{Provider: "azure-openai", Model: cfg.Model.AzureOpenAIDeployment, ModelConfigVersion: cfg.Model.ConfigurationID, PlanningPrompt: "planning-v2", SynthesisPrompt: "synthesis-v2", ToolSchemaVersion: "catalog-v1", ModelCallReservationTTL: cfg.Model.Timeout + 30*time.Second}, payloadRecorder)
	if err != nil {
		return nil, err
	}
	manifestSink, err := contextbudget.NewPostgresSink(pool)
	if err != nil {
		return nil, err
	}
	budgetManager, err := contextbudget.New(contextbudget.Config{MaximumInputTokens: cfg.ContextMaxTokens, MaximumMemoryTokens: cfg.MemoryMaxTokens, MaximumMemoryEntries: cfg.MemoryMaxEntries, MaximumOutputTokens: int64(cfg.Model.MaxOutputTokens), FixedMarginTokens: 256, FallbackFactorMillionths: contextbudget.DefaultConfig().FallbackFactorMillionths, InputMicrosPerMillion: cfg.Model.InputMicrosPerMillionTokens, OutputMicrosPerMillion: cfg.Model.OutputMicrosPerMillionTokens}, contextbudget.JSONHeuristicEstimator{}, manifestSink)
	if err != nil {
		return nil, err
	}
	if err := budgetManager.ConfigureProviderDocumenter(provider); err != nil {
		return nil, err
	}
	if err := budgetManager.ConfigureCalibration(manifestSink, contextbudget.CalibrationKey{Provider: "azure-openai", Model: cfg.Model.AzureOpenAIDeployment, ConfigurationID: cfg.Model.ConfigurationID}); err != nil {
		return nil, err
	}
	if err := planner.ConfigureContextBudget(budgetManager); err != nil {
		return nil, err
	}
	checkpointStore, err := investigationcontext.NewPostgresStore(pool)
	if err != nil {
		return nil, err
	}
	// The engine's evidence allowance was a hardcoded 4,000 tokens while the
	// investigator ran with a 32,000-token context, and mandatory evidence that
	// exceeds it fails the transition outright rather than being trimmed. Live
	// runs died on their fifth decision for exactly this reason. Derive it from
	// the configured context budget instead, leaving room for tools, coverage,
	// prior actions, and the memory sub-allocation.
	engineConfig := investigationcontext.DefaultEngineConfig()
	if available := cfg.ContextMaxTokens - cfg.MemoryMaxTokens; available > 0 {
		engineConfig.EvidenceAllowanceTokens = max(engineConfig.EvidenceAllowanceTokens, available/2)
	}
	contextEngine, err := investigationcontext.NewEngine(engineConfig, checkpointStore)
	if err != nil {
		return nil, err
	}
	if err := planner.ConfigureContextEngine(contextEngine); err != nil {
		return nil, err
	}
	mode := clustermemory.Mode(cfg.MemoryMode)
	if mode != clustermemory.ModeDisabled {
		if err := planner.ConfigureMemory(memoryStore, mode); err != nil {
			return nil, err
		}
	}
	return application.NewInvestigationController(store, planner, executor, clock, ids)
}

// diagnosticToolDefinitions is empty unless an operator named the cluster in
// SHERLOCK_DIAGNOSTIC_EXECUTION_CLUSTERS. An empty allow-list means the
// definition is never constructed, so a deployment that has not opted in
// advertises no diagnostic and the catalog cannot be asked for one.
//
// The re-execution intervals are the reviewed currency of each observation.
// GPU device state is stable over roughly a minute, which is long enough to
// stop a planner re-probing inside one turn and short enough that a workload
// draining between probes is still visible.
func diagnosticToolDefinitions(clusters []domain.ClusterID) []investigationtools.Definition {
	if len(clusters) == 0 {
		return nil
	}
	base := func(id, description string) investigationtools.Definition {
		return investigationtools.Definition{
			SchemaVersion: investigationtools.SchemaVersion, ID: investigationtools.ToolID(id), Description: description,
			Operation: investigationtools.OperationDiagnostic, AllowedClusters: clusters,
			RequiredCapabilities:        []auth.Capability{auth.CapabilityInvestigationsRun},
			RequiredClusterCapabilities: []investigationtools.ClusterCapability{"gpu.diagnostics.execute"},
			Scope:                       investigationtools.ScopePolicy{EntityKinds: []string{"node", "entity"}, MaxTargets: 8, MaxWindow: time.Hour},
			Timeout:                     30 * time.Second, CostWeight: 20, MinimumReexecutionInterval: time.Minute,
		}
	}
	return []investigationtools.Definition{
		base(investigationapi.ECCCountersToolID, "Read current and lifetime GPU ECC error counters from the target nodes. A high lifetime count beside a low current one is a device with a history; the reverse is a fault happening now."),
		base(investigationapi.RetiredPagesToolID, "Read GPU retired page counts by cause and any pending retirement from the target nodes. Single-bit retirements are routine; double-bit retirements and a pending count are not."),
		base(investigationapi.RowRemapToolID, "Read GPU row-remap pending and failure state from the target nodes. Pending means a remap is queued and needs a reset; failure means remapping itself failed."),
		// The scope window bounds what an investigation may request, not what the
		// node reads: the signed argv fixes the journal window at seven days and
		// takes no parameter, so the reviewed one-hour tool bound still returns
		// events far older than the requested range.
		base(investigationtools.DiagnosticKernelXIDToolID, "Read the target nodes' own kernel journal for NVIDIA XID events over the last seven days. This is the kernel's record of what happened rather than a sampled gauge, so it establishes onset, recurrence, and which GPU reported each event."),
	}
}

// investigationExecutor routes evidence lookups and diagnostics to their owners.
// With no diagnostic cluster configured it returns the evidence executor
// unchanged, so a deployment that has not opted in behaves exactly as before.
func investigationExecutor(cfg config.Investigator, pool *pgxpool.Pool, store *storepg.InvestigationStore, lookups application.InvestigationExecutor, diagnosticClusters []domain.ClusterID, clock application.Clock, ids application.IDGenerator) (application.InvestigationExecutor, error) {
	if len(diagnosticClusters) == 0 {
		return lookups, nil
	}
	verified, err := verifiedCommandPack(cfg, clock)
	if err != nil {
		return nil, err
	}
	diagnostics, err := storepg.NewDiagnosticStore(pool)
	if err != nil {
		return nil, err
	}
	projections, err := storepg.NewDiagnosticQueryStore(pool)
	if err != nil {
		return nil, err
	}
	dispatcher, err := investigationapi.NewQueuedDispatcher(diagnostics, projections, clock, ids)
	if err != nil {
		return nil, err
	}
	envelopes, err := storepg.NewEvidenceStore(pool)
	if err != nil {
		return nil, err
	}
	evidenceSink, err := investigationapi.NewCommittingEvidenceSink(envelopes)
	if err != nil {
		return nil, err
	}
	executor, err := investigationapi.NewDiagnosticExecutor(store, verified, dispatcher, evidenceSink, clock, diagnosticClusters)
	if err != nil {
		return nil, err
	}
	return investigationapi.NewRoutingExecutor(lookups, executor)
}

func toolDefinitions(clusters []domain.ClusterID) []investigationtools.Definition {
	return []investigationtools.Definition{
		{SchemaVersion: investigationtools.SchemaVersion, ID: investigationapi.EvidenceLookupToolID, Description: "Attach bounded immutable Sherlock evidence already collected for the requested targets and time window.", Operation: investigationtools.OperationReadOnly, AllowedClusters: clusters, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, RequiredClusterCapabilities: []investigationtools.ClusterCapability{"evidence.read"}, Scope: investigationtools.ScopePolicy{EntityKinds: []string{"cluster", "node", "gpu", "job", "source", "entity"}, MaxTargets: 64, MaxWindow: 24 * time.Hour}, Timeout: 5 * time.Second, CostWeight: 1},
		{SchemaVersion: investigationtools.SchemaVersion, ID: investigationapi.XIDEvidenceToolID, Description: "Attach only precommitted, normalized Prometheus DCGM XID evidence.", Operation: investigationtools.OperationReadOnly, AllowedClusters: clusters, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, RequiredClusterCapabilities: []investigationtools.ClusterCapability{"metrics.xid.read"}, Scope: investigationtools.ScopePolicy{EntityKinds: []string{"cluster", "node", "gpu", "entity"}, MaxTargets: 64, MaxWindow: investigationapi.XIDEvidenceMaximumWindow}, Timeout: 5 * time.Second, CostWeight: 1},
		{SchemaVersion: investigationtools.SchemaVersion, ID: investigationapi.KernelEventsToolID, Description: "Attach only precommitted, reviewed kernel-event evidence; no free-form log query or command is accepted.", Operation: investigationtools.OperationReadOnly, AllowedClusters: clusters, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, RequiredClusterCapabilities: []investigationtools.ClusterCapability{"kernel.evidence.read"}, Scope: investigationtools.ScopePolicy{EntityKinds: []string{"node", "entity"}, MaxTargets: 32, MaxWindow: time.Hour}, Timeout: 5 * time.Second, CostWeight: 2},
		{SchemaVersion: investigationtools.SchemaVersion, ID: investigationapi.GPUHealthToolID, Description: "Attach only precommitted GPU identity, utilization, temperature, power, memory, and ECC evidence.", Operation: investigationtools.OperationReadOnly, AllowedClusters: clusters, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, RequiredClusterCapabilities: []investigationtools.ClusterCapability{"gpu.health.evidence.read"}, Scope: investigationtools.ScopePolicy{EntityKinds: []string{"cluster", "node", "gpu", "entity"}, MaxTargets: 64, MaxWindow: 15 * time.Minute}, Timeout: 5 * time.Second, CostWeight: 1},
		{SchemaVersion: investigationtools.SchemaVersion, ID: investigationapi.WorkloadToolID, Description: "Attach only precommitted bounded Slurm job and accounting evidence.", Operation: investigationtools.OperationReadOnly, AllowedClusters: clusters, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, RequiredClusterCapabilities: []investigationtools.ClusterCapability{"workload.evidence.read"}, Scope: investigationtools.ScopePolicy{EntityKinds: []string{"cluster", "node", "job", "entity"}, MaxTargets: 64, MaxWindow: 24 * time.Hour}, Timeout: 5 * time.Second, CostWeight: 2},
		{SchemaVersion: investigationtools.SchemaVersion, ID: investigationapi.SchedulerToolID, Description: "Attach only precommitted bounded Slurm inventory, node, and partition evidence.", Operation: investigationtools.OperationReadOnly, AllowedClusters: clusters, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, RequiredClusterCapabilities: []investigationtools.ClusterCapability{"scheduler.evidence.read"}, Scope: investigationtools.ScopePolicy{EntityKinds: []string{"cluster", "node", "job", "entity"}, MaxTargets: 64, MaxWindow: time.Hour}, Timeout: 5 * time.Second, CostWeight: 1},
		{SchemaVersion: investigationtools.SchemaVersion, ID: investigationapi.SourceFreshnessToolID, Description: "Attach only precommitted source-health and freshness evidence.", Operation: investigationtools.OperationReadOnly, AllowedClusters: clusters, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, RequiredClusterCapabilities: []investigationtools.ClusterCapability{"source.freshness.evidence.read"}, Scope: investigationtools.ScopePolicy{EntityKinds: []string{"cluster", "node", "source", "entity"}, MaxTargets: 64, MaxWindow: time.Hour}, Timeout: 5 * time.Second, CostWeight: 1},
		{SchemaVersion: investigationtools.SchemaVersion, ID: investigationapi.BMCSensorsToolID, Description: "Attach only precommitted bounded Redfish inventory, sensor, and event evidence; no BMC mutation is available.", Operation: investigationtools.OperationReadOnly, AllowedClusters: clusters, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, RequiredClusterCapabilities: []investigationtools.ClusterCapability{"bmc.evidence.read"}, Scope: investigationtools.ScopePolicy{EntityKinds: []string{"cluster", "node", "source", "entity"}, MaxTargets: 32, MaxWindow: time.Hour}, Timeout: 5 * time.Second, CostWeight: 2},
	}
}

func investigatorClusterCapabilities() []investigationtools.ClusterCapability {
	return []investigationtools.ClusterCapability{
		"gpu.diagnostics.execute",
		"evidence.read", "metrics.xid.read", "kernel.evidence.read", "gpu.health.evidence.read",
		"workload.evidence.read", "scheduler.evidence.read", "source.freshness.evidence.read", "bmc.evidence.read",
	}
}

// verifiedCommandPack loads and signature-verifies the reviewed pack. The
// investigator resolves every argv from this pack, and the target's sealed
// runner verifies the same pack again independently, so a control plane that
// could not verify it must refuse to start rather than execute anything.
func verifiedCommandPack(cfg config.Investigator, clock application.Clock) (*commandpack.Catalog, error) {
	return commandpack.LoadVerifiedCatalog(cfg.CommandPackFile, cfg.TrustRootsFile, cfg.RunnerVersion, clock.Now())
}
