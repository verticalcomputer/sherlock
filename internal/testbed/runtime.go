package testbed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/contextbudget"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigation"
	"github.com/verticalcomputer/sherlock/internal/investigationcontext"
	"github.com/verticalcomputer/sherlock/internal/investigationtools"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
func ledgerSource(w worldAdapter) investigation.LedgerContextSource {
	return investigation.LedgerContextSource{Loader: w}
}

type clock struct{ at time.Time }

func (c clock) Now() time.Time { return c.at }

func components(ctx context.Context, pool *pgxpool.Pool, id domain.InvestigationID) (*application.InvestigationController, *storepg.InvestigationStore, *investigationcontext.Engine, *investigationcontext.Builder, error) {
	return faultComponents(ctx, pool, id, nil)
}

func faultComponents(ctx context.Context, pool *pgxpool.Pool, id domain.InvestigationID, fault *pipelineFault) (*application.InvestigationController, *storepg.InvestigationStore, *investigationcontext.Engine, *investigationcontext.Builder, error) {
	store, err := storepg.NewInvestigationStore(pool)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	snapshot, found, err := store.LoadInvestigation(ctx, id)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if !found {
		return nil, nil, nil, nil, fmt.Errorf("testbed investigation not found")
	}
	request := snapshot.Investigation.Request()
	definitions := []investigationtools.Definition{}
	for _, tool := range []string{"evidence.lookup.v1", "node.detail.v1"} {
		definitions = append(definitions, investigationtools.Definition{SchemaVersion: 1, ID: investigationtools.ToolID(tool), Description: "Read bounded simulated source evidence", Operation: investigationtools.OperationReadOnly, AllowedClusters: []domain.ClusterID{request.ClusterID}, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, RequiredClusterCapabilities: []investigationtools.ClusterCapability{"testbed.read"}, Scope: investigationtools.ScopePolicy{EntityKinds: []string{request.Scope.EntityKind}, MaxTargets: 1, MaxWindow: time.Hour}, Timeout: time.Second, CostWeight: 1})
	}
	if strings.HasPrefix(string(request.ClusterID), "tb-pipeline-") {
		definitions = nil
		for _, tool := range investigationtools.XIDRequiredEvidenceTools() {
			definitions = append(definitions, investigationtools.Definition{SchemaVersion: 1, ID: tool, Description: "Simulated unavailable diagnostic; no node access", Operation: investigationtools.OperationDiagnostic, MinimumReexecutionInterval: time.Minute, AllowedClusters: []domain.ClusterID{request.ClusterID}, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, RequiredClusterCapabilities: []investigationtools.ClusterCapability{"testbed.read"}, Scope: investigationtools.ScopePolicy{EntityKinds: []string{request.Scope.EntityKind}, MaxTargets: 1, MaxWindow: time.Hour}, Timeout: time.Second, CostWeight: 1})
		}
	}
	catalog, err := investigationtools.NewCatalog(definitions)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	builder, err := investigationcontext.NewBuilder(investigationcontext.DefaultLimits())
	if err != nil {
		return nil, nil, nil, nil, err
	}
	audits, err := storepg.NewModelCallAuditStore(pool)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	adapter := worldAdapter{pool: pool, id: id}
	c := clock{request.RequestedAt.Add(time.Minute)}
	planner, err := investigation.NewOrchestrator(simulator{pool}, catalog, investigation.StaticAuthority{Actor: []auth.Capability{auth.CapabilityInvestigationsRun}, Cluster: []investigationtools.ClusterCapability{"testbed.read"}}, store, ledgerSource(adapter), builder, audits, c, platform.RandomIDGenerator{}, investigation.Config{Provider: "testbed", Model: PlannerVersion, ModelConfigVersion: SchemaVersion, PlanningPrompt: "planning-v2", SynthesisPrompt: "synthesis-v2", ToolSchemaVersion: "catalog-v1", ModelCallReservationTTL: time.Minute})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	sink, err := contextbudget.NewPostgresSink(pool)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	manager, err := contextbudget.New(contextbudget.DefaultConfig(), contextbudget.JSONHeuristicEstimator{}, sink)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if err = planner.ConfigureContextBudget(manager); err != nil {
		return nil, nil, nil, nil, err
	}
	checkpoints, err := investigationcontext.NewPostgresStore(pool)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	config := investigationcontext.DefaultEngineConfig()
	config.MaximumPerClass = 1
	config.MaximumPerSource = 64
	engine, err := investigationcontext.NewEngine(config, checkpoints)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if err = planner.ConfigureContextEngine(engine); err != nil {
		return nil, nil, nil, nil, err
	}
	var controllerStore application.InvestigationStore = store
	var executor application.InvestigationExecutor = adapter
	if fault != nil {
		controllerStore = crashInvestigationStore{InvestigationStore: store, fault: fault}
		executor = crashExecutor{adapter, fault}
	}
	controller, err := application.NewInvestigationController(controllerStore, planner, executor, c, platform.RandomIDGenerator{})
	return controller, store, engine, builder, err
}

// Worker can run in a separate process. Its decisions depend only on PostgreSQL
// and the current request; it never receives an Oracle or queued model replies.
func Worker(ctx context.Context, pool *pgxpool.Pool, id domain.InvestigationID, stopAfterActions int) error {
	if _, err := pool.Exec(ctx, `INSERT INTO testbed_workers(investigation_id,process_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, os.Getpid()); err != nil {
		return err
	}
	controller, store, _, _, err := components(ctx, pool, id)
	if err != nil {
		return err
	}
	for range 64 {
		snapshot, err := controller.Advance(ctx, id)
		if err != nil {
			return err
		}
		if snapshot.Investigation.Status().Terminal() {
			return nil
		}
		if stopAfterActions > 0 && snapshot.Investigation.Status() == domain.InvestigationPlanning && len(snapshot.PriorActions) >= stopAfterActions {
			return nil
		}
	}
	snapshot, _, _ := store.LoadInvestigation(ctx, id)
	return fmt.Errorf("testbed exceeded 64 transitions at %s", snapshot.Investigation.Status())
}

func probe(ctx context.Context, pool *pgxpool.Pool, id domain.InvestigationID) ([]byte, error) {
	_, store, engine, builder, err := components(ctx, pool, id)
	if err != nil {
		return nil, err
	}
	snapshot, _, err := store.LoadInvestigation(ctx, id)
	if err != nil {
		return nil, err
	}
	input, err := ledgerSource(worldAdapter{pool, id}).InvestigationContext(ctx, snapshot)
	if err != nil {
		return nil, err
	}
	input, _, err = engine.Prepare(ctx, snapshot, input)
	if err != nil {
		return nil, err
	}
	built, err := builder.Build(input)
	if err != nil {
		return nil, err
	}
	return json.Marshal(built)
}

func prepare(ctx context.Context, pool *pgxpool.Pool, s Scenario, prefix string) (domain.InvestigationID, error) {
	clusterID := domain.ClusterID(prefix)
	id := domain.InvestigationID(prefix + "-investigation")
	sourceID := domain.SourceID(prefix + "-source")
	collections, _ := storepg.NewCollectionStore(pool)
	if err := collections.EnsureSource(ctx, clusterID, "Synthetic testbed cluster", sourceID, "Synthetic source"); err != nil {
		return "", err
	}
	evidenceStore, _ := storepg.NewEvidenceStore(pool)
	for _, e := range s.World.Evidence {
		targets := []domain.EvidenceTarget{{Kind: domain.EvidenceTargetNode, ID: "node-1"}}
		coverage := domain.EvidenceCoverage{Expected: targets}
		if e.Status == domain.EvidenceComplete || e.Status == domain.EvidenceNoData {
			coverage.Covered = slices.Clone(targets)
		}
		eid := domain.EvidenceID(prefix + "-" + e.ID)
		envelope, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{ID: eid, SchemaVersion: 1, ClusterID: clusterID, Status: e.Status, Source: domain.EvidenceSourceReference{SourceID: sourceID, Operation: domain.EvidenceOperationID("testbed." + e.Role), DefinitionVersion: "1", Reference: "synthetic:normalized"}, TimeRange: domain.EvidenceTimeRange{Start: s.World.Start, End: s.World.End}, CollectedAt: s.World.End.Add(time.Second), Coverage: coverage})
		if err != nil {
			return "", err
		}
		if _, err = evidenceStore.CreateEvidence(ctx, envelope); err != nil {
			return "", err
		}
		var committed time.Time
		if err = pool.QueryRow(ctx, `SELECT created_at FROM evidence_envelopes WHERE evidence_id=$1`, eid).Scan(&committed); err != nil {
			return "", err
		}
		input := investigationcontext.EvidenceInput{EvidenceID: eid, ClusterID: clusterID, Operation: envelope.Source().Operation, EvidenceClass: e.Role, Status: e.Status, EntityIDs: []string{"node-1"}, ObservedFrom: s.World.Start, ObservedTo: s.World.End, CollectedAt: s.World.End.Add(time.Second), Source: string(sourceID), Summary: e.Summary, SummaryQuality: "MEANINGFUL", SummaryVersion: "testbed-v1", Coverage: coverage, ExpectedFrom: s.World.Start, ExpectedTo: s.World.End, CommittedAt: committed, Retained: true, ArtifactAvailable: true, CitationEligible: true, KeepDistinct: true}
		raw, _ := json.Marshal(input)
		if _, err = pool.Exec(ctx, `INSERT INTO testbed_evidence(evidence_id,investigation_id,role,available_after,projection) VALUES($1,$2,$3,$4,$5)`, eid, id, e.Role, e.AvailableAfterAction, raw); err != nil {
			return "", err
		}
	}
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return "", err
	}
	now = now.UTC()
	if now.Before(s.World.End.Add(time.Minute)) {
		now = s.World.End.Add(time.Minute)
	}
	incidentID := domain.IncidentID(prefix + "-incident")
	// Explicit fixture admission: this does not pretend to exercise incident
	// creation, notification delivery or detectors not covered by detection.go.
	if _, err := pool.Exec(ctx, `INSERT INTO incidents(incident_id,cluster_id,title,severity,status,created_by,created_at,updated_at) VALUES($1,$2,'Synthetic investigation','HIGH','OPEN','testbed',$3,$3)`, incidentID, clusterID, now); err != nil {
		return "", err
	}
	raw, _ := json.Marshal(s.World)
	if _, err := pool.Exec(ctx, `INSERT INTO testbed_worlds(investigation_id,world) VALUES($1,$2)`, id, raw); err != nil {
		return "", err
	}
	request := domain.InvestigationRequest{ID: id, IncidentID: incidentID, ClusterID: clusterID, Question: s.World.Question, RequestedBy: "testbed", IdempotencyKey: string(id), Scope: domain.InvestigationScope{EntityKind: "node", EntityIDs: []string{"node-1"}, Start: s.World.Start, End: s.World.End}, SuccessCriteria: []string{"Report supported observations and explicit uncertainty"}, Budget: domain.InvestigationBudget{MaxDecisions: 8, MaxToolCalls: 4, MaxFanOut: 1, MaxModelTokens: 200000, MaxCostMicros: 100000}, RequestedAt: now, Deadline: now.Add(time.Hour)}
	store, _ := storepg.NewInvestigationStore(pool)
	controller, err := application.NewInvestigationController(store, application.ScriptedInvestigationPlanner{}, worldAdapter{pool, id}, clock{now}, platform.RandomIDGenerator{})
	if err != nil {
		return "", err
	}
	_, _, err = controller.Start(ctx, application.StartInvestigationInput{Request: request})
	return id, err
}
