//go:build integration

package adminui_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adapters/investigationapi"
	"github.com/verticalcomputer/sherlock/internal/adminui"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// The UI projection sees a recent attempt, while the durable current-warning
// set also includes an older diagnostic stream. Exercise the actual form flow,
// admission, reload, executor and synthesis transition against PostgreSQL.
func TestRepairUIAdmitsOldCurrentWarningsAndReachesSynthesis(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("requires fresh migrated integration database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	cluster, source := domain.ClusterID("repair-ui-"+suffix), domain.SourceID("source-"+suffix)
	collections, _ := storepg.NewCollectionStore(pool)
	if err := collections.EnsureSource(ctx, cluster, "repair UI", source, "source"); err != nil {
		t.Fatal(err)
	}
	evidenceStore, _ := storepg.NewEvidenceStore(pool)
	store, _ := storepg.NewInvestigationStore(pool)
	old := time.Now().UTC().Truncate(time.Microsecond).Add(-7 * 24 * time.Hour)
	insert := func(name, operation string, status domain.EvidenceStatus, at time.Time) domain.EvidenceID {
		t.Helper()
		targets := []domain.EvidenceTarget{{Kind: domain.EvidenceTargetNode, ID: "node-1"}}
		var covered []domain.EvidenceTarget
		if status == domain.EvidenceComplete {
			covered = targets
		}
		envelope, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{ID: domain.EvidenceID(name + "-" + suffix), SchemaVersion: 1, ClusterID: cluster, Status: status, Source: domain.EvidenceSourceReference{SourceID: source, Operation: domain.EvidenceOperationID(operation), DefinitionVersion: "v1", Reference: "fixture://repair-ui"}, TimeRange: domain.EvidenceTimeRange{Start: at, End: at}, CollectedAt: at, Coverage: domain.EvidenceCoverage{Expected: targets, Covered: covered}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evidenceStore.CreateEvidence(ctx, envelope); err != nil {
			t.Fatal(err)
		}
		return envelope.ID()
	}
	oldID := insert("old-warning", "gpu.ecc_counters", domain.EvidenceUnavailable, old)
	insert("superseded-warning", "gpu.retired_pages", domain.EvidenceUnavailable, old.Add(time.Minute))
	insert("superseding-success", "gpu.retired_pages", domain.EvidenceComplete, old.Add(2*time.Minute))
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	incident := domain.IncidentID("incident-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO incidents(incident_id,cluster_id,title,severity,status,created_by,created_at,updated_at) VALUES($1,$2,'repair','HIGH','OPEN','test',$3,$3)`, incident, cluster, now); err != nil {
		t.Fatal(err)
	}
	planner := &repairAdmissionPlanner{}
	executor, _ := investigationapi.NewEvidenceExecutor(store, []domain.ClusterID{cluster})
	var controller *application.InvestigationController
	provider := &repairAdmissionProvider{t: t, cluster: cluster, incident: incident, id: domain.InvestigationID("repair-ui-inv-" + suffix), now: now}
	adminui.ExerciseRepairFormForIntegration(t, now, string(cluster), string(provider.id), func(base adminui.DataProvider, clock application.Clock) adminui.DataProvider {
		controller, err = application.NewInvestigationController(store, planner, executor, clock, platform.RandomIDGenerator{})
		if err != nil {
			t.Fatal(err)
		}
		provider.DataProvider, provider.controller = base, controller
		return provider
	})
	if !provider.started.WindowStart.Equal(now.Add(-24 * time.Hour)) {
		t.Fatal("fixture did not reproduce the narrow UI window")
	}
	admitted, found, err := store.LoadInvestigation(ctx, provider.id)
	if err != nil || !found || !admitted.Investigation.Request().Scope.Start.Equal(old) {
		t.Fatalf("scope was not normalized: found=%t err=%v scope=%+v", found, err, admitted.Investigation.Request().Scope)
	}
	// Even an envelope backdated to the request cutoff after admission cannot
	// replace an admitted warning or inject another stream into the proposal.
	lateSuccess := insert("late-success", "gpu.ecc_counters", domain.EvidenceComplete, now.Add(-time.Minute))
	lateWarning := insert("late-warning", "gpu.row_remap", domain.EvidenceUnavailable, old.Add(time.Hour))
	if _, err := pool.Exec(ctx, `UPDATE evidence_envelopes SET created_at=$2 WHERE evidence_id=ANY($1::text[])`, []string{string(lateSuccess), string(lateWarning)}, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 15; step++ {
		snapshot, err := controller.Advance(ctx, provider.id)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Investigation.Status() == domain.InvestigationSynthesizing {
			if len(snapshot.Evidence.Entries()) != 1 || snapshot.Evidence.Entries()[0].EvidenceID != oldID {
				t.Fatalf("frozen warnings changed: %+v", snapshot.Evidence.Entries())
			}
			return
		}
		if snapshot.Investigation.Status().Terminal() {
			t.Fatalf("terminated before synthesis: %s", snapshot.Investigation.Status())
		}
	}
	t.Fatal("UI proposal never reached synthesis")
}

type repairAdmissionProvider struct {
	adminui.DataProvider
	t          *testing.T
	started    adminui.InvestigationStart
	controller *application.InvestigationController
	cluster    domain.ClusterID
	incident   domain.IncidentID
	id         domain.InvestigationID
	now        time.Time
	startErr   error
}

func (provider *repairAdmissionProvider) StartInvestigation(ctx context.Context, _ string, input adminui.InvestigationStart, _ adminui.MutationContext) (adminui.InvestigationStartResult, error) {
	provider.started = input
	request := domain.InvestigationRequest{ID: provider.id, IncidentID: provider.incident, ClusterID: provider.cluster, Purpose: input.Purpose, Question: input.Question, RequestedBy: "admin-ui-test", IdempotencyKey: input.IdempotencyKey, Scope: domain.InvestigationScope{EntityKind: input.EntityKind, EntityIDs: input.EntityIDs, Start: input.WindowStart, End: input.WindowEnd}, SuccessCriteria: input.SuccessCriteria, Budget: domain.InvestigationBudget{MaxDecisions: input.MaxDecisions, MaxToolCalls: input.MaxToolCalls, MaxDiagnosticCalls: input.MaxDiagnosticCalls, MaxFanOut: input.MaxFanOut, MaxModelTokens: input.MaxModelTokens, MaxCostMicros: input.MaxCostMicrounits}, RequestedAt: provider.now, Deadline: input.Deadline}
	_, _, provider.startErr = provider.controller.Start(ctx, application.StartInvestigationInput{Request: request})
	if provider.startErr != nil {
		provider.t.Logf("admission failed: %v", provider.startErr)
	}
	return adminui.InvestigationStartResult{ID: string(provider.id)}, provider.startErr
}

type repairAdmissionPlanner struct{}

func (*repairAdmissionPlanner) Decide(_ context.Context, snapshot application.InvestigationSnapshot) (application.InvestigationDecision, error) {
	if len(snapshot.PriorActions) > 0 {
		return application.InvestigationDecision{Stop: true, Outcome: domain.InvestigationPartial, Reason: domain.StopNoUsefulAction}, nil
	}
	request := snapshot.Investigation.Request()
	return application.InvestigationDecision{Action: &domain.InvestigationAction{ID: domain.InvestigationActionID("lookup-" + string(request.ID)), ToolID: investigationapi.EvidenceLookupToolID, Digest: domain.ChecksumSHA256([]byte(fmt.Sprint(request.Scope))), Targets: request.Scope.EntityIDs, Start: request.Scope.Start, End: request.Scope.End, FanOut: 1}}, nil
}

func (*repairAdmissionPlanner) Synthesize(context.Context, application.InvestigationSnapshot) (application.InvestigationSynthesis, error) {
	panic("test stops at the durable synthesis boundary")
}
