//go:build integration

package investigationapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	publicapi "github.com/verticalcomputer/sherlock/internal/api"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestPostgresInvestigationAPIIdempotencyAndSupervisor(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	clusterID := domain.ClusterID("adapter-cluster-" + suffix)
	collections, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := collections.EnsureSource(ctx, clusterID, "Adapter test", domain.SourceID("source-"+suffix), "Source"); err != nil {
		t.Fatal(err)
	}
	store, err := storepg.NewInvestigationStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	clock := &adapterClock{now: time.Now().UTC().Truncate(time.Microsecond)}
	controller, err := NewFailClosedController(store, clock, &adapterIDs{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(pool, controller, clock)
	if err != nil {
		t.Fatal(err)
	}
	incidentInput := publicapi.CreateIncidentInput{ClusterID: clusterID, ActorID: "actor-1", IdempotencyKey: "incident-key-" + suffix, Title: "GPU incident", Summary: "Synthetic", Severity: "HIGH", TargetIDs: []string{"node-1"}, EvidenceIDs: []string{}}
	incident, replayed, err := service.CreateIncident(ctx, incidentInput)
	if err != nil || replayed {
		t.Fatalf("create incident replayed=%t err=%v", replayed, err)
	}
	if _, replayed, err := service.CreateIncident(ctx, incidentInput); err != nil || !replayed {
		t.Fatalf("replay incident replayed=%t err=%v", replayed, err)
	}
	changedIncident := incidentInput
	changedIncident.Title = "Different"
	if _, _, err := service.CreateIncident(ctx, changedIncident); !errors.Is(err, publicapi.ErrInvestigationConflict) {
		t.Fatalf("changed incident error = %v", err)
	}
	start := publicapi.StartInvestigationInput{
		ClusterID: clusterID, ActorID: "actor-1", IdempotencyKey: "investigation-key-" + suffix,
		IncidentID: incident.IncidentID, Question: "Why is node-1 unhealthy?",
		Scope:           publicapi.InvestigationScopeResource{EntityKind: "NODE", EntityIDs: []string{"node-1"}, Start: clock.now.Add(-time.Hour), End: clock.now},
		SuccessCriteria: []string{"identify the limiting condition"},
		Budget:          publicapi.InvestigationBudgetResource{MaxDecisions: 3, MaxToolCalls: 2, MaxFanOut: 2},
		Deadline:        clock.now.Add(time.Hour),
	}
	investigation, replayed, err := service.StartInvestigation(ctx, start)
	if err != nil || replayed {
		t.Fatalf("start investigation replayed=%t err=%v", replayed, err)
	}
	if investigation.Scope.EntityKind != "node" {
		t.Fatalf("entity kind was not canonicalized: %q", investigation.Scope.EntityKind)
	}
	if _, replayed, err := service.StartInvestigation(ctx, start); err != nil || !replayed {
		t.Fatalf("replay investigation replayed=%t err=%v", replayed, err)
	}
	changedStart := start
	changedStart.Question = "Different question"
	if _, _, err := service.StartInvestigation(ctx, changedStart); !errors.Is(err, publicapi.ErrInvestigationConflict) {
		t.Fatalf("changed investigation error = %v", err)
	}
	beforeAdvance, found, err := service.GetInvestigation(ctx, investigation.InvestigationID)
	if err != nil || !found || string(beforeAdvance.Status) != string(domain.InvestigationInitializing) {
		t.Fatalf("API unexpectedly advanced investigation: status=%s found=%t err=%v", beforeAdvance.Status, found, err)
	}
	// M9.2 removed advancement from the API service. Drive the fail-closed
	// controller explicitly here as the separately leased investigator would.
	for range 4 {
		if _, err := controller.Advance(ctx, domain.InvestigationID(investigation.InvestigationID)); err != nil {
			t.Fatal(err)
		}
	}
	got, found, err := service.GetInvestigation(ctx, investigation.InvestigationID)
	if err != nil || !found {
		t.Fatalf("get investigation found=%t err=%v", found, err)
	}
	if got.Status != "BLOCKED" || got.StopReason != string(domain.StopAccessUnavailable) {
		t.Fatalf("terminal state = %s/%s", got.Status, got.StopReason)
	}
	incidents, _, err := service.ListIncidents(ctx, clusterID, publicapi.IncidentListOptions{})
	if err != nil || len(incidents) != 1 || len(incidents[0].InvestigationIDs) != 1 {
		t.Fatalf("incidents=%+v err=%v", incidents, err)
	}
}

type adapterClock struct{ now time.Time }

func (clock *adapterClock) Now() time.Time {
	clock.now = clock.now.Add(time.Second)
	return clock.now
}

type adapterIDs struct{ next int }

func (ids *adapterIDs) NewID() (string, error) {
	ids.next++
	return fmt.Sprintf("event-%d", ids.next), nil
}
