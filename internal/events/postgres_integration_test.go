//go:build integration

package events_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/events"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestDurableEventsAreClusterScopedReplayableAndWaitable(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated migrated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	eventStore, err := events.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	collectionStore, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterA, clusterB := domain.ClusterID("events-a-"+suffix), domain.ClusterID("events-b-"+suffix)
	sourceA, sourceB := domain.SourceID("events-source-a-"+suffix), domain.SourceID("events-source-b-"+suffix)
	if err := collectionStore.EnsureSource(ctx, clusterA, "Events A", sourceA, "Prometheus A"); err != nil {
		t.Fatal(err)
	}
	if err := collectionStore.EnsureSource(ctx, clusterB, "Events B", sourceB, "Prometheus B"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	first, err := eventStore.Append(ctx, clusterA, events.CollectionUpdatedV1{
		RunID: "events-run-a-" + domain.RunID(suffix), SourceID: sourceA,
		Status: domain.ResultSucceeded, CompletedAt: now, CoverageComplete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := eventStore.Append(ctx, clusterA, events.SourceUpdatedV1{
		SourceID: sourceA, Availability: events.SourceAvailable, LastAttemptAt: now, LastSuccessAt: &now,
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := eventStore.Append(ctx, clusterB, events.SourceUpdatedV1{
		SourceID: sourceB, Availability: events.SourceUnavailable, LastAttemptAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != 1 || second.ID != 2 || other.ID != 1 {
		t.Fatalf("event IDs are not per-stream monotonic: A=%d,%d B=%d", first.ID, second.ID, other.ID)
	}

	page, err := eventStore.ListAfter(ctx, clusterA, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 1 || page.Events[0].ID != first.ID || page.NextAfterID != first.ID || !page.HasMore {
		t.Fatalf("unexpected first page: %+v", page)
	}
	replay, err := eventStore.ListAfter(ctx, clusterA, page.NextAfterID, events.MaxPageSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(replay.Events) != 1 || replay.Events[0].ID != second.ID || replay.HasMore {
		t.Fatalf("unexpected replay page: %+v", replay)
	}

	result := make(chan events.Page, 1)
	errs := make(chan error, 1)
	go func() {
		page, err := eventStore.WaitAfter(ctx, clusterA, second.ID, 10, time.Second)
		result <- page
		errs <- err
	}()
	time.Sleep(75 * time.Millisecond)
	third, err := eventStore.Append(ctx, clusterA, events.SourceUpdatedV1{
		SourceID: sourceA, Availability: events.SourceUnavailable, LastAttemptAt: now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	woken := <-result
	if len(woken.Events) != 1 || woken.Events[0].ID != third.ID {
		t.Fatalf("wait did not re-read durable state: %+v", woken)
	}

	// The collection mutation and both public update events commit together.
	resultTask := domain.CollectionTask{
		RunID: "events-persisted-run-" + domain.RunID(suffix), ClusterID: clusterA, SourceID: sourceA,
		Query: domain.QuerySourceHealth, ScheduledFor: now.Add(2 * time.Second),
		Deadline: now.Add(3 * time.Second), IdempotencyKey: "events/result/" + suffix,
	}
	collectionResult := domain.CollectionResult{
		Task: resultTask, Status: domain.ResultNoData, StartedAt: now.Add(2 * time.Second),
		CompletedAt: now.Add(2500 * time.Millisecond), Coverage: domain.Coverage{Complete: true},
	}
	inserted, err := collectionStore.RecordResult(ctx, collectionResult)
	if err != nil || !inserted {
		t.Fatalf("record collection result inserted=%v err=%v", inserted, err)
	}
	updates, err := eventStore.ListAfter(ctx, clusterA, third.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(updates.Events) != 2 || updates.Events[0].Type != events.CollectionUpdatedType || updates.Events[1].Type != events.SourceUpdatedType {
		t.Fatalf("collection mutation did not publish both updates: %+v", updates)
	}
	collectionPayload, ok := updates.Events[0].Payload.(events.CollectionUpdatedV1)
	if !ok || collectionPayload.RunID != resultTask.RunID || collectionPayload.Status != domain.ResultNoData {
		t.Fatalf("unexpected collection update payload: %#v", updates.Events[0].Payload)
	}
}
