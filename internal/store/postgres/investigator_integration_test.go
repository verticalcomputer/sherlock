//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestInvestigatorClaimsAndModelCallReservationsAreExclusive(t *testing.T) {
	ctx := context.Background()
	pool := durableTestDatabase(t)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("m9-cluster-" + suffix)
	collections, _ := storepg.NewCollectionStore(pool)
	if err := collections.EnsureSource(ctx, clusterID, "M9 cluster", domain.SourceID("m9-source-"+suffix), "M9 source"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	investigationID := domain.InvestigationID("investigation-schedule-m9-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO investigations (investigation_id,cluster_id,question,requested_by,scope,window_start,window_end,success_criteria,status,created_at,updated_at) VALUES ($1,$2,'M9 lease test','sherlock-remediator','{"entity_kind":"node","entity_ids":["node-1"]}'::jsonb,$3,$4,'["exclusive progress"]'::jsonb,'PLANNING',$4,$4)`, investigationID, clusterID, now.Add(-time.Hour), now); err != nil {
		t.Fatal(err)
	}
	leasesA, _ := storepg.NewInvestigationLeaseStore(pool)
	leasesB, _ := storepg.NewInvestigationLeaseStore(pool)
	leaseA, claimed, err := leasesA.Claim(ctx, "worker-a", now, 30*time.Second, 2, 1)
	if err != nil || !claimed {
		t.Fatalf("first claim=%t err=%v", claimed, err)
	}
	if _, claimed, err := leasesB.Claim(ctx, "worker-b", now, 30*time.Second, 2, 1); err != nil || claimed {
		t.Fatalf("concurrent claim=%t err=%v", claimed, err)
	}
	leaseB, claimed, err := leasesB.Claim(ctx, "worker-b", now.Add(31*time.Second), 30*time.Second, 2, 1)
	if err != nil || !claimed || leaseB.Epoch <= leaseA.Epoch {
		t.Fatalf("reclaim=%+v claimed=%t err=%v", leaseB, claimed, err)
	}
	if err := leasesA.Release(ctx, leaseA, now.Add(32*time.Second), now.Add(32*time.Second)); err == nil {
		t.Fatal("stale lease released a reclaimed investigation")
	}

	audits, _ := storepg.NewModelCallAuditStore(pool)
	key := "investigation/" + string(investigationID) + "/planning/1"
	if err := audits.ReserveModelCall(ctx, investigationID, clusterID, key, application.ModelCallPlanning, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := audits.ReserveModelCall(ctx, investigationID, clusterID, key, application.ModelCallPlanning, now, now.Add(time.Minute)); !errors.Is(err, application.ErrModelCallInFlight) {
		t.Fatalf("duplicate reservation=%v", err)
	}
	if err := audits.ReserveModelCall(ctx, investigationID, clusterID, key, application.ModelCallPlanning, now.Add(61*time.Second), now.Add(2*time.Minute)); !errors.Is(err, application.ErrModelCallOutcomeUnknown) {
		t.Fatalf("expired reservation=%v", err)
	}
	if err := audits.ReserveModelCall(ctx, investigationID, clusterID, key, application.ModelCallPlanning, now.Add(2*time.Minute), now.Add(3*time.Minute)); !errors.Is(err, application.ErrModelCallAlreadyAttempted) {
		t.Fatalf("uncertain call was retryable: %v", err)
	}
}
