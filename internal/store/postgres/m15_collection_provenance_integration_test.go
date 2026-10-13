//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestM15CollectionProvenanceGuards(t *testing.T) {
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	p, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	s, err := storepg.NewCollectionStore(p)
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("m15-prov-%d", time.Now().UnixNano())
	cluster, source := domain.ClusterID("cluster-"+suffix), domain.SourceID("source-"+suffix)
	if err := s.EnsureSource(ctx, cluster, "M15", source, "Prometheus"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := p.Exec(ctx, `DELETE FROM collection_runs WHERE cluster_id=$1`, cluster); err != nil {
			t.Errorf("cleanup runs: %v", err)
		}
		if _, err := p.Exec(ctx, `DELETE FROM collection_run_jobs WHERE cluster_id=$1`, cluster); err != nil {
			t.Errorf("cleanup provenance: %v", err)
		}
		if _, err := p.Exec(ctx, `DELETE FROM collection_jobs WHERE cluster_id=$1`, cluster); err != nil {
			t.Errorf("cleanup jobs: %v", err)
		}
		if _, err := p.Exec(ctx, `DELETE FROM sources WHERE cluster_id=$1`, cluster); err != nil {
			t.Errorf("cleanup source: %v", err)
		}
		if _, err := p.Exec(ctx, `DELETE FROM clusters WHERE cluster_id=$1`, cluster); err != nil {
			t.Errorf("cleanup cluster: %v", err)
		}
	}()
	when := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	jobID := "job-" + suffix
	if err := s.EnsureJob(ctx, jobID, cluster, source, domain.QueryGPUUtilization, "node-a", time.Minute, when); err != nil {
		t.Fatal(err)
	}
	job, found, err := s.ClaimDueSourceJob(ctx, "owner-a", time.Minute, source)
	if err != nil || !found {
		t.Fatalf("claim found=%v err=%v", found, err)
	}
	canonical, err := s.BindCollectionJob(ctx, job, "owner-a", domain.RunID("caller-run-"+suffix))
	if err != nil {
		t.Fatal(err)
	}
	if canonical != domain.RunID("caller-run-"+suffix) {
		t.Fatalf("canonical run=%q", canonical)
	}
	if _, err := p.Exec(ctx, `UPDATE collection_jobs SET active=false WHERE job_id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureJob(ctx, jobID, cluster, source, domain.QueryGPUUtilization, "node-a", time.Minute, when); err != nil {
		t.Fatal(err)
	}
	var active bool
	if err := p.QueryRow(ctx, `SELECT active FROM collection_jobs WHERE job_id=$1`, jobID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("EnsureJob unexpectedly reactivated disabled job")
	}
	wrong := job
	wrong.SourceID = "other-source"
	if _, err := s.BindCollectionJob(ctx, wrong, "owner-a", domain.RunID("wrong-source")); err == nil {
		t.Fatal("accepted wrong-source provenance")
	}
	if err := s.CompleteJob(ctx, job, "owner-a"); err == nil {
		t.Fatal("stale completion unexpectedly succeeded after disable")
	}
	// Restore the exact values, while attempting to spoof both revisions. The
	// triggers must retain the ABA history and reject the original lease.
	var configBefore, scheduleBefore, configAfter, scheduleAfter int64
	if err := p.QueryRow(ctx, `SELECT configuration_revision,schedule_revision FROM collection_jobs WHERE job_id=$1`, jobID).Scan(&configBefore, &scheduleBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `UPDATE collection_jobs SET active=true,configuration_revision=0,schedule_revision=0 WHERE job_id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(ctx, `SELECT configuration_revision,schedule_revision FROM collection_jobs WHERE job_id=$1`, jobID).Scan(&configAfter, &scheduleAfter); err != nil {
		t.Fatal(err)
	}
	if configAfter != configBefore+1 || scheduleAfter != scheduleBefore+1 {
		t.Fatalf("ABA revisions config %d->%d schedule %d->%d", configBefore, configAfter, scheduleBefore, scheduleAfter)
	}
	if err := s.CompleteJob(ctx, job, "owner-a"); err == nil {
		t.Fatal("original completion accepted after configuration ABA")
	}
	if _, err := p.Exec(ctx, `UPDATE collection_jobs SET configuration_revision=0,schedule_revision=0 WHERE job_id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	var configFinal, scheduleFinal int64
	if err := p.QueryRow(ctx, `SELECT configuration_revision,schedule_revision FROM collection_jobs WHERE job_id=$1`, jobID).Scan(&configFinal, &scheduleFinal); err != nil {
		t.Fatal(err)
	}
	if configFinal != configAfter || scheduleFinal != scheduleAfter {
		t.Fatal("direct revision write erased history")
	}
}
