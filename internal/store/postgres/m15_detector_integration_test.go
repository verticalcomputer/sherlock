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

func TestM15DetectorRefusesUnknownAndMakesFairProgress(t *testing.T) {
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	p, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	suffix := fmt.Sprintf("m15-det-%d", time.Now().UnixNano())
	cluster, source := domain.ClusterID("cluster-"+suffix), domain.SourceID("source-"+suffix)
	s, _ := storepg.NewCollectionStore(p)
	r, _ := storepg.NewRemediationStore(p)
	if err = s.EnsureSource(ctx, cluster, "fixture", source, "fixture"); err != nil {
		t.Fatal(err)
	}
	// No collection result is manufactured: unknown source/collector/sample facts
	// must remain unknown, and a poison first job must not starve later decisions.
	for i := 0; i < 3; i++ {
		if err = s.EnsureJob(ctx, fmt.Sprintf("%s-%d", suffix, i), cluster, source, domain.QueryGPUUtilization, fmt.Sprintf("node-%d", i), time.Second, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if err = r.DetectScheduleRepair(ctx, cluster, 1); err != nil {
			t.Fatal(err)
		}
	}
	var decisions, detections int
	if err = p.QueryRow(ctx, `SELECT count(*) FROM schedule_repair_decisions WHERE cluster_id=$1 AND code='SOURCE_UNAVAILABLE'`, cluster).Scan(&decisions); err != nil {
		t.Fatal(err)
	}
	if err = p.QueryRow(ctx, `SELECT count(*) FROM schedule_repair_detections WHERE cluster_id=$1`, cluster).Scan(&detections); err != nil {
		t.Fatal(err)
	}
	if decisions != 3 || detections != 0 {
		t.Fatalf("decisions=%d detections=%d", decisions, detections)
	}
	for _, q := range []string{`DELETE FROM schedule_repair_decisions WHERE cluster_id=$1`, `DELETE FROM collection_jobs WHERE cluster_id=$1`, `DELETE FROM sources WHERE cluster_id=$1`, `DELETE FROM clusters WHERE cluster_id=$1`} {
		if _, err = p.Exec(ctx, q, cluster); err != nil {
			t.Fatal(err)
		}
	}
}
