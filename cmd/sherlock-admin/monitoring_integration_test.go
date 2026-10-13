//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/monitoring"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// This test only targets the explicitly configured, migrated disposable lane.
// It exercises the actual CLI composition; no operator-store fake is involved.
func TestMonitoringCLIControlCASAndAuditPersistence(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated migrated test database")
	}
	t.Setenv("SHERLOCK_DATABASE_URL", databaseURL)
	t.Setenv("SHERLOCK_BOOTSTRAP_TTL", "30m")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal("create fixture pool")
	}
	defer pool.Close()
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	cluster, source, job, id := "cli-monitor-cluster-"+suffix, "cli-monitor-source-"+suffix, "cli-monitor-job-"+suffix, "cli-monitor-policy-"+suffix
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("synthetic fixture setup: %v", err)
		}
	}
	exec(`INSERT INTO clusters(cluster_id,display_name) VALUES($1,'Synthetic CLI monitoring fixture')`, cluster)
	exec(`INSERT INTO sources(source_id,cluster_id,kind,display_name,availability) VALUES($1,$2,'prometheus','Synthetic monitoring source','UNKNOWN')`, source, cluster)
	exec(`INSERT INTO collection_jobs(job_id,cluster_id,source_id,query_kind,interval_seconds,next_run_at) VALUES($1,$2,$3,'dcgm_gpu_temperature',30,clock_timestamp())`, job, cluster, source)
	exec(`INSERT INTO desired_schedules(cluster_id,source_id,operation,enabled,mode,interval_seconds,timeout_ms,jitter_ms,max_targets,max_bytes,priority,legacy_query_kind,legacy_job_id) VALUES($1,$2,'prometheus.gpu_temperature.v1',true,'legacy',30,5000,0,100,1048576,50,'dcgm_gpu_temperature',$3)`, cluster, source, job)
	policy := monitoring.Policy{ID: id, ClusterID: domain.ClusterID(cluster), SourceID: domain.SourceID(source), EntityKey: "source/" + source, Rule: monitoring.RuleTelemetryLoss, RuleVersion: 1, Binding: monitoring.Binding{Operation: "prometheus.gpu_temperature.v1", Scope: domain.CollectionScope{Nodes: []domain.StableNodeID{}}, ScheduleRevision: 1}, StartupGraceSeconds: 60, FreshForSeconds: 60, ConfirmCount: 1, ConfirmWindowSeconds: 120, ConfirmMinDurationSeconds: 0, RecoverCount: 1, RecoverWindowSeconds: 120, RecoverMinDurationSeconds: 0, MaxSampleGapSeconds: 60, Severity: domain.HealthSeverityCritical}
	path := filepath.Join(t.TempDir(), "synthetic-reviewed-policy.json")
	writePolicy := func() {
		t.Helper()
		body, err := json.Marshal(policy)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writePolicy()
	invoke := func(args []string, want int) []byte {
		t.Helper()
		var stdout, stderr bytes.Buffer
		got := run(append([]string{"monitoring"}, args...), &stdout, &stderr)
		if got != want {
			t.Fatalf("CLI exit=%d want=%d safe stderr=%q", got, want, stderr.String())
		}
		if want != 0 && stdout.Len() != 0 {
			t.Fatal("failed CLI request returned accepted DTO")
		}
		if strings.Contains(stderr.String(), databaseURL) {
			t.Fatal("database URL escaped safe error boundary")
		}
		return stdout.Bytes()
	}
	enroll := func(revision int64, want int) storepg.MonitoringEnrollment {
		t.Helper()
		body := invoke([]string{"enroll", "--policy", path, "--expected-revision", strconv.FormatInt(revision, 10), "--actor", "fixture-local-operator"}, want)
		var out storepg.MonitoringEnrollment
		if want == 0 && json.Unmarshal(body, &out) != nil {
			t.Fatal("invalid enrollment DTO")
		}
		return out
	}
	first := enroll(0, 0)
	if first.Revision != 1 || first.Policy.Revision != 1 || first.Policy.EnrolledAt.IsZero() || !first.Enabled {
		t.Fatal("server-owned enrollment/control stamps missing")
	}
	body := invoke([]string{"status", "--cluster", cluster, "--policy-id", id}, 0)
	var status storepg.MonitoringStatus
	if json.Unmarshal(body, &status) != nil || len(status.Audit) != 1 || status.Audit[0].Actor != "fixture-local-operator" || status.Audit[0].ActorKind != "LOCAL_OPERATOR" {
		t.Fatal("durable local actor audit missing")
	}
	disabledBody := invoke([]string{"disable", "--cluster", cluster, "--policy-id", id, "--expected-revision", "1", "--actor", "fixture-local-operator"}, 0)
	var disabled storepg.MonitoringEnrollment
	if json.Unmarshal(disabledBody, &disabled) != nil || disabled.Enabled || disabled.Revision != 2 {
		t.Fatal("disable did not fence control revision")
	}
	enroll(0, 1) // create-only retry must never silently re-enable.
	enroll(1, 1) // stale control fence must fail.
	resumed := enroll(2, 0)
	if !resumed.Enabled || resumed.Revision != 3 || resumed.Policy.Revision != 1 || !resumed.Policy.EnrolledAt.Equal(first.Policy.EnrolledAt) {
		t.Fatal("identical re-enable changed immutable enrollment")
	}
	policy.FreshForSeconds = 90
	writePolicy()
	enroll(3, 1) // semantic updates require a new ID.
	body = invoke([]string{"status", "--cluster", cluster, "--policy-id", id}, 0)
	if json.Unmarshal(body, &status) != nil || status.Enrollment.Revision != 3 || status.Enrollment.Policy.FreshForSeconds != 60 || len(status.Audit) != 3 {
		t.Fatal("rejected request altered persistent policy/audit")
	}
	invoke([]string{"status", "--cluster", "foreign-cluster", "--policy-id", id}, 1)
}
