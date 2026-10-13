//go:build integration

package postgres_test

import (
	"context"
	"strings"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/monitoring"
)

func TestMonitoringPublicationFailureDoesNotExposePrivateDriverDetail(t *testing.T) {
	f := newMonitoringFixture(t)
	binding := f.schedule(t, domain.QueryGPUTemperature)
	policy := f.policy(t, "redaction", monitoring.RuleTelemetryLoss, "", binding)
	if _, err := f.monitor.Enroll(context.Background(), policy, 0, "fixture-local-operator"); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `CREATE FUNCTION monitor_private_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic-private-credential-do-not-echo'; END $$; CREATE TRIGGER monitor_private_failure BEFORE INSERT ON gp09_alert_outbox FOR EACH ROW EXECUTE FUNCTION monitor_private_failure()`)
	err := f.monitor.Refresh(context.Background())
	if err == nil || strings.Contains(err.Error(), "synthetic-private-credential") || strings.Contains(err.Error(), "SQLSTATE") {
		t.Fatalf("monitoring failure must use closed safe error codes: %v", err)
	}
	status := f.status(t, policy.ID)
	if status.Enrollment.LastFailureCode != "EVALUATION_FAILED" || status.Enrollment.State.Open || len(status.Episodes) != 0 {
		t.Fatalf("failed atomic transition changed episode or hid failure: %+v", status)
	}
	var incidents, intents int
	if err := f.pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM incidents WHERE cluster_id='monitor-cluster'),(SELECT count(*) FROM gp09_alert_outbox WHERE cluster_id='monitor-cluster')`).Scan(&incidents, &intents); err != nil {
		t.Fatal(err)
	}
	if incidents != 0 || intents != 0 {
		t.Fatal("failed publication left an incident or notification intent")
	}
}
