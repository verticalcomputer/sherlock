//go:build integration

package postgres_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestRecordCollectorHeartbeatIsAtomicAndPreservesNewerSourceHealth(t *testing.T) {
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
	collections, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	control, err := storepg.NewCollectorControlStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := domain.ClusterID("heartbeat-cluster-" + suffix)
	sourceID := domain.SourceID("heartbeat-source-" + suffix)
	collectorID := domain.CollectorID("heartbeat-collector-" + suffix)
	if err := collections.EnsureSource(ctx, clusterID, "Heartbeat cluster", sourceID, "Heartbeat source"); err != nil {
		t.Fatal(err)
	}
	if err := control.RegisterCollector(ctx, storepg.CollectorRegistration{CollectorID: collectorID, ClusterID: clusterID, DisplayName: "Heartbeat collector", Version: "1.0.0", BuildCommit: "old", ProtocolMin: 1, ProtocolMax: 1, OperatingSystem: "linux", Architecture: "amd64"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	report := collectorcontrol.Heartbeat{
		CollectorID: collectorID, Version: "1.1.0", BuildCommit: "new", ReportedAt: now,
		Capabilities: []collectorcontrol.CapabilityReport{{Name: string(domain.QuerySourceHealth), Version: "v1"}},
		CommandPacks: []collectorcontrol.CommandPackReport{{PackID: "base", Version: "2026.08", DigestSHA256: strings.Repeat("a", 64)}},
		SourceHealth: []collectorcontrol.SourceHealthReport{{SourceID: sourceID, Availability: collectorcontrol.SourceAvailable, SafeMessage: "reachable", CheckedAt: now}},
	}
	if err := control.RecordHeartbeat(ctx, report); err != nil {
		t.Fatal(err)
	}
	var version, capability, packID, availability string
	if err := pool.QueryRow(ctx, `
		SELECT c.version, cap.capability, p.pack_id, h.availability
		FROM collectors c
		JOIN collector_capabilities cap USING (collector_id)
		JOIN collector_command_packs p USING (collector_id)
		JOIN collector_source_health h USING (collector_id)
		WHERE c.collector_id=$1 AND h.source_id=$2`, collectorID, sourceID).Scan(&version, &capability, &packID, &availability); err != nil {
		t.Fatal(err)
	}
	if version != "1.1.0" || capability != string(domain.QuerySourceHealth) || packID != "base" || availability != string(collectorcontrol.SourceAvailable) {
		t.Fatalf("unexpected persisted heartbeat: version=%s capability=%s pack=%s availability=%s", version, capability, packID, availability)
	}
	report.Version = "1.2.0"
	report.SourceHealth[0] = collectorcontrol.SourceHealthReport{SourceID: sourceID, Availability: collectorcontrol.SourceUnavailable, SafeMessage: "stale", CheckedAt: now.Add(-time.Minute)}
	if err := control.RecordHeartbeat(ctx, report); err != nil {
		t.Fatalf("stale source snapshot should be idempotently accepted: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT availability FROM collector_source_health WHERE collector_id=$1 AND source_id=$2`, collectorID, sourceID).Scan(&availability); err != nil {
		t.Fatal(err)
	}
	if availability != string(collectorcontrol.SourceAvailable) {
		t.Fatalf("stale heartbeat overwrote newer source health: %s", availability)
	}
	report.Version = "should-roll-back"
	report.SourceHealth[0].SourceID = domain.SourceID("outside-cluster-" + suffix)
	if err := control.RecordHeartbeat(ctx, report); err == nil {
		t.Fatal("expected out-of-cluster source rejection")
	}
	if err := pool.QueryRow(ctx, `SELECT version FROM collectors WHERE collector_id=$1`, collectorID).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != "1.2.0" {
		t.Fatalf("failed heartbeat was not atomic: version=%s", version)
	}
}
