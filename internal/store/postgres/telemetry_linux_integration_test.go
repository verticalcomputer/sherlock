//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

// These values are explicitly synthetic wire fixtures, not host observations.
func residentFixtureFrame(t *testing.T, profile, source, cluster, node, prefix string, at time.Time, sequence uint64) telemetry.SourceFrame {
	t.Helper()
	if profile == telemetry.FixtureProfile {
		f, err := telemetry.NewFixtureFrame(source, cluster, node, prefix, at, sequence)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	f := telemetry.SourceFrame{SourceID: source, SchemaVersion: 1, AdapterVersion: profile, ProfileID: profile, StartedAt: at, CompletedAt: at, Status: "PARTIAL"}
	entity := cluster + "/NODE/" + node + "//"
	defs := telemetry.ProfileFields(profile)
	for i, def := range defs {
		state, reason := "SUPPORTED", "OBSERVED"
		if i == len(defs)-1 {
			state, reason = "UNKNOWN", "MISSING"
		}
		f.Fields = append(f.Fields, telemetry.FieldSupport{EntityKey: entity, Metric: def.Metric, State: state, Reason: reason})
		if state == "UNKNOWN" {
			continue
		}
		v := telemetry.Scalar{Kind: "unsigned", Unsigned: "1152921504606846976"}
		if def.ScalarKind == "float" {
			n := 1.25
			v = telemetry.Scalar{Kind: "float", Float: &n}
		}
		f.Records = append(f.Records, telemetry.Record{ID: prefix + "-" + strconv.Itoa(i), EntityKey: entity, Metric: def.Metric, Unit: def.Unit, Kind: "gauge", Reset: "not_applicable", ObservedAt: at, CollectedAt: at, Value: v})
	}
	f.Coverage = telemetry.Coverage{Expected: int64(len(defs)), Returned: int64(len(f.Records))}
	return f
}

func TestLinuxEnrollmentProfileImmutabilityAndRollbackPreservesData(t *testing.T) {
	f := newTelemetryFixture(t)
	ctx := context.Background()
	if _, err := f.store.RevokeEnrollment(ctx, f.request.ClusterID, f.request.EnrollmentID, 1, "synthetic-linux-operator"); err != nil {
		t.Fatal(err)
	}
	f.request.EnrollmentID += "-linux"
	id := string(f.request.SourceIDs[0])
	f.request.SourceProfiles = map[string]string{id: telemetry.LinuxRootProfile, "foreign-source": telemetry.LinuxHostProfile}
	if _, err := f.store.CreateEnrollment(ctx, f.request, 0, "synthetic-linux-operator"); !errors.Is(err, telemetry.ErrInvalid) {
		t.Fatal("foreign source map", err)
	}
	delete(f.request.SourceProfiles, "foreign-source")
	g, err := f.store.CreateEnrollment(ctx, f.request, 0, "synthetic-linux-operator")
	if err != nil || g.Sources[0].ProfileID != telemetry.LinuxRootProfile {
		t.Fatal("Linux enrollment", err)
	}
	f.open(t, 1)
	batch := f.batch(t, 1, 1)
	receipt := f.accept(t, batch)
	if !receipt.HistoryOnly {
		t.Fatal("unqualified source entered health")
	}
	f.request.SourceProfiles[id] = telemetry.LinuxHostProfile
	if _, err = f.store.CreateEnrollment(ctx, f.request, 0, "synthetic-linux-operator"); !errors.Is(err, telemetry.ErrConflict) {
		t.Fatal("immutable profile changed", err)
	}
	down, err := os.ReadFile(filepath.Join("..", "..", "..", "migrations", "000080_linux_resident_sources.down.sql"))
	if err != nil {
		t.Fatal(err)
	}
	up, err := os.ReadFile(filepath.Join("..", "..", "..", "migrations", "000080_linux_resident_sources.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SAVEPOINT linux_rollback"); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, string(down)); err == nil {
		t.Fatal("populated Linux rollback succeeded")
	}
	if _, err = tx.Exec(ctx, "ROLLBACK TO linux_rollback"); err != nil {
		t.Fatal(err)
	}
	var digest string
	if err = tx.QueryRow(ctx, "SELECT digest FROM gp06f_telemetry_batches WHERE enrollment_id=$1", f.request.EnrollmentID).Scan(&digest); err != nil || digest != batch.Digest {
		t.Fatal("rollback lost signed evidence", err)
	}
	// Both directions are checked only inside this disposable rolled-back tx.
	if _, err = tx.Exec(ctx, "TRUNCATE gp06f_telemetry_enrollments CASCADE"); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, string(down)); err != nil {
		t.Fatal("empty down", err)
	}
	if _, err = tx.Exec(ctx, string(up)); err != nil {
		t.Fatal("empty up", err)
	}
}
