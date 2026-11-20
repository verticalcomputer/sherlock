//go:build integration

package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestProductionAssessmentAuthorityLockAttribution(t *testing.T) {
	f, store, c, _ := productionStoreFixture(t)
	b := c.Assessment.Bindings[0]
	asset := c.Assessment.Assets[0]
	const advisory = `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`
	for _, tc := range []struct {
		stage string
		block string
		args  []any
	}{
		{"profile_family_lock", advisory, []any{"prometheus-cooling-profile-family:" + b.UploadProfileID}},
		{"profile_revision_lock", advisory, []any{fmt.Sprintf("prometheus-cooling-profile:%s:%d", b.UploadProfileID, b.ScheduleRevision)}},
		{"profile", `LOCK TABLE prometheus_cooling_upload_profiles IN ACCESS EXCLUSIVE MODE`, nil},
		{"inventory", `LOCK TABLE goodput_inventory_revisions IN ACCESS EXCLUSIVE MODE`, nil},
		{"inventory_assets", `LOCK TABLE goodput_inventory_revision_entities IN ACCESS EXCLUSIVE MODE`, nil},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			blocker, err := f.admin.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackMonitoringTx(blocker)
			if _, err = blocker.Exec(t.Context(), tc.block, tc.args...); err != nil {
				t.Fatal(err)
			}
			err = store.refreshAsset(t.Context(), asset, false)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "55P03" || errors.Is(err, ErrMonitoringAuthority) || assessmentFailureCode(err) != "STORE_FAILURE" {
				t.Fatalf("lock timeout lost its DB cause: %v", err)
			}
			d := AssessmentDiagnosticFields(err)[1].([]assessmentDiagnostic)[0]
			if d.Stage != "production.input."+tc.stage || d.SQLState != "55P03" || d.ErrorClass != "lock_unavailable" || d.CommitOutcome != "not_attempted" {
				t.Fatalf("incorrect lock diagnostic: %+v", d)
			}
		})
	}
	t.Run("context deadline during authority lookup", func(t *testing.T) {
		blocker, err := f.admin.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackMonitoringTx(blocker)
		if _, err := blocker.Exec(t.Context(), `LOCK TABLE prometheus_cooling_upload_profiles IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		// Start the deadline at the authority read to isolate it from pool checkout
		// and engine restore. The server-side lock timeout must expire later.
		tx, err := f.admin.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackMonitoringTx(tx)
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
		defer cancel()
		_, err = validateAssessmentAuthority(ctx, tx, c.Assessment, asset, b, time.Now().UTC())
		if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrMonitoringAuthority) || assessmentFailureCode(err) != "TIME_BUDGET" {
			t.Fatalf("masked authority query deadline: %v", err)
		}
	})
	for _, tc := range []struct {
		name, stage, invalidate string
	}{
		{"absent profile", "profile", `UPDATE clusters SET removed_at=clock_timestamp() WHERE cluster_id=$1`},
		{"absent inventory asset", "inventory_assets", `DELETE FROM goodput_inventory_revision_entities WHERE cluster_id=$1 AND entity_kind='GPU'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := beginProductionAssessmentTx(t.Context(), f.admin)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackMonitoringTx(tx)
			if _, err := tx.Exec(t.Context(), tc.invalidate, c.Assessment.ClusterID); err != nil {
				t.Fatal(err)
			}
			_, err = loadAssessmentInput(t.Context(), tx, c.Assessment, asset, time.Now().UTC())
			if !errors.Is(err, ErrMonitoringAuthority) || assessmentFailureCode(err) != "AUTHORITY_LOST" {
				t.Fatalf("lost authority accepted or misclassified: %v", err)
			}
			d := AssessmentDiagnosticFields(err)[1].([]assessmentDiagnostic)[0]
			if d.Stage != "production.input."+tc.stage || d.ErrorClass != "authority_lost" || d.SQLState != "" {
				t.Fatalf("incorrect authority diagnostic: %+v", d)
			}
		})
	}
}
