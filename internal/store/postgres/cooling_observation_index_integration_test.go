//go:build integration

package postgres

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestCoolingReceiptObservationUpgrade(t *testing.T) {
	migration := func(name string) string {
		t.Helper()
		body, err := os.ReadFile("../../../migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up := migration("000090_cooling_receipt_observations.up.sql")
	down := migration("000090_cooling_receipt_observations.down.sql")
	for _, original89 := range []bool{false, true} {
		name := "populated_88"
		if original89 {
			name = "already_applied_89"
		}
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			f := newAssessmentFixtureThrough(t, "000088_production_assessment_fairness.up.sql")
			now := time.Now().UTC()
			writer, profile, hash := seedAssessmentUploadProfile(t, f, now)
			slot := now.Truncate(domain.CoolingUploadInterval)
			report := assessmentUploadReport(profile, hash, domain.QueryGPUTemperature, slot)
			if ok, err := writer.RecordCoolingUpload(ctx, profile.CollectorID, profile.ClusterID, report); !ok || err != nil {
				t.Fatalf("pre-cutover receipt admitted=%t: %v", ok, err)
			}
			// A separate run already has observations but no receipt at cutover.
			result := assessmentUploadReport(profile, hash, domain.QueryGPUPower, slot).Result
			prepareCoolingUploadResult(&result, profile)
			result.Task.IdempotencyKey = "prometheus-cooling-report-v2-" + hash
			tx, err := f.admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackMonitoringTx(tx)
			if ok, err := persistCollectionResultRowsTx(ctx, tx, result, nil, false); !ok || err != nil {
				t.Fatalf("seed receipt-free run inserted=%t: %v", ok, err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}

			if original89 {
				f.exec(t, `CREATE INDEX observations_cooling_run_entity_idx ON public.observations
					(run_id, entity_key) WHERE starts_with(run_id, 'prometheus-cooling-v2-')`)
			} else {
				f.exec(t, migration("000089_cooling_observation_lookup.up.sql"))
			}
			blocker, err := f.admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackMonitoringTx(blocker)
			if _, err = blocker.Exec(ctx, `LOCK TABLE public.observations IN ROW EXCLUSIVE MODE`); err != nil {
				t.Fatal(err)
			}
			_, err = f.admin.Exec(ctx, up)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
				t.Fatalf("expected bounded DDL lock timeout, got %v", err)
			}
			if err := blocker.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			upgrade, err := f.admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackMonitoringTx(upgrade)
			if _, err = upgrade.Exec(ctx, up); err != nil {
				t.Fatal(err)
			}
			var touched, locators int
			var proven, hasIndex bool
			err = upgrade.QueryRow(ctx, `SELECT seq_tup_read+coalesce(idx_tup_fetch,0),
				(SELECT count(*) FROM public.prometheus_cooling_receipt_observations),
				(SELECT observation_lookup_complete FROM public.prometheus_cooling_upload_receipts),
				to_regclass('public.observations_cooling_run_entity_idx') IS NOT NULL
				FROM pg_stat_xact_user_tables WHERE relid='public.observations'::regclass`).Scan(&touched, &locators, &proven, &hasIndex)
			if err != nil || touched != 0 || locators != 0 || proven || hasIndex != original89 {
				t.Fatalf("upgrade raw tuples read=%d locators=%d proven=%t old index=%t: %v", touched, locators, proven, hasIndex, err)
			}
			if err := upgrade.Commit(ctx); err != nil {
				t.Fatal(err)
			}

			// A late raw insert can hold a snapshot predating receipt certification.
			// Its locator commits with the new observation independently of that snapshot.
			late, err := f.admin.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackMonitoringTx(late)
			run := result.Task.RunID
			_, err = late.Exec(ctx, `INSERT INTO public.observations
				(observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,
				 observed_at,collected_at,source_reference,sample_fingerprint)
				SELECT 'alternate',run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,
				 observed_at,collected_at,source_reference,'alternate'::bytea FROM public.observations WHERE run_id=$1 LIMIT 1`, run)
			if err != nil {
				t.Fatal(err)
			}
			f.exec(t, `INSERT INTO public.prometheus_cooling_upload_receipts
				(run_id,profile_id,profile_revision,profile_hash,collector_id,payload_hash)
				VALUES($1,$2,$3,$4,$5,$4)`, run, profile.ProfileID, profile.Revision, hash, profile.CollectorID)
			if err := late.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			assertLookup := func(want int) {
				t.Helper()
				var total, matching int
				err := f.admin.QueryRow(ctx, `SELECT u.observation_lookup_complete, count(l.observation_id), count(o.observation_id)
					FROM public.prometheus_cooling_upload_receipts u
					LEFT JOIN public.prometheus_cooling_receipt_observations l USING(run_id)
					LEFT JOIN public.observations o USING(run_id,entity_key,observation_id)
					WHERE u.run_id=$1 GROUP BY u.observation_lookup_complete`, run).Scan(&proven, &total, &matching)
				if err != nil || !proven || total != want || matching != want {
					t.Fatalf("receipt proven=%t locators=%d actual matches=%d want=%d: %v", proven, total, matching, want, err)
				}
			}
			assertLookup(len(result.Observations) + 1)
			f.exec(t, `UPDATE public.observations SET entity_key='changed',observation_id='renamed' WHERE observation_id='alternate'`)
			assertLookup(len(result.Observations) + 1)
			f.exec(t, `DELETE FROM public.observations WHERE observation_id='renamed'`)
			assertLookup(len(result.Observations))
			f.exec(t, down)
			var receipts int
			if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM public.prometheus_cooling_upload_receipts`).Scan(&receipts); err != nil || receipts != 2 {
				t.Fatalf("down migration retained %d receipts: %v", receipts, err)
			}
		})
	}
}
