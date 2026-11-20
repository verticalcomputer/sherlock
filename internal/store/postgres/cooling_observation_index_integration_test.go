//go:build integration

package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
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

			// A large unrelated entity in this run must never hide another GPU.
			const unrelatedRows = 257
			addUnrelated := func(prefix string) {
				t.Helper()
				f.exec(t, `INSERT INTO public.observations
					(observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,
					 observed_at,collected_at,source_reference,sample_fingerprint)
					SELECT $2||n,o.run_id,o.cluster_id,o.source_id,o.schema_version,o.kind,'unrelated',o.metric,o.labels,o.value,o.unit,
					 o.observed_at,o.collected_at,o.source_reference,decode(md5($2||n),'hex')
					FROM (SELECT * FROM public.observations WHERE run_id=$1 LIMIT 1) o,
					     generate_series(1,$3::int) n`, result.Task.RunID, prefix, unrelatedRows)
			}
			addUnrelated("before-")
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
				t.Fatalf("expected DDL lock refusal, got %v", err)
			}
			if err := blocker.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			// Isolate the migration's PostgreSQL counters from fixture loads
			// still awaiting a statistics flush on pooled connections.
			migrator, err := pgx.Connect(ctx, f.dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer migrator.Close(ctx)
			upgrade, err := migrator.Begin(ctx)
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
			want := len(result.Observations) + 1 + unrelatedRows
			assertLookup(want)
			addUnrelated("after-")
			want += unrelatedRows
			assertLookup(want)
			f.exec(t, `UPDATE public.observations SET entity_key='changed',observation_id='renamed' WHERE observation_id='alternate'`)
			assertLookup(want)
			f.exec(t, `DELETE FROM public.observations WHERE observation_id='renamed'`)
			assertLookup(want - 1)
			f.exec(t, down)
			var receipts int
			if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM public.prometheus_cooling_upload_receipts`).Scan(&receipts); err != nil || receipts != 2 {
				t.Fatalf("down migration retained %d receipts: %v", receipts, err)
			}
		})
	}
}

func TestCoolingReceiptProofAcrossCutoverSnapshots(t *testing.T) {
	for _, tc := range []struct {
		isolation pgx.TxIsoLevel
		reinstall bool
	}{{pgx.ReadCommitted, false}, {pgx.RepeatableRead, false}, {pgx.Serializable, false}, {pgx.RepeatableRead, true}} {
		isolation := tc.isolation
		name := string(isolation)
		if tc.reinstall {
			name += "_across_down_and_reinstall"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			f := newAssessmentFixtureThrough(t, "000088_production_assessment_fairness.up.sql")
			now := time.Now().UTC()
			_, profile, hash := seedAssessmentUploadProfile(t, f, now)
			slot := now.Truncate(domain.CoolingUploadInterval)
			run := profile.Task(domain.QueryGPUTemperature, slot).RunID
			secondRun := profile.Task(domain.QueryGPUPower, slot).RunID
			secondPayload := strings.Repeat("0", 64)
			const insertRun = `INSERT INTO public.collection_runs
				(run_id,cluster_id,source_id,query_kind,idempotency_key,status,scheduled_for,started_at,completed_at,series_returned,bytes_read,coverage_complete)
				VALUES($1,$2,$3,$6,'prometheus-cooling-report-v2-'||$4,'SUCCEEDED',$5,$5,$5,1,1,true)`
			f.exec(t, insertRun, run, profile.ClusterID, profile.SourceID, hash, slot, domain.QueryGPUTemperature)
			f.exec(t, insertRun, secondRun, profile.ClusterID, profile.SourceID, secondPayload, slot, domain.QueryGPUPower)

			up, err := os.ReadFile("../../../migrations/000090_cooling_receipt_observations.up.sql")
			if err != nil {
				t.Fatal(err)
			}
			if tc.reinstall {
				f.exec(t, string(up)+"INSERT INTO public.schema_migrations(version) VALUES (90)")
			}
			receipt, err := f.admin.BeginTx(ctx, pgx.TxOptions{IsoLevel: isolation})
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackMonitoringTx(receipt)
			var found bool
			// Pin the old transaction snapshot without locking the objects upgraded by 90.
			if err := receipt.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.collection_runs WHERE run_id=$1)`, run).Scan(&found); err != nil || !found {
				t.Fatalf("pre-cutover run visible=%t: %v", found, err)
			}
			const insert = `INSERT INTO public.prometheus_cooling_upload_receipts
				(run_id,profile_id,profile_revision,profile_hash,collector_id,payload_hash) VALUES($1,$2,$3,$4,$5,$6)`
			insertReceipt := func() error {
				_, err := receipt.Exec(ctx, insert, run, profile.ProfileID, profile.Revision, hash, profile.CollectorID, hash)
				return err
			}
			// The reverse race starts a raw writer on the other run before DDL,
			// then commits that row after a fresh, complete empty receipt.
			raw, err := f.admin.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackMonitoringTx(raw)
			if err := raw.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.collection_runs WHERE run_id=$1)`, secondRun).Scan(&found); err != nil || !found {
				t.Fatalf("pre-cutover raw writer sees run=%t: %v", found, err)
			}
			upgrade, err := f.admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackMonitoringTx(upgrade)
			if tc.reinstall {
				down, err := os.ReadFile("../../../migrations/000090_cooling_receipt_observations.down.sql")
				if err != nil {
					t.Fatal(err)
				}
				f.exec(t, string(down)+"DELETE FROM public.schema_migrations WHERE version=90")
			}
			var pending chan error
			if isolation == pgx.ReadCommitted {
				// Hold the catalog cutover open so the actual INSERT statement is
				// already waiting when the last pre-trigger raw observation commits.
				if _, err := upgrade.Exec(ctx, `LOCK TABLE public.prometheus_cooling_upload_receipts IN ACCESS EXCLUSIVE MODE`); err != nil {
					t.Fatal(err)
				}
				pid := receipt.Conn().PgConn().PID()
				pending = make(chan error, 1)
				go func() { pending <- insertReceipt() }()
				for {
					var waiting bool
					err := f.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1
						AND relation='public.prometheus_cooling_upload_receipts'::regclass AND NOT granted)`, pid).Scan(&waiting)
					if err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
			f.exec(t, `INSERT INTO public.observations
				(observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,
				 observed_at,collected_at,source_reference,sample_fingerprint)
				VALUES('pre-cutover-alternate',$1,$2,$3,1,'gpu_temperature','fixture','fixture','[]',1,'celsius',
				$4,$4,'fixture','fixture'::bytea)`, run, profile.ClusterID, profile.SourceID, slot)
			// Match sherlock-migrate's atomic DDL and migration-ledger commit.
			if _, err := upgrade.Exec(ctx, string(up)+"INSERT INTO public.schema_migrations(version) VALUES (90)"); err != nil {
				t.Fatal(err)
			}
			if err := upgrade.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if pending != nil {
				err = <-pending
			} else {
				err = insertReceipt()
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := receipt.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			var proven bool
			var locators int
			err = f.admin.QueryRow(ctx, `SELECT observation_lookup_complete,
				(SELECT count(*) FROM public.prometheus_cooling_receipt_observations WHERE run_id=$1)
				FROM public.prometheus_cooling_upload_receipts WHERE run_id=$1`, run).Scan(&proven, &locators)
			if err != nil || proven != (isolation == pgx.ReadCommitted) || (proven && locators != 1) {
				t.Fatalf("cutover receipt proven=%t locator count=%d: %v", proven, locators, err)
			}
			fresh, err := f.admin.BeginTx(ctx, pgx.TxOptions{IsoLevel: isolation})
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackMonitoringTx(fresh)
			if _, err = fresh.Exec(ctx, insert, secondRun, profile.ProfileID, profile.Revision, hash, profile.CollectorID, secondPayload); err != nil {
				t.Fatal(err)
			}
			if err := fresh.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			_, err = raw.Exec(ctx, `INSERT INTO public.observations
				(observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,
				 observed_at,collected_at,source_reference,sample_fingerprint)
				VALUES('late-alternate',$1,$2,$3,1,'gpu_power','fixture','fixture','[]',1,'watts',
				$4,$4,'fixture','fixture'::bytea)`, secondRun, profile.ClusterID, profile.SourceID, slot)
			if err != nil {
				t.Fatal(err)
			}
			if err := raw.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			err = f.admin.QueryRow(ctx, `SELECT observation_lookup_complete,
				(SELECT count(*) FROM public.prometheus_cooling_receipt_observations WHERE run_id=$1 AND observation_id='late-alternate')
				FROM public.prometheus_cooling_upload_receipts WHERE run_id=$1`, secondRun).Scan(&proven, &locators)
			if err != nil || !proven || locators != 1 {
				t.Fatalf("post-upgrade receipt proven=%t concurrent locators=%d: %v", proven, locators, err)
			}
		})
	}
}

func TestCoolingReceiptMigrationDefersToUpload(t *testing.T) {
	for _, direction := range []string{"up", "down"} {
		t.Run(direction, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			last := "000089_cooling_observation_lookup.up.sql"
			if direction == "down" {
				last = "000090_cooling_receipt_observations.up.sql"
			}
			f := newAssessmentFixtureThrough(t, last)
			now := time.Now().UTC()
			writer, profile, hash := seedAssessmentUploadProfile(t, f, now)
			report := assessmentUploadReport(profile, hash, domain.QueryGPUTemperature, now.Truncate(domain.CoolingUploadInterval))
			// Pause the real writer after its deduplication SELECT and before it
			// takes the observations write lock. It still holds ACCESS SHARE on receipts.
			f.exec(t, `CREATE FUNCTION fixture_pause_upload() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN PERFORM pg_advisory_xact_lock(9021); RETURN NEW; END $$;
				CREATE TRIGGER fixture_pause_upload AFTER INSERT ON public.collection_runs
				FOR EACH ROW EXECUTE FUNCTION fixture_pause_upload()`)
			barrier, err := f.admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackMonitoringTx(barrier)
			if _, err = barrier.Exec(ctx, `SELECT pg_advisory_xact_lock(9021)`); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				ok, err := writer.RecordCoolingUpload(ctx, profile.CollectorID, profile.ClusterID, report)
				if err == nil && !ok {
					err = errors.New("upload was not admitted")
				}
				done <- err
			}()
			for {
				var paused bool
				err := f.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks a
					JOIN pg_locks r ON a.pid=r.pid
					WHERE a.locktype='advisory' AND a.objid=9021 AND NOT a.granted
					AND r.relation='public.prometheus_cooling_upload_receipts'::regclass
					AND r.granted AND r.mode='AccessShareLock')`).Scan(&paused)
				if err != nil {
					t.Fatal(err)
				}
				if paused {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			body, err := os.ReadFile("../../../migrations/000090_cooling_receipt_observations." + direction + ".sql")
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.admin.Exec(ctx, string(body))
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "55P03" || !strings.Contains(pgErr.Message, "could not obtain lock on relation") {
				t.Fatalf("migration must yield immediately to upload's receipt lock: %v", err)
			}
			if err := barrier.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			var samples int
			if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM public.prometheus_cooling_upload_receipts u
				JOIN public.observations o USING(run_id) WHERE u.run_id=$1`, report.Result.Task.RunID).Scan(&samples); err != nil || samples != len(profile.Assets) {
				t.Fatalf("concurrent upload committed %d samples: %v", samples, err)
			}
			f.exec(t, string(body))
		})
	}
}
