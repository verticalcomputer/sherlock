//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func productionFleetFixture(t *testing.T, n int) (*assessmentFixture, *ProductionAssessmentStore, a.ProductionConfig, domain.CoolingUploadProfile, string, time.Time) {
	t.Helper()
	f := newAssessmentFixture(t)
	var now time.Time
	if err := f.admin.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	writer, profile, _ := seedAssessmentUploadProfile(t, f, now.UTC())
	profile.Version = 3
	profile.Revision++
	profile.State = "ENABLED"
	profile.EndsAt = time.Time{}
	profile.Assets = nil
	c := f.config
	c.Assets = nil
	c.Implementation = 2
	c.RunDurationSeconds = 0
	c.BudgetsMS = []int64{120000}
	c.Limits.GPUCount = 128
	c.Limits.NodeCount = 16
	nodes := []string{}
	for i := 0; i < n; i++ {
		node := fmt.Sprintf("fixture-comp%03d", i/8)
		gpu := fmt.Sprintf("GPU-00000000-0000-0000-0000-%012d", i)
		if i%8 == 0 {
			nodes = append(nodes, node)
			f.exec(t, `INSERT INTO goodput_inventory_revision_entities(cluster_id,revision_id,entity_kind,stable_node_id)VALUES($1,$2,'NODE',$3)`, c.ClusterID, c.InventoryRevision, node)
		}
		f.exec(t, `INSERT INTO goodput_inventory_revision_entities(cluster_id,revision_id,entity_kind,stable_node_id,physical_gpu_uuid)VALUES($1,$2,'GPU',$3,$4)`, c.ClusterID, c.InventoryRevision, node, gpu)
		c.Assets = append(c.Assets, a.Asset{EntityKey: fmt.Sprintf("%s/GPU/%s/%s/", c.ClusterID, node, gpu), NodeID: node, GPUUUID: gpu})
		profile.Assets = append(profile.Assets, domain.CoolingUploadAsset{NodeID: domain.StableNodeID(node), GPUUUID: domain.PhysicalGPUUUID(gpu)})
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	hash := domain.ChecksumSHA256(raw).String()
	if err = writer.RegisterCoolingUploadProfile(t.Context(), profile, hash); err != nil {
		t.Fatal(err)
	}
	for i := range c.Bindings {
		c.Bindings[i].ScheduleRevision = profile.Revision
		c.Bindings[i].UploadProfileHash = hash
		c.Bindings[i].ScopeNodes = nodes
	}
	registry, err := a.NewRegistry(cooling.Category{}, cooling.ProductionCategory{})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := a.NormalizeProductionConfig(t.Context(), a.ProductionConfig{Schema: 1, Revision: 1, Assessment: c}, registry)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewProductionAssessmentStore(t.Context(), f.admin, registry, cfg)
	if err != nil {
		t.Fatal(err)
	}
	startup, stop := context.WithTimeout(t.Context(), 5*time.Second)
	began := time.Now()
	err = store.Start(startup)
	stop()
	if err != nil {
		t.Fatalf("fleet admission %d GPUs: %v", n, err)
	}
	t.Logf("%d-GPU production startup: %s", n, time.Since(began))
	return f, store, cfg, profile, hash, now.UTC()
}

func seedFleetSnapshots(t *testing.T, f *assessmentFixture, s *ProductionAssessmentStore, c a.ProductionConfig, entry time.Time, final bool) {
	t.Helper()
	f.exec(t, `UPDATE production_assessment_enrollments SET created_at=$2 WHERE enrollment_id=$1`, c.Assessment.RunID, entry)
	through := 30
	if final {
		through = 150
	}
	for _, asset := range c.Assessment.Assets {
		one := c
		one.Assessment.Assets = []a.Asset{asset}
		e, err := a.NewProductionAssetEngine(t.Context(), c, entry, s.registry, asset.EntityKey)
		if err != nil {
			t.Fatal(err)
		}
		for sec := 0; sec <= through; sec += 15 {
			at := entry.Add(time.Duration(sec) * time.Second)
			if err = e.Advance(t.Context(), at, at, at, productionStoreSamples(t, one, at), nil); err != nil {
				t.Fatal(err)
			}
		}
		if len(e.Candidates) != 1 {
			t.Fatalf("fleet snapshot expected candidate: %+v", e.Failures)
		}
		snapshot, err := e.SnapshotProduction(asset.EntityKey, entry.Add(time.Duration(through)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		var due *time.Time
		if !final {
			due = &e.Candidates[0].DueAt
		}
		f.exec(t, `UPDATE production_assessment_states SET snapshot=$3,next_due_at=$4 WHERE enrollment_id=$1 AND asset=$2`, c.Assessment.RunID, asset.EntityKey, snapshot, due)
	}
}

func TestProductionFleetFairPartialRefreshAndRestart(t *testing.T) {
	f, s, c, _, _, now := productionFleetFixture(t, 128)
	seedFleetSnapshots(t, f, s, c, now.Add(-5*time.Minute), false)
	// A malformed oldest due asset must not repeatedly consume the head of both
	// lanes. Other assets remain valid and retain their original due timestamps.
	broken := c.Assessment.Assets[0].EntityKey
	f.exec(t, `UPDATE production_assessment_states SET snapshot=convert_to('{}','UTF8') WHERE asset=$1`, broken)
	// Each real snapshot commit takes 80ms in this disposable fixture, forcing
	// partial 2s slices without approaching the unchanged 250ms GPU deadline.
	f.exec(t, `CREATE FUNCTION fleet_slow_commit()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.snapshot IS DISTINCT FROM OLD.snapshot THEN PERFORM pg_sleep(0.08); END IF; RETURN NEW;END$$; CREATE TRIGGER fleet_slow_commit BEFORE UPDATE ON production_assessment_states FOR EACH ROW EXECUTE FUNCTION fleet_slow_commit()`)
	began := time.Now()
	_ = s.Refresh(t.Context())
	if time.Since(began) > a.ShadowRefreshBudget+300*time.Millisecond {
		t.Fatal("unbounded fleet refresh")
	}
	var dueDone, acquired, unattemptedFailures int
	if err := f.admin.QueryRow(t.Context(), `SELECT count(*) FILTER(WHERE last_due_attempt_at IS NOT NULL),count(*) FILTER(WHERE last_acquire_attempt_at IS NOT NULL),count(*) FILTER(WHERE last_due_attempt_at IS NULL AND last_acquire_attempt_at IS NULL AND failure_count<>0) FROM production_assessment_states`).Scan(&dueDone, &acquired, &unattemptedFailures); err != nil {
		t.Fatal(err)
	}
	if dueDone == 0 || acquired == 0 || dueDone == 128 || acquired == 128 || unattemptedFailures != 0 {
		t.Fatalf("partial lane progress due%d acquired%d unattemptedfailures%d", dueDone, acquired, unattemptedFailures)
	}
	// A fresh store has no memory cursor; progress survives restart exclusively
	// through durable per-lane timestamps.
	restarted, err := NewProductionAssessmentStore(t.Context(), f.admin, s.registry, c)
	if err != nil {
		t.Fatal(err)
	}
	due, acq, err := restarted.refreshQueues(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if due[0].dueAttempt != nil || acq[0].acquireAttempt != nil {
		t.Fatal("restart forgot untouched fleet work")
	}
	f.exec(t, `DROP TRIGGER fleet_slow_commit ON production_assessment_states;DROP FUNCTION fleet_slow_commit()`)
	for pass := 0; pass < 64; pass++ {
		_ = restarted.Refresh(t.Context())
		if err = f.admin.QueryRow(t.Context(), `SELECT count(*) FROM production_assessment_states WHERE (next_due_at IS NOT NULL AND last_due_attempt_at IS NULL) OR last_acquire_attempt_at IS NULL`).Scan(&unattemptedFailures); err != nil {
			t.Fatal(err)
		}
		if unattemptedFailures == 0 {
			break
		}
	}
	if unattemptedFailures != 0 {
		t.Fatalf("starved %d fleet assets", unattemptedFailures)
	}
	var deadlines int
	if err = f.admin.QueryRow(t.Context(), `SELECT count(*) FROM production_assessment_states WHERE next_due_at IS NOT NULL AND asset<>$1`, broken).Scan(&deadlines); err != nil || deadlines != 0 {
		t.Fatalf("due backlog did not terminate: %d %v", deadlines, err)
	}
	var preservedDeadlines int
	if err = f.admin.QueryRow(t.Context(), `SELECT count(*) FROM production_assessment_decisions WHERE kind='TERMINAL' AND logical_at<=$1 AND (convert_from(evidence,'UTF8')::jsonb#>>'{decision,lateness_us}')::bigint>0`, now.Add(-3*time.Minute+30*time.Second)).Scan(&preservedDeadlines); err != nil || preservedDeadlines != 127 {
		t.Fatalf("deadline reset or missing observed lateness: %d %v", preservedDeadlines, err)
	}
	var untouchedBefore, untouchedAfter int
	if err = f.admin.QueryRow(t.Context(), `SELECT sum(failure_count) FROM production_assessment_states`).Scan(&untouchedBefore); err != nil {
		t.Fatal(err)
	}
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if err = restarted.Refresh(canceled); err == nil {
		t.Fatal("cancellation ignored")
	}
	if err = f.admin.QueryRow(t.Context(), `SELECT sum(failure_count) FROM production_assessment_states`).Scan(&untouchedAfter); err != nil || untouchedAfter != untouchedBefore {
		t.Fatal("canceled refresh charged unattempted GPUs")
	}
}

func TestProductionFleetScopeCannotChangeOnRestart(t *testing.T) {
	f, s, c, _, _, _ := productionFleetFixture(t, 112)
	changed := c
	changed.Assessment.Assets = changed.Assessment.Assets[:111]
	other, err := NewProductionAssessmentStore(t.Context(), f.admin, s.registry, changed)
	if err != nil {
		t.Fatal(err)
	}
	if err = other.Start(t.Context()); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("fleet shrink silently changed authority: %v", err)
	}
}

func TestProductionFleetStatusAndDowngradeGuard(t *testing.T) {
	f, _, c, _, _, _ := productionFleetFixture(t, 128)
	status, err := ReadProductionAssessmentStatus(t.Context(), f.admin, c.Assessment.ClusterID, c.Assessment.RunID)
	if err != nil || len(status.Assets) != 128 {
		t.Fatalf("fleet status truncated: %d %v", len(status.Assets), err)
	}
	body, err := os.ReadFile("../../../migrations/000088_production_assessment_fairness.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.admin.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), string(body)); err == nil {
		t.Fatal("fleet fairness downgrade allowed")
	}
	_ = tx.Rollback(t.Context())
	var columns int
	if err = f.admin.QueryRow(t.Context(), `SELECT count(*) FROM information_schema.columns WHERE table_name='production_assessment_states' AND column_name IN ('last_due_attempt_at','last_acquire_attempt_at')`).Scan(&columns); err != nil || columns != 2 {
		t.Fatalf("refused downgrade changed schema %d %v", columns, err)
	}
	// Empty unused fixture enrollment can be deliberately removed; no history is
	// dropped by the migration to make rollback succeed.
	f.exec(t, `DELETE FROM production_assessment_states;DELETE FROM production_assessment_controls;DELETE FROM production_assessment_enrollments`)
	tx, err = f.admin.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), string(body)); err != nil {
		t.Fatal("empty downgrade rejected", err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// Query-local de-duplication must preserve whole-document validation, conflicting
// duplicate fields and each receipt's task timing even when JSON bodies repeat.
func TestProductionFleetReceiptDocumentDeduplication(t *testing.T) {
	f, s, c, profile, hash, now := productionFleetFixture(t, 128)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles DISABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	f.exec(t, `UPDATE prometheus_cooling_upload_profiles SET registered_at=starts_at-interval '1 second' WHERE profile_id=$1 AND revision=$2`, profile.ProfileID, profile.Revision)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles ENABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	writer, _ := NewCollectionStore(f.admin)
	query := domain.CoolingUploadQueries()[0]
	ids := []string{}
	for i := 0; i < 7; i++ {
		slot := now.Truncate(15 * time.Second).Add(time.Duration(i-6) * 15 * time.Second)
		report := assessmentUploadReport(profile, hash, query, slot)
		report.Version = 3
		if _, err := writer.RecordCoolingUpload(t.Context(), profile.CollectorID, profile.ClusterID, report); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, string(profile.Task(query, slot).RunID))
	}
	asset := c.Assessment.Assets[0]
	var binding a.Binding
	field, _ := domain.CoolingUploadField(query)
	for _, b := range c.Assessment.Bindings {
		if b.Metric == field.Name {
			binding = b
		}
	}
	if binding.Metric == "" {
		t.Fatal("fixture query binding missing")
	}
	conflict := domain.DCGMFieldEvidence{NodeID: domain.StableNodeID(asset.NodeID), GPU: domain.PhysicalGPUUUID(asset.GPUUUID), Metric: binding.Metric, State: "UNSUPPORTED", Reason: "fixture conflict"}
	raw, _ := json.Marshal([]domain.DCGMFieldEvidence{conflict})
	for _, id := range ids[2:4] {
		f.exec(t, `UPDATE collection_runs SET metric_fields=metric_fields||$2::jsonb WHERE run_id=$1`, id, raw)
	}
	f.exec(t, `UPDATE collection_runs SET metric_fields=metric_fields||'[{"node_id":7}]'::jsonb WHERE run_id=$1`, ids[4])
	f.exec(t, `UPDATE collection_runs SET metric_fields=metric_fields||jsonb_build_array(jsonb_build_object('reason',repeat('x',70000))) WHERE run_id=$1`, ids[5])
	// This newest row owns the shared healthy-document ordinal; its timing is
	// invalid, but it must not hide the usable older receipts sharing the body.
	f.exec(t, `UPDATE collection_runs SET scheduled_for=scheduled_for+interval '1 second' WHERE run_id=$1`, ids[6])
	var at time.Time
	if err := f.admin.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	tx, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	attempts, selected, truncated, err := loadProductionUploadAttempts(t.Context(), tx, c.Assessment, asset, binding, query, at.Add(-15*time.Minute), at)
	if err != nil || truncated || len(selected) != 6 {
		t.Fatalf("receipt selection: count%d truncated%t %v", len(selected), truncated, err)
	}
	for i, id := range ids[:6] {
		if attempts[id].usable != (i < 2) {
			t.Fatalf("receipt%d usable%t", i, attempts[id].usable)
		}
	}
	if _, ok := attempts[ids[6]]; ok {
		t.Fatal("invalid task admitted through shared metadata")
	}
}

func TestProductionFleetReceiptProfileRevisionsRemainScoped(t *testing.T) {
	f, s, c, profile, hash, now := productionFleetFixture(t, 128)
	writer, _ := NewCollectionStore(f.admin)
	query := domain.CoolingUploadQueries()[0]
	expected := map[string]int64{}
	for generation := 0; generation < 3; generation++ {
		if generation > 0 {
			profile.Revision++
			if generation == 2 {
				profile.Assets = profile.Assets[1:]
			}
			raw, _ := json.Marshal(profile)
			hash = domain.ChecksumSHA256(raw).String()
			if err := writer.RegisterCoolingUploadProfile(t.Context(), profile, hash); err != nil {
				t.Fatal(err)
			}
		}
		f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles DISABLE TRIGGER prometheus_cooling_upload_profile_guard`)
		f.exec(t, `UPDATE prometheus_cooling_upload_profiles SET registered_at=starts_at-interval '1 second' WHERE profile_id=$1 AND revision=$2`, profile.ProfileID, profile.Revision)
		f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles ENABLE TRIGGER prometheus_cooling_upload_profile_guard`)
		for i := 0; i < 2; i++ {
			slot := now.Truncate(15 * time.Second).Add(time.Duration(generation*2+i-6) * 15 * time.Second)
			report := assessmentUploadReport(profile, hash, query, slot)
			report.Version = 3
			if _, err := writer.RecordCoolingUpload(t.Context(), profile.CollectorID, profile.ClusterID, report); err != nil {
				t.Fatal(err)
			}
			if generation < 2 {
				expected[string(profile.Task(query, slot).RunID)] = profile.Revision
			}
		}
	}
	field, _ := domain.CoolingUploadField(query)
	var binding a.Binding
	for _, b := range c.Assessment.Bindings {
		if b.Metric == field.Name {
			binding = b
		}
	}
	var at time.Time
	if err := f.admin.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	tx, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	attempts, ids, truncated, err := loadProductionUploadAttempts(t.Context(), tx, c.Assessment, c.Assessment.Assets[0], binding, query, at.Add(-15*time.Minute), at)
	if err != nil || truncated || len(ids) != len(expected) {
		t.Fatalf("mixed-profile selection %d %v %v", len(ids), truncated, err)
	}
	for id, revision := range expected {
		got, ok := attempts[id]
		if !ok || !got.usable || got.provenance.ScheduleRevision != revision {
			t.Fatalf("profile-specific proof lost: revision%d %+v", revision, got)
		}
	}
}

// The receipt directory must agree with the legacy selector plus its
// existing upload validation, including malformed and mismatched identities.
func TestProductionFleetSampleSelectionPreservesValidation(t *testing.T) {
	f, s, c, profile, hash, now := productionFleetFixture(t, 8)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles DISABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	f.exec(t, `UPDATE prometheus_cooling_upload_profiles SET registered_at=starts_at-interval '1 second' WHERE profile_id=$1 AND revision=$2`, profile.ProfileID, profile.Revision)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles ENABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	writer, _ := NewCollectionStore(f.admin)
	query := domain.CoolingUploadQueries()[0]
	slot := now.Truncate(domain.CoolingUploadInterval)
	report := assessmentUploadReport(profile, hash, query, slot)
	report.Version = 3
	if _, err := writer.RecordCoolingUpload(t.Context(), profile.CollectorID, profile.ClusterID, report); err != nil {
		t.Fatal(err)
	}
	var at time.Time
	if err := f.admin.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	asset := c.Assessment.Assets[0]
	field, _ := domain.CoolingUploadField(query)
	var binding a.Binding
	for _, b := range c.Assessment.Bindings {
		if b.Metric == field.Name {
			binding = b
		}
	}
	for _, tc := range []struct {
		name, change  string
		extraRows     int
		badExtraLabel bool
		want          int
		wantTruncated bool
	}{
		{name: "canonical", want: 1},
		{name: "wrong canonical entity with matching UUID labels", change: `entity_key=entity_key||'other'`},
		{name: "legacy entity with matching UUID labels", change: `entity_key='node/fixture-comp000/gpu/GPU-00000000-0000-0000-0000-000000000000'`},
		{name: "malformed labels", change: `labels='[{"name":7}]'::jsonb`, wantTruncated: true},
		{name: "wrong source contract", change: `source_reference='other'`},
		{name: "future source sample", change: `observed_at=observed_at+interval '1 second'`},
		{name: "expired source slot", change: `observed_at=observed_at-interval '15 seconds'`},
		{name: "wrong unit", change: `unit='watts'`},
		{name: "absent metric", change: `metric='other'`},
		{name: "alternate sample ID only", change: `metric='other'`, extraRows: 1, want: 1},
		{name: "extra sample ID", extraRows: 1, want: 2},
		{name: "malformed extra row", extraRows: 1, badExtraLabel: true, want: 1, wantTruncated: true},
		{name: "row limit", extraRows: 255, want: 256},
		{name: "row limit sentinel", extraRows: 256, want: 256, wantTruncated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := s.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context())
			if tc.extraRows > 0 {
				_, err = tx.Exec(t.Context(), `INSERT INTO observations
 (observation_id,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,labels,value,unit,
  observed_at,collected_at,source_reference,sample_fingerprint,metric_semantics)
 SELECT 'alternate-'||n,run_id,cluster_id,source_id,schema_version,kind,entity_key,metric,
  CASE WHEN $3 THEN '[{"name":7}]'::jsonb ELSE labels END,value,unit,observed_at,collected_at,source_reference,
  int4send(n),metric_semantics
 FROM observations CROSS JOIN generate_series(1,$2::int) n WHERE entity_key=$1`, asset.EntityKey, tc.extraRows, tc.badExtraLabel)
				if err != nil {
					t.Fatal(err)
				}
			}
			if tc.change != "" {
				if _, err := tx.Exec(t.Context(), `UPDATE observations SET `+tc.change+` WHERE entity_key=$1 AND observation_id LIKE 'prom-cooling-sample-%'`, asset.EntityKey); err != nil {
					t.Fatal(err)
				}
			}
			attempts, ids, truncated, err := loadProductionUploadAttempts(t.Context(), tx, c.Assessment, asset, binding, query, at.Add(-15*time.Minute), at)
			if err != nil || truncated || len(ids) != 1 {
				t.Fatalf("attempts %d truncated%t: %v", len(ids), truncated, err)
			}
			got, truncated, err := loadAssessmentSamples(t.Context(), tx, c.Assessment, asset, binding, query, at.Add(-15*time.Minute), at, attempts, ids, nil)
			if err != nil || truncated != tc.wantTruncated || len(got) != tc.want {
				t.Fatalf("production samples %d truncated%t: %v", len(got), truncated, err)
			}
			legacy, truncated, err := loadAssessmentSamples(t.Context(), tx, f.config, asset, binding, query, at.Add(-15*time.Minute), at, attempts, ids, nil)
			if err != nil || truncated != tc.wantTruncated || !reflect.DeepEqual(got, legacy) {
				t.Fatalf("selector validation differs: production%v legacy%v truncated%t: %v", got, legacy, truncated, err)
			}
		})
	}
}

func TestProductionReceiptLookupEmptyAndPartial(t *testing.T) {
	f, _, c, profile, hash, now := productionFleetFixture(t, 2)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles DISABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	f.exec(t, `UPDATE prometheus_cooling_upload_profiles SET registered_at=starts_at-interval '1 second' WHERE profile_id=$1 AND revision=$2`, profile.ProfileID, profile.Revision)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles ENABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	writer, err := NewCollectionStore(f.admin)
	if err != nil {
		t.Fatal(err)
	}
	slot := now.Truncate(domain.CoolingUploadInterval)
	for _, query := range domain.CoolingUploadQueries() {
		report := assessmentUploadReport(profile, hash, query, slot)
		report.Version = domain.CoolingUploadProductionVersion
		if query == domain.QueryGPUTemperature {
			report.Result.Status = domain.ResultPartial
			report.Result.Observations = report.Result.Observations[:1]
			report.Result.Coverage = domain.Coverage{SeriesReturned: 1}
			report.Result.Failures = []domain.CollectionFailure{{Code: domain.FailurePartialData, Message: "missing one sample"}}
		} else {
			report.Result.Status = domain.ResultFailed
			report.Result.Observations = nil
			report.Result.Coverage = domain.Coverage{}
			report.Result.Failures = []domain.CollectionFailure{{Code: domain.FailureSourceUnavailable, Message: "source unavailable"}}
		}
		if accepted, err := writer.RecordCoolingUpload(t.Context(), profile.CollectorID, profile.ClusterID, report); err != nil || !accepted {
			t.Fatalf("receipt accepted=%t: %v", accepted, err)
		}
	}
	tx, err := beginProductionAssessmentTx(t.Context(), f.admin)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	if err = tx.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	for _, asset := range c.Assessment.Assets {
		facts, err := loadAssessmentInput(t.Context(), tx, c.Assessment, asset, now)
		if err != nil || len(facts) != len(c.Assessment.Bindings) {
			t.Fatalf("per-attempt coverage: %d facts, %v", len(facts), err)
		}
		records := map[string]bool{}
		for _, fact := range facts {
			var coverage a.Coverage
			if fact.Kind != "COVERAGE" || json.Unmarshal(fact.Body, &coverage) != nil || coverage.Code != "UNSUPPORTED" {
				t.Fatalf("partial or failed receipt produced unexpected fact: %+v", fact)
			}
			records[coverage.SourceRecord] = true
		}
		for _, query := range domain.CoolingUploadQueries() {
			if !records[string(profile.Task(query, slot).RunID)] {
				t.Fatalf("missing coverage for %s", query)
			}
		}
	}
}

func TestProductionReceiptLookupCutoverPreservesPendingProof(t *testing.T) {
	f, store, c, profile, hash, now := productionFleetFixture(t, 1)
	asset := c.Assessment.Assets[0]
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles DISABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	f.exec(t, `UPDATE prometheus_cooling_upload_profiles SET registered_at=starts_at-interval '1 second' WHERE profile_id=$1 AND revision=$2`, profile.ProfileID, profile.Revision)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_profiles ENABLE TRIGGER prometheus_cooling_upload_profile_guard`)
	writer, err := NewCollectionStore(f.admin)
	if err != nil {
		t.Fatal(err)
	}
	slot := now.Truncate(domain.CoolingUploadInterval)
	upload := func(query domain.QueryKind, at time.Time) {
		t.Helper()
		report := assessmentUploadReport(profile, hash, query, at)
		report.Version = domain.CoolingUploadProductionVersion
		if accepted, err := writer.RecordCoolingUpload(t.Context(), profile.CollectorID, profile.ClusterID, report); err != nil || !accepted {
			t.Fatalf("receipt accepted=%t: %v", accepted, err)
		}
	}
	// Admit the first report against the previous schema and then run the
	// actual forward migration before admitting another report.
	migrate := func(direction string) {
		t.Helper()
		sql, err := os.ReadFile("../../../migrations/000090_cooling_receipt_observations." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		f.exec(t, string(sql))
	}
	migrate("down")
	oldSlot := slot.Add(-domain.CoolingUploadInterval)
	upload(domain.QueryGPUPower, oldSlot)
	legacy := string(profile.Task(domain.QueryGPUPower, oldSlot).RunID)
	migrate("up")
	upload(domain.QueryGPUTemperature, slot)

	occurrence, due := seedProductionDue(t, f, store, c, now)
	var original []byte
	if err = f.admin.QueryRow(t.Context(), `SELECT snapshot FROM production_assessment_states WHERE asset=$1`, asset.EntityKey).Scan(&original); err != nil {
		t.Fatal(err)
	}
	err = store.refreshAsset(t.Context(), asset, false)
	if !errors.Is(err, errReceiptLookupIncomplete) {
		t.Fatalf("mixed cutover window admitted: %v", err)
	}
	diagnostic := AssessmentDiagnosticFields(err)[1].([]assessmentDiagnostic)[0]
	if assessmentFailureCode(err) != "RECEIPT_LOOKUP_INCOMPLETE" || diagnostic.Stage != "production.input.receipts" || diagnostic.ErrorClass != "receipt_lookup_incomplete" {
		t.Fatalf("cutover diagnostic: %+v %s", diagnostic, assessmentFailureCode(err))
	}
	var intact bool
	if err = f.admin.QueryRow(t.Context(), `SELECT snapshot=$2 AND next_due_at=$3 AND NOT EXISTS(SELECT 1 FROM production_assessment_decisions) FROM production_assessment_states WHERE asset=$1`, asset.EntityKey, original, due).Scan(&intact); err != nil || !intact {
		t.Fatalf("failed acquisition changed proof or decided from missing input: %v", err)
	}
	// Refresh runs the deadline lane first. Its stored proof must produce a
	// single decision at the original deadline even while acquisition fails.
	if err = store.Refresh(t.Context()); !errors.Is(err, errReceiptLookupIncomplete) {
		t.Fatalf("cutover refresh: %v", err)
	}
	var count int
	if err = f.admin.QueryRow(t.Context(), `SELECT count(*) FROM production_assessment_decisions WHERE occurrence_id=$1 AND logical_at=$2 AND kind='TERMINAL'`, occurrence, due).Scan(&count); err != nil || count != 1 {
		t.Fatalf("retained deadline count=%d: %v", count, err)
	}

	// Advance only the fixture's old receipt past the receipt-time cutoff to
	// exercise the next acquisition without waiting for the window to expire.
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_receipts DISABLE TRIGGER USER`)
	f.exec(t, `UPDATE prometheus_cooling_upload_receipts SET received_at=received_at-interval '16 minutes' WHERE run_id=$1`, legacy)
	f.exec(t, `ALTER TABLE prometheus_cooling_upload_receipts ENABLE TRIGGER USER`)
	if err = store.refreshAsset(t.Context(), asset, false); err != nil {
		t.Fatalf("new receipt acquisition: %v", err)
	}
	if err = f.admin.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM production_assessment_states s, jsonb_array_elements(convert_from(s.snapshot,'UTF8')::jsonb->'facts') fact WHERE s.asset=$1 AND fact#>>'{body,provenance,collection_run_id}'=$2)`, asset.EntityKey, string(profile.Task(domain.QueryGPUTemperature, slot).RunID)).Scan(&intact); err != nil || !intact {
		t.Fatalf("fresh receipt missing after cutover: %v", err)
	}
}
