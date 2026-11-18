//go:build integration

package postgres

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func seedAssessmentUploadProfile(t *testing.T, f *assessmentFixture, now time.Time) (*CollectionStore, domain.CoolingUploadProfile, string) {
	t.Helper()
	cfg := &f.config
	cfg.Assets = nil
	cfg.Limits.GPUCount, cfg.Limits.NodeCount = 8, 2
	lastSlot := now.Truncate(domain.CoolingUploadInterval)
	profile := domain.CoolingUploadProfile{Version: domain.CoolingUploadVersion, ProfileID: "assessment-upload-profile", Revision: 9, CollectorID: "assessment-upload-collector",
		ClusterID: domain.ClusterID(cfg.ClusterID), SourceID: domain.SourceID(cfg.SourceID), InventoryRevision: cfg.InventoryRevision,
		StartsAt: lastSlot.Add(-16 * time.Minute), EndsAt: lastSlot.Add(2 * time.Minute)}
	old := now.Add(-time.Hour)
	f.exec(t, `INSERT INTO clusters(cluster_id,display_name) VALUES($1,'Assessment upload fixture')`, cfg.ClusterID)
	f.exec(t, `INSERT INTO sources(source_id,cluster_id,kind,display_name,availability) VALUES($1,$2,'prometheus','Assessment upload fixture','UNKNOWN')`, cfg.SourceID, cfg.ClusterID)
	f.exec(t, `INSERT INTO collectors(collector_id,cluster_id,display_name,status,version,build_commit,protocol_min,protocol_max,operating_system,architecture) VALUES($1,$2,'fixture','ACTIVE','fixture','fixture',1,2,'linux','amd64')`, profile.CollectorID, cfg.ClusterID)
	f.exec(t, `INSERT INTO goodput_inventory_revisions(revision_id,cluster_id,source_id,inventory_class,schema_version,content_digest,source_at,effective_at,observed_at) VALUES($1,$2,$3,'EXPECTED',1,decode(repeat('ab',32),'hex'),$4,$4,$4)`, cfg.InventoryRevision, cfg.ClusterID, cfg.SourceID, old)
	f.exec(t, `INSERT INTO goodput_inventory_revision_validity(cluster_id,revision_id,valid_from) VALUES($1,$2,$3)`, cfg.ClusterID, cfg.InventoryRevision, old)
	nodes := []string{"node-1", "node-2"}
	for nodeIndex, node := range nodes {
		f.exec(t, `INSERT INTO goodput_inventory_revision_entities(cluster_id,revision_id,entity_kind,stable_node_id) VALUES($1,$2,'NODE',$3)`, cfg.ClusterID, cfg.InventoryRevision, node)
		for i := range 4 {
			gpu := fmt.Sprintf("GPU-%012d", nodeIndex*4+i+1)
			identity := domain.EntityIdentity{ClusterID: profile.ClusterID, Kind: domain.EntityGPU, NodeID: domain.StableNodeID(node), PhysicalGPUUUID: domain.PhysicalGPUUUID(gpu)}
			profile.Assets = append(profile.Assets, domain.CoolingUploadAsset{NodeID: identity.NodeID, GPUUUID: identity.PhysicalGPUUUID})
			cfg.Assets = append(cfg.Assets, a.Asset{EntityKey: identity.Key(), NodeID: node, GPUUUID: gpu})
			f.exec(t, `INSERT INTO goodput_inventory_revision_entities(cluster_id,revision_id,entity_kind,stable_node_id,physical_gpu_uuid) VALUES($1,$2,'GPU',$3,$4)`, cfg.ClusterID, cfg.InventoryRevision, node, gpu)
		}
	}
	body, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	hash := domain.ChecksumSHA256(body).String()
	for i := range cfg.Bindings {
		b := &cfg.Bindings[i]
		b.UploadProfileID, b.UploadProfileHash = profile.ProfileID, hash
		b.UploadCollectorID = string(profile.CollectorID)
		b.ScheduleRevision, b.ScopeNodes = profile.Revision, nodes
	}
	ctx := t.Context()
	writer, err := NewCollectionStore(f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.RegisterCoolingUploadProfile(ctx, profile, hash); err != nil {
		t.Fatal(err)
	}
	// Seed the original enrollment time for this disposable history fixture.
	// Keep the guard active for ingestion, cutoff and revocation assertions.
	tx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackMonitoringTx(tx)
	if _, err = tx.Exec(ctx, `ALTER TABLE public.prometheus_cooling_upload_profiles DISABLE TRIGGER prometheus_cooling_upload_profile_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE public.prometheus_cooling_upload_profiles SET registered_at=$1 WHERE profile_id=$2 AND revision=$3`, profile.StartsAt.Add(-time.Second), profile.ProfileID, profile.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `ALTER TABLE public.prometheus_cooling_upload_profiles ENABLE TRIGGER prometheus_cooling_upload_profile_guard`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return writer, profile, hash
}

func assessmentUploadReport(profile domain.CoolingUploadProfile, hash string, query domain.QueryKind, slot time.Time) domain.CoolingUploadReport {
	task := profile.Task(query, slot)
	field, _ := domain.CoolingUploadField(query)
	value := float64(75)
	if query == domain.QueryGPUPower {
		value = 200
	}
	result := domain.CollectionResult{Task: task, StartedAt: slot, CompletedAt: slot, Status: domain.ResultSucceeded,
		Coverage: domain.Coverage{Complete: true, SeriesReturned: len(profile.Assets)}}
	for i, asset := range profile.Assets {
		identity := domain.EntityIdentity{ClusterID: profile.ClusterID, Kind: domain.EntityGPU, NodeID: asset.NodeID, PhysicalGPUUUID: asset.GPUUUID}
		result.Observations = append(result.Observations, domain.Observation{ID: domain.ObservationID(fmt.Sprintf("fixture-gpu-%d", i)), ClusterID: profile.ClusterID,
			SourceID: profile.SourceID, SchemaVersion: 1, Kind: strings.TrimPrefix(string(query), "dcgm_"), EntityKey: identity.Key(), Metric: field.Name,
			Labels: []domain.Label{{Name: "Hostname", Value: string(asset.NodeID)}, {Name: "UUID", Value: string(asset.GPUUUID)}}, Value: value, Unit: field.Unit,
			ObservedAt: slot, CollectedAt: slot, SourceReference: domain.DCGMSourceReference(query)})
	}
	return domain.CoolingUploadReport{Version: domain.CoolingUploadVersion, ProfileID: profile.ProfileID, ProfileRevision: profile.Revision, ProfileHash: hash, Result: result}
}

func TestAssessmentUploadReceiptsAndBoundedHistory(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := t.Context()
	var now time.Time
	if err := f.admin.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	writer, profile, hash := seedAssessmentUploadProfile(t, f, now.UTC())
	pool := f.restrictedPool(t)
	if _, err := NewAssessmentStore(ctx, pool, f.registry, f.config, "test-upload-build"); !errors.Is(err, ErrAssessmentPrivileges) {
		t.Fatalf("upload assessment without receipt grants returned %v", err)
	}
	const uploadTables = "public.prometheus_cooling_upload_profiles, public.prometheus_cooling_upload_receipts"
	role := pgx.Identifier{f.role}.Sanitize()
	f.exec(t, "GRANT SELECT ON "+uploadTables+" TO "+role)
	if err := f.admin.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	last := now.UTC().Truncate(domain.CoolingUploadInterval)
	first := last.Add(-15*time.Minute + domain.CoolingUploadInterval)
	// The 60-slot window is used unless setup lands on the retention boundary.
	if now.Sub(last) > 14*time.Second {
		first = first.Add(domain.CoolingUploadInterval)
	}
	gap := last.Add(-time.Minute)
	for slot := first; !slot.After(last); slot = slot.Add(domain.CoolingUploadInterval) {
		for _, query := range domain.CoolingUploadQueries() {
			report := assessmentUploadReport(profile, hash, query, slot)
			if slot.Equal(gap) && query == domain.QueryGPUTemperature {
				// Deliberately start with the same validated run and observation
				// rows but omit the authenticated receipt.
				result := report.Result
				prepareCoolingUploadResult(&result, profile)
				tx, err := f.admin.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				inserted, err := persistCollectionResultRowsTx(ctx, tx, result, nil, false)
				if err != nil || !inserted {
					rollbackMonitoringTx(tx)
					t.Fatalf("receipt-free control row inserted=%v: %v", inserted, err)
				}
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				continue
			}
			accepted, err := writer.RecordCoolingUpload(ctx, profile.CollectorID, profile.ClusterID, report)
			if err != nil || !accepted {
				t.Fatalf("upload %s %s accepted=%v: %v", query, slot, accepted, err)
			}
		}
	}
	store, err := NewAssessmentStore(ctx, pool, f.registry, f.config, "test-upload-build")
	if err != nil {
		t.Fatal(err)
	}
	mismatch, err := a.Clone(f.config)
	if err != nil {
		t.Fatal(err)
	}
	for i := range mismatch.Bindings {
		mismatch.Bindings[i].UploadCollectorID = "other-collector"
	}
	invalid, err := NewAssessmentStore(ctx, pool, f.registry, mismatch, "test-upload-build")
	if err != nil {
		t.Fatal(err)
	}
	if err := invalid.Start(ctx); !errors.Is(err, ErrMonitoringAuthority) {
		t.Fatalf("upload assessment with the wrong collector returned %v", err)
	}
	if err := store.Start(ctx); err != nil {
		t.Fatal(err)
	}
	unavailable, err := a.NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, "REVOKE SELECT ON "+uploadTables+" FROM "+role)
	if _, err := NewAssessmentStore(ctx, pool, unavailable, f.config, "test-upload-build"); !errors.Is(err, ErrAssessmentPrivileges) {
		t.Fatalf("upload recovery without receipt grants returned %v", err)
	}
	f.exec(t, "GRANT SELECT ON "+uploadTables+" TO "+role)
	read := func(at time.Time) ([]a.Fact, error) {
		tx, err := beginAssessmentTx(ctx, pool)
		if err != nil {
			return nil, err
		}
		defer rollbackMonitoringTx(tx)
		var facts []a.Fact
		for _, asset := range f.config.Assets {
			rows, err := loadAssessmentInput(ctx, tx, f.config, asset, at.UTC())
			if err != nil {
				return nil, err
			}
			facts = append(facts, rows...)
		}
		return facts, nil
	}
	if beforeReceipt, err := read(last); err != nil || len(beforeReceipt) != 0 {
		t.Fatalf("delayed reports appeared before the server receipt: %d, %v", len(beforeReceipt), err)
	}
	var at time.Time
	if err = f.admin.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	at = at.UTC()
	readStarted := time.Now()
	facts, err := read(at)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("loaded %d receipt-qualified facts across 8 GPUs and 2 nodes in %v", len(facts), time.Since(readStarted))
	slots := 0
	for slot := first; !slot.After(last); slot = slot.Add(domain.CoolingUploadInterval) {
		if at.Sub(slot) < 15*time.Minute {
			slots++
		}
	}
	if slots < 58 || len(facts) != len(f.config.Assets)*(slots*2-1) {
		t.Fatalf("wrong bounded history count: %d facts across %d slots", len(facts), slots)
	}
	for _, fact := range facts {
		sample, err := a.DecodeSample(ctx, f.config.Category, fact)
		p := sample.Provenance
		if err != nil || p.Mode != "upload" || p.CollectorID != string(profile.CollectorID) || p.UploadProfileID != profile.ProfileID ||
			p.UploadProfileHash != hash || p.ScheduleRevision != profile.Revision || p.InventoryRevision != profile.InventoryRevision ||
			p.JobID != "" || p.ConfigurationRevision != nil || p.WorkID != "" || !sample.SourceAt.Equal(sample.CollectedAt) ||
			!sample.SourceAt.Equal(sample.CompletedAt) || !fact.AvailableAt.Equal(at) ||
			sample.SourceAt.Equal(gap) && sample.Metric == "DCGM_FI_DEV_GPU_TEMP" {
			t.Fatalf("upload fact lost receipt/source provenance: %+v, %v", sample, err)
		}
	}
	var maxGPU, maxRefresh time.Duration
	store.observeGPU = func(_ string, elapsed time.Duration) {
		maxGPU = max(maxGPU, elapsed)
	}
	for range f.config.Assets {
		refreshStarted := time.Now()
		if err := store.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		maxRefresh = max(maxRefresh, time.Since(refreshStarted))
	}
	var assessmentCandidates, budgetFailures int
	if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM assessment_candidates WHERE run_id=$1),
 (SELECT coalesce(sum(count),0)::bigint FROM assessment_failures WHERE run_id=$1 AND code='TIME_BUDGET')`, f.config.RunID).Scan(&assessmentCandidates, &budgetFailures); err != nil || assessmentCandidates != 40 {
		t.Fatalf("persisted upload candidates=%d: %v", assessmentCandidates, err)
	}
	t.Logf("upload scope over %d restricted live refresh passes: maximum refresh %v, maximum GPU work %v, time-budget failures %d", len(f.config.Assets), maxRefresh, maxGPU, budgetFailures)
	// Advance a separate engine on the verified input to settle all five
	// budgets without making the test wait through the longest arm.
	engine, err := a.NewEngine(ctx, f.config, at, f.registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Advance(ctx, at, at, at, facts, nil); err != nil {
		t.Fatal(err)
	}
	for _, budget := range a.Budgets[1:] {
		due := at.Add(time.Duration(budget) * time.Millisecond)
		if err := engine.Advance(ctx, due, due, due, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(engine.Candidates) != 40 {
		t.Fatalf("upload replay candidates=%d", len(engine.Candidates))
	}
	for _, c := range engine.Candidates {
		if c.Terminal == nil || c.Phase != "FINAL" {
			t.Fatalf("upload replay did not settle %s arm %d", c.Asset, c.BudgetMS)
		}
	}
	if expired, err := read(profile.EndsAt.Add(time.Microsecond)); err != nil || len(expired) == 0 {
		t.Fatalf("profile expiry discarded eligible historical receipts: %d, %v", len(expired), err)
	}
	f.exec(t, `UPDATE public.prometheus_cooling_upload_profiles SET revoked_at=clock_timestamp() WHERE profile_id=$1 AND revision=$2`, profile.ProfileID, profile.Revision)
	if _, err := read(profile.EndsAt.Add(time.Microsecond)); !errors.Is(err, ErrMonitoringAuthority) {
		t.Fatalf("revoked upload profile returned %v", err)
	}
}
