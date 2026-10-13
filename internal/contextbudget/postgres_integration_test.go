//go:build integration

package contextbudget

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestPostgresSinkPersistsEmptyCollectionsAsJSONContainers(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated migrated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	now := time.Now().UTC().Truncate(time.Microsecond)
	suffix := now.Format("20060102150405.000000000")
	clusterID := domain.ClusterID("m10-context-" + suffix)
	investigationID := domain.InvestigationID("m10-context-inv-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(cluster_id,display_name) VALUES($1,'M10 context test')`, clusterID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM clusters WHERE cluster_id=$1`, clusterID) })
	if _, err := pool.Exec(ctx, `INSERT INTO investigations(investigation_id,cluster_id,question,requested_by,scope,window_start,window_end,success_criteria,status,created_at,updated_at) VALUES($1,$2,'why','test','{"entity_kind":"node","entity_ids":["node-1"]}',$3,$3,'["cite"]','PLANNING',$3,$3)`, investigationID, clusterID, now); err != nil {
		t.Fatal(err)
	}

	sink, err := NewPostgresSink(pool)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{
		ID: "manifest-" + suffix, ClusterID: clusterID, InvestigationID: investigationID,
		CallKey: "investigation/" + string(investigationID) + "/planning/1", CallKind: application.ModelCallPlanning,
		EstimatorVersion: "test-v1", AllowanceTokens: 32_000, EstimatedInputTokens: 1_000,
		MemoryAllowanceTokens: 8_000, FallbackState: "LEXICAL", ShadowOnly: true, CreatedAt: now,
		ExclusionReasons: map[string]int{"memory_entry_limit": 1}, SectionTokens: map[string]int64{"memory": 24},
	}
	if err := sink.RecordContextManifest(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	if err := sink.RecordContextManifest(ctx, manifest); err != nil {
		t.Fatalf("idempotent write: %v", err)
	}
	var selectedType, exclusionsType, sectionsType string
	if err := pool.QueryRow(ctx, `SELECT jsonb_typeof(selected_memory_ids),jsonb_typeof(exclusion_reasons),jsonb_typeof(section_tokens) FROM investigation_context_manifests WHERE manifest_id=$1`, manifest.ID).Scan(&selectedType, &exclusionsType, &sectionsType); err != nil {
		t.Fatal(err)
	}
	if selectedType != "array" || exclusionsType != "object" || sectionsType != "object" {
		t.Fatalf("JSON container types selected=%s exclusions=%s sections=%s", selectedType, exclusionsType, sectionsType)
	}
}

// The calibration loop is what lets the conservative fallback factor be
// replaced by measurement. It stayed silently dead in the pilot because its
// table had never been migrated, so exercise the whole round trip against a
// real database: record a sample, read it back, and confirm the factor moves.
func TestCalibrationSampleRoundTripReplacesTheFallbackFactor(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated migrated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	now := time.Now().UTC().Truncate(time.Microsecond)
	suffix := now.Format("20060102150405.000000000")
	sink, err := NewPostgresSink(pool)
	if err != nil {
		t.Fatal(err)
	}
	key := CalibrationKey{
		Provider: "azure-openai", Model: "calibration-" + suffix, ConfigurationID: "config-v1",
		PromptSchemaVersion: "planning-v2", ToolSchemaVersion: "catalog-v1", EstimatorVersion: "test-v1",
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM model_token_calibration_samples WHERE model=$1`, key.Model)
	})
	if ratios, err := sink.LoadCalibrationRatios(ctx, key, 200); err != nil || len(ratios) != 0 {
		t.Fatalf("ratios=%v err=%v", ratios, err)
	}
	// A pilot-shaped sample: the JSON heuristic underestimates real tokenization
	// of identifier-dense payloads by well over the historical 1.6 fallback.
	manifest := Manifest{ID: "calibration-manifest-" + suffix, RawEstimatedInputTokens: 17_309}
	if err := sink.RecordCalibrationSample(ctx, key, manifest, 41_003); err != nil {
		t.Fatal(err)
	}
	ratios, err := sink.LoadCalibrationRatios(ctx, key, 200)
	if err != nil || len(ratios) != 1 {
		t.Fatalf("ratios=%v err=%v", ratios, err)
	}
	if ratios[0] < 2_360_000 || ratios[0] > 2_380_000 {
		t.Fatalf("recorded ratio %d does not reflect the measured 2.37x underestimate", ratios[0])
	}
	// Below the sample threshold the fallback still governs, but it must never
	// sit under a ratio that has actually been observed.
	factor := CalibrationFactor(ratios, DefaultConfig().FallbackFactorMillionths)
	if factor < ratios[0] {
		t.Fatalf("factor %d is below the observed ratio %d", factor, ratios[0])
	}
	// The fallback is deliberately not raised to the worst dense-payload ratio:
	// over-estimating is fatal (REQUIRED_CONTEXT_EXCEEDS_ALLOWANCE) while
	// under-estimating only spends budget faster, so it must stay within the
	// range that small payloads can survive until calibration supersedes it.
	if factor := DefaultConfig().FallbackFactorMillionths; factor < 1_000_000 || factor > 2_000_000 {
		t.Fatalf("fallback factor %d is outside the survivable range", factor)
	}
}
