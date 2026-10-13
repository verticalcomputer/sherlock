-- Per-run field assessments reuse collection history; they confer no execution
-- or schedule authority. Metadata is normalized by the ingestion transaction.
ALTER TABLE collection_runs ADD COLUMN metric_fields jsonb NOT NULL DEFAULT '[]'::jsonb CHECK(jsonb_typeof(metric_fields)='array');
ALTER TABLE observations ADD COLUMN metric_semantics jsonb CHECK(metric_semantics IS NULL OR jsonb_typeof(metric_semantics)='object');
