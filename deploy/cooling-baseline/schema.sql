-- Independent operational summaries. The evaluator's application schema is separate.
BEGIN;
SET LOCAL lock_timeout = '1s';
CREATE SCHEMA IF NOT EXISTS cooling_history;
CREATE TABLE IF NOT EXISTS cooling_history.refresh (
  enrollment_id text NOT NULL, cutoff timestamptz NOT NULL,
  start_at timestamptz NOT NULL, cluster_id text NOT NULL, source_id text NOT NULL,
  input text NOT NULL CHECK (input IN ('seed','sherlock')),
  published_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  asset_count integer NOT NULL CHECK (asset_count > 0),
  PRIMARY KEY (enrollment_id, cutoff), CHECK (start_at < cutoff)
);
CREATE TABLE IF NOT EXISTS cooling_history.gpu (
  enrollment_id text NOT NULL, cutoff timestamptz NOT NULL, asset text NOT NULL,
  paired_samples bigint NOT NULL CHECK (paired_samples >= 0),
  covered_intervals integer NOT NULL CHECK (covered_intervals >= 0),
  PRIMARY KEY (enrollment_id, cutoff, asset),
  FOREIGN KEY (enrollment_id, cutoff) REFERENCES cooling_history.refresh
);
CREATE TABLE IF NOT EXISTS cooling_history.temperature_band (
  enrollment_id text NOT NULL, cutoff timestamptz NOT NULL, asset text NOT NULL,
  power_w integer NOT NULL CHECK (power_w BETWEEN 0 AND 2000 AND power_w % 25 = 0),
  median_c double precision NOT NULL, p95_c double precision NOT NULL,
  samples bigint NOT NULL, days integer NOT NULL, periods bigint NOT NULL,
  last_at timestamptz NOT NULL, histogram jsonb NOT NULL,
  CHECK (median_c BETWEEN 0 AND 150 AND p95_c BETWEEN median_c AND 150),
  CHECK (days > 0 AND periods > 0 AND samples >= greatest(days,periods)),
  CHECK (last_at < cutoff AND jsonb_typeof(histogram) = 'object'),
  PRIMARY KEY (enrollment_id, cutoff, asset, power_w),
  FOREIGN KEY (enrollment_id, cutoff, asset) REFERENCES cooling_history.gpu
);
-- A separate transaction records when a reader first observed committed data.
CREATE TABLE IF NOT EXISTS cooling_history.available_refresh (
 enrollment_id text NOT NULL, cutoff timestamptz NOT NULL,
 available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (enrollment_id,cutoff),
 FOREIGN KEY (enrollment_id,cutoff) REFERENCES cooling_history.refresh
);
CREATE OR REPLACE VIEW cooling_history.latest_temperature_band AS
SELECT r.cluster_id, r.source_id, r.start_at, r.published_at, b.*
FROM (SELECT DISTINCT ON (enrollment_id) * FROM cooling_history.refresh
      ORDER BY enrollment_id, cutoff DESC) r
JOIN cooling_history.temperature_band b USING (enrollment_id,cutoff);
COMMIT;
