-- Default-off GP-07a fact storage. Runtime collection and template enrollment
-- are separate reviewed steps. A sample's natural key excludes the run that
-- saw it; overlapping windows can add provenance without duplicating output.
CREATE TABLE goodput_progress_templates (
    cluster_id text NOT NULL,
    source_id text NOT NULL,
    template_id text NOT NULL,
    template_revision integer NOT NULL CHECK (template_revision > 0),
    metric_name text NOT NULL,
    scheduler_namespace text NOT NULL,
    cohort text NOT NULL,
    unit text NOT NULL,
    job_id_label text NOT NULL,
    submit_at_label text NOT NULL,
    attempt_label text NOT NULL,
    reset_epoch_label text NOT NULL,
    static_labels jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(static_labels)='object'),
    max_age_seconds integer NOT NULL CHECK (max_age_seconds BETWEEN 1 AND 600),
    approved_by text NOT NULL,
    approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz,
    PRIMARY KEY (cluster_id, source_id, template_id, template_revision),
    FOREIGN KEY (cluster_id, source_id) REFERENCES sources(cluster_id, source_id)
);

CREATE TABLE goodput_progress_samples (
    sample_key bytea PRIMARY KEY CHECK (octet_length(sample_key)=32),
    cluster_id text NOT NULL,
    source_id text NOT NULL,
    template_id text NOT NULL,
    template_revision integer NOT NULL CHECK (template_revision > 0),
    schema_version integer NOT NULL CHECK (schema_version=1),
    scheduler_namespace text NOT NULL,
    scheduler_job_id text NOT NULL,
    submit_at timestamptz NOT NULL,
    attempt integer NOT NULL CHECK (attempt >= 0),
    cohort text NOT NULL,
    state text NOT NULL CHECK (state IN ('UNKNOWN','MEASURED','UNMEASURED','UNSUPPORTED')),
    unit text NOT NULL DEFAULT '',
    committed double precision,
    reset_epoch text NOT NULL DEFAULT '',
    source_at timestamptz NOT NULL,
    effective_at timestamptz NOT NULL,
    content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256)=32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (cluster_id, source_id) REFERENCES sources(cluster_id, source_id),
    FOREIGN KEY (cluster_id, source_id, template_id, template_revision)
        REFERENCES goodput_progress_templates(cluster_id, source_id, template_id, template_revision),
    CHECK ((state='MEASURED' AND unit<>'' AND reset_epoch<>'' AND committed IS NOT NULL
            AND committed>=0 AND committed<'Infinity'::double precision)
        OR (state<>'MEASURED' AND unit='' AND reset_epoch='' AND committed IS NULL))
);
CREATE INDEX goodput_progress_samples_history_idx ON goodput_progress_samples
    (cluster_id, source_id, scheduler_namespace, scheduler_job_id, submit_at, attempt,
     effective_at DESC, template_id, template_revision);

-- Run ids remain as durable provenance after ordinary collection-run
-- retention. The writer verifies cluster/source/operation/status against the
-- run inside its transaction before inserting a receipt.
CREATE TABLE goodput_progress_sample_receipts (
    sample_key bytea NOT NULL REFERENCES goodput_progress_samples(sample_key),
    run_id text NOT NULL,
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (sample_key, run_id)
);
CREATE INDEX goodput_progress_sample_receipts_run_idx
    ON goodput_progress_sample_receipts (run_id);
