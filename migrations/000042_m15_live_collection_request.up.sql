-- M15 live Tier 1 adapter state. A repair requests one additional collection
-- occurrence; it never owns or rewrites collection_jobs.next_run_at.
ALTER TABLE remediation_schedule_snapshots
    ADD COLUMN prior_configuration_revision bigint,
    ADD COLUMN live_request_id text;

CREATE TABLE collection_repair_requests (
    request_id text PRIMARY KEY,
    cluster_id text NOT NULL,
    run_id text NOT NULL,
    attempt_id text NOT NULL,
    job_id text NOT NULL,
    operation text NOT NULL CHECK (operation IN ('SHERLOCK_EVIDENCE_COLLECTION_REQUEUE','SHERLOCK_EVIDENCE_COLLECTION_RESTORE')),
    configuration_revision bigint NOT NULL CHECK (configuration_revision >= 0),
    schedule_revision bigint NOT NULL CHECK (schedule_revision >= 0),
    idempotency_key text NOT NULL UNIQUE,
    status text NOT NULL CHECK (status IN ('REQUESTED','CLAIMED','COMPLETED','CANCEL_REQUESTED','CANCELLED','CONTAINED')),
    deadline_at timestamptz NOT NULL,
    effect_receipt text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    UNIQUE(cluster_id,run_id,attempt_id,job_id),
    FOREIGN KEY (cluster_id,run_id) REFERENCES remediation_runs(cluster_id,run_id),
    FOREIGN KEY (cluster_id,attempt_id) REFERENCES remediation_attempts(cluster_id,attempt_id),
    FOREIGN KEY (cluster_id,job_id) REFERENCES collection_jobs(cluster_id,job_id)
);

CREATE INDEX collection_repair_requests_pending_idx
    ON collection_repair_requests(cluster_id,status,deadline_at)
    WHERE status IN ('REQUESTED','CLAIMED','CANCEL_REQUESTED');

ALTER TABLE remediation_schedule_snapshots
    ADD CONSTRAINT remediation_snapshot_live_request_fk
    FOREIGN KEY (live_request_id) REFERENCES collection_repair_requests(request_id);
