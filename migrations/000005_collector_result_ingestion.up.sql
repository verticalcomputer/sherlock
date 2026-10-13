CREATE TABLE collector_result_chunks (
    work_id text NOT NULL,
    attempt integer NOT NULL,
    chunk_index integer NOT NULL CHECK (chunk_index BETWEEN 0 AND 63),
    payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 262144),
    sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
    byte_count integer NOT NULL CHECK (byte_count = octet_length(payload)),
    uploaded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (work_id, attempt, chunk_index),
    FOREIGN KEY (work_id, attempt)
        REFERENCES collector_work_attempts(work_id, attempt) ON DELETE CASCADE
);

CREATE TABLE collector_result_ingestions (
    work_id text NOT NULL,
    attempt integer NOT NULL,
    collector_id text NOT NULL REFERENCES collectors(collector_id),
    run_id text NOT NULL UNIQUE REFERENCES collection_runs(run_id),
    result_status text NOT NULL CHECK (result_status IN ('SUCCEEDED', 'NO_DATA', 'PARTIAL', 'FAILED')),
    chunk_count integer NOT NULL CHECK (chunk_count BETWEEN 1 AND 64),
    byte_count bigint NOT NULL CHECK (byte_count > 0),
    sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
    finalized_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (work_id, attempt),
    FOREIGN KEY (work_id, attempt)
        REFERENCES collector_work_attempts(work_id, attempt) ON DELETE RESTRICT
);
