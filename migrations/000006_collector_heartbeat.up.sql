CREATE TABLE collector_command_packs (
    collector_id text NOT NULL REFERENCES collectors(collector_id) ON DELETE CASCADE,
    pack_id text NOT NULL,
    version text NOT NULL,
    digest_sha256 bytea NOT NULL CHECK (octet_length(digest_sha256) = 32),
    reported_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (collector_id, pack_id)
);
