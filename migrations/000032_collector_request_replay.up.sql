CREATE TABLE collector_request_nonces (
    certificate_fingerprint bytea NOT NULL,
    correlation_id text NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (certificate_fingerprint, correlation_id),
    CHECK (octet_length(certificate_fingerprint) = 32),
    CHECK (char_length(correlation_id) BETWEEN 1 AND 128),
    CHECK (expires_at > observed_at)
);

CREATE INDEX collector_request_nonces_expiry_idx
    ON collector_request_nonces (expires_at);
