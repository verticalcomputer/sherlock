-- GP-06 "Discover BCM inventory": a second bounded, reviewed operation in the
-- existing credential access-test family. It runs the identical fixed cmsh
-- listing as bcm.access_test.v1 and differs only in retaining the sanitized
-- device rows. No column holds a secret: the rows are the three reviewed
-- listing columns, bounded and sanitized before they are accepted.
ALTER TABLE credential_access_tests DROP CONSTRAINT credential_access_tests_operation_check;
ALTER TABLE credential_access_tests
    ADD CONSTRAINT credential_access_tests_operation_check
    CHECK (operation IN ('bcm.access_test.v1','bcm.inventory_discovery.v1'));

-- Retained listing rows for one inventory discovery. Rows exist only for a
-- SUCCEEDED bcm.inventory_discovery.v1 test; the store inserts them in the
-- same transaction that marks the test terminal and never for any other
-- operation or outcome. Ordinal preserves the order the head reported.
CREATE TABLE credential_access_test_devices (
    test_id text NOT NULL REFERENCES credential_access_tests(test_id) ON DELETE CASCADE,
    ordinal integer NOT NULL CHECK (ordinal >= 0 AND ordinal < 512),
    device_type text NOT NULL CHECK (length(device_type) BETWEEN 1 AND 128),
    hostname text NOT NULL CHECK (length(hostname) BETWEEN 1 AND 128),
    status text NOT NULL DEFAULT '' CHECK (length(status) <= 128),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (test_id, ordinal),
    UNIQUE (test_id, device_type, hostname)
);

CREATE INDEX credential_access_test_devices_test_idx
    ON credential_access_test_devices (test_id, ordinal);
