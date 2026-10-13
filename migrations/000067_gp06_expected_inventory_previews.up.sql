-- GP-06a expected-inventory preview: the durable, digest-bound proposal an
-- operator approves before any expected inventory revision exists. The row is
-- evidence, not authority: nothing here is an inventory revision, and the
-- canonical write still goes through RecordExpectedInventoryRevision against
-- the goodput tables. No column holds a secret: the content is the reconciled
-- device rows, stable node identities and physical GPU UUIDs, all of which
-- the credential access-test family already retains in sanitized form.
CREATE TABLE expected_inventory_previews (
    preview_id text PRIMARY KEY
        CHECK (preview_id LIKE 'ipv\_%' AND length(preview_id) BETWEEN 5 AND 128),
    -- A removed cluster takes its proposals with it: a preview is evidence
    -- about one cluster and means nothing once that cluster is gone.
    cluster_id text NOT NULL REFERENCES clusters(cluster_id) ON DELETE CASCADE,
    source_id text NOT NULL,
    -- The discovery is the provenance of the proposal and is stated
    -- explicitly rather than left to the default: a discovery that a preview
    -- was built from must not be deletable out from under it.
    discovery_test_id text NOT NULL REFERENCES credential_access_tests(test_id) ON DELETE RESTRICT,
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    content jsonb NOT NULL CHECK (octet_length(content::text) <= 262144),
    blocking boolean NOT NULL,
    node_count integer NOT NULL DEFAULT 0 CHECK (node_count >= 0),
    gpu_count integer NOT NULL DEFAULT 0 CHECK (gpu_count >= 0),
    generated_by text NOT NULL CHECK (length(generated_by) BETWEEN 1 AND 256),
    generated_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > generated_at),
    -- Import state is recorded after the revision is durable. The three
    -- columns move together so a preview can never claim an import without
    -- naming the revision and the operator who approved it.
    imported_revision_id text NULL,
    imported_by text NULL,
    imported_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((imported_revision_id IS NULL) = (imported_at IS NULL)),
    CHECK ((imported_by IS NULL) = (imported_at IS NULL)),
    FOREIGN KEY (cluster_id, source_id) REFERENCES sources(cluster_id, source_id)
);

CREATE INDEX expected_inventory_previews_recent_idx
    ON expected_inventory_previews (cluster_id, generated_at DESC, preview_id DESC);

-- Proposing and approving an expected inventory are actions on the discovery
-- the proposal was reconciled from, so they join the same append-only event
-- vocabulary rather than a second audit table with its own retention.
ALTER TABLE credential_access_test_events DROP CONSTRAINT credential_access_test_events_event_kind_check;
ALTER TABLE credential_access_test_events
    ADD CONSTRAINT credential_access_test_events_event_kind_check
    CHECK (event_kind IN ('ACCESS_TEST_REQUESTED','ACCESS_TEST_CLAIMED','CREDENTIAL_DELIVERED',
        'CREDENTIAL_DELIVERY_REFUSED','ACCESS_TEST_COMPLETED','ACCESS_TEST_RESULT_REJECTED',
        'ACCESS_TEST_CANCELLED','ACCESS_TEST_EXPIRED',
        'EXPECTED_INVENTORY_PREVIEWED','EXPECTED_INVENTORY_IMPORTED'));
