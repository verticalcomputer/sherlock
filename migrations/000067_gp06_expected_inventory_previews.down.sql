-- Dropping the preview table removes only the proposals and their import
-- record. Every expected inventory revision that was imported from one stays
-- in goodput_inventory_revisions: the revision is the durable fact, and the
-- preview was the evidence an operator approved it from. Reversing this
-- migration therefore loses the approval trail, not the inventory.
DROP TABLE expected_inventory_previews;

-- Restoring the narrower event vocabulary fails if any preview or import
-- event was recorded. That is deliberate: reversing this migration means the
-- expected-inventory approval flow is no longer authorized, and keeping
-- events that name it would leave an unenforceable record behind. Delete or
-- reclassify those event rows out of band before rolling back.
ALTER TABLE credential_access_test_events DROP CONSTRAINT credential_access_test_events_event_kind_check;
ALTER TABLE credential_access_test_events
    ADD CONSTRAINT credential_access_test_events_event_kind_check
    CHECK (event_kind IN ('ACCESS_TEST_REQUESTED','ACCESS_TEST_CLAIMED','CREDENTIAL_DELIVERED',
        'CREDENTIAL_DELIVERY_REFUSED','ACCESS_TEST_COMPLETED','ACCESS_TEST_RESULT_REJECTED',
        'ACCESS_TEST_CANCELLED','ACCESS_TEST_EXPIRED'));
