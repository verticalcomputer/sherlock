-- Restoring the single-value CHECK fails if any inventory discovery row
-- exists in credential_access_tests. That is deliberate: reversing this
-- migration means the second operation is no longer authorized, and silently
-- keeping rows that name it would leave unenforceable authority in the table.
-- Delete or reclassify those test rows out of band before rolling back.
DROP TABLE credential_access_test_devices;

ALTER TABLE credential_access_tests DROP CONSTRAINT credential_access_tests_operation_check;
ALTER TABLE credential_access_tests
    ADD CONSTRAINT credential_access_tests_operation_check
    CHECK (operation = 'bcm.access_test.v1');
