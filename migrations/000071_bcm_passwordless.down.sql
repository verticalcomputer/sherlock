-- Existing passwordless records must be revoked/removed before reversal.
ALTER TABLE credential_access_tests DROP CONSTRAINT credential_access_tests_purpose_check;
ALTER TABLE credential_access_tests ADD CONSTRAINT credential_access_tests_purpose_check
    CHECK (purpose = 'BCM_READ_ONLY');
ALTER TABLE cluster_credentials DROP CONSTRAINT cluster_credentials_purpose_check;
ALTER TABLE cluster_credentials ADD CONSTRAINT cluster_credentials_purpose_check
    CHECK (purpose = 'BCM_READ_ONLY');
