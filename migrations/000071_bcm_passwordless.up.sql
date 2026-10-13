-- A distinct purpose makes passwordless BCM authorization explicit and
-- prevents an existing password credential from silently changing mode.
ALTER TABLE cluster_credentials DROP CONSTRAINT cluster_credentials_purpose_check;
ALTER TABLE cluster_credentials ADD CONSTRAINT cluster_credentials_purpose_check
    CHECK (purpose IN ('BCM_READ_ONLY', 'BCM_READ_ONLY_PASSWORDLESS'));
ALTER TABLE credential_access_tests DROP CONSTRAINT credential_access_tests_purpose_check;
ALTER TABLE credential_access_tests ADD CONSTRAINT credential_access_tests_purpose_check
    CHECK (purpose IN ('BCM_READ_ONLY', 'BCM_READ_ONLY_PASSWORDLESS'));
