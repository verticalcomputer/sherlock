-- Dropping the column discards the retained categories. Previews already
-- approved are unaffected: an approved preview is a digest-bound stored
-- document and is never recomputed from these rows.
ALTER TABLE credential_access_test_devices DROP COLUMN category;
