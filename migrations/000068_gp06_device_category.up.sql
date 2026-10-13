-- GP-06 expected-inventory classification by BCM device category. The
-- inventory discovery operation's fixed cmsh listing gains one reviewed
-- column, and the retained rows gain the matching column. The value is BCM
-- configuration (the head's own grouping of nodes), never a secret and never
-- a telemetry fact: it is what lets a preview tell a GPU compute category
-- apart from a login or service category instead of guessing per node.
--
-- The column is NOT NULL DEFAULT '' so every row retained before this
-- migration reads as "no category reported", which is exactly what those
-- discoveries observed: their listing never asked for the column. The bound
-- mirrors the other retained device fields.
ALTER TABLE credential_access_test_devices
    ADD COLUMN category text NOT NULL DEFAULT '' CHECK (length(category) <= 128);
