-- NULL denotes a historical request; an empty array is an admitted empty set.
ALTER TABLE investigations ADD COLUMN repair_warning_ids text[];
ALTER TABLE investigations ADD CONSTRAINT investigations_repair_warning_snapshot_check
    CHECK (repair_warning_ids IS NULL OR
      (purpose = 'EVIDENCE_REPAIR_PLAN' AND cardinality(repair_warning_ids) <= 256
       AND array_position(repair_warning_ids, NULL) IS NULL));
