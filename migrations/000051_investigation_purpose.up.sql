ALTER TABLE investigations ADD COLUMN purpose text NOT NULL DEFAULT '' CHECK (purpose IN ('', 'EVIDENCE_REPAIR_PLAN'));
