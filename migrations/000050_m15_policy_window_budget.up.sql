ALTER TABLE remediation_policies ADD COLUMN max_forward_attempts integer NOT NULL DEFAULT 0 CHECK (max_forward_attempts BETWEEN 0 AND 100);
COMMENT ON COLUMN remediation_policies.max_forward_attempts IS 'Zero preserves legacy unlimited window; positive values cap forward reservations for cluster/recipe within not_before/not_after. Rollback remains separately bounded.';
