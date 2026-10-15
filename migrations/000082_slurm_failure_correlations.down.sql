DO $$ BEGIN IF EXISTS(SELECT 1 FROM slurm_failure_correlations) THEN RAISE EXCEPTION 'preserve published Slurm correlations before rollback'; END IF; END $$;
DROP INDEX slurm_correlation_observation_window_idx;
DROP TABLE slurm_failure_correlations;
DROP FUNCTION slurm_correlation_immutable();
