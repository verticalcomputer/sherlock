ALTER TABLE investigation_context_manifests
	DROP COLUMN estimator_underrun,
	DROP COLUMN actual_input_tokens,
    DROP COLUMN delta_from_version,
    DROP COLUMN checkpoint_digest,
    DROP COLUMN context_mode,
    DROP COLUMN selected_evidence_ids,
    DROP COLUMN maximum_output_tokens,
    DROP COLUMN fixed_margin_tokens,
    DROP COLUMN calibration_sample_count,
    DROP COLUMN calibration_factor_millionths,
    DROP COLUMN raw_estimated_input_tokens;

DROP TABLE model_token_calibration_samples;
DROP TABLE investigation_context_checkpoints;
