package monitoring

const (
	RuleTelemetryLoss RuleID = "telemetry_loss"
	RuleGPUThermal    RuleID = "gpu_thermal"
	RuleHBMThermal    RuleID = "hbm_thermal"
	RuleECCHistorical RuleID = "ecc_historical_count"
	RuleRemapFailure  RuleID = "row_remap_failure"
	RuleLegacyXID     RuleID = "legacy_xid"
	RuleLegacyNetwork RuleID = "legacy_network"
)

type RuleDefinition struct {
	ID      RuleID
	Version int
	Owner   string
	Metrics []string
	// ReadAliases preserve historical evidence; they are never policy metrics.
	ReadAliases []string
	Kind        string
	Unit        string
	Recovery    string
}

func Registry() []RuleDefinition {
	return []RuleDefinition{
		{ID: RuleTelemetryLoss, Version: 1, Owner: "monitoring", Kind: "collection_deadline", Recovery: "distinct_relevant_successful_collection"},
		{ID: RuleGPUThermal, Version: 1, Owner: "monitoring", Metrics: []string{"DCGM_FI_DEV_GPU_TEMP"}, Kind: "gauge", Unit: "celsius", Recovery: "distinct_fresh_below_hysteresis"},
		{ID: RuleHBMThermal, Version: 1, Owner: "monitoring", Metrics: []string{"DCGM_FI_DEV_MEMORY_TEMP"}, Kind: "gauge", Unit: "celsius", Recovery: "distinct_fresh_below_hysteresis"},
		{ID: RuleECCHistorical, Version: 1, Owner: "monitoring", Metrics: []string{"DCGM_FI_DEV_ECC_SBE_VOL_TOTAL", "DCGM_FI_DEV_ECC_DBE_VOL_TOTAL", "DCGM_FI_DEV_ECC_SBE_AGG_TOTAL", "DCGM_FI_DEV_ECC_DBE_AGG_TOTAL", "DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS", "DCGM_FI_DEV_UNCORRECTABLE_REMAPPED_ROWS"}, Kind: "counter", Unit: "count", Recovery: "reviewed_occurrence_disposition"},
		{ID: RuleRemapFailure, Version: 1, Owner: "monitoring", Metrics: []string{"DCGM_FI_DEV_ROW_REMAP_FAILURE"}, ReadAliases: []string{"DCGM_FI_DEV_ROW_REMAP_FAILED"}, Kind: "gauge", Unit: "boolean", Recovery: "distinct_fresh_zero"},
		{ID: RuleLegacyXID, Version: 1, Owner: "existing_xid_evaluator", Metrics: []string{"DCGM_FI_DEV_XID_ERRORS"}, Kind: "gauge", Unit: "xid_code", Recovery: "existing_contract"},
		{ID: RuleLegacyNetwork, Version: 1, Owner: "existing_network_evaluator", Kind: "reviewed_network_observation", Recovery: "existing_two_fresh_observations"},
	}
}
