-- Historical {} payloads remain valid. New stop metadata contains only reviewed
-- machine codes, never arbitrary error, provider, command, or host text.
ALTER TABLE investigation_events ADD CONSTRAINT investigation_event_stop_details_check CHECK (
  payload = '{}'::jsonb OR COALESCE((
    event_type = 'STATE_TRANSITION'
    AND to_status IN ('COMPLETED','PARTIAL','BLOCKED','CANCELLED')
    AND payload - ARRAY['stop_reason','failure_code','failure_stage']::text[] = '{}'::jsonb
    AND jsonb_typeof(payload->'stop_reason') = 'string'
    AND payload->>'stop_reason' IN (
      'SUCCESS_CRITERIA_MET','NO_USEFUL_ACTION','BUDGET_EXCEEDED','APPROVAL_DENIED',
      'APPROVAL_EXPIRED','ACCESS_UNAVAILABLE','SOURCE_UNAVAILABLE','OPERATOR_CANCELLED',
      'CONTEXT_EXHAUSTED','POLICY_EXHAUSTED')
    AND ((NOT (payload ? 'failure_code') AND NOT (payload ? 'failure_stage')) OR (
      jsonb_typeof(payload->'failure_code') = 'string'
      AND jsonb_typeof(payload->'failure_stage') = 'string'
      AND payload->>'failure_code' IN (
        'UNCLASSIFIED','REQUIRED_CONTEXT_EXCEEDS_ALLOWANCE','REQUIRED_EVIDENCE_EXCEEDS_ALLOWANCE',
        'CONTEXT_EXCEEDS_ENCODED_LIMIT','PROVIDER_INPUT_EXCEEDS_ALLOWANCE','EVIDENCE_CONTEXT_UNUSABLE',
        'CONTEXT_CHECKPOINT_MISMATCH','TOKEN_ESTIMATOR_UNDERRUN','BUDGET_EXCEEDED',
        'REPAIR_WARNING_SNAPSHOT_INVALID')
      AND payload->>'failure_stage' IN (
        'LOAD','PLANNING','POLICY_CHECK','EXECUTION','EVIDENCE_RECORDING',
        'LEDGER_UPDATE','SYNTHESIS','TRANSITION_PERSISTENCE')
    ))
  ), false)
);
