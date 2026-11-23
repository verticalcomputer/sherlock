SET LOCAL lock_timeout = '1s';
-- Queue lookups need only the flag, never the serialized replay evidence.
ALTER TABLE production_assessment_states
 ADD COLUMN replay_pending boolean NOT NULL DEFAULT false,
 ADD COLUMN last_input_at timestamptz,
 ADD COLUMN last_input_gap tstzrange;
