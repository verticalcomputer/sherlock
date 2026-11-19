-- Independent durable fairness for bounded deadline and acquisition slices.
-- Existing next_due_at remains the original candidate deadline, never a cursor.
ALTER TABLE production_assessment_states
 ADD COLUMN last_due_attempt_at timestamptz,
 ADD COLUMN last_acquire_attempt_at timestamptz;
