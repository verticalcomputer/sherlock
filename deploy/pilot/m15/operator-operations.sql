-- This entry point is observation-only. Do not mix a rehearsal with a mutation.
\ir observe.sql
-- Separately authorized global stop: psql ... -f deploy/pilot/m15/kill-switch.sql
-- Scoped lifecycle control uses the restricted LIVE process and signed catalog:
-- /app/sherlock-remediator control cancel REVIEWED_RUN_ID
-- /app/sherlock-remediator control rollback REVIEWED_RUN_ID
-- /app/sherlock-remediator control reconcile REVIEWED_RUN_ID
-- Read docs/M15_OPERATIONS_RUNBOOK.md for lease waiting and containment semantics.
