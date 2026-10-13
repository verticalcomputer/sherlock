-- Repair requests supervise one already-bound collector work item.  The work
-- remains the authoritative execution record; request state records only the
-- remediation lifecycle and never rewrites ordinary collection scheduling.
ALTER TABLE collection_repair_requests
    ADD COLUMN work_id text UNIQUE,
    ADD COLUMN lease_owner text,
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN cancellation_requested_at timestamptz,
	ADD COLUMN cancellation_attempt_id text,
    ADD COLUMN cancellation_outcome text CHECK (cancellation_outcome IN ('CANCELLED','COMPLETED','CONTAINED')),
    ADD COLUMN claimed_attempt integer;

ALTER TABLE remediation_runs
    ADD COLUMN supervisor_generation bigint NOT NULL DEFAULT 0 CHECK (supervisor_generation >= 0);

-- The M14 trigger must own the revision value as well as its increment.  A
-- writer cannot forge an old revision after an ABA update by assigning the
-- column directly.
CREATE OR REPLACE FUNCTION remediation_schedule_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.schedule_revision := OLD.schedule_revision;
  IF ROW(NEW.active,NEW.interval_seconds,NEW.next_run_at)
       IS DISTINCT FROM ROW(OLD.active,OLD.interval_seconds,OLD.next_run_at) THEN
    NEW.schedule_revision := OLD.schedule_revision+1;
  END IF;
  RETURN NEW;
END $$;

ALTER TABLE collection_repair_requests
    ADD CONSTRAINT collection_repair_requests_work_fk
    FOREIGN KEY (work_id) REFERENCES collector_work_items(work_id),
	ADD CONSTRAINT collection_repair_requests_cancellation_attempt_fk
	FOREIGN KEY (cluster_id,cancellation_attempt_id) REFERENCES remediation_attempts(cluster_id,attempt_id),
	ADD CONSTRAINT collection_repair_requests_cancellation_attempt_unique UNIQUE(cluster_id,cancellation_attempt_id),
    ADD CONSTRAINT collection_repair_requests_lease_pair
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL));

CREATE INDEX collection_repair_requests_claim_idx
    ON collection_repair_requests(cluster_id, status, created_at)
    WHERE status IN ('REQUESTED','CLAIMED','CANCEL_REQUESTED');

-- Result ingestion is the only successful execution proof.  Keep a cancelled
-- request truthful when a collector had already started: its evidence remains
-- durable and the request records that cancellation raced completion.
CREATE FUNCTION m15_repair_request_work_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status IN ('SUCCEEDED','FAILED','CANCELLED') THEN
    UPDATE collection_repair_requests r
       SET status = CASE WHEN r.status='CANCEL_REQUESTED' AND NEW.status='CANCELLED' THEN 'CANCELLED'
                         WHEN r.status='CANCEL_REQUESTED' THEN 'CONTAINED'
                         WHEN NEW.status='CANCELLED' THEN 'CANCELLED'
                         ELSE 'COMPLETED' END,
           completed_at=clock_timestamp(), lease_owner=NULL, lease_expires_at=NULL,
           cancellation_outcome=CASE WHEN r.status='CANCEL_REQUESTED' AND NEW.status='CANCELLED' THEN 'CANCELLED'
                                     WHEN r.status='CANCEL_REQUESTED' THEN 'CONTAINED' ELSE r.cancellation_outcome END
     WHERE r.work_id=NEW.work_id AND r.status IN ('REQUESTED','CLAIMED','CANCEL_REQUESTED');
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER m15_repair_request_work_lifecycle
AFTER UPDATE OF status ON collector_work_items
FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status)
EXECUTE FUNCTION m15_repair_request_work_lifecycle();
