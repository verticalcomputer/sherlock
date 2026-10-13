-- Additive ownership metadata only. Original batch/loss/lifecycle evidence is retained.
ALTER TABLE gp06f_telemetry_enrollments ADD COLUMN retired_through_epoch numeric(20,0) NOT NULL DEFAULT 0 CHECK(retired_through_epoch BETWEEN 0 AND highest_epoch);
ALTER TABLE gp06f_telemetry_keys ADD COLUMN archived_at timestamptz CHECK(archived_at IS NULL OR state<>'ACTIVE');
CREATE UNIQUE INDEX gp06f_telemetry_key_material_once ON gp06f_telemetry_keys(enrollment_id,public_key);
ALTER TABLE gp06f_telemetry_sessions
 ADD COLUMN released_through numeric(20,0) NOT NULL DEFAULT 0 CHECK(released_through BETWEEN 0 AND 18446744073709551615),
 ADD COLUMN node_completed_through numeric(20,0) NOT NULL DEFAULT 0 CHECK(node_completed_through BETWEEN 0 AND released_through),
 ADD COLUMN retirement_receipts_expired_through numeric(20,0) NOT NULL DEFAULT 0 CHECK(retirement_receipts_expired_through BETWEEN 0 AND node_completed_through),
 ADD COLUMN empty_release_completed boolean NOT NULL DEFAULT false,
 ADD CHECK(NOT empty_release_completed OR (finalized_at IS NOT NULL AND last_allocated_sequence=0)),
 ADD CHECK(last_allocated_sequence IS NULL OR released_through<=last_allocated_sequence),
 ADD CHECK(retired_at IS NULL OR (last_allocated_sequence=node_completed_through AND (last_allocated_sequence>0 OR empty_release_completed)));
CREATE INDEX gp06f_telemetry_session_key_history ON gp06f_telemetry_sessions(enrollment_id,key_id,session_epoch);
CREATE INDEX gp06f_telemetry_unretired_key ON gp06f_telemetry_sessions(enrollment_id,key_id) WHERE finalized_at IS NULL OR retired_at IS NULL;
CREATE TABLE gp06f_telemetry_retirements (
 enrollment_id text NOT NULL,
 release_id text NOT NULL CHECK(length(release_id) BETWEEN 1 AND 128),
 session_epoch numeric(20,0) NOT NULL,
 session_id text NOT NULL,
 signing_key_id text NOT NULL,
 from_sequence numeric(20,0) NOT NULL CHECK(from_sequence BETWEEN 0 AND 18446744073709551615),
 through_sequence numeric(20,0) NOT NULL CHECK(through_sequence BETWEEN from_sequence AND 18446744073709551615),
 release_digest text NOT NULL CHECK(release_digest ~ '^[0-9a-f]{64}$'),
 manifest_digest text NOT NULL CHECK(manifest_digest ~ '^[0-9a-f]{64}$'),
 request jsonb NOT NULL CHECK(jsonb_typeof(request)='object' AND octet_length(request::text)<=8192),
 manifest jsonb NOT NULL CHECK(jsonb_typeof(manifest)='object' AND octet_length(manifest::text)<=409600),
 gateway_admission_id text NOT NULL CHECK(length(gateway_admission_id) BETWEEN 1 AND 128),
 admission jsonb NOT NULL CHECK(jsonb_typeof(admission)='object' AND octet_length(admission::text)<=8192),
 prepared_receipt_id text NOT NULL UNIQUE CHECK(length(prepared_receipt_id) BETWEEN 1 AND 128),
 prepared_receipt jsonb NOT NULL CHECK(jsonb_typeof(prepared_receipt)='object' AND octet_length(prepared_receipt::text)<=8192),
 prepared_at timestamptz NOT NULL,
 gateway_commit_id text CHECK(length(gateway_commit_id) BETWEEN 1 AND 128),
 gateway_commit jsonb CHECK(jsonb_typeof(gateway_commit)='object' AND octet_length(gateway_commit::text)<=8192),
 final_receipt_id text UNIQUE CHECK(length(final_receipt_id) BETWEEN 1 AND 128),
 final_receipt jsonb CHECK(jsonb_typeof(final_receipt)='object' AND octet_length(final_receipt::text)<=8192),
 final_at timestamptz,
 node_completion_id text CHECK(length(node_completion_id) BETWEEN 1 AND 128),
 node_completion jsonb CHECK(jsonb_typeof(node_completion)='object' AND octet_length(node_completion::text)<=8192),
 completion_receipt_id text UNIQUE CHECK(length(completion_receipt_id) BETWEEN 1 AND 128),
 completion_receipt jsonb CHECK(jsonb_typeof(completion_receipt)='object' AND octet_length(completion_receipt::text)<=8192),
 completed_at timestamptz,
 PRIMARY KEY(enrollment_id,release_id),
 UNIQUE(enrollment_id,gateway_admission_id),
 UNIQUE(enrollment_id,gateway_commit_id),
 UNIQUE(enrollment_id,node_completion_id),
 FOREIGN KEY(enrollment_id,session_epoch,session_id) REFERENCES gp06f_telemetry_sessions(enrollment_id,session_epoch,session_id) ON DELETE RESTRICT,
 FOREIGN KEY(enrollment_id,signing_key_id) REFERENCES gp06f_telemetry_keys(enrollment_id,key_id) ON DELETE RESTRICT,
 CHECK((from_sequence=0)=(through_sequence=0)),
 CHECK(through_sequence-from_sequence<4096),
 CHECK((gateway_commit_id IS NULL)=(gateway_commit IS NULL) AND (gateway_commit IS NULL)=(final_receipt_id IS NULL) AND (final_receipt_id IS NULL)=(final_receipt IS NULL) AND (final_receipt IS NULL)=(final_at IS NULL)),
 CHECK((node_completion_id IS NULL)=(node_completion IS NULL) AND (node_completion IS NULL)=(completion_receipt_id IS NULL) AND (completion_receipt_id IS NULL)=(completion_receipt IS NULL) AND (completion_receipt IS NULL)=(completed_at IS NULL)),
 CHECK(completed_at IS NULL OR final_at IS NOT NULL)
);
CREATE UNIQUE INDEX gp06f_telemetry_one_pending_release ON gp06f_telemetry_retirements(enrollment_id,session_epoch) WHERE completed_at IS NULL;
CREATE INDEX gp06f_telemetry_recent_releases ON gp06f_telemetry_retirements(enrollment_id,session_epoch,through_sequence DESC);
CREATE FUNCTION gp06f_telemetry_retirement_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE expired numeric;
BEGIN
 IF TG_OP='DELETE' THEN
  SELECT retirement_receipts_expired_through INTO expired FROM gp06f_telemetry_sessions WHERE enrollment_id=OLD.enrollment_id AND session_epoch=OLD.session_epoch;
  IF OLD.completed_at IS NULL OR OLD.through_sequence=0 OR expired<OLD.through_sequence THEN
   RAISE EXCEPTION 'ownership proof is not eligible for bounded receipt retirement' USING ERRCODE='23514';
  END IF;
  RETURN OLD;
 END IF;
 IF ROW(NEW.enrollment_id,NEW.release_id,NEW.session_epoch,NEW.session_id,NEW.signing_key_id,NEW.from_sequence,NEW.through_sequence,NEW.release_digest,NEW.manifest_digest,NEW.request,NEW.manifest,NEW.gateway_admission_id,NEW.admission,NEW.prepared_receipt_id,NEW.prepared_receipt,NEW.prepared_at)
 IS DISTINCT FROM ROW(OLD.enrollment_id,OLD.release_id,OLD.session_epoch,OLD.session_id,OLD.signing_key_id,OLD.from_sequence,OLD.through_sequence,OLD.release_digest,OLD.manifest_digest,OLD.request,OLD.manifest,OLD.gateway_admission_id,OLD.admission,OLD.prepared_receipt_id,OLD.prepared_receipt,OLD.prepared_at)
 OR (OLD.final_at IS NOT NULL AND ROW(NEW.gateway_commit_id,NEW.gateway_commit,NEW.final_receipt_id,NEW.final_receipt,NEW.final_at) IS DISTINCT FROM ROW(OLD.gateway_commit_id,OLD.gateway_commit,OLD.final_receipt_id,OLD.final_receipt,OLD.final_at))
 OR (OLD.completed_at IS NOT NULL AND ROW(NEW.node_completion_id,NEW.node_completion,NEW.completion_receipt_id,NEW.completion_receipt,NEW.completed_at) IS DISTINCT FROM ROW(OLD.node_completion_id,OLD.node_completion,OLD.completion_receipt_id,OLD.completion_receipt,OLD.completed_at))
 THEN RAISE EXCEPTION 'ownership retirement identity is immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER gp06f_telemetry_retirement_immutable BEFORE UPDATE OR DELETE ON gp06f_telemetry_retirements FOR EACH ROW EXECUTE FUNCTION gp06f_telemetry_retirement_immutable();
CREATE FUNCTION gp06f_telemetry_retirement_progress() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.released_through<OLD.released_through OR NEW.node_completed_through<OLD.node_completed_through OR NEW.retirement_receipts_expired_through<OLD.retirement_receipts_expired_through OR (OLD.empty_release_completed AND NOT NEW.empty_release_completed) OR (OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at)
 THEN RAISE EXCEPTION 'ownership retirement progress is monotonic' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER gp06f_telemetry_retirement_progress BEFORE UPDATE ON gp06f_telemetry_sessions FOR EACH ROW EXECUTE FUNCTION gp06f_telemetry_retirement_progress();
CREATE FUNCTION gp06f_telemetry_key_archive() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.archived_at IS NOT NULL AND (NEW.archived_at IS DISTINCT FROM OLD.archived_at OR NEW.state IS DISTINCT FROM OLD.state)
 THEN RAISE EXCEPTION 'archived signing authority is permanent' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER gp06f_telemetry_key_archive BEFORE UPDATE ON gp06f_telemetry_keys FOR EACH ROW EXECUTE FUNCTION gp06f_telemetry_key_archive();
CREATE FUNCTION gp06f_telemetry_epoch_retirement_progress() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.retired_through_epoch<OLD.retired_through_epoch
 THEN RAISE EXCEPTION 'retired session epoch is monotonic' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER gp06f_telemetry_epoch_retirement_progress BEFORE UPDATE ON gp06f_telemetry_enrollments FOR EACH ROW EXECUTE FUNCTION gp06f_telemetry_epoch_retirement_progress();
