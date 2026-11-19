-- Separate continuous production lifecycle. No enrollment or publication is
-- enabled by migration, and the shadow role receives no additional privileges.
CREATE TABLE production_assessment_enrollments (
 enrollment_id text PRIMARY KEY CHECK(length(enrollment_id) BETWEEN 1 AND 128),
 cluster_id text NOT NULL,
 source_id text NOT NULL,
 category text NOT NULL,
 config jsonb NOT NULL CHECK(octet_length(config::text)<=65536),
 config_hash text NOT NULL CHECK(config_hash ~ '^[0-9a-f]{64}$'),
 revision bigint NOT NULL CHECK(revision>0),
 retained_events bigint NOT NULL DEFAULT 0 CHECK(retained_events BETWEEN 0 AND 10000),
 retained_bytes bigint NOT NULL DEFAULT 0 CHECK(retained_bytes BETWEEN 0 AND 536870912),
 notifications_enabled boolean NOT NULL DEFAULT false,
 notifications_enabled_at timestamptz,
 evidence_base_url text NOT NULL CHECK(length(evidence_base_url)<=512),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(cluster_id,source_id) REFERENCES sources(cluster_id,source_id),
 UNIQUE(enrollment_id,cluster_id)
);
CREATE TABLE production_assessment_states (
 enrollment_id text NOT NULL REFERENCES production_assessment_enrollments,
 asset text NOT NULL CHECK(length(asset)<=256),
 cluster_id text NOT NULL,
 source_id text NOT NULL,
 category text NOT NULL,
 snapshot bytea NOT NULL DEFAULT '' CHECK(octet_length(snapshot)<=16777216),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 next_due_at timestamptz,
 last_attempt_at timestamptz,
 last_failure_code text NOT NULL DEFAULT '' CHECK(length(last_failure_code)<=64),
 last_failure_at timestamptz,
 failure_count bigint NOT NULL DEFAULT 0,
 PRIMARY KEY(enrollment_id,asset),
 UNIQUE(cluster_id,source_id,category,asset),
 FOREIGN KEY(enrollment_id,cluster_id) REFERENCES production_assessment_enrollments(enrollment_id,cluster_id)
);
CREATE TABLE production_assessment_decisions (
 event_id text PRIMARY KEY CHECK(event_id ~ '^[0-9a-f]{64}$'),
 enrollment_id text NOT NULL REFERENCES production_assessment_enrollments,
 occurrence_id text NOT NULL CHECK(occurrence_id ~ '^[0-9a-f]{64}$'),
 asset text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('TERMINAL','UPDATE','RECOVER')),
 logical_at timestamptz NOT NULL,
 committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 closed_at timestamptz,
 evidence bytea NOT NULL CHECK(octet_length(evidence)<=4194304),
 evidence_hash text NOT NULL CHECK(evidence_hash ~ '^[0-9a-f]{64}$'),
 FOREIGN KEY(enrollment_id,asset) REFERENCES production_assessment_states(enrollment_id,asset)
);
CREATE INDEX production_assessment_decisions_occurrence ON production_assessment_decisions(enrollment_id,occurrence_id);
CREATE INDEX production_assessment_decisions_retention ON production_assessment_decisions(closed_at) WHERE closed_at IS NOT NULL;
CREATE TABLE production_assessment_controls (
 enrollment_id text NOT NULL REFERENCES production_assessment_enrollments,
 revision bigint NOT NULL,
 notifications_enabled boolean NOT NULL,
 actor text NOT NULL DEFAULT 'configuration' CHECK(length(actor) BETWEEN 1 AND 128),
 changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(enrollment_id,revision)
);

CREATE FUNCTION production_assessment_retained_capacity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  UPDATE production_assessment_enrollments SET retained_events=retained_events+1,retained_bytes=retained_bytes+octet_length(NEW.evidence) WHERE enrollment_id=NEW.enrollment_id;
  RETURN NEW;
 ELSE
  UPDATE production_assessment_enrollments SET retained_events=retained_events-1,retained_bytes=retained_bytes-octet_length(OLD.evidence) WHERE enrollment_id=OLD.enrollment_id;
  RETURN OLD;
 END IF;
END $$;
CREATE TRIGGER production_assessment_retained_capacity AFTER INSERT OR DELETE ON production_assessment_decisions FOR EACH ROW EXECUTE FUNCTION production_assessment_retained_capacity();

-- Preserve the existing shadow role's executable-routine allow-list. Trigger
-- execution uses its installed binding; no caller EXECUTE grant is required.
REVOKE EXECUTE ON FUNCTION public.production_assessment_retained_capacity() FROM PUBLIC;
