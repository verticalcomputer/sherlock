-- Additive fixture.v1 telemetry history only. No collection results, ordinary
-- observations/projections, availability, diagnostic or repair authority.
CREATE TABLE gp06f_telemetry_enrollments (
 enrollment_id text PRIMARY KEY CHECK(length(enrollment_id) BETWEEN 1 AND 128),
 cluster_id text NOT NULL REFERENCES clusters(cluster_id) ON DELETE RESTRICT,
 node_id text NOT NULL CHECK(length(node_id) BETWEEN 1 AND 128),
 inventory_revision_id text NOT NULL,
 gateway_collector_id text NOT NULL REFERENCES collectors(collector_id) ON DELETE RESTRICT,
 enrollment_revision bigint NOT NULL DEFAULT 1 CHECK(enrollment_revision=1),
 control_revision bigint NOT NULL DEFAULT 1 CHECK(control_revision>0),
 status text NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','REVOKED')),
 agent_version text NOT NULL CHECK(length(agent_version) BETWEEN 1 AND 128),
 build_sha256 text NOT NULL CHECK(build_sha256 ~ '^[0-9a-f]{64}$'),
 gateway_spki_sha256 text NOT NULL CHECK(gateway_spki_sha256 ~ '^[0-9a-f]{64}$'),
 highest_epoch numeric(20,0) NOT NULL DEFAULT 0 CHECK(highest_epoch BETWEEN 0 AND 18446744073709551615),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 revoked_at timestamptz,
 UNIQUE(cluster_id,enrollment_id),
 FOREIGN KEY(cluster_id,inventory_revision_id) REFERENCES goodput_inventory_revisions(cluster_id,revision_id) ON DELETE RESTRICT,
 CHECK((status='REVOKED')=(revoked_at IS NOT NULL))
);
CREATE UNIQUE INDEX gp06f_telemetry_active_node ON gp06f_telemetry_enrollments(cluster_id,node_id) WHERE status='ACTIVE';
CREATE TABLE gp06f_telemetry_sources (
 cluster_id text NOT NULL,
 enrollment_id text NOT NULL,
 source_id text NOT NULL,
 schema_version integer NOT NULL CHECK(schema_version=1),
 profile_id text NOT NULL CHECK(profile_id='fixture.v1'),
 PRIMARY KEY(enrollment_id,source_id),
 FOREIGN KEY(cluster_id,enrollment_id) REFERENCES gp06f_telemetry_enrollments(cluster_id,enrollment_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,source_id) REFERENCES sources(cluster_id,source_id) ON DELETE RESTRICT
);
CREATE TABLE gp06f_telemetry_keys (
 enrollment_id text NOT NULL REFERENCES gp06f_telemetry_enrollments(enrollment_id) ON DELETE RESTRICT,
 key_id text NOT NULL CHECK(length(key_id) BETWEEN 1 AND 128),
 key_epoch numeric(20,0) NOT NULL CHECK(key_epoch BETWEEN 1 AND 18446744073709551615),
 public_key bytea NOT NULL CHECK(octet_length(public_key)=32),
 state text NOT NULL CHECK(state IN ('ACTIVE','VERIFY_ONLY','REVOKED')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(enrollment_id,key_id),
 UNIQUE(enrollment_id,key_epoch)
);
CREATE UNIQUE INDEX gp06f_telemetry_active_key ON gp06f_telemetry_keys(enrollment_id) WHERE state='ACTIVE';
CREATE TABLE gp06f_telemetry_sessions (
 enrollment_id text NOT NULL REFERENCES gp06f_telemetry_enrollments(enrollment_id) ON DELETE RESTRICT,
 session_epoch numeric(20,0) NOT NULL CHECK(session_epoch BETWEEN 1 AND 18446744073709551615),
 session_id text NOT NULL CHECK(length(session_id) BETWEEN 1 AND 128),
 boot_id text NOT NULL CHECK(length(boot_id) BETWEEN 1 AND 128),
 key_id text NOT NULL,
 opened_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 finalized_at timestamptz,
 last_allocated_sequence numeric(20,0) CHECK(last_allocated_sequence BETWEEN 0 AND 18446744073709551615),
 highest_received_sequence numeric(20,0) NOT NULL DEFAULT 0 CHECK(highest_received_sequence BETWEEN 0 AND 18446744073709551615),
 retired_at timestamptz,
 PRIMARY KEY(enrollment_id,session_epoch),
 UNIQUE(enrollment_id,session_id),
 UNIQUE(enrollment_id,session_epoch,session_id),
 UNIQUE(enrollment_id,boot_id,key_id),
 FOREIGN KEY(enrollment_id,key_id) REFERENCES gp06f_telemetry_keys(enrollment_id,key_id) ON DELETE RESTRICT,
 CHECK((finalized_at IS NULL)=(last_allocated_sequence IS NULL)),
 CHECK(retired_at IS NULL OR finalized_at IS NOT NULL)
);
CREATE TABLE gp06f_telemetry_lifecycle (
 enrollment_id text NOT NULL,
 session_epoch numeric(20,0) NOT NULL,
 session_id text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('OPEN','FINALIZE')),
 digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 message jsonb NOT NULL CHECK(jsonb_typeof(message)='object' AND octet_length(message::text)<=2097152),
 receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object' AND octet_length(receipt::text)<=4096),
 receipt_id text NOT NULL UNIQUE CHECK(length(receipt_id) BETWEEN 1 AND 128),
 stored_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(enrollment_id,session_epoch,kind),
 FOREIGN KEY(enrollment_id,session_epoch,session_id) REFERENCES gp06f_telemetry_sessions(enrollment_id,session_epoch,session_id) ON DELETE RESTRICT
);
CREATE TABLE gp06f_telemetry_batches (
 enrollment_id text NOT NULL,
 session_epoch numeric(20,0) NOT NULL,
 session_id text NOT NULL,
 sequence numeric(20,0) NOT NULL CHECK(sequence BETWEEN 1 AND 18446744073709551615),
 digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 gateway_receipt_id text NOT NULL CHECK(length(gateway_receipt_id) BETWEEN 1 AND 128),
 receipt_id text NOT NULL UNIQUE CHECK(length(receipt_id) BETWEEN 1 AND 128),
 body jsonb NOT NULL CHECK(jsonb_typeof(body)='object' AND octet_length(body::text)<=2097152),
 history_only boolean NOT NULL,
 stored_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(enrollment_id,session_epoch,sequence),
 FOREIGN KEY(enrollment_id,session_epoch,session_id) REFERENCES gp06f_telemetry_sessions(enrollment_id,session_epoch,session_id) ON DELETE RESTRICT
);
CREATE INDEX gp06f_telemetry_batch_history ON gp06f_telemetry_batches(enrollment_id,stored_at DESC,session_epoch DESC,sequence DESC);
-- These facts remain immutable even when a later batch fills a declared loss.
CREATE TABLE gp06f_telemetry_loss (
 enrollment_id text NOT NULL,
 loss_id text NOT NULL CHECK(length(loss_id) BETWEEN 1 AND 128),
 session_epoch numeric(20,0) NOT NULL,
 session_id text NOT NULL,
 source_id text NOT NULL,
 from_sequence numeric(20,0) NOT NULL CHECK(from_sequence BETWEEN 1 AND 18446744073709551615),
 through_sequence numeric(20,0) NOT NULL CHECK(through_sequence BETWEEN from_sequence AND 18446744073709551615),
 fact jsonb NOT NULL CHECK(jsonb_typeof(fact)='object' AND octet_length(fact::text)<=4096),
 stored_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(enrollment_id,loss_id),
 FOREIGN KEY(enrollment_id,source_id) REFERENCES gp06f_telemetry_sources(enrollment_id,source_id) ON DELETE RESTRICT,
 FOREIGN KEY(enrollment_id,session_epoch,session_id) REFERENCES gp06f_telemetry_sessions(enrollment_id,session_epoch,session_id) ON DELETE RESTRICT
);
CREATE INDEX gp06f_telemetry_loss_history ON gp06f_telemetry_loss(enrollment_id,session_epoch,stored_at DESC,loss_id);
-- Bounded rebuildable interval ledger; RECEIVED means cloud receipt, LOST is
-- source-specific. Highest sequence never stands in for holes or coverage.
CREATE TABLE gp06f_telemetry_intervals (
 enrollment_id text NOT NULL,
 session_epoch numeric(20,0) NOT NULL,
 source_id text NOT NULL DEFAULT '',
 kind text NOT NULL CHECK(kind IN ('RECEIVED','LOST')),
 from_sequence numeric(20,0) NOT NULL CHECK(from_sequence BETWEEN 1 AND 18446744073709551615),
 through_sequence numeric(20,0) NOT NULL CHECK(through_sequence BETWEEN from_sequence AND 18446744073709551615),
 PRIMARY KEY(enrollment_id,session_epoch,kind,source_id,from_sequence),
 FOREIGN KEY(enrollment_id,session_epoch) REFERENCES gp06f_telemetry_sessions(enrollment_id,session_epoch) ON DELETE RESTRICT,
 CHECK((kind='RECEIVED')=(source_id=''))
);
CREATE TABLE gp06f_telemetry_audit (
 audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 enrollment_id text NOT NULL REFERENCES gp06f_telemetry_enrollments(enrollment_id) ON DELETE RESTRICT,
 control_revision bigint NOT NULL CHECK(control_revision>0),
 action text NOT NULL CHECK(action IN ('ENROLLED','REVOKED','KEY_ROTATED','KEY_COMPROMISED')),
 actor text NOT NULL CHECK(length(actor) BETWEEN 1 AND 128),
 actor_kind text NOT NULL DEFAULT 'LOCAL_OPERATOR' CHECK(actor_kind='LOCAL_OPERATOR'),
 details jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(details)='object' AND octet_length(details::text)<=4096),
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION gp06f_telemetry_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'telemetry historical evidence is immutable' USING ERRCODE='23514'; END $$;
CREATE TRIGGER gp06f_telemetry_sources_immutable BEFORE UPDATE OR DELETE ON gp06f_telemetry_sources FOR EACH ROW EXECUTE FUNCTION gp06f_telemetry_immutable();
CREATE TRIGGER gp06f_telemetry_lifecycle_immutable BEFORE UPDATE OR DELETE ON gp06f_telemetry_lifecycle FOR EACH ROW EXECUTE FUNCTION gp06f_telemetry_immutable();
CREATE TRIGGER gp06f_telemetry_batches_immutable BEFORE UPDATE OR DELETE ON gp06f_telemetry_batches FOR EACH ROW EXECUTE FUNCTION gp06f_telemetry_immutable();
CREATE TRIGGER gp06f_telemetry_loss_immutable BEFORE UPDATE OR DELETE ON gp06f_telemetry_loss FOR EACH ROW EXECUTE FUNCTION gp06f_telemetry_immutable();
CREATE TRIGGER gp06f_telemetry_audit_immutable BEFORE UPDATE OR DELETE ON gp06f_telemetry_audit FOR EACH ROW EXECUTE FUNCTION gp06f_telemetry_immutable();
CREATE FUNCTION gp06f_telemetry_enrollment_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.enrollment_id,NEW.cluster_id,NEW.node_id,NEW.inventory_revision_id,NEW.gateway_collector_id,NEW.enrollment_revision,NEW.agent_version,NEW.build_sha256,NEW.gateway_spki_sha256,NEW.created_at)
 IS DISTINCT FROM ROW(OLD.enrollment_id,OLD.cluster_id,OLD.node_id,OLD.inventory_revision_id,OLD.gateway_collector_id,OLD.enrollment_revision,OLD.agent_version,OLD.build_sha256,OLD.gateway_spki_sha256,OLD.created_at)
 THEN RAISE EXCEPTION 'telemetry enrollment scope is immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER gp06f_telemetry_enrollment_immutable BEFORE UPDATE ON gp06f_telemetry_enrollments FOR EACH ROW EXECUTE FUNCTION gp06f_telemetry_enrollment_immutable();
CREATE FUNCTION gp06f_telemetry_key_identity_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.enrollment_id,NEW.key_id,NEW.key_epoch,NEW.public_key,NEW.created_at)
 IS DISTINCT FROM ROW(OLD.enrollment_id,OLD.key_id,OLD.key_epoch,OLD.public_key,OLD.created_at)
 THEN RAISE EXCEPTION 'telemetry signing identity is immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER gp06f_telemetry_key_identity_immutable BEFORE UPDATE ON gp06f_telemetry_keys FOR EACH ROW EXECUTE FUNCTION gp06f_telemetry_key_identity_immutable();
CREATE FUNCTION gp06f_telemetry_session_identity_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.enrollment_id,NEW.session_epoch,NEW.session_id,NEW.boot_id,NEW.key_id,NEW.opened_at)
 IS DISTINCT FROM ROW(OLD.enrollment_id,OLD.session_epoch,OLD.session_id,OLD.boot_id,OLD.key_id,OLD.opened_at)
 OR (OLD.finalized_at IS NOT NULL AND ROW(NEW.finalized_at,NEW.last_allocated_sequence) IS DISTINCT FROM ROW(OLD.finalized_at,OLD.last_allocated_sequence))
 THEN RAISE EXCEPTION 'telemetry session identity is immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER gp06f_telemetry_session_identity_immutable BEFORE UPDATE ON gp06f_telemetry_sessions FOR EACH ROW EXECUTE FUNCTION gp06f_telemetry_session_identity_immutable();
