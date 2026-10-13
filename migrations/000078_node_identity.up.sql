-- CSR-bound bootstrap only; no workload, telemetry-source or repair authority.
-- Hashes are domain-separated random bearer-token digests; raw tokens never persist.
CREATE TABLE gp06f_node_bootstrap (
 token_hash text PRIMARY KEY CHECK(token_hash ~ '^[0-9a-f]{64}$'),
 enrollment_id text NOT NULL,
 key_id text NOT NULL,
 enrollment_revision bigint NOT NULL CHECK(enrollment_revision=1),
 minted_control_revision bigint NOT NULL CHECK(minted_control_revision>0),
 csr_sha256 text NOT NULL CHECK(csr_sha256 ~ '^[0-9a-f]{64}$'),
 spki_sha256 text NOT NULL CHECK(spki_sha256 ~ '^[0-9a-f]{64}$'),
 request jsonb NOT NULL CHECK(jsonb_typeof(request)='object' AND octet_length(request::text)<=49152),
 minted_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK(expires_at>minted_at AND expires_at<=minted_at+interval '10 minutes'),
 consumed_at timestamptz,
 certificate_expires_at timestamptz,
 bundle jsonb CHECK(jsonb_typeof(bundle)='object' AND octet_length(bundle::text)<=65536),
 FOREIGN KEY(enrollment_id,key_id) REFERENCES gp06f_telemetry_keys(enrollment_id,key_id) ON DELETE RESTRICT,
 CHECK((consumed_at IS NULL)=(bundle IS NULL)),
 CHECK((consumed_at IS NULL)=(certificate_expires_at IS NULL)),
 CHECK(consumed_at IS NULL OR (consumed_at<expires_at AND certificate_expires_at>consumed_at AND certificate_expires_at<=consumed_at+interval '24 hours'))
);
CREATE INDEX gp06f_node_bootstrap_enrollment ON gp06f_node_bootstrap(enrollment_id,minted_at DESC);
CREATE TABLE gp06f_node_identity_audit (
 audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 token_hash text NOT NULL REFERENCES gp06f_node_bootstrap(token_hash) ON DELETE RESTRICT,
 enrollment_id text NOT NULL REFERENCES gp06f_telemetry_enrollments(enrollment_id) ON DELETE RESTRICT,
 control_revision bigint NOT NULL CHECK(control_revision>0),
 action text NOT NULL CHECK(action IN ('BOOTSTRAP_MINTED','CERTIFICATE_ISSUED')),
 actor text NOT NULL CHECK(length(actor) BETWEEN 1 AND 128),
 actor_kind text NOT NULL CHECK(actor_kind IN ('LOCAL_OPERATOR','AUTHENTICATED_COLLECTOR')),
 occurred_at timestamptz NOT NULL
);
CREATE TRIGGER gp06f_node_identity_audit_immutable BEFORE UPDATE OR DELETE ON gp06f_node_identity_audit FOR EACH ROW EXECUTE FUNCTION gp06f_telemetry_immutable();
CREATE FUNCTION gp06f_node_bootstrap_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'node bootstrap retention is not qualified' USING ERRCODE='23514'; END IF;
 IF ROW(NEW.token_hash,NEW.enrollment_id,NEW.key_id,NEW.enrollment_revision,NEW.minted_control_revision,NEW.csr_sha256,NEW.spki_sha256,NEW.request,NEW.minted_at,NEW.expires_at)
 IS DISTINCT FROM ROW(OLD.token_hash,OLD.enrollment_id,OLD.key_id,OLD.enrollment_revision,OLD.minted_control_revision,OLD.csr_sha256,OLD.spki_sha256,OLD.request,OLD.minted_at,OLD.expires_at)
 OR OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL
 THEN RAISE EXCEPTION 'node bootstrap identity is immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER gp06f_node_bootstrap_immutable BEFORE UPDATE OR DELETE ON gp06f_node_bootstrap FOR EACH ROW EXECUTE FUNCTION gp06f_node_bootstrap_immutable();
