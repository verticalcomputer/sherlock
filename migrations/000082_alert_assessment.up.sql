-- Assessment is an isolated experiment. These objects confer no production
-- mutation or notification authority. Canonical payload bytes remain bytea.
CREATE FUNCTION assessment_sorted_set(v text[], cap integer) RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
 SELECT v IS NOT NULL AND cardinality(v)<=cap AND NOT EXISTS(SELECT 1 FROM unnest(v) x WHERE x IS NULL OR octet_length(x)=0 OR octet_length(x)>128)
 AND v=COALESCE((SELECT array_agg(x ORDER BY x COLLATE "C") FROM (SELECT DISTINCT unnest(v) x) s),'{}'::text[])
$$;
CREATE TABLE assessment_runs (
 run_id text PRIMARY KEY CHECK(octet_length(run_id) BETWEEN 1 AND 128),
 config bytea NOT NULL CHECK(octet_length(config)<=65536), config_hash text NOT NULL CHECK(config_hash ~ '^[0-9a-f]{64}$'),
 input_config_hash text CHECK(input_config_hash ~ '^[0-9a-f]{64}$'),
 descriptor bytea NOT NULL CHECK(octet_length(descriptor)<=16384), descriptor_hash text NOT NULL CHECK(descriptor_hash ~ '^[0-9a-f]{64}$'), build_hash text NOT NULL CHECK(build_hash ~ '^[0-9a-f]{64}$'),
 mode text NOT NULL CHECK(mode IN ('replay','shadow')),state text NOT NULL CHECK(state IN ('ACTIVE','DRAINING','CLOSED')),
 start_at timestamptz NOT NULL,admission_end_at timestamptz NOT NULL,stopped_at timestamptz,stop_reason text,closed_at timestamptz,last_success_at timestamptz,
 payload_bytes bigint NOT NULL DEFAULT 0 CHECK(payload_bytes BETWEEN 0 AND 536870912),fact_count bigint NOT NULL DEFAULT 0 CHECK(fact_count BETWEEN 0 AND 200000),physical_count bigint NOT NULL DEFAULT 0 CHECK(physical_count BETWEEN 0 AND 256),record_count bigint NOT NULL DEFAULT 0 CHECK(record_count BETWEEN 0 AND 1000000),overflow_count bigint NOT NULL DEFAULT 0 CHECK(overflow_count>=0),unknown_from timestamptz,unknown_through timestamptz,
 coverage bytea NOT NULL DEFAULT convert_to('[]','UTF8') CHECK(octet_length(coverage)<=262144),incomplete_count bigint NOT NULL DEFAULT 0 CHECK(incomplete_count>=0),followup_truncated boolean NOT NULL DEFAULT false,
 CHECK(admission_end_at>start_at AND admission_end_at<=start_at+interval '24 hours'),
 CHECK((state='CLOSED')=(closed_at IS NOT NULL)),CHECK((state='ACTIVE')=(stopped_at IS NULL)),CHECK((stopped_at IS NULL)=(stop_reason IS NULL)),
 CHECK(stopped_at IS NULL OR stopped_at>=start_at),CHECK(closed_at IS NULL OR closed_at>=stopped_at),CHECK((unknown_from IS NULL)=(unknown_through IS NULL)),CHECK(unknown_from IS NULL OR unknown_from<=unknown_through)
);
CREATE UNIQUE INDEX assessment_one_open_run ON assessment_runs((1)) WHERE state<>'CLOSED';
CREATE TABLE assessment_enrollments (
 run_id text NOT NULL REFERENCES assessment_runs ON DELETE RESTRICT,category text NOT NULL CHECK(octet_length(category) BETWEEN 1 AND 128),asset text NOT NULL CHECK(octet_length(asset) BETWEEN 1 AND 256),node_id text NOT NULL,gpu_uuid text NOT NULL,inventory_revision text NOT NULL,
 bindings bytea NOT NULL CHECK(octet_length(bindings)<=8192),discovery_floor timestamptz NOT NULL,next_due_at timestamptz NOT NULL,last_attempt_at timestamptz,sequence bigint NOT NULL CHECK(sequence>=0),revision bigint NOT NULL CHECK(revision>0),rearm_eligible boolean NOT NULL,
 tracker bytea CHECK(octet_length(tracker)<=16384),tracker_hash text CHECK(tracker_hash ~ '^[0-9a-f]{64}$'),PRIMARY KEY(run_id,category,asset),CHECK((tracker IS NULL)=(tracker_hash IS NULL))
);
CREATE INDEX assessment_enrollment_due ON assessment_enrollments(next_due_at,last_attempt_at,asset);
CREATE TABLE assessment_facts (
 run_id text NOT NULL REFERENCES assessment_runs ON DELETE RESTRICT,id text NOT NULL CHECK(id ~ '^[0-9a-f]{64}$'),asset text NOT NULL CHECK(octet_length(asset) BETWEEN 1 AND 256),kind text NOT NULL CHECK(kind IN ('SAMPLE','PROVENANCE','COVERAGE','QUALIFIED','CONFLICT','TRACKER_CONTEXT','FEATURE')),available_at timestamptz NOT NULL,
 body bytea NOT NULL CHECK(octet_length(body)<=CASE kind WHEN 'FEATURE' THEN 65536 WHEN 'TRACKER_CONTEXT' THEN 24576 ELSE 16384 END),PRIMARY KEY(run_id,id),UNIQUE(run_id,asset,id)
);
CREATE INDEX assessment_fact_time ON assessment_facts(run_id,asset,available_at,id);
CREATE INDEX assessment_fact_qualified ON assessment_facts(run_id,asset,available_at,id) WHERE kind='QUALIFIED';
-- Canonical source timestamps are UTC. Pin parsing independently of session settings.
CREATE FUNCTION assessment_sample_source(bytea) RETURNS timestamptz LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET TimeZone='UTC' AS $$SELECT (convert_from($1,'UTF8')::jsonb#>>'{body,source_at}')::timestamptz$$;
CREATE INDEX assessment_fact_source ON assessment_facts(run_id,asset,assessment_sample_source(body),id) WHERE kind='SAMPLE';

CREATE TABLE assessment_bundles (
 run_id text NOT NULL REFERENCES assessment_runs ON DELETE RESTRICT,id text NOT NULL CHECK(id ~ '^[0-9a-f]{64}$'),asset text NOT NULL CHECK(octet_length(asset) BETWEEN 1 AND 256),logical_at timestamptz NOT NULL,availability_cutoff timestamptz NOT NULL,body bytea NOT NULL CHECK(octet_length(body)<=262144),PRIMARY KEY(run_id,id),UNIQUE(run_id,asset,id),CHECK(availability_cutoff<=logical_at)
);
CREATE INDEX assessment_bundle_time ON assessment_bundles(run_id,asset,logical_at,id);
CREATE TABLE assessment_candidates (
 run_id text NOT NULL REFERENCES assessment_runs ON DELETE RESTRICT,id text NOT NULL CHECK(id ~ '^[0-9a-f]{64}$'),category text NOT NULL,asset text NOT NULL,sequence bigint NOT NULL CHECK(sequence>0),budget_ms bigint NOT NULL CHECK(budget_ms IN (0,15000,30000,60000,120000)),revision bigint NOT NULL CHECK(revision>0),phase text NOT NULL CHECK(phase IN ('OBSERVING','FINAL','QUARANTINED')),
 entered_at timestamptz NOT NULL,due_at timestamptz NOT NULL,entry_bundle text NOT NULL,entry bytea NOT NULL CHECK(octet_length(entry)<=8192),initial_state bytea NOT NULL CHECK(octet_length(initial_state)<=16384),initial_hash text NOT NULL CHECK(initial_hash ~ '^[0-9a-f]{64}$'),state bytea NOT NULL CHECK(octet_length(state)<=16384),state_hash text NOT NULL CHECK(state_hash ~ '^[0-9a-f]{64}$'),terminal_id text CHECK(terminal_id ~ '^[0-9a-f]{64}$'),terminal bytea CHECK(octet_length(terminal)<=8192),reserved_codes text[] NOT NULL DEFAULT '{}' CHECK(assessment_sorted_set(reserved_codes,8)),
 PRIMARY KEY(run_id,id),UNIQUE(run_id,category,asset,sequence,budget_ms),FOREIGN KEY(run_id,category,asset) REFERENCES assessment_enrollments ON DELETE RESTRICT,FOREIGN KEY(run_id,asset,entry_bundle) REFERENCES assessment_bundles(run_id,asset,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 CHECK(due_at=entered_at+budget_ms*interval '1 millisecond'),CHECK((terminal IS NULL)=(terminal_id IS NULL)),CHECK((phase='FINAL')=(terminal IS NOT NULL))
);
CREATE INDEX assessment_candidate_due ON assessment_candidates(due_at,id) WHERE phase='OBSERVING';
CREATE TABLE assessment_decisions (
 run_id text NOT NULL REFERENCES assessment_runs ON DELETE RESTRICT,id text NOT NULL CHECK(id ~ '^[0-9a-f]{64}$'),candidate_id text NOT NULL,kind text NOT NULL CHECK(kind IN ('TERMINAL','UPDATE')),logical_at timestamptz NOT NULL,executed_at timestamptz NOT NULL,committed_at timestamptz NOT NULL,lateness_us bigint NOT NULL CHECK(lateness_us>=0),action text NOT NULL CHECK(action IN ('NONE','INVESTIGATE','URGENT')),decision_source text NOT NULL CHECK(decision_source IN ('CATEGORY','HOST_FALLBACK')),outcome text,host_cause text,failure_code text,bundle_id text NOT NULL,
 codes text[] NOT NULL CHECK(assessment_sorted_set(codes,8)),reasons text[] NOT NULL CHECK(assessment_sorted_set(reasons,8)),support text[] NOT NULL CHECK(assessment_sorted_set(support,32)),summary text NOT NULL CHECK(octet_length(summary)<=2048),details bytea CHECK(octet_length(details)<=4096),details_hash text CHECK(details_hash ~ '^[0-9a-f]{64}$'),metadata bytea NOT NULL CHECK(octet_length(metadata)<=8192),PRIMARY KEY(run_id,id),
 FOREIGN KEY(run_id,candidate_id) REFERENCES assessment_candidates ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,FOREIGN KEY(run_id,bundle_id) REFERENCES assessment_bundles ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 CHECK((details IS NULL)=(details_hash IS NULL)),CHECK((kind='TERMINAL')=(cardinality(codes)=0)),CHECK(logical_at<=executed_at AND executed_at<=committed_at),
 CHECK((decision_source='CATEGORY' AND host_cause IS NULL AND ((kind='TERMINAL' AND outcome IS NOT NULL) OR (kind='UPDATE' AND outcome IS NULL))) OR (decision_source='HOST_FALLBACK' AND kind='TERMINAL' AND action='INVESTIGATE' AND outcome IS NULL AND host_cause IS NOT NULL AND host_cause='DEADLINE_FALLBACK' AND failure_code IS NOT NULL))
);
CREATE UNIQUE INDEX assessment_terminal_once ON assessment_decisions(run_id,candidate_id) WHERE kind='TERMINAL';
CREATE TABLE assessment_failures (
 run_id text NOT NULL REFERENCES assessment_runs ON DELETE RESTRICT,id text NOT NULL CHECK(id ~ '^[0-9a-f]{64}$'),category text,asset text,kind text NOT NULL CHECK(kind IN ('COMPONENT','COVERAGE','QUALIFIED_TELEMETRY')),code text NOT NULL,scope_key text NOT NULL,first_at timestamptz NOT NULL,last_at timestamptz NOT NULL,count bigint NOT NULL CHECK(count>0),body bytea NOT NULL CHECK(octet_length(body)<=16384),PRIMARY KEY(run_id,id),CHECK(last_at>=first_at)
);
CREATE INDEX assessment_failure_time ON assessment_failures(run_id,asset,first_at,id);

CREATE FUNCTION assessment_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r assessment_runs; oldj jsonb;newj jsonb;oldbody jsonb;newbody jsonb;
BEGIN
 IF TG_OP='DELETE' THEN
  IF TG_TABLE_NAME='assessment_runs' THEN r:=OLD; ELSE SELECT * INTO STRICT r FROM assessment_runs WHERE run_id=OLD.run_id FOR UPDATE; END IF;
  IF r.state<>'CLOSED' OR r.closed_at>clock_timestamp()-interval '7 days' THEN RAISE EXCEPTION 'assessment retention protected' USING ERRCODE='23514';END IF;
  RETURN OLD;
 END IF;
 newj:=to_jsonb(NEW);
 IF TG_TABLE_NAME<>'assessment_runs' THEN
  SELECT * INTO STRICT r FROM assessment_runs WHERE run_id=NEW.run_id FOR UPDATE;
  IF r.state='CLOSED' THEN RAISE EXCEPTION 'closed assessment is immutable' USING ERRCODE='23514';END IF;
  IF TG_OP='INSERT' AND TG_TABLE_NAME IN ('assessment_enrollments','assessment_candidates') AND r.state<>'ACTIVE' THEN RAISE EXCEPTION 'assessment admission closed' USING ERRCODE='23514';END IF;
 END IF;
 IF TG_TABLE_NAME='assessment_runs' THEN
  IF TG_OP='INSERT' AND (NEW.payload_bytes<>0 OR NEW.fact_count<>0 OR NEW.physical_count<>0 OR NEW.record_count<>0 OR NEW.incomplete_count<>0 OR NEW.state<>'ACTIVE') THEN RAISE EXCEPTION 'assessment counters are derived' USING ERRCODE='23514';END IF;
  IF TG_OP='UPDATE' THEN
   oldj:=to_jsonb(OLD);
   IF pg_trigger_depth()=1 AND (NEW.payload_bytes,NEW.fact_count,NEW.physical_count,NEW.record_count,NEW.incomplete_count) IS DISTINCT FROM (OLD.payload_bytes,OLD.fact_count,OLD.physical_count,OLD.record_count,OLD.incomplete_count) THEN RAISE EXCEPTION 'assessment counters are derived' USING ERRCODE='23514';END IF;
   IF (oldj-ARRAY['state','stopped_at','stop_reason','closed_at','last_success_at','payload_bytes','fact_count','physical_count','record_count','overflow_count','unknown_from','unknown_through','coverage','incomplete_count','followup_truncated']) IS DISTINCT FROM (newj-ARRAY['state','stopped_at','stop_reason','closed_at','last_success_at','payload_bytes','fact_count','physical_count','record_count','overflow_count','unknown_from','unknown_through','coverage','incomplete_count','followup_truncated']) OR OLD.state='CLOSED' AND (oldj-ARRAY['payload_bytes','fact_count','physical_count','record_count','incomplete_count']) IS DISTINCT FROM (newj-ARRAY['payload_bytes','fact_count','physical_count','record_count','incomplete_count']) OR OLD.state='DRAINING' AND NEW.state='ACTIVE' OR OLD.stopped_at IS NOT NULL AND (NEW.stopped_at,NEW.stop_reason) IS DISTINCT FROM (OLD.stopped_at,OLD.stop_reason) THEN RAISE EXCEPTION 'immutable assessment run' USING ERRCODE='23514';END IF;
   IF NEW.state='CLOSED' AND OLD.state<>'CLOSED' AND EXISTS(SELECT 1 FROM assessment_candidates WHERE run_id=NEW.run_id AND phase='OBSERVING') THEN RAISE EXCEPTION 'assessment has pending candidates' USING ERRCODE='23514';END IF;
  END IF;
 ELSIF TG_OP='UPDATE' THEN
  oldj:=to_jsonb(OLD);
  IF TG_TABLE_NAME IN ('assessment_facts','assessment_bundles','assessment_decisions') THEN RAISE EXCEPTION 'immutable assessment evidence' USING ERRCODE='23514';END IF;
  IF TG_TABLE_NAME='assessment_enrollments' THEN
   IF (oldj-ARRAY['discovery_floor','next_due_at','last_attempt_at','sequence','revision','rearm_eligible','tracker','tracker_hash']) IS DISTINCT FROM (newj-ARRAY['discovery_floor','next_due_at','last_attempt_at','sequence','revision','rearm_eligible','tracker','tracker_hash']) OR NEW.revision<OLD.revision OR NEW.sequence<OLD.sequence OR NEW.discovery_floor<OLD.discovery_floor THEN RAISE EXCEPTION 'immutable assessment enrollment' USING ERRCODE='23514';END IF;
  ELSIF TG_TABLE_NAME='assessment_candidates' THEN
   IF (oldj-ARRAY['revision','phase','state','state_hash','terminal_id','terminal','reserved_codes']) IS DISTINCT FROM (newj-ARRAY['revision','phase','state','state_hash','terminal_id','terminal','reserved_codes']) OR OLD.phase='FINAL' AND (oldj-ARRAY['revision','reserved_codes']) IS DISTINCT FROM (newj-ARRAY['revision','reserved_codes']) OR NEW.revision<OLD.revision THEN RAISE EXCEPTION 'immutable assessment candidate' USING ERRCODE='23514';END IF;
  ELSIF TG_TABLE_NAME='assessment_failures' THEN
   IF (oldj-ARRAY['last_at','count','body']) IS DISTINCT FROM (newj-ARRAY['last_at','count','body']) OR NEW.count<OLD.count OR NEW.last_at<OLD.last_at THEN RAISE EXCEPTION 'immutable assessment failure' USING ERRCODE='23514';END IF;
   oldbody:=convert_from(OLD.body,'UTF8')::jsonb;newbody:=convert_from(NEW.body,'UTF8')::jsonb;
   IF OLD.kind='QUALIFIED_TELEMETRY' THEN
    IF (oldbody-'recover_fact') IS DISTINCT FROM (newbody-'recover_fact') OR oldbody ? 'recover_fact' AND oldbody->>'recover_fact' IS DISTINCT FROM newbody->>'recover_fact' THEN RAISE EXCEPTION 'immutable telemetry routing/recovery' USING ERRCODE='23514';END IF;
   ELSIF NEW.body IS DISTINCT FROM OLD.body THEN RAISE EXCEPTION 'immutable first assessment failure evidence' USING ERRCODE='23514';END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
DO $$DECLARE t text;BEGIN FOREACH t IN ARRAY ARRAY['runs','enrollments','facts','bundles','candidates','decisions','failures'] LOOP EXECUTE format('CREATE TRIGGER assessment_guard BEFORE INSERT OR UPDATE OR DELETE ON assessment_%I FOR EACH ROW EXECUTE FUNCTION assessment_guard()',t);END LOOP;END$$;

-- A dependency view lets deferred validation and retention use the same graph.
CREATE VIEW assessment_edges WITH (security_invoker=true) AS
 SELECT f.run_id,'facts'::text AS from_table,f.id AS from_id,'facts'::text AS to_table,x.id AS to_id,f.asset,
 f.available_at AS cutoff FROM assessment_facts f CROSS JOIN LATERAL jsonb_array_elements_text(CASE f.kind WHEN 'FEATURE' THEN convert_from(f.body,'UTF8')::jsonb#>'{body,support}' WHEN 'CONFLICT' THEN convert_from(f.body,'UTF8')::jsonb#>'{body,values}' ELSE '[]'::jsonb END) x(id)
 UNION ALL SELECT f.run_id,'facts',f.id,'facts',convert_from(f.body,'UTF8')::jsonb#>>'{body,sample_id}',f.asset,f.available_at FROM assessment_facts f WHERE kind='PROVENANCE'
 UNION ALL SELECT f.run_id,'facts',f.id,'bundles',convert_from(f.body,'UTF8')::jsonb#>>'{body,bundle_id}',f.asset,f.available_at FROM assessment_facts f WHERE kind='TRACKER_CONTEXT'
 UNION ALL SELECT b.run_id,'bundles',b.id,'facts',x.id,b.asset,b.availability_cutoff FROM assessment_bundles b CROSS JOIN LATERAL jsonb_array_elements_text((convert_from(b.body,'UTF8')::jsonb->'facts')||(convert_from(b.body,'UTF8')::jsonb->'features')) x(id)
 UNION ALL SELECT d.run_id,'decisions',d.id,'facts',x.id,c.asset,d.logical_at FROM assessment_decisions d JOIN assessment_candidates c ON c.run_id=d.run_id AND c.id=d.candidate_id CROSS JOIN LATERAL unnest(d.support) x(id)
 UNION ALL SELECT d.run_id,'decisions',d.id,'bundles',d.bundle_id,c.asset,d.logical_at FROM assessment_decisions d JOIN assessment_candidates c ON c.run_id=d.run_id AND c.id=d.candidate_id
 UNION ALL SELECT c.run_id,'candidates',c.id,'bundles',c.entry_bundle,c.asset,c.entered_at FROM assessment_candidates c
 UNION ALL SELECT f.run_id,'failures',f.id,'facts',x.id,f.asset,CASE WHEN x.id=convert_from(f.body,'UTF8')::jsonb->>'recover_fact' THEN f.last_at ELSE f.first_at END FROM assessment_failures f CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(convert_from(f.body,'UTF8')::jsonb->'fact_ids','[]'::jsonb)||CASE WHEN convert_from(f.body,'UTF8')::jsonb ? 'open_fact' THEN jsonb_build_array(convert_from(f.body,'UTF8')::jsonb->>'open_fact') ELSE '[]'::jsonb END||CASE WHEN convert_from(f.body,'UTF8')::jsonb ? 'recover_fact' THEN jsonb_build_array(convert_from(f.body,'UTF8')::jsonb->>'recover_fact') ELSE '[]'::jsonb END) x(id)
 UNION ALL SELECT f.run_id,'failures',f.id,'bundles',convert_from(f.body,'UTF8')::jsonb->>'bundle_id',f.asset,f.first_at FROM assessment_failures f WHERE convert_from(f.body,'UTF8')::jsonb ? 'bundle_id';

CREATE FUNCTION assessment_references() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE rid text; f assessment_facts; b jsonb; edge record; target assessment_facts; newest timestamptz;ctx_revision bigint; reserved text[];used text[];total bigint;cid text;
BEGIN
 rid:=COALESCE(NEW.run_id,OLD.run_id);
 -- Raw leaves have no outgoing references. Avoid a whole dependency view scan
 -- for every admitted sample; projection checks below still run for every row.
 IF NOT (TG_TABLE_NAME='assessment_facts' AND TG_OP<>'DELETE' AND to_jsonb(NEW)->>'kind' IN ('SAMPLE','COVERAGE','QUALIFIED')) THEN
 -- Ignore removed sources but never leave a surviving dangling or foreign edge.
 FOR edge IN SELECT * FROM assessment_edges WHERE run_id=rid AND ((TG_OP<>'DELETE' AND from_table=substr(TG_TABLE_NAME,12) AND from_id=NEW.id) OR (TG_OP='DELETE' AND to_table=substr(TG_TABLE_NAME,12) AND to_id=OLD.id)) LOOP
  IF edge.to_table='facts' THEN
   SELECT * INTO target FROM assessment_facts WHERE run_id=rid AND id=edge.to_id;
   IF NOT FOUND OR target.asset IS DISTINCT FROM edge.asset OR target.available_at>edge.cutoff THEN RAISE EXCEPTION 'invalid assessment fact reference' USING ERRCODE='23514';END IF;
  ELSIF NOT EXISTS(SELECT 1 FROM assessment_bundles q WHERE q.run_id=rid AND q.id=edge.to_id AND q.asset=edge.asset AND q.availability_cutoff<=edge.cutoff) THEN RAISE EXCEPTION 'invalid assessment bundle reference' USING ERRCODE='23514';END IF;
 END LOOP;
 END IF;
 IF TG_TABLE_NAME='assessment_facts' AND TG_OP<>'DELETE' THEN
  SELECT * INTO f FROM assessment_facts WHERE run_id=rid AND id=NEW.id;IF FOUND THEN
   b:=convert_from(f.body,'UTF8')::jsonb;
   IF b->>'id' IS DISTINCT FROM f.id OR b->>'run' IS DISTINCT FROM f.run_id OR b->>'asset' IS DISTINCT FROM f.asset OR b->>'kind' IS DISTINCT FROM f.kind OR (b->>'available_at')::timestamptz IS DISTINCT FROM f.available_at THEN RAISE EXCEPTION 'fact projection mismatch' USING ERRCODE='23514';END IF;
   IF f.kind IN ('FEATURE','CONFLICT','PROVENANCE') THEN
    FOR edge IN SELECT * FROM assessment_edges WHERE run_id=rid AND from_table='facts' AND from_id=f.id LOOP
     SELECT * INTO STRICT target FROM assessment_facts WHERE run_id=rid AND id=edge.to_id;
     IF (f.kind='FEATURE' AND target.kind NOT IN ('SAMPLE','COVERAGE','QUALIFIED')) OR (f.kind IN ('CONFLICT','PROVENANCE') AND target.kind<>'SAMPLE') THEN RAISE EXCEPTION 'forbidden assessment dependency' USING ERRCODE='23514';END IF;
    END LOOP;
    IF f.kind='FEATURE' THEN SELECT max(q.available_at) INTO newest FROM assessment_edges e JOIN assessment_facts q ON q.run_id=e.run_id AND q.id=e.to_id WHERE e.run_id=rid AND e.from_table='facts' AND e.from_id=f.id;IF newest IS DISTINCT FROM f.available_at THEN RAISE EXCEPTION 'feature availability mismatch' USING ERRCODE='23514';END IF;END IF;
   ELSIF f.kind='TRACKER_CONTEXT' THEN
    ctx_revision:=(b#>>'{body,revision}')::bigint;
    IF EXISTS(SELECT 1 FROM assessment_edges e JOIN assessment_facts q ON q.run_id=e.run_id AND q.id=e.to_id WHERE e.run_id=rid AND e.from_table='bundles' AND e.from_id=b#>>'{body,bundle_id}' AND (q.id=f.id OR q.kind='TRACKER_CONTEXT' AND (convert_from(q.body,'UTF8')::jsonb#>>'{body,revision}')::bigint>=ctx_revision)) THEN RAISE EXCEPTION 'cyclic assessment context' USING ERRCODE='23514';END IF;
   END IF;
  END IF;
 END IF;
 IF TG_TABLE_NAME='assessment_bundles' AND TG_OP<>'DELETE' THEN
  b:=convert_from(NEW.body,'UTF8')::jsonb;IF b->>'id' IS DISTINCT FROM NEW.id OR b->>'run' IS DISTINCT FROM NEW.run_id OR b->>'asset' IS DISTINCT FROM NEW.asset OR (b->>'logical_at')::timestamptz IS DISTINCT FROM NEW.logical_at OR (b->>'availability_cutoff')::timestamptz IS DISTINCT FROM NEW.availability_cutoff THEN RAISE EXCEPTION 'bundle projection mismatch' USING ERRCODE='23514';END IF;
 END IF;
 IF TG_TABLE_NAME='assessment_failures' AND TG_OP<>'DELETE' THEN
  b:=convert_from(NEW.body,'UTF8')::jsonb;
  IF NEW.kind='QUALIFIED_TELEMETRY' THEN
   SELECT * INTO target FROM assessment_facts WHERE run_id=rid AND id=b->>'open_fact';
   IF target.kind IS DISTINCT FROM 'QUALIFIED' OR convert_from(target.body,'UTF8')::jsonb#>>'{body,transition}' IS DISTINCT FROM 'OPEN' OR convert_from(target.body,'UTF8')::jsonb#>>'{body,rule}' IS DISTINCT FROM 'telemetry_loss' OR convert_from(target.body,'UTF8')::jsonb#>>'{body,policy_id}' IS DISTINCT FROM b->>'policy_id' OR convert_from(target.body,'UTF8')::jsonb#>'{body,occurrence}' IS DISTINCT FROM b->'occurrence' THEN RAISE EXCEPTION 'invalid qualified telemetry open' USING ERRCODE='23514';END IF;
   IF b ? 'recover_fact' THEN
    SELECT * INTO target FROM assessment_facts WHERE run_id=rid AND id=b->>'recover_fact';
    IF target.kind IS DISTINCT FROM 'QUALIFIED' OR convert_from(target.body,'UTF8')::jsonb#>>'{body,transition}' IS DISTINCT FROM 'RECOVER' OR convert_from(target.body,'UTF8')::jsonb#>>'{body,rule}' IS DISTINCT FROM 'telemetry_loss' OR convert_from(target.body,'UTF8')::jsonb#>>'{body,policy_id}' IS DISTINCT FROM b->>'policy_id' OR convert_from(target.body,'UTF8')::jsonb#>'{body,occurrence}' IS DISTINCT FROM b->'occurrence' THEN RAISE EXCEPTION 'invalid qualified telemetry recovery' USING ERRCODE='23514';END IF;
   END IF;
  END IF;
 END IF;
 IF TG_TABLE_NAME IN ('assessment_candidates','assessment_decisions') THEN
  cid:=CASE WHEN TG_TABLE_NAME='assessment_candidates' THEN COALESCE(NEW.id,OLD.id) ELSE COALESCE(to_jsonb(NEW)->>'candidate_id',to_jsonb(OLD)->>'candidate_id') END;
  -- A live OBSERVING result cannot survive a deadline crossed during writes.
  -- Deferred checking sees final transaction state, allowing a due terminal
  -- inserted later in the same unit and preserving logical replay fixtures.
  IF TG_OP<>'DELETE' AND EXISTS(SELECT 1 FROM assessment_candidates c JOIN assessment_runs r ON r.run_id=c.run_id WHERE c.run_id=rid AND c.id=cid AND c.phase='OBSERVING' AND r.mode='shadow' AND c.due_at<=clock_timestamp()) THEN RAISE EXCEPTION 'assessment deadline crossed' USING ERRCODE='40001';END IF;
  IF TG_TABLE_NAME='assessment_decisions' AND TG_OP<>'DELETE' AND (to_jsonb(NEW)->>'logical_at')::timestamptz>clock_timestamp() AND EXISTS(SELECT 1 FROM assessment_runs WHERE run_id=rid AND mode='shadow') THEN RAISE EXCEPTION 'assessment cutoff is not yet eligible' USING ERRCODE='40001';END IF;
  IF EXISTS(SELECT 1 FROM assessment_candidates WHERE run_id=rid AND id=cid AND phase='QUARANTINED') AND NOT EXISTS(SELECT 1 FROM assessment_failures WHERE run_id=rid AND code='HOST_STATE' AND scope_key=cid) THEN RAISE EXCEPTION 'quarantine requires host state failure' USING ERRCODE='23514';END IF;
  SELECT reserved_codes INTO reserved FROM assessment_candidates WHERE run_id=rid AND id=cid;
  IF FOUND THEN
   SELECT COALESCE(array_agg(DISTINCT code COLLATE "C" ORDER BY code COLLATE "C"),'{}'),count(*) INTO used,total FROM assessment_decisions d CROSS JOIN LATERAL unnest(d.codes) code WHERE d.run_id=rid AND d.candidate_id=cid AND d.kind='UPDATE';
   IF (used IS DISTINCT FROM reserved OR total<>cardinality(used)) AND NOT (TG_OP='DELETE' AND EXISTS(SELECT 1 FROM assessment_runs WHERE run_id=rid AND state='CLOSED' AND closed_at<=clock_timestamp()-interval '7 days')) THEN RAISE EXCEPTION 'assessment update reservation mismatch' USING ERRCODE='23514';END IF;
  END IF;
 END IF;
 RETURN NULL;
END$$;
DO $$DECLARE t text;BEGIN FOREACH t IN ARRAY ARRAY['facts','bundles','candidates','decisions','failures'] LOOP EXECUTE format('CREATE CONSTRAINT TRIGGER assessment_references AFTER INSERT OR UPDATE OR DELETE ON assessment_%I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION assessment_references()',t);END LOOP;END$$;

-- Physical copies count independently. UTF-8 text and compact JSON string arrays
-- match assessment-json-v1; timestamps/numerics=8, booleans=1, NULL=0.
CREATE FUNCTION assessment_row_bytes(table_name text,row_data jsonb) RETURNS bigint LANGUAGE plpgsql STABLE AS $$
DECLARE c record;v jsonb;n bigint:=0;item jsonb;s text;
BEGIN
 FOR c IN SELECT attname,atttypid FROM pg_attribute WHERE attrelid=('public.'||table_name)::regclass AND attnum>0 AND NOT attisdropped LOOP
  v:=row_data->c.attname;IF v IS NULL OR v='null'::jsonb THEN CONTINUE;END IF;
  IF c.atttypid='bytea'::regtype THEN n:=n+(length(v#>>'{}')-2)/2;
  ELSIF c.atttypid='text'::regtype THEN n:=n+octet_length(v#>>'{}');
  ELSIF c.atttypid='text[]'::regtype THEN
   n:=n+2+greatest(jsonb_array_length(v)-1,0);
   FOR item IN SELECT value FROM jsonb_array_elements(v) LOOP s:=item::text;s:=replace(replace(replace(s,'&','\u0026'),'<','\u003c'),'>','\u003e');s:=replace(replace(s,chr(8232),'\u2028'),chr(8233),'\u2029');n:=n+octet_length(s);END LOOP;
  ELSIF c.atttypid='boolean'::regtype THEN n:=n+1;
  ELSE n:=n+8;END IF;
 END LOOP;RETURN n;
END$$;
CREATE FUNCTION assessment_account() RETURNS trigger LANGUAGE plpgsql SET bytea_output='hex' AS $$
DECLARE rid text;delta bigint:=0;records bigint:=0;facts bigint:=0;physical bigint:=0;incomplete bigint:=0;r assessment_runs;limits jsonb;
BEGIN
 IF pg_trigger_depth()>1 AND TG_TABLE_NAME='assessment_runs' THEN RETURN NULL;END IF;
 IF TG_TABLE_NAME='assessment_facts' AND TG_OP='INSERT' THEN RETURN NULL;END IF;
 rid:=COALESCE(NEW.run_id,OLD.run_id);
 IF TG_OP<>'DELETE' THEN delta:=assessment_row_bytes(TG_TABLE_NAME,to_jsonb(NEW));END IF;
 IF TG_OP<>'INSERT' THEN delta:=delta-assessment_row_bytes(TG_TABLE_NAME,to_jsonb(OLD));END IF;
 records:=CASE TG_OP WHEN 'INSERT' THEN 1 WHEN 'DELETE' THEN -1 ELSE 0 END;
 IF TG_TABLE_NAME='assessment_facts' THEN facts:=records;END IF;
 IF TG_TABLE_NAME='assessment_candidates' THEN
  incomplete:=CASE WHEN TG_OP<>'DELETE' AND to_jsonb(NEW)->>'phase'='QUARANTINED' THEN 1 ELSE 0 END - CASE WHEN TG_OP<>'INSERT' AND to_jsonb(OLD)->>'phase'='QUARANTINED' THEN 1 ELSE 0 END;
 END IF;
 IF TG_TABLE_NAME='assessment_runs' AND TG_OP='DELETE' THEN RETURN NULL;END IF;
 SELECT * INTO STRICT r FROM assessment_runs WHERE run_id=rid FOR UPDATE;
 IF TG_TABLE_NAME='assessment_candidates' AND TG_OP IN ('INSERT','DELETE') THEN
  SELECT count(*)-r.physical_count INTO physical FROM (SELECT DISTINCT category,asset,sequence FROM assessment_candidates WHERE run_id=rid) groups;
 END IF;
 limits:=convert_from(r.config,'UTF8')::jsonb->'limits';
 IF TG_TABLE_NAME='assessment_failures' AND TG_OP='INSERT' AND (SELECT count(*) FROM assessment_failures WHERE run_id=rid)>1024 THEN RAISE EXCEPTION 'assessment capacity failures exceeded' USING ERRCODE='23514';END IF;
 IF r.payload_bytes+delta>(limits->>'payload_bytes')::bigint OR r.fact_count+facts>(limits->>'fact_count')::bigint OR r.physical_count+physical>(limits->>'physical_candidates')::bigint OR r.record_count+records>1000000 THEN RAISE EXCEPTION 'assessment capacity exceeded' USING ERRCODE='23514';END IF;
 IF TG_TABLE_NAME='assessment_facts' AND TG_OP='INSERT' AND to_jsonb(NEW)->>'kind' IN ('SAMPLE','PROVENANCE','COVERAGE','QUALIFIED','CONFLICT') AND (r.state<>'ACTIVE' OR r.payload_bytes+delta>(limits->>'payload_bytes')::bigint-4194304) THEN RAISE EXCEPTION 'assessment acquisition reserve protected' USING ERRCODE='23514';END IF;
 UPDATE assessment_runs SET payload_bytes=payload_bytes+delta,record_count=record_count+records,fact_count=fact_count+facts,physical_count=physical_count+physical,incomplete_count=incomplete_count+incomplete WHERE run_id=rid;
 RETURN NULL;
END$$;
DO $$DECLARE t text;BEGIN FOREACH t IN ARRAY ARRAY['runs','enrollments','facts','bundles','candidates','decisions','failures'] LOOP EXECUTE format('CREATE TRIGGER assessment_account AFTER INSERT OR UPDATE OR DELETE ON assessment_%I FOR EACH ROW EXECUTE FUNCTION assessment_account()',t);END LOOP;END$$;

-- Transition tables contain only actual inserts, including ON CONFLICT batches.
-- All fact columns have fixed types, so exact accounting needs no catalog walk.
CREATE FUNCTION assessment_account_fact_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE rid text; records bigint;delta bigint;acquired boolean;r assessment_runs;limits jsonb;
BEGIN
 FOR rid IN SELECT DISTINCT run_id FROM new_facts ORDER BY run_id LOOP
  SELECT count(*),COALESCE(sum(octet_length(run_id)+octet_length(id)+octet_length(asset)+octet_length(kind)+8+octet_length(body)),0),bool_or(kind IN ('SAMPLE','PROVENANCE','COVERAGE','QUALIFIED','CONFLICT')) INTO records,delta,acquired FROM new_facts WHERE run_id=rid;
  SELECT * INTO STRICT r FROM assessment_runs WHERE run_id=rid FOR UPDATE;
  limits:=convert_from(r.config,'UTF8')::jsonb->'limits';
  IF r.payload_bytes+delta>(limits->>'payload_bytes')::bigint OR r.fact_count+records>(limits->>'fact_count')::bigint OR r.record_count+records>1000000 THEN RAISE EXCEPTION 'assessment capacity exceeded' USING ERRCODE='23514';END IF;
  IF acquired AND (r.state<>'ACTIVE' OR r.payload_bytes+delta>(limits->>'payload_bytes')::bigint-4194304) THEN RAISE EXCEPTION 'assessment acquisition reserve protected' USING ERRCODE='23514';END IF;
  UPDATE assessment_runs SET payload_bytes=payload_bytes+delta,record_count=record_count+records,fact_count=fact_count+records WHERE run_id=rid;
 END LOOP;
 RETURN NULL;
END$$;
CREATE TRIGGER assessment_account_fact_insert AFTER INSERT ON assessment_facts REFERENCING NEW TABLE AS new_facts FOR EACH STATEMENT EXECUTE FUNCTION assessment_account_fact_insert();
