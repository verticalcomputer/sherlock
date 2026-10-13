-- Freeze collection membership/configuration during LIVE authority decisions
-- without blocking unrelated ordinary schedule progress. A row trigger must
-- never wait for this advisory lock after acquiring a row lock: fail with the
-- standard transaction-retry code instead, preventing inverse lock ordering.
CREATE FUNCTION m15_collection_population_fence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND
    ROW(NEW.job_id,NEW.cluster_id,NEW.source_id,NEW.query_kind,NEW.node_filter,NEW.active,NEW.interval_seconds)
    IS NOT DISTINCT FROM
    ROW(OLD.job_id,OLD.cluster_id,OLD.source_id,OLD.query_kind,OLD.node_filter,OLD.active,OLD.interval_seconds)
 THEN RETURN NEW; END IF;
 IF TG_OP IN ('UPDATE','DELETE') THEN
  IF NOT pg_try_advisory_xact_lock(hashtextextended('m15-repair:'||OLD.cluster_id,0)) THEN
   RAISE EXCEPTION 'collection configuration authority busy; retry transaction' USING ERRCODE='40001';
  END IF;
 END IF;
 IF TG_OP IN ('UPDATE','INSERT') THEN
  IF NOT pg_try_advisory_xact_lock(hashtextextended('m15-repair:'||NEW.cluster_id,0)) THEN
   RAISE EXCEPTION 'collection configuration authority busy; retry transaction' USING ERRCODE='40001';
  END IF;
  RETURN NEW;
 END IF;
 RETURN OLD;
END $$;
CREATE TRIGGER m15_collection_population_fence BEFORE INSERT OR UPDATE OR DELETE
 ON collection_jobs FOR EACH ROW EXECUTE FUNCTION m15_collection_population_fence();
