DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM gp06f_node_bootstrap) OR EXISTS(SELECT 1 FROM gp06f_node_identity_audit)
 THEN RAISE EXCEPTION 'node identity rollback requires preservation of bootstrap and issuance history' USING ERRCODE='23514'; END IF;
END $$;
DROP TABLE gp06f_node_identity_audit;
DROP TABLE gp06f_node_bootstrap;
DROP FUNCTION gp06f_node_bootstrap_immutable();
