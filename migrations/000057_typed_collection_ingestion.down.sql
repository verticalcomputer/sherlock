DROP TABLE collector_source_cursors;
DROP TABLE goodput_metric_nodes;
DROP TABLE goodput_collection_events;
DROP TABLE goodput_source_coverage;
DROP TABLE collector_typed_result_ingestions;
DROP TRIGGER guard_typed_collection_plan ON collector_work_items;
DROP FUNCTION guard_typed_collection_plan();
ALTER TABLE collector_work_items DROP COLUMN typed_plan;
ALTER TABLE sources DROP CONSTRAINT sources_kind_check;
-- Refuse downgrade while configured Slurm sources remain, rather than relabeling them.
ALTER TABLE sources ADD CONSTRAINT sources_kind_check
    CHECK (kind IN ('prometheus', 'model', 'diagnostic'));
