-- Zero means unenrolled. Policy initialization is immutable through the worker;
-- the cursor is shared by control replicas and survives worker/collector restarts.
ALTER TABLE collectors
 ADD COLUMN collection_dispatch_floor integer NOT NULL DEFAULT 0,
 ADD COLUMN collection_dispatch_period integer NOT NULL DEFAULT 0,
 ADD COLUMN collection_dispatch_turn integer NOT NULL DEFAULT 0,
 ADD CONSTRAINT collection_dispatch_policy CHECK (
   (collection_dispatch_floor=0 AND collection_dispatch_period=0 AND collection_dispatch_turn=0)
   OR (collection_dispatch_floor>=1 AND collection_dispatch_floor<collection_dispatch_period
       AND collection_dispatch_period BETWEEN 2 AND 100
       AND collection_dispatch_turn>=0 AND collection_dispatch_turn<collection_dispatch_period));
