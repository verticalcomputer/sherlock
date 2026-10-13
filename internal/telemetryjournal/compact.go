package telemetryjournal

import (
	"database/sql"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"strings"
)

// Schema2 stores each scope/session/source identity once and compact immutable
// receipt facts. The compatibility view preserves the queue's typed read model;
// it is not a migration from an initialized schema1 journal.
var compactSchema = compactStatements([]string{
	`CREATE TABLE IF NOT EXISTS store(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL,role TEXT NOT NULL,scope BLOB NOT NULL) STRICT`,
	`CREATE TABLE IF NOT EXISTS source_dictionary(slot INTEGER PRIMARY KEY CHECK(slot BETWEEN 0 AND 15),name TEXT NOT NULL UNIQUE) STRICT`,
	`CREATE TABLE IF NOT EXISTS session_identity(epoch TEXT PRIMARY KEY,id TEXT NOT NULL) STRICT, WITHOUT ROWID`,
	`CREATE TABLE IF NOT EXISTS item_rows(id TEXT PRIMARY KEY,epoch TEXT NOT NULL REFERENCES session_identity(epoch),sequence TEXT NOT NULL,digest BLOB NOT NULL,wire BLOB,bytes INTEGER,created INTEGER,stored INTEGER NOT NULL,lane INTEGER NOT NULL,source_mask INTEGER NOT NULL,state INTEGER NOT NULL,receipt_id TEXT,receipt_at INTEGER,ack_id TEXT,ack_at INTEGER,acked INTEGER,loss BLOB,pending_loss BLOB) STRICT, WITHOUT ROWID`,
	`CREATE TABLE IF NOT EXISTS source_loss(id TEXT PRIMARY KEY,epoch TEXT NOT NULL,source TEXT NOT NULL,digest BLOB NOT NULL,body BLOB NOT NULL) STRICT, WITHOUT ROWID`,
	`CREATE TABLE IF NOT EXISTS batch_loss(item_id TEXT NOT NULL REFERENCES item_rows(id),loss_id TEXT NOT NULL REFERENCES source_loss(id),PRIMARY KEY(item_id,loss_id)) STRICT, WITHOUT ROWID`,
	`CREATE TABLE IF NOT EXISTS loss_order(ordinal INTEGER PRIMARY KEY AUTOINCREMENT,item_id TEXT NOT NULL UNIQUE REFERENCES item_rows(id)) STRICT`,
	`CREATE INDEX IF NOT EXISTS pending ON item_rows(state,stored,id) WHERE state IN (0,1)`,
	`CREATE VIEW IF NOT EXISTS items AS SELECT r.id,
 CAST(json_object('cluster_id',json_extract(s.scope,'$.ClusterID'),'node_id',json_extract(s.scope,'$.NodeID'),'enrollment_id',json_extract(s.scope,'$.EnrollmentID'),'session_epoch',r.epoch,'session_id',si.id,'sequence',r.sequence) AS BLOB) AS key,
 lower(hex(r.digest)) AS digest,lower(hex(r.wire)) AS wire,coalesce(r.bytes,1) AS bytes,coalesce(r.created,r.stored) AS created,r.stored,
 CASE r.lane WHEN 0 THEN 'DATA' WHEN 1 THEN 'CONTACT' ELSE 'LOSS' END AS lane,
 CAST((SELECT json_group_array(name) FROM (SELECT name FROM source_dictionary WHERE (r.source_mask & (1<<slot))<>0 ORDER BY slot)) AS BLOB) AS sources,
 CASE r.state WHEN 0 THEN 'STAGING' WHEN 1 THEN 'OWNED' WHEN 2 THEN 'TRANSFERRED' ELSE 'LOST' END AS state,
 CASE WHEN r.receipt_id IS NULL THEN CAST('{}' AS BLOB) ELSE CAST(json_object('protocol_version',1,'id',r.receipt_id,'key',json_object('cluster_id',json_extract(s.scope,'$.ClusterID'),'node_id',json_extract(s.scope,'$.NodeID'),'enrollment_id',json_extract(s.scope,'$.EnrollmentID'),'session_epoch',r.epoch,'session_id',si.id,'sequence',r.sequence),'digest',lower(hex(r.digest)),'stored_at',r.receipt_at,'durability',s.role) AS BLOB) END AS receipt,
 CASE WHEN r.ack_id IS NULL THEN NULL ELSE CAST(json_object('protocol_version',1,'id',r.ack_id,'key',json_object('cluster_id',json_extract(s.scope,'$.ClusterID'),'node_id',json_extract(s.scope,'$.NodeID'),'enrollment_id',json_extract(s.scope,'$.EnrollmentID'),'session_epoch',r.epoch,'session_id',si.id,'sequence',r.sequence),'digest',lower(hex(r.digest)),'stored_at',r.ack_at,'durability',CASE s.role WHEN 'NODE' THEN 'GATEWAY' ELSE 'CLOUD' END) AS BLOB) END AS ack,r.acked,r.loss,r.pending_loss
 FROM item_rows r JOIN session_identity si ON si.epoch=r.epoch JOIN store s ON s.singleton=1`,
	`CREATE TRIGGER IF NOT EXISTS items_insert INSTEAD OF INSERT ON items BEGIN
 INSERT OR IGNORE INTO session_identity(epoch,id)VALUES(json_extract(NEW.key,'$.session_epoch'),json_extract(NEW.key,'$.session_id'));
 SELECT CASE WHEN (SELECT id FROM session_identity WHERE epoch=json_extract(NEW.key,'$.session_epoch'))<>json_extract(NEW.key,'$.session_id') THEN RAISE(ABORT,'identity mismatch') END;
 SELECT CASE WHEN (SELECT count(*) FROM json_each(NEW.sources))<>(SELECT count(*) FROM source_dictionary WHERE name IN(SELECT value FROM json_each(NEW.sources))) THEN RAISE(ABORT,'source mismatch') END;
 INSERT INTO item_rows(id,epoch,sequence,digest,wire,bytes,created,stored,lane,source_mask,state,receipt_id,receipt_at,ack_id,ack_at,acked,loss,pending_loss)VALUES(NEW.id,json_extract(NEW.key,'$.session_epoch'),json_extract(NEW.key,'$.sequence'),unhex(NEW.digest),CASE NEW.state WHEN 'TRANSFERRED' THEN NULL ELSE unhex(NEW.wire) END,CASE NEW.state WHEN 'TRANSFERRED' THEN NULL ELSE NEW.bytes END,CASE NEW.state WHEN 'TRANSFERRED' THEN NULL ELSE NEW.created END,NEW.stored,CASE NEW.lane WHEN 'DATA' THEN 0 WHEN 'CONTACT' THEN 1 ELSE 2 END,(SELECT sum(1<<slot)FROM source_dictionary WHERE name IN(SELECT value FROM json_each(NEW.sources))),CASE NEW.state WHEN 'STAGING' THEN 0 WHEN 'OWNED' THEN 1 WHEN 'TRANSFERRED' THEN 2 ELSE 3 END,nullif(json_extract(NEW.receipt,'$.id'),''),json_extract(NEW.receipt,'$.stored_at'),json_extract(NEW.ack,'$.id'),json_extract(NEW.ack,'$.stored_at'),NEW.acked,NEW.loss,NEW.pending_loss);
 END`,
	`CREATE TRIGGER IF NOT EXISTS items_update INSTEAD OF UPDATE ON items BEGIN
 UPDATE item_rows SET digest=unhex(NEW.digest),wire=CASE NEW.state WHEN 'TRANSFERRED' THEN NULL ELSE unhex(NEW.wire) END,bytes=CASE NEW.state WHEN 'TRANSFERRED' THEN NULL ELSE NEW.bytes END,created=CASE NEW.state WHEN 'TRANSFERRED' THEN NULL ELSE NEW.created END,stored=NEW.stored,lane=CASE NEW.lane WHEN 'DATA' THEN 0 WHEN 'CONTACT' THEN 1 ELSE 2 END,state=CASE NEW.state WHEN 'STAGING' THEN 0 WHEN 'OWNED' THEN 1 WHEN 'TRANSFERRED' THEN 2 ELSE 3 END,receipt_id=nullif(json_extract(NEW.receipt,'$.id'),''),receipt_at=json_extract(NEW.receipt,'$.stored_at'),ack_id=json_extract(NEW.ack,'$.id'),ack_at=json_extract(NEW.ack,'$.stored_at'),acked=NEW.acked,loss=NEW.loss,pending_loss=NEW.pending_loss WHERE id=OLD.id;
 INSERT OR IGNORE INTO loss_order(item_id) SELECT NEW.id WHERE NEW.state='LOST';
 END`, sessionSchema,
})

func compactStatements(statements []string) []string {
	for i, s := range statements {
		s = strings.ReplaceAll(s, "'stored_at',r.receipt_at", "'stored_at',"+compactAt("r.receipt_at"))
		s = strings.ReplaceAll(s, "'stored_at',r.ack_at", "'stored_at',"+compactAt("r.ack_at"))
		s = strings.ReplaceAll(s, "json_extract(NEW.receipt,'$.stored_at')", "CASE WHEN nullif(json_extract(NEW.receipt,'$.id'),'')IS NULL THEN NULL ELSE "+compactNanoseconds("json_extract(NEW.receipt,'$.stored_at')")+" END")
		s = strings.ReplaceAll(s, "json_extract(NEW.ack,'$.stored_at')", compactNanoseconds("json_extract(NEW.ack,'$.stored_at')"))
		statements[i] = s
	}
	return statements
}

// Receipt times are normalized UTC before persistence; parsing never goes
// through floating point or SQLite's millisecond-truncated julianday values.
func compactNanoseconds(v string) string {
	return "(unixepoch(substr(" + v + ",1,19))*1000000000+CASE WHEN length(" + v + ")>20 THEN CAST(substr(substr(" + v + ",21,length(" + v + ")-21)||'000000000',1,9)AS INTEGER)ELSE 0 END)"
}
func compactAt(v string) string {
	return "(strftime('%Y-%m-%dT%H:%M:%S'," + v + "/1000000000,'unixepoch')||'.'||printf('%09d'," + v + "%1000000000)||'Z')"
}

func (q *Queue) validateCompactState() error {
	var invalid int
	maximumMask := (1 << len(q.opts.SourceIDs)) - 1
	e := q.db.QueryRow(`SELECT 1 FROM item_rows WHERE length(id)<>32 OR length(digest)<>32 OR source_mask<1 OR source_mask>? OR lane NOT IN(0,1,2) OR state NOT IN(0,1,2,3) OR (state IN(0,1)AND(length(wire)<>32 OR bytes<1 OR bytes>? OR created IS NULL)) OR (state=2 AND(wire IS NOT NULL OR bytes IS NOT NULL OR created IS NOT NULL)) LIMIT 1`, maximumMask, telemetry.MaxBatchBytes).Scan(&invalid)
	if e != sql.ErrNoRows {
		return ErrCorrupt
	}
	var raw, projected, lost, ordered int
	if q.db.QueryRow(`SELECT count(*) FROM item_rows`).Scan(&raw) != nil || q.db.QueryRow(`SELECT count(*) FROM items`).Scan(&projected) != nil || raw != projected || q.db.QueryRow(`SELECT count(*) FROM item_rows WHERE state=3`).Scan(&lost) != nil || q.db.QueryRow(`SELECT count(*)FROM loss_order o JOIN item_rows i ON i.id=o.item_id WHERE i.state=3`).Scan(&ordered) != nil || lost != ordered {
		return ErrCorrupt
	}
	var extra int
	if q.db.QueryRow(`SELECT count(*) FROM loss_order`).Scan(&extra) != nil || extra != ordered {
		return ErrCorrupt
	}
	if q.opts.RequireSessions {
		var mismatched int
		e = q.db.QueryRow(`SELECT 1 FROM session_identity i LEFT JOIN sessions s ON s.epoch=i.epoch LEFT JOIN retained_sessions r ON r.epoch=i.epoch WHERE coalesce(s.id,r.id) IS NULL OR coalesce(s.id,r.id)<>i.id LIMIT 1`).Scan(&mismatched)
		if e != sql.ErrNoRows {
			return ErrCorrupt
		}
	}
	return nil
}
