package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"time"
)

// publishIncidentTransition is the common transaction boundary for deterministic
// monitoring and assessment producers. Producer-specific authority is checked by
// the caller under its ownership lock; a human investigation is never closed by
// measured recovery.
func publishIncidentTransition(ctx context.Context, tx pgx.Tx, cluster, incidentID, evidenceID, kind, title, summary, severity, actor string, at time.Time, payload json.RawMessage) error {
	switch kind {
	case "OPEN":
		if _, err := tx.Exec(ctx, `INSERT INTO incidents(incident_id,cluster_id,title,summary,severity,status,created_by,version,next_event_sequence,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'OPEN',$6,1,2,$7,$7)`, incidentID, cluster, title, summary, severity, actor, at); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO incident_events(cluster_id,incident_id,sequence,event_key,event_type,actor_id,incident_version,payload,occurred_at) VALUES($1,$2,1,$3,'CREATED',$4,1,$5,$6)`, cluster, incidentID, evidenceID, actor, payload, at)
		return err
	case "WORSEN", "RECOVER":
		var version, sequence int64
		var status string
		if err := tx.QueryRow(ctx, `SELECT version,next_event_sequence,status FROM incidents WHERE cluster_id=$1 AND incident_id=$2 FOR UPDATE`, cluster, incidentID).Scan(&version, &sequence, &status); err != nil {
			return err
		}
		eventType := "NOTE_ADDED"
		if kind == "RECOVER" && status != "INVESTIGATING" && status != "CLOSED" && status != "RESOLVED" {
			status = "RESOLVED"
			eventType = "STATUS_CHANGED"
		}
		if _, err := tx.Exec(ctx, `UPDATE incidents SET status=$2,resolved_at=CASE WHEN $2 IN ('RESOLVED','CLOSED') THEN coalesce(resolved_at,$3) ELSE NULL END,version=version+1,next_event_sequence=next_event_sequence+1,updated_at=greatest(updated_at,$3) WHERE incident_id=$1`, incidentID, status, at); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO incident_events(cluster_id,incident_id,sequence,event_key,event_type,actor_id,incident_version,payload,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, cluster, incidentID, sequence, evidenceID, eventType, actor, version+1, payload, at)
		return err
	default:
		return fmt.Errorf("unsupported incident transition")
	}
}
