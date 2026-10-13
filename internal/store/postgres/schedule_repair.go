package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgconn"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediation"
	"github.com/verticalcomputer/sherlock/internal/scheduleinvestigation"
)

// DetectScheduleRepair records one bounded, deterministic scheduling diagnosis.
// Only committed collection and collector health data can supply its facts.
// The job lock serializes the decision with every scheduler/configuration writer.
func (s *RemediationStore) DetectScheduleRepair(ctx context.Context, cluster domain.ClusterID, limit int) error {
	if limit < 1 || limit > 32 {
		return fmt.Errorf("invalid schedule detection batch")
	}
	// A normally due occurrence cannot be repaired by this recipe. Exclude it
	// before per-job diagnosis/locking so ordinary collection does not pay for
	// a full health/evidence read on every supervisor poll.
	rows, err := s.pool.Query(ctx, `SELECT j.job_id FROM collection_jobs j LEFT JOIN schedule_repair_decisions d ON d.cluster_id=j.cluster_id AND d.job_id=j.job_id WHERE j.cluster_id=$1 AND j.active AND j.next_run_at>clock_timestamp()+(j.interval_seconds*interval '1 second') ORDER BY d.observed_at NULLS FIRST,j.job_id LIMIT $2`, cluster, limit)
	if err != nil {
		return err
	}
	var jobs []string
	for rows.Next() {
		var job string
		if err = rows.Scan(&job); err != nil {
			rows.Close()
			return err
		}
		jobs = append(jobs, job)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, job := range jobs {
		// A concurrent normal scheduler may win the repeatable-read snapshot.
		// Retry the read-only diagnosis transaction boundedly; no committed
		// incident or evidence can be duplicated by a serialization abort.
		for attempt := 0; attempt < 3; attempt++ {
			err = s.detectScheduleJob(ctx, cluster, job)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "40001" {
				break
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *RemediationStore) detectScheduleJob(ctx context.Context, cluster domain.ClusterID, job string) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var f remediation.ScheduleFacts
	var source domain.SourceID
	var config, revision int64
	var interval int
	err = tx.QueryRow(ctx, `SELECT clock_timestamp(),j.source_id,j.active,j.interval_seconds,j.next_run_at,COALESCE(j.lease_expires_at,'epoch'),j.configuration_revision,j.schedule_revision,
 EXISTS(SELECT 1 FROM collector_work_items w JOIN collection_run_jobs b ON b.run_id=w.run_id AND b.cluster_id=w.cluster_id WHERE b.cluster_id=j.cluster_id AND b.job_id=j.job_id AND w.status IN ('AVAILABLE','LEASED')),
 COALESCE((SELECT bool_or(h.availability='AVAILABLE' AND h.checked_at BETWEEN clock_timestamp()-interval '2 minutes' AND clock_timestamp()) FROM collector_source_health h JOIN collectors c USING(collector_id) WHERE c.cluster_id=j.cluster_id AND c.status='ACTIVE' AND h.source_id=j.source_id),false),
 COALESCE((SELECT max(h.checked_at) FROM collector_source_health h JOIN collectors c USING(collector_id) WHERE c.cluster_id=j.cluster_id AND c.status='ACTIVE' AND h.source_id=j.source_id),'epoch'),
 EXISTS(SELECT 1 FROM collectors c JOIN collector_capabilities cap USING(collector_id) WHERE c.cluster_id=j.cluster_id AND c.status='ACTIVE' AND c.identity_not_after>clock_timestamp() AND cap.capability=j.query_kind AND c.last_heartbeat_at BETWEEN clock_timestamp()-interval '2 minutes' AND clock_timestamp()),
 COALESCE((SELECT max(c.last_heartbeat_at) FROM collectors c JOIN collector_capabilities cap USING(collector_id) WHERE c.cluster_id=j.cluster_id AND c.status='ACTIVE' AND cap.capability=j.query_kind),'epoch'),
 (SELECT count(*) FROM collection_target_inventory v WHERE v.cluster_id=j.cluster_id AND v.source_id=j.source_id AND (j.node_filter='' OR v.node_id=j.node_filter OR v.target_id=j.node_filter))
 FROM collection_jobs j WHERE j.cluster_id=$1 AND j.job_id=$2 FOR UPDATE OF j`, cluster, job).Scan(&f.Now, &source, &f.Active, &interval, &f.NextRun, &f.LeaseUntil, &config, &revision, &f.ActiveWork, &f.SourceAvailable, &f.SourceCheckedAt, &f.CollectorAvailable, &f.CollectorHeartbeat, &f.InventoryCount)
	if err != nil {
		return fmt.Errorf("read schedule facts: %w", err)
	}
	f.Interval = time.Duration(interval) * time.Second
	err = tx.QueryRow(ctx, `SELECT r.status='SUCCEEDED',r.coverage_complete,COALESCE(r.series_expected,0),r.series_returned,COALESCE((SELECT min(o.observed_at) FROM observations o WHERE o.cluster_id=r.cluster_id AND o.run_id=r.run_id),'epoch'),r.completed_at FROM collection_runs r JOIN collection_run_jobs b ON b.run_id=r.run_id AND b.cluster_id=r.cluster_id AND b.job_id=r.job_id JOIN collection_jobs j ON j.cluster_id=b.cluster_id AND j.job_id=b.job_id AND j.source_id=b.source_id AND j.query_kind=b.query_kind AND j.node_filter=b.node_filter AND j.configuration_revision=b.configuration_revision WHERE r.cluster_id=$1 AND r.job_id=$2 ORDER BY r.completed_at DESC LIMIT 1`, cluster, job).Scan(&f.LastRunSucceeded, &f.LastRunComplete, &f.ExpectedSeries, &f.ReturnedSeries, &f.LastSample, &f.LastCompleted)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	code := remediation.EvaluateScheduleRepair(f)
	if _, err = tx.Exec(ctx, `INSERT INTO schedule_repair_decisions(cluster_id,job_id,code,observed_at) VALUES($1,$2,$3,$4) ON CONFLICT(cluster_id,job_id) DO UPDATE SET code=EXCLUDED.code,observed_at=EXCLUDED.observed_at`, cluster, job, code, f.Now); err != nil {
		return err
	}
	if code != remediation.ScheduleEligible {
		return tx.Commit(ctx)
	}
	digest := domain.ChecksumSHA256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%d", cluster, job, config, revision)))
	suffix := digest.String()[:32]
	detection, incident, investigation, evidence := "schedule-"+suffix, "incident-schedule-"+suffix, "investigation-schedule-"+suffix, "evidence-schedule-"+suffix
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schedule_repair_detections WHERE detection_id=$1)`, detection).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return tx.Commit(ctx)
	}
	targets := []domain.EvidenceTarget{{Kind: domain.EvidenceTargetSource, ID: domain.EvidenceTargetID(job)}}
	envelope, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{ID: domain.EvidenceID(evidence), SchemaVersion: domain.EvidenceSchemaVersion, ClusterID: cluster, Status: domain.EvidenceComplete, Source: domain.EvidenceSourceReference{SourceID: source, Operation: "schedule_dispatch_gap", DefinitionVersion: "1", Reference: domain.EvidenceSourceLocator(detection)}, TimeRange: domain.EvidenceTimeRange{Start: f.Now, End: f.Now}, CollectedAt: f.Now, Coverage: domain.EvidenceCoverage{Expected: targets, Covered: targets}})
	if err != nil {
		return err
	}
	if _, err = insertEvidenceEnvelope(ctx, tx, envelope); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO incidents(incident_id,cluster_id,title,summary,severity,status,created_by,next_event_sequence,created_at,updated_at) VALUES($1,$2,'Collection scheduling gap','A previously complete stream is stale while its next occurrence is incorrectly deferred.','HIGH','OPEN','sherlock-remediator',2,$3,$3)`, incident, cluster, f.Now); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO incident_events(cluster_id,incident_id,sequence,event_key,event_type,actor_id,incident_version,payload,occurred_at) VALUES($1,$2,1,$2,'CREATED','sherlock-remediator',1,'{}',$3)`, cluster, incident, f.Now); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO anomaly_incidents(fingerprint,cluster_id,rule_id,entity_key,incident_id,first_signal_at,last_signal_at,cooldown_until) VALUES($1,$2,$3,$4,$5,$6,$6,$6::timestamptz+interval '1 hour')`, digest[:], cluster, remediation.IncidentKindEvidenceStreamStale, job, incident, f.Now); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO incident_evidence(incident_id,evidence_id,attached_at) VALUES($1,$2,$3)`, incident, evidence, f.Now); err != nil {
		return err
	}
	encoded, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO schedule_repair_detections(detection_id,cluster_id,job_id,source_id,configuration_revision,schedule_revision,evidence_id,incident_id,investigation_id,facts,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, detection, cluster, job, source, config, revision, evidence, incident, investigation, encoded, f.Now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// PendingScheduleInvestigations reconstructs restartable controller starts from
// the detector's committed records, never from user-provided card text.
func (s *RemediationStore) PendingScheduleInvestigations(ctx context.Context, cluster domain.ClusterID, limit int) ([]domain.InvestigationRequest, error) {
	rows, err := s.pool.Query(ctx, `SELECT d.investigation_id,d.incident_id,d.job_id,d.observed_at FROM schedule_repair_detections d LEFT JOIN investigations i ON i.cluster_id=d.cluster_id AND i.investigation_id=d.investigation_id WHERE d.cluster_id=$1 AND (i.investigation_id IS NULL OR i.status NOT IN ('COMPLETED','PARTIAL','BLOCKED','CANCELLED')) ORDER BY d.created_at,d.detection_id LIMIT $2`, cluster, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.InvestigationRequest
	for rows.Next() {
		var r domain.InvestigationRequest
		var job string
		var at time.Time
		if err = rows.Scan(&r.ID, &r.IncidentID, &job, &at); err != nil {
			return nil, err
		}
		r.ClusterID = cluster
		r.Question = "Does committed evidence prove a bounded collection scheduling gap?"
		r.RequestedBy = "sherlock-remediator"
		r.IdempotencyKey = string(r.ID)
		r.Scope = domain.InvestigationScope{EntityKind: "collection_job", EntityIDs: []string{job}, Start: at, End: at}
		r.SuccessCriteria = []string{"Cite the exact committed scheduling gap and propose one bounded collection request"}
		r.Budget = domain.InvestigationBudget{MaxDecisions: 3, MaxToolCalls: 1, MaxFanOut: 1}
		r.RequestedAt = at
		r.Deadline = at.Add(time.Hour)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *RemediationStore) ReadScheduleInvestigation(ctx context.Context, id domain.InvestigationID) (scheduleinvestigation.Snapshot, error) {
	var v scheduleinvestigation.Snapshot
	var facts []byte
	err := s.pool.QueryRow(ctx, `SELECT d.cluster_id,d.incident_id,d.investigation_id,d.job_id,d.source_id,d.evidence_id,d.observed_at,d.facts FROM schedule_repair_detections d JOIN evidence_envelopes e ON e.evidence_id=d.evidence_id AND e.cluster_id=d.cluster_id AND e.source_id=d.source_id AND e.operation='schedule_dispatch_gap' AND e.status='COMPLETE' JOIN incident_evidence ie ON ie.incident_id=d.incident_id AND ie.evidence_id=d.evidence_id WHERE d.investigation_id=$1`, id).Scan(&v.ClusterID, &v.IncidentID, &v.InvestigationID, &v.JobID, &v.SourceID, &v.Evidence.EvidenceID, &v.Evidence.ObservedEnd, &facts)
	if err != nil {
		return v, err
	}
	var f remediation.ScheduleFacts
	if err = json.Unmarshal(facts, &f); err != nil {
		return v, err
	}
	v.Eligible = remediation.EvaluateScheduleRepair(f) == remediation.ScheduleEligible
	v.Evidence.ClusterID = v.ClusterID
	v.Evidence.InvestigationID = id
	v.Evidence.Status = domain.EvidenceComplete
	v.Evidence.EntityIDs = []string{v.JobID}
	v.Evidence.ObservedStart = v.Evidence.ObservedEnd
	v.Evidence.RecordedAt = v.Evidence.ObservedEnd
	store, _ := NewInvestigationStore(s.pool)
	var found bool
	v.Current, found, err = store.LoadInvestigation(ctx, id)
	if err != nil {
		return v, err
	}
	if !found {
		return v, application.ErrInvestigationNotFound
	}
	return v, nil
}

func (s *RemediationStore) InvestigationStore() *InvestigationStore {
	return &InvestigationStore{pool: s.pool}
}
