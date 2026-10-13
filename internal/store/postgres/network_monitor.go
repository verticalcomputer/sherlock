package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/networkmonitor"
)

type NetworkMonitorStore struct{ pool *pgxpool.Pool }

func NewNetworkMonitorStore(pool *pgxpool.Pool) *NetworkMonitorStore {
	return &NetworkMonitorStore{pool: pool}
}

var ErrNetworkNotEnrolled = errors.New("network monitor is not enrolled for this identity")

// Enroll is deliberately immutable. A new topology needs explicit disabling
// and a separately reviewed revision, never implicit discovery reconciliation.
func (s *NetworkMonitorStore) Enroll(ctx context.Context, e networkmonitor.Enrollment) error {
	if e.ManagementRevision != "" || len(e.Bonds) > 0 || e.ManagementEnabled {
		return errors.New("use explicit additive management enrollment")
	}
	if err := networkmonitor.Validate(e); err != nil {
		return err
	}
	document, err := json.Marshal(e)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO gp09_network_monitors(cluster_id,collector_id,revision,enrollment)
 SELECT $1,$2,$3,$4 FROM collectors c JOIN clusters k USING(cluster_id)
 WHERE c.collector_id=$2 AND c.cluster_id=$1 AND c.status='ACTIVE' AND k.removed_at IS NULL
 ON CONFLICT(cluster_id) DO NOTHING`, e.ClusterID, e.CollectorID, e.Revision, document)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var stored []byte
		var enabled bool
		err = s.pool.QueryRow(ctx, `SELECT enrollment,enabled FROM gp09_network_monitors WHERE cluster_id=$1`, e.ClusterID).Scan(&stored, &enabled)
		if err != nil || !enabled || string(stored) == "" {
			return ErrNetworkNotEnrolled
		}
		var old networkmonitor.Enrollment
		if json.Unmarshal(stored, &old) != nil {
			return ErrNetworkNotEnrolled
		}
		canonical, _ := json.Marshal(old)
		if string(canonical) != string(document) {
			return errors.New("network enrollment revision conflict")
		}
	}
	return nil
}
func (s *NetworkMonitorStore) RecordNetworkCycle(ctx context.Context, cluster, collector string, c networkmonitor.Cycle) error {
	return s.evaluate(ctx, cluster, collector, &c)
}
func (s *NetworkMonitorStore) Refresh(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT m.cluster_id FROM gp09_network_monitors m JOIN clusters k USING(cluster_id) WHERE m.enabled AND k.removed_at IS NULL ORDER BY m.cluster_id`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.evaluate(ctx, id, "", nil); err != nil {
			return err
		}
	}
	return nil
}
func (s *NetworkMonitorStore) evaluate(ctx context.Context, cluster, collector string, cycle *networkmonitor.Cycle) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var doc []byte
	var enabled bool
	var bound string
	var created, now time.Time
	var received *time.Time
	err = tx.QueryRow(ctx, `SELECT enrollment,enabled,collector_id,created_at,last_received_at,clock_timestamp() FROM gp09_network_monitors WHERE cluster_id=$1 FOR UPDATE`, cluster).Scan(&doc, &enabled, &bound, &created, &received, &now)
	if errors.Is(err, pgx.ErrNoRows) || !enabled || (cycle != nil && bound != collector) {
		return ErrNetworkNotEnrolled
	}
	if err != nil {
		return err
	}
	var e networkmonitor.Enrollment
	if err := json.Unmarshal(doc, &e); err != nil {
		return err
	}
	if err := networkmonitor.Validate(e); err != nil {
		return err
	}
	var polls []application.NetworkNodePoll
	var durationMS int64
	rows, err := tx.Query(ctx, `SELECT polls,duration_ms FROM gp09_network_cycles WHERE cluster_id=$1 ORDER BY cycle_id DESC LIMIT 4`, cluster)
	if err != nil {
		return err
	}
	for rows.Next() {
		var data []byte
		var elapsed int64
		if err := rows.Scan(&data, &elapsed); err != nil {
			rows.Close()
			return err
		}
		var p []application.NetworkNodePoll
		if err := json.Unmarshal(data, &p); err != nil {
			rows.Close()
			return err
		}
		if len(polls) == 0 {
			durationMS = elapsed
		}
		polls = append(polls, p...)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if cycle != nil {
		var live bool
		if err := tx.QueryRow(ctx, `SELECT true FROM collectors c JOIN clusters k USING(cluster_id) WHERE c.collector_id=$1 AND c.cluster_id=$2 AND c.status='ACTIVE' AND k.removed_at IS NULL FOR SHARE OF c,k`, collector, cluster).Scan(&live); err != nil || !live {
			return ErrNetworkNotEnrolled
		}
		if err := networkmonitor.ValidateCycle(e, *cycle, now); err != nil {
			return err
		}
		latest := map[string]time.Time{}
		for _, p := range polls {
			if p.ObservedAt.After(latest[p.Node]) {
				latest[p.Node] = p.ObservedAt
			}
		}
		incoming := append([]application.NetworkNodePoll(nil), cycle.Polls...)
		for i := range incoming {
			p := &incoming[i]
			if !p.ObservedAt.After(latest[p.Node]) {
				return errors.New("network cycle is old or replayed")
			}
			if p.ObservedAt.After(now) {
				p.ObservedAt = now
			}
		}
		data, err := json.Marshal(incoming)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO gp09_network_cycles(cluster_id,polls,duration_ms) VALUES($1,$2,$3)`, cluster, data, cycle.DurationMS); err != nil {
			return err
		}
		polls = append(polls, incoming...)
		received = &now
		durationMS = cycle.DurationMS
		if _, err := tx.Exec(ctx, `DELETE FROM gp09_network_cycles WHERE cluster_id=$1 AND cycle_id NOT IN (SELECT cycle_id FROM gp09_network_cycles WHERE cluster_id=$1 ORDER BY cycle_id DESC LIMIT 4)`, cluster); err != nil {
			return err
		}
	}
	management, err := networkmonitor.AssessManagement(e, polls, now)
	if err != nil {
		return err
	}
	assessments, err := networkmonitor.Assess(e, polls, now)
	if err != nil {
		return err
	}
	summary := networkmonitor.Summary{Enrolled: true, Revision: e.Revision, State: application.NetworkHealthy, IntervalSeconds: 60, ExpectedNodes: 14, ExpectedPorts: len(e.Ports), LastReceivedAt: received, Details: assessments, Management: management}
	var latest time.Time
	for _, a := range assessments {
		if a.ObservedAt.After(latest) {
			latest = a.ObservedAt
		}

		switch a.Condition {
		case application.NetworkHealthy:
			summary.HealthyPorts++
		case application.NetworkDown:
			summary.DownPorts++
		case application.NetworkUnknown:
			summary.UnknownPorts++
		default:
			summary.DegradedPorts++
		}
	}
	if !latest.IsZero() {
		summary.LastObservedAt = &latest
		summary.CycleDurationMS = durationMS
	}
	if summary.DownPorts > 0 || summary.DegradedPorts > 0 {
		summary.State = application.NetworkDegraded
	}
	if summary.UnknownPorts > 0 {
		summary.State = application.NetworkUnknown
	}
	summary.InfiniBandState = summary.State
	if management.Enrolled && management.State != application.NetworkHealthy && summary.State != application.NetworkUnknown {
		summary.State = management.State
	}
	// One source episode per node avoids eight duplicate pages for one lost SSH
	// path. Port failures remain separate and cannot recover while the source is blind.
	active := map[string]application.NetworkPortAssessment{}
	healthy := map[string]bool{}
	for _, a := range assessments {
		entity := a.Key.Node + "/" + a.Key.Device + fmt.Sprintf("/%d", a.Key.Port)
		if a.Condition == application.NetworkHealthy {
			healthy[entity] = true
		}
		if a.Condition == application.NetworkDown {
			active[entity] = a
		}
		if a.Condition == application.NetworkUnknown && (a.Reason != "NO_OBSERVATION" || now.Sub(created) > networkmonitor.MaxAge) {
			active[a.Key.Node+"/source"] = a
		}
		if a.Reason == "LINK_DOWNED_INCREASE" {
			active[entity] = a
		}
	}
	for _, a := range assessments {
		if a.Condition == application.NetworkHealthy {
			healthy[a.Key.Node+"/source"] = true
		}
		if a.Condition == application.NetworkUnknown {
			healthy[a.Key.Node+"/source"] = false
		}
	}
	// Do not infer node-source recovery from just one healthy port.
	for _, a := range assessments {
		if a.Condition != application.NetworkHealthy {
			delete(healthy, a.Key.Node+"/source")
		}
	}
	for _, a := range management.Details {
		key := a.Node + "/management/" + a.Interface
		if a.Condition == application.NetworkHealthy {
			healthy[key] = true
		}
		if a.Condition == application.NetworkDown {
			active[key] = application.NetworkPortAssessment{Key: application.NetworkPortKey{Node: a.Node, Device: a.Interface}, Condition: a.Condition, Reason: a.Reason, State: a.OperState, PhysicalState: a.Carrier, ReadError: a.ReadError, ObservedAt: a.ObservedAt}
		}
		if a.Condition == application.NetworkUnknown && (a.Reason != "NO_OBSERVATION" && a.Reason != "MANAGEMENT_NOT_OBSERVED" || now.Sub(e.ManagementEnrolledAt) > networkmonitor.MaxAge) {
			// A whole-node SSH failure is already represented by its shared source
			// episode. Only a management-specific read/topology gap gets another key.
			sourceKey := a.Node + "/source"
			gapKey := a.Node + "/management/source"
			if _, shared := active[sourceKey]; !shared {
				active[gapKey] = application.NetworkPortAssessment{Key: application.NetworkPortKey{Node: a.Node, Device: a.Bond}, Condition: a.Condition, Reason: a.Reason, ReadError: a.ReadError, ObservedAt: a.ObservedAt}
			}
		}
	}
	for _, a := range management.Details {
		if a.Condition == application.NetworkHealthy {
			healthy[a.Node+"/management/source"] = true
		}
	}
	for _, a := range management.Details {
		if a.Condition != application.NetworkHealthy {
			delete(healthy, a.Node+"/management/source")
			delete(healthy, a.Node+"/source")
		}
	}
	rows, err = tx.Query(ctx, `SELECT episode_id,entity_key FROM gp09_network_episodes WHERE cluster_id=$1 AND closed_at IS NULL`, cluster)
	if err != nil {
		return err
	}
	open := map[string]string{}
	for rows.Next() {
		var id, key string
		if err := rows.Scan(&id, &key); err != nil {
			rows.Close()
			return err
		}
		open[key] = id
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for key, id := range open {
		if healthy[key] {
			if _, err := tx.Exec(ctx, `UPDATE gp09_network_episodes SET closed_at=clock_timestamp() WHERE episode_id=$1`, id); err != nil {
				return err
			}
			if err := enqueueNetworkTransition(ctx, tx, cluster, id, "RECOVERED", fmt.Sprintf("Sherlock network RECOVERED | cluster=%s | entity=%s | UTC=%s | two fresh healthy polls for the enrolled interface (IB ACTIVE/LinkUp or management carrier=1/operstate=up)", cluster, key, now.UTC().Format(time.RFC3339))); err != nil {
				return err
			}
			delete(open, key)
		}
	}
	for key, a := range active {
		if _, exists := open[key]; exists {
			continue
		}
		id, err := NewAlertID()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO gp09_network_episodes(episode_id,cluster_id,entity_key,reason) VALUES($1,$2,$3,$4)`, id, cluster, key, a.Reason); err != nil {
			return err
		}
		transition := "PORT_DOWN"
		if a.Reason == "LINK_DOWNED_INCREASE" {
			transition = "LINK_EVENT"
		}
		if strings.HasSuffix(key, "/source") {
			transition = "SOURCE_GAP"
		}
		message := fmt.Sprintf("Sherlock network %s | cluster=%s | entity=%s | reason=%s | state=%q | physical_state=%q | read_error=%s | observed_UTC=%s | evaluated_UTC=%s | polling=60s | physical rail/switch mapping unreviewed", transition, cluster, key, a.Reason, a.State, a.PhysicalState, a.ReadError, a.ObservedAt.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
		if strings.Contains(key, "/management/") && transition == "PORT_DOWN" {
			message = fmt.Sprintf("Sherlock management link DOWN | cluster=%s | entity=%s | reason=%s | carrier=%q | operstate=%q | observed_UTC=%s | evaluated_UTC=%s | polling=60s | local interface evidence; switch reachability unverified", cluster, key, a.Reason, a.PhysicalState, a.State, a.ObservedAt.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
		}
		if a.Reason == "LINK_DOWNED_INCREASE" {
			message += fmt.Sprintf(" | link_downed_delta=%d; historical counter increase, not proof of current port down", a.LinkDownDelta)
		}
		if err := enqueueNetworkTransition(ctx, tx, cluster, id, transition, message); err != nil {
			return err
		}
		open[key] = id
	}
	summary.OpenEpisodes = len(open)
	if err := tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE status IN ('PENDING','LEASED')),count(*) FILTER(WHERE status='FAILED') FROM gp09_alert_outbox WHERE cluster_id=$1 AND transition<>'TEST'`, cluster).Scan(&summary.PendingAlerts, &summary.FailedAlerts); err != nil {
		return err
	}
	data, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE gp09_network_monitors SET last_received_at=$2,summary=$3 WHERE cluster_id=$1`, cluster, received, data); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func enqueueNetworkTransition(ctx context.Context, tx pgx.Tx, cluster, id, transition, message string) error {
	alertID, err := NewAlertID()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO gp09_alert_outbox(alert_id,cluster_id,event_key,transition,message) VALUES($1,$2,$3,$4,$5) ON CONFLICT(cluster_id,event_key,transition) DO NOTHING`, alertID, cluster, id, transition, message)
	return err
}

// EnableManagement is an explicit additive enrollment, serialized with cycle
// ingestion. The reviewed IB inventory and its retained confirmation window
// cannot change. A database timestamp grants the new source its startup grace.
func (s *NetworkMonitorStore) EnableManagement(ctx context.Context, e networkmonitor.Enrollment) error {
	if err := networkmonitor.Validate(e); err != nil {
		return err
	}
	if !e.ManagementEnabled {
		return errors.New("management enrollment must be enabled")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var data []byte
	var enabled bool
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT enrollment,enabled,clock_timestamp() FROM gp09_network_monitors WHERE cluster_id=$1 FOR UPDATE`, e.ClusterID).Scan(&data, &enabled, &now); err != nil {
		return err
	}
	if !enabled {
		return ErrNetworkNotEnrolled
	}
	var old networkmonitor.Enrollment
	if err := json.Unmarshal(data, &old); err != nil {
		return err
	}
	var live bool
	if err := tx.QueryRow(ctx, `SELECT true FROM collectors c JOIN clusters k USING(cluster_id) WHERE c.collector_id=$1 AND c.cluster_id=$2 AND c.status='ACTIVE' AND k.removed_at IS NULL FOR SHARE OF c,k`, e.CollectorID, e.ClusterID).Scan(&live); err != nil || !live {
		return ErrNetworkNotEnrolled
	}
	base := e
	base.ManagementRevision = ""
	base.ManagementEnabled = false
	base.ManagementEnrolledAt = time.Time{}
	base.Bonds = nil
	oldBase := old
	oldBase.ManagementRevision = ""
	oldBase.ManagementEnabled = false
	oldBase.ManagementEnrolledAt = time.Time{}
	oldBase.Bonds = nil
	a, _ := json.Marshal(base)
	b, _ := json.Marshal(oldBase)
	if string(a) != string(b) {
		return errors.New("management enrollment cannot change IB inventory or collector")
	}
	if old.ManagementRevision != "" {
		comparable := old
		comparable.ManagementEnabled = true
		comparable.ManagementEnrolledAt = time.Time{}
		candidate := e
		candidate.ManagementEnrolledAt = time.Time{}
		a, _ = json.Marshal(comparable)
		b, _ = json.Marshal(candidate)
		if string(a) != string(b) {
			return errors.New("management enrollment revision conflict")
		}
		if old.ManagementEnabled {
			return tx.Commit(ctx)
		}
	}
	e.ManagementEnrolledAt = now
	data, err = json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE gp09_network_monitors SET enrollment=$2 WHERE cluster_id=$1`, e.ClusterID, data); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DisableManagement leaves the IB monitor and durable episode history intact.
// It never fabricates recovery for a deliberately disabled source.
func (s *NetworkMonitorStore) DisableManagement(ctx context.Context, cluster string) error {
	_, err := s.pool.Exec(ctx, `UPDATE gp09_network_monitors SET enrollment=jsonb_set(enrollment,'{ManagementEnabled}','false'::jsonb), summary=jsonb_set(summary,'{management,enrolled}','false'::jsonb) WHERE cluster_id=$1`, cluster)
	return err
}
