package postgres

import (
	"context"
	"math"
	"slices"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
)

// Admission validates the whole signed upload, including expected GPU identities,
// field units, clocks, and the profile task. Only use original, jointly written
// receipt/run/observation rows, with the per-enrollment binding for each metric.
// Pair observations at exactly the same GPU source timestamp before comparing GPUs.
// The outer caller supplies only enrolled peers on the target's physical node.
const suspectedPeerRowsSQL = `
WITH scoped_profiles AS MATERIALIZED (
 SELECT p.*, ARRAY(SELECT DISTINCT x->>'node_id' COLLATE "C" AS node
                   FROM jsonb_array_elements(p.profile->'assets') x ORDER BY node) AS nodes
 FROM prometheus_cooling_upload_profiles p
 WHERE p.cluster_id=$1 AND p.source_id=$2 AND p.inventory_revision=$5
   AND p.protocol_version=3 AND p.collection_state='ENABLED'
   AND p.registered_at<$4 AND p.starts_at<=$4
   AND (p.revoked_at IS NULL OR p.revoked_at >= $4::timestamptz-interval '135 seconds')
   AND ((p.profile_id=$6 AND p.revision>=$7 AND p.collector_id=$8)
     OR (p.profile_id=$9 AND p.revision>=$10 AND p.collector_id=$11))
   AND p.profile->'assets' @> jsonb_build_array(jsonb_build_object('node_id',$14::text,'gpu_uuid',$15::text))
), paired AS (
 SELECT o.entity_key,o.observed_at,
        min(o.value) FILTER (WHERE o.metric='DCGM_FI_DEV_GPU_TEMP') AS low_c,
        max(o.value) FILTER (WHERE o.metric='DCGM_FI_DEV_GPU_TEMP') AS high_c,
        min(o.value) FILTER (WHERE o.metric='DCGM_FI_DEV_POWER_USAGE') AS low_w,
        max(o.value) FILTER (WHERE o.metric='DCGM_FI_DEV_POWER_USAGE') AS high_w
 FROM observations o
 JOIN prometheus_cooling_upload_receipts u ON u.run_id=o.run_id AND u.xmin=o.xmin
 JOIN collection_runs r ON r.run_id=u.run_id AND r.xmin=u.xmin
 JOIN scoped_profiles p ON p.profile_id=u.profile_id AND p.revision=u.profile_revision
    AND p.collector_id=u.collector_id AND p.profile_hash=u.profile_hash
 WHERE o.cluster_id=$1 AND o.source_id=$2 AND o.entity_key=ANY($3::text[])
   AND o.observed_at BETWEEN $4::timestamptz-interval '135 seconds' AND $4
   AND u.received_at BETWEEN o.observed_at AND $4 AND r.completed_at<=u.received_at
   AND p.registered_at<r.scheduled_for AND p.starts_at<=r.scheduled_for
   AND (p.revoked_at IS NULL OR u.received_at<=p.revoked_at)
   AND (SELECT CASE WHEN i.source_at<=r.completed_at THEN i.revision_id END
        FROM goodput_inventory_revisions i WHERE i.cluster_id=$1 AND i.source_id=$2
          AND i.inventory_class='EXPECTED' AND i.effective_at<=r.scheduled_for AND i.observed_at<=r.completed_at
        ORDER BY i.effective_at DESC,i.observed_at DESC,i.source_at DESC,i.revision_id DESC LIMIT 1)=$5
   AND r.cluster_id=$1 AND r.source_id=$2 AND r.status='SUCCEEDED' AND r.coverage_complete
   AND r.idempotency_key='prometheus-cooling-report-v2-'||u.payload_hash
   AND ((o.metric='DCGM_FI_DEV_GPU_TEMP' AND r.query_kind='dcgm_gpu_temperature'
        AND p.profile_id=$6 AND p.revision>=$7 AND p.collector_id=$8 AND p.nodes=$12::text[])
     OR (o.metric='DCGM_FI_DEV_POWER_USAGE' AND r.query_kind='dcgm_gpu_power'
        AND p.profile_id=$9 AND p.revision>=$10 AND p.collector_id=$11 AND p.nodes=$13::text[]))
 GROUP BY o.entity_key,o.observed_at
)
SELECT entity_key,observed_at,low_c,low_w FROM paired
WHERE low_c=high_c AND low_w=high_w AND low_c BETWEEN 0 AND 150 AND low_w BETWEEN 0 AND 2000
ORDER BY entity_key,observed_at LIMIT 2049`

type peerReading struct {
	key         string
	at          time.Time
	temp, watts float64
}

func (s *ProductionAssessmentStore) suspectedPeers(ctx context.Context, asset string, at time.Time, c cooling.WarmingContext) *cooling.PeerContext {
	cfg := s.config.Assessment
	idx := slices.IndexFunc(cfg.Assets, func(v a.Asset) bool { return v.EntityKey == asset })
	if idx < 0 || at.IsZero() {
		return &cooling.PeerContext{Status: "unavailable"}
	}
	var keys []string
	for _, v := range cfg.Assets {
		if v.NodeID == cfg.Assets[idx].NodeID && v.GPUUUID != cfg.Assets[idx].GPUUUID {
			keys = append(keys, v.EntityKey)
		}
	}
	if len(keys) == 0 {
		return &cooling.PeerContext{Status: "no_enrolled_peers"}
	}
	var temp, power a.Binding
	for _, b := range cfg.Bindings {
		switch b.Metric {
		case cooling.Temperature:
			temp = b
		case cooling.Power:
			power = b
		}
	}
	if temp.UploadProfileID == "" || power.UploadProfileID == "" {
		return &cooling.PeerContext{Status: "unavailable"}
	}
	bounded, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	rows, err := s.pool.Query(bounded, suspectedPeerRowsSQL, cfg.ClusterID, cfg.SourceID, keys, at, cfg.InventoryRevision, temp.UploadProfileID, temp.ScheduleRevision, temp.UploadCollectorID, power.UploadProfileID, power.ScheduleRevision, power.UploadCollectorID, temp.ScopeNodes, power.ScopeNodes, cfg.Assets[idx].NodeID, cfg.Assets[idx].GPUUUID)
	if err != nil {
		return &cooling.PeerContext{Status: "lookup_error"}
	}
	defer rows.Close()
	var readings []peerReading
	for rows.Next() {
		var r peerReading
		if err := rows.Scan(&r.key, &r.at, &r.temp, &r.watts); err != nil {
			return &cooling.PeerContext{Status: "lookup_error"}
		}
		if len(readings) >= 2048 {
			return &cooling.PeerContext{Status: "capacity"}
		}
		readings = append(readings, r)
	}
	if rows.Err() != nil {
		return &cooling.PeerContext{Status: "lookup_error"}
	}
	return summarizeSuspectedPeers(at, c, readings)
}

func summarizeSuspectedPeers(at time.Time, c cooling.WarmingContext, readings []peerReading) *cooling.PeerContext {
	out := &cooling.PeerContext{Status: "sparse"}
	distinct := make(map[string]bool)
	for _, target := range c.Rows {
		if target[0] == nil || target[1] == nil || target[2] == nil {
			continue
		}
		sec := *target[0]
		if math.IsNaN(sec) || sec < -120 || sec > 0 {
			continue
		}
		targetAt := at.Add(time.Duration(math.Round(sec*1e6)) * time.Microsecond)
		nearest := make(map[string]peerReading)
		for _, r := range readings {
			gap := r.at.Sub(targetAt).Abs()
			if r.at.After(at) || gap > 15*time.Second {
				continue
			}
			prior, seen := nearest[r.key]
			if !seen || gap < prior.at.Sub(targetAt).Abs() || (gap == prior.at.Sub(targetAt).Abs() && r.at.Before(prior.at)) {
				nearest[r.key] = r
			}
		}
		var temps []float64
		for key, r := range nearest {
			if math.Abs(r.watts-*target[2]) <= 25 {
				distinct[key] = true
				temps = append(temps, r.temp)
			}
		}
		if len(temps) == 0 {
			continue
		}
		slices.Sort(temps)
		n := len(temps)
		out.Rows = append(out.Rows, cooling.PeerComparison{SecondsBeforeOpen: -sec, TargetC: *target[1], TargetW: *target[2], Peers: n, MedianC: (temps[n/2] + temps[(n-1)/2]) / 2, MaxC: temps[n-1]})
		if n >= 2 {
			out.Status = "available"
		}
	}
	out.DistinctPeers = len(distinct)
	return out
}
