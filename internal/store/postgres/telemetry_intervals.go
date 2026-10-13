package postgres

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

type telemetryInterval struct {
	kind, source  string
	from, through uint64
}

func telemetryU64(v string) (uint64, error) {
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != v {
		return 0, telemetry.ErrInvalid
	}
	return n, nil
}
func loadTelemetryIntervals(ctx context.Context, tx pgx.Tx, id, epoch string) (out []telemetryInterval, err error) {
	rows, err := tx.Query(ctx, `SELECT kind,source_id,from_sequence::text,through_sequence::text FROM gp06f_telemetry_intervals WHERE enrollment_id=$1 AND session_epoch=$2 ORDER BY kind,source_id,from_sequence LIMIT 257`, id, epoch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var interval telemetryInterval
		var first, last string
		if err = rows.Scan(&interval.kind, &interval.source, &first, &last); err != nil {
			return nil, err
		}
		interval.from, err = telemetryU64(first)
		if err != nil {
			return nil, err
		}
		interval.through, err = telemetryU64(last)
		if err != nil {
			return nil, err
		}
		out = append(out, interval)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(out) > 256 {
		return nil, telemetry.ErrBackpressure
	}
	return out, nil
}
func mergeTelemetryInterval(all []telemetryInterval, added telemetryInterval) ([]telemetryInterval, error) {
	all = append(append([]telemetryInterval(nil), all...), added)
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		if a.source != b.source {
			return a.source < b.source
		}
		return a.from < b.from
	})
	out := make([]telemetryInterval, 0, len(all))
	for _, current := range all {
		if len(out) > 0 {
			previous := &out[len(out)-1]
			touches := current.from <= previous.through || previous.through != ^uint64(0) && current.from == previous.through+1
			if current.kind == previous.kind && current.source == previous.source && touches {
				if current.through > previous.through {
					previous.through = current.through
				}
				continue
			}
		}
		out = append(out, current)
	}
	if len(out) > 256 {
		return nil, telemetry.ErrBackpressure
	}
	return out, nil
}
func persistTelemetryInterval(ctx context.Context, tx pgx.Tx, id, epoch string, added telemetryInterval) error {
	all, err := loadTelemetryIntervals(ctx, tx, id, epoch)
	if err != nil {
		return err
	}
	merged, err := mergeTelemetryInterval(all, added)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM gp06f_telemetry_intervals WHERE enrollment_id=$1 AND session_epoch=$2`, id, epoch); err != nil {
		return err
	}
	return replaceTelemetryIntervals(ctx, tx, id, epoch, merged)
}
func telemetryCovered(all []telemetryInterval, sources []telemetry.SourceGrant, terminal uint64) bool {
	if terminal == 0 {
		return true
	}
	for _, source := range sources {
		var intervals []telemetryInterval
		for _, interval := range all {
			if interval.kind == "RECEIVED" || interval.kind == "LOST" && interval.source == source.SourceID {
				intervals = append(intervals, interval)
			}
		}
		sort.Slice(intervals, func(i, j int) bool { return intervals[i].from < intervals[j].from })
		next := uint64(1)
		covered := false
		for _, interval := range intervals {
			if interval.from > next {
				break
			}
			if interval.through >= terminal {
				covered = true
				break
			}
			if interval.through >= next {
				next = interval.through + 1
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// Immutable loss facts are inserted in one bounded query. Session coverage is
// merged once per affected session, avoiding one SQL round trip per loss fact.
func storeTelemetryLosses(ctx context.Context, tx pgx.Tx, g telemetry.Grant, losses []telemetry.SessionLoss) error {
	if len(losses) == 0 {
		return nil
	}
	if len(losses) > telemetry.MaxLossRanges {
		return telemetry.ErrInvalid
	}
	type knownLoss struct {
		source string
		fact   telemetry.LossRange
	}
	ids := make([]string, 0, len(losses))
	for _, loss := range losses {
		ids = append(ids, loss.Range.ID)
	}
	rows, err := tx.Query(ctx, `SELECT loss_id,source_id,fact FROM gp06f_telemetry_loss WHERE enrollment_id=$1 AND loss_id=ANY($2)`, g.EnrollmentID, ids)
	if err != nil {
		return err
	}
	known := map[string]knownLoss{}
	for rows.Next() {
		var id string
		var fact knownLoss
		var body []byte
		if err = rows.Scan(&id, &fact.source, &body); err != nil {
			rows.Close()
			return err
		}
		if err = json.Unmarshal(body, &fact.fact); err != nil {
			rows.Close()
			return err
		}
		known[id] = fact
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	type lossInsert struct {
		Enrollment string              `json:"enrollment"`
		ID         string              `json:"id"`
		Epoch      string              `json:"epoch"`
		Session    string              `json:"session"`
		Source     string              `json:"source"`
		First      string              `json:"first"`
		Last       string              `json:"last"`
		Fact       telemetry.LossRange `json:"fact"`
	}
	var inserts []lossInsert
	ledgers := map[string][]telemetryInterval{}
	fences := map[string][]telemetryInterval{}
	terminals := map[string]*string{}
	sessions := map[string]string{}
	for _, loss := range losses {
		l := loss.Range
		if prior, ok := known[l.ID]; ok {
			if prior.source != loss.SourceID || !telemetryLossEqual(prior.fact, l) {
				return telemetry.ErrConflict
			}
			continue
		}
		epoch := l.AffectedKey.SessionEpoch
		if _, ok := ledgers[epoch]; !ok {
			var terminal *string
			var session string
			if err = tx.QueryRow(ctx, `SELECT session_id,last_allocated_sequence::text FROM gp06f_telemetry_sessions WHERE enrollment_id=$1 AND session_epoch=$2`, g.EnrollmentID, epoch).Scan(&session, &terminal); err != nil {
				return err
			}
			sessions[epoch] = session
			terminals[epoch] = terminal
			ledgers[epoch], err = loadTelemetryIntervals(ctx, tx, g.EnrollmentID, epoch)
			if err != nil {
				return err
			}
			// Enrollment serialization makes one bounded fence read per affected
			// session sufficient for the whole loss batch, avoiding 256 SQL trips.
			fences[epoch], err = loadTelemetryRetirementFences(ctx, tx, g.EnrollmentID, epoch)
			if err != nil {
				return err
			}
		}
		if sessions[epoch] != l.AffectedKey.SessionID {
			return telemetry.ErrConflict
		}
		first, e := telemetryU64(l.AffectedKey.Sequence)
		if e != nil {
			return e
		}
		last, e := telemetryU64(l.ThroughSequence)
		if e != nil {
			return e
		}
		if telemetryFenceOverlap(fences[epoch], first, last) {
			return telemetry.ErrConflict
		}
		if terminals[epoch] != nil {
			terminal, e := telemetryU64(*terminals[epoch])
			if e != nil {
				return e
			}
			if last > terminal {
				return telemetry.ErrConflict
			}
		}
		for _, interval := range ledgers[epoch] {
			if interval.kind == "RECEIVED" && first <= interval.through && last >= interval.from {
				// Expiry/overflow describe discarded local copies. A gateway
				// receipt may have been committed but its response lost before
				// node expiry. Preserve both facts; actual received coverage wins.
				if l.Reason != "SPOOL_EXPIRED" && l.Reason != "SPOOL_OVERFLOW" {
					return telemetry.ErrConflict
				}
			}
		}
		ledgers[epoch], err = mergeTelemetryInterval(ledgers[epoch], telemetryInterval{kind: "LOST", source: loss.SourceID, from: first, through: last})
		if err != nil {
			return err
		}
		body, e := json.Marshal(l)
		if e != nil || len(body) > 4096 {
			return telemetry.ErrInvalid
		}
		inserts = append(inserts, lossInsert{g.EnrollmentID, l.ID, epoch, l.AffectedKey.SessionID, loss.SourceID, l.AffectedKey.Sequence, l.ThroughSequence, l})
	}
	if len(inserts) > 0 {
		body, e := json.Marshal(inserts)
		if e != nil {
			return e
		}
		if _, err = tx.Exec(ctx, `INSERT INTO gp06f_telemetry_loss(enrollment_id,loss_id,session_epoch,session_id,source_id,from_sequence,through_sequence,fact) SELECT enrollment,id,epoch::numeric,session,source,first::numeric,last::numeric,fact FROM jsonb_to_recordset($1::jsonb) AS x(enrollment text,id text,epoch text,session text,source text,first text,last text,fact jsonb)`, body); err != nil {
			return err
		}
	}
	for epoch, ledger := range ledgers {
		if _, err = tx.Exec(ctx, `DELETE FROM gp06f_telemetry_intervals WHERE enrollment_id=$1 AND session_epoch=$2`, g.EnrollmentID, epoch); err != nil {
			return err
		}
		if err = replaceTelemetryIntervals(ctx, tx, g.EnrollmentID, epoch, ledger); err != nil {
			return err
		}
	}
	return nil
}
func replaceTelemetryIntervals(ctx context.Context, tx pgx.Tx, id, epoch string, ledger []telemetryInterval) error {
	type intervalInsert struct {
		Kind   string `json:"kind"`
		Source string `json:"source"`
		First  string `json:"first"`
		Last   string `json:"last"`
	}
	items := make([]intervalInsert, 0, len(ledger))
	for _, i := range ledger {
		items = append(items, intervalInsert{i.kind, i.source, formatTelemetryU64(i.from), formatTelemetryU64(i.through)})
	}
	body, err := json.Marshal(items)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO gp06f_telemetry_intervals(enrollment_id,session_epoch,source_id,kind,from_sequence,through_sequence) SELECT $1,$2::numeric,source,kind,first::numeric,last::numeric FROM jsonb_to_recordset($3::jsonb) AS x(kind text,source text,first text,last text)`, id, epoch, body)
	return err
}

func formatTelemetryU64(value uint64) string { return strconv.FormatUint(value, 10) }

func telemetryLossEqual(a, b telemetry.LossRange) bool {
	if a.ID != b.ID || a.AffectedKey != b.AffectedKey || a.ThroughSequence != b.ThroughSequence || a.Reason != b.Reason || a.CountKnown != b.CountKnown || a.Count != b.Count || (a.FromAt == nil) != (b.FromAt == nil) || (a.ThroughAt == nil) != (b.ThroughAt == nil) {
		return false
	}
	return (a.FromAt == nil || a.FromAt.Equal(*b.FromAt)) && (a.ThroughAt == nil || a.ThroughAt.Equal(*b.ThroughAt))
}
