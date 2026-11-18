package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

type assessmentSnapshot struct {
	facts, bundles     map[string]bool
	candidateRevision  map[string]int64
	enrollmentRevision map[string]int64
	decisionIDs        map[string]bool
	failureCount       map[string]int64
	selected           []string
}

func newAssessmentSnapshot() assessmentSnapshot {
	return assessmentSnapshot{map[string]bool{}, map[string]bool{}, map[string]int64{}, map[string]int64{}, map[string]bool{}, map[string]int64{}, []string{}}
}

// Stored facts use canonical byte order. Checking the already typed envelope
// avoids constructing an intermediate JSON tree for its separately validated
// body on every rolling history read.
type assessmentFactRecord struct {
	Asset       string          `json:"asset"`
	AvailableAt time.Time       `json:"available_at"`
	Body        json.RawMessage `json:"body"`
	ID          string          `json:"id"`
	Kind        string          `json:"kind"`
	Run         string          `json:"run"`
}

func encodeAssessmentFact(f a.Fact) ([]byte, error) {
	return json.Marshal(assessmentFactRecord{Asset: f.Asset, AvailableAt: f.AvailableAt.UTC().Truncate(time.Microsecond), Body: f.Body, ID: f.ID, Kind: f.Kind, Run: f.Run})
}

func decodeAssessmentFact(body []byte, limit int) (a.Fact, error) {
	if len(body) > limit {
		return a.Fact{}, a.ErrInvalid
	}
	var wire assessmentFactRecord
	if err := json.Unmarshal(body, &wire); err != nil {
		return a.Fact{}, err
	}
	f := a.Fact{Asset: wire.Asset, AvailableAt: wire.AvailableAt, Body: wire.Body, ID: wire.ID, Kind: wire.Kind, Run: wire.Run}
	canonical, err := encodeAssessmentFact(f)
	if err != nil || !bytes.Equal(canonical, body) {
		return a.Fact{}, a.ErrInvalid
	}
	return f, nil
}

func (s *AssessmentStore) loadEngine(ctx context.Context, tx pgx.Tx, at time.Time, dueOnly ...bool) (*a.Engine, assessmentSnapshot, error) {
	historical := len(dueOnly) > 0 && dueOnly[0]
	return s.loadEngineSnapshot(ctx, tx, at, historical, len(dueOnly) > 0 && !historical, "")
}

// A failed category disposition may have exceeded remaining persistence
// capacity. Retry only the common trusted deadline path in a fresh unit.
func (s *AssessmentStore) loadEngineForFallback(ctx context.Context, tx pgx.Tx, at time.Time, cause string) (*a.Engine, assessmentSnapshot, error) {
	return s.loadEngineSnapshot(ctx, tx, at, true, false, cause)
}

func (s *AssessmentStore) loadEngineSnapshot(ctx context.Context, tx pgx.Tx, at time.Time, historical, selectNow bool, forced string) (*a.Engine, assessmentSnapshot, error) {
	snap := newAssessmentSnapshot()
	var config, descriptor, coverage []byte
	var start, end time.Time
	var closed, unknownFrom, unknownThrough *time.Time
	var state, configHash, descriptorHash string
	var truncated bool
	var overflow int64
	err := tx.QueryRow(ctx, `SELECT config,config_hash,descriptor,descriptor_hash,start_at,admission_end_at,closed_at,state,followup_truncated,overflow_count,unknown_from,unknown_through,coverage FROM assessment_runs WHERE run_id=$1 FOR UPDATE`, s.config.RunID).Scan(&config, &configHash, &descriptor, &descriptorHash, &start, &end, &closed, &state, &truncated, &overflow, &unknownFrom, &unknownThrough, &coverage)
	if err != nil {
		return nil, snap, err
	}
	pinned, err := matchedAssessmentDescriptor(s.config, config, descriptor, configHash, descriptorHash)
	if err != nil {
		return nil, snap, err
	}
	_, _, installedHash, installedErr := s.registry.LookupVersion(s.config.Category, s.config.Implementation)
	recoverOnly := s.recoveryOnly || installedErr != nil || installedHash != descriptorHash
	if forced == "" && state == "DRAINING" {
		var blocked bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM assessment_failures WHERE run_id=$1 AND asset IS NULL AND code='CAPACITY' AND scope_key='deadline_capacity')`, s.config.RunID).Scan(&blocked); err != nil {
			return nil, snap, err
		}
		if !blocked {
			var intervals []assessmentCoverageInterval
			if err := a.DecodeStrict(coverage, &intervals, 256<<10); err != nil || len(intervals) > 1024 {
				return nil, snap, a.ErrInvalid
			}
			for _, interval := range intervals {
				blocked = blocked || interval.Code == "DEADLINE_CAPACITY"
			}
		}
		if blocked {
			historical, selectNow, forced = true, false, "CAPACITY"
		}
	}
	var e *a.Engine
	if recoverOnly || forced != "" {
		e, err = a.NewRecoveryEngine(ctx, s.config, start, pinned, configHash, descriptorHash)
	} else {
		e, err = a.NewEngine(ctx, s.config, start, s.registry)
		if err != nil && ctx.Err() == nil {
			recoverOnly = true
			e, err = a.NewRecoveryEngine(ctx, s.config, start, pinned, configHash, descriptorHash)
		}
	}
	if err != nil {
		return nil, snap, err
	}
	e.State = state
	e.AdmissionEndAt = end.UTC()
	e.FollowupTruncated = truncated
	e.FailureOverflow = overflow
	if (unknownFrom == nil) != (unknownThrough == nil) {
		return nil, snap, a.ErrInvalid
	}
	if unknownFrom != nil {
		from, through := unknownFrom.UTC(), unknownThrough.UTC()
		e.UnknownFrom, e.UnknownThrough = &from, &through
	}
	if err := a.DecodeStrict(coverage, &e.CoverageIntervals, 256<<10); err != nil || len(e.CoverageIntervals) > 1024 {
		return nil, snap, a.ErrInvalid
	}
	if closed != nil {
		e.ClosedAt = closed.UTC()
	}
	e.Shadow = true
	e.ObserveGPU = s.observeGPU
	if recoverOnly && e.State != "CLOSED" {
		e.BeginDrain("UNSUPPORTED_VERSION")
		historical, selectNow, forced = true, false, "UNSUPPORTED_VERSION"
	}
	if forced != "" {
		e.ForceDeadlineFallback(forced)
	}
	type schedulable struct {
		asset     string
		due       time.Time
		attempted *time.Time
	}
	var ready []schedulable
	rows, err := tx.Query(ctx, `SELECT asset,discovery_floor,next_due_at,last_attempt_at,sequence,revision,rearm_eligible,tracker,tracker_hash FROM assessment_enrollments WHERE run_id=$1 ORDER BY asset FOR UPDATE`, s.config.RunID)
	if err != nil {
		return nil, snap, err
	}
	for rows.Next() {
		var asset string
		var floor, nextDue time.Time
		var attempted *time.Time
		var sequence, revision int64
		var rearm bool
		var tracker []byte
		var hash *string
		if err = rows.Scan(&asset, &floor, &nextDue, &attempted, &sequence, &revision, &rearm, &tracker, &hash); err != nil {
			rows.Close()
			return nil, snap, err
		}
		en, ok := e.Enrollments[asset]
		if !ok {
			rows.Close()
			return nil, snap, a.ErrInvalid
		}
		en.DiscoveryFloor = floor.UTC()
		if attempted != nil {
			en.ProcessedAt = attempted.UTC()
		}
		nextDue = nextDue.UTC()
		en.NextLogicalAt = &nextDue
		if selectNow && !nextDue.After(at) {
			ready = append(ready, schedulable{asset: asset, due: nextDue, attempted: attempted})
		}
		en.Sequence = sequence
		en.Revision = revision
		en.Active = !rearm
		if tracker != nil {
			if hash == nil {
				return nil, snap, a.ErrInvalid
			}
			p := a.Payload{Category: s.config.Category, Kind: "tracker", Schema: pinned.TrackerSchema, Hash: *hash, Body: tracker}
			en.Tracker = &p
		}
		snap.enrollmentRevision[asset] = revision
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, snap, err
	}
	sort.Slice(ready, func(i, j int) bool {
		a, b := ready[i], ready[j]
		if !a.due.Equal(b.due) {
			return a.due.Before(b.due)
		}
		if a.attempted != nil && b.attempted != nil && !a.attempted.Equal(*b.attempted) {
			return a.attempted.Before(*b.attempted)
		}
		if (a.attempted == nil) != (b.attempted == nil) {
			return a.attempted == nil
		}
		return a.asset < b.asset
	})
	// Use one acquisition slot to limit contention with monitoring. Deadline
	// processing has its own pass and remains independent of this selection.
	if len(ready) > 0 {
		snap.selected = append(snap.selected, ready[0].asset)
	}
	rows, err = tx.Query(ctx, `SELECT c.id,c.asset,c.sequence,c.budget_ms,c.revision,c.phase,c.entered_at,c.due_at,c.entry,c.initial_state,c.initial_hash,c.state,c.state_hash,c.terminal,c.reserved_codes FROM assessment_candidates c JOIN assessment_enrollments n ON n.run_id=c.run_id AND n.category=c.category AND n.asset=c.asset WHERE c.run_id=$1 AND (c.sequence=n.sequence OR c.phase='OBSERVING') ORDER BY c.asset,c.budget_ms FOR UPDATE OF c`, s.config.RunID)
	if err != nil {
		return nil, snap, err
	}
	for rows.Next() {
		var c a.Candidate
		var entry, initial, state, terminal []byte
		var ih, sh string
		if err = rows.Scan(&c.ID, &c.Asset, &c.Sequence, &c.BudgetMS, &c.Revision, &c.Phase, &c.EnteredAt, &c.DueAt, &entry, &initial, &ih, &state, &sh, &terminal, &c.ReservedCodes); err != nil {
			rows.Close()
			return nil, snap, err
		}
		if len(e.Candidates) >= 40 {
			rows.Close()
			return nil, snap, ErrAssessmentCapacity
		}
		if err = a.DecodeStrict(entry, &c.Entry, 8192); err != nil {
			c.Entry = a.Entry{}
			if c.Phase != "OBSERVING" && c.Phase != "QUARANTINED" {
				rows.Close()
				return nil, snap, fmt.Errorf("HOST_STATE")
			}
		}
		c.InitialState = a.Payload{Category: s.config.Category, Kind: "candidate", Schema: pinned.CandidateSchema, Hash: ih, Body: initial}
		c.State = a.Payload{Category: s.config.Category, Kind: "candidate", Schema: pinned.CandidateSchema, Hash: sh, Body: state}
		if terminal != nil {
			var terminalValue a.Terminal
			if err = a.DecodeStrict(terminal, &terminalValue, 8192); err != nil {
				rows.Close()
				return nil, snap, fmt.Errorf("HOST_STATE")
			}
			c.Terminal = &terminalValue
		}
		c.EnteredAt = c.EnteredAt.UTC()
		c.DueAt = c.DueAt.UTC()
		snap.candidateRevision[c.ID] = c.Revision
		e.Candidates = append(e.Candidates, &c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, snap, err
	}
	// Rolling views cannot spend the independent allowance for resolving the
	// trusted entry support needed by a failed asset or deadline fallback.
	lazyFacts := make(map[string]a.Fact)
	lazyBytes := 0
	loadFact := func(id string) (a.Fact, bool) {
		if f, ok := lazyFacts[id]; ok {
			f.Body = bytes.Clone(f.Body)
			return f, true
		}
		var body []byte
		if len(lazyFacts) >= 6144 {
			return a.Fact{}, false
		}
		if err := tx.QueryRow(ctx, `SELECT body FROM assessment_facts WHERE run_id=$1 AND id=$2`, s.config.RunID, id).Scan(&body); err != nil {
			return a.Fact{}, false
		}
		f, decodeErr := decodeAssessmentFact(body, min(65536, a.MaxInputBytes-lazyBytes))
		if decodeErr != nil {
			return a.Fact{}, false
		}
		h, err := a.FactIdentity(s.config.Category, f)
		if err != nil || h != id || f.ID != id || f.Run != s.config.RunID {
			return a.Fact{}, false
		}
		lazyBytes += len(body)
		lazyFacts[id] = f
		f.Body = bytes.Clone(f.Body)
		snap.facts[f.ID] = true
		return f, true
	}
	e.LookupFact = loadFact
	e.LookupContext = func(asset string, cutoff, floor time.Time) (a.Fact, bool) {
		var body []byte
		if tx.QueryRow(ctx, `SELECT body FROM assessment_facts WHERE run_id=$1 AND asset=$2 AND kind='TRACKER_CONTEXT' AND available_at BETWEEN $3 AND $4 ORDER BY available_at DESC,(convert_from(body,'UTF8')::jsonb#>>'{body,revision}')::bigint DESC,id DESC LIMIT 1`, s.config.RunID, asset, floor, cutoff).Scan(&body) != nil {
			return a.Fact{}, false
		}
		fact, err := decodeAssessmentFact(body, 24576)
		if err != nil {
			return a.Fact{}, false
		}
		snap.facts[fact.ID] = true
		return fact, true
	}
	// Entry and tracker bundles are reused by several arms. Cache only positive
	// immutable hits from this transaction, and copy arrays at the boundary.
	lazyBundles := make(map[string]a.Bundle)
	lazyBundleBytes := 0
	e.LookupBundle = func(id string) (a.Bundle, bool) {
		if b, ok := lazyBundles[id]; ok {
			b.Facts, b.Features = slices.Clone(b.Facts), slices.Clone(b.Features)
			return b, true
		}
		var body []byte
		if tx.QueryRow(ctx, `SELECT body FROM assessment_bundles WHERE run_id=$1 AND id=$2`, s.config.RunID, id).Scan(&body) != nil {
			return a.Bundle{}, false
		}
		var b a.Bundle
		if a.DecodeStrict(body, &b, 262144) != nil {
			return a.Bundle{}, false
		}
		h, err := a.BundleID(s.config.Category, b)
		if err != nil || h != id || b.ID != id || b.Run != s.config.RunID {
			return a.Bundle{}, false
		}
		snap.bundles[b.ID] = true
		if len(lazyBundles) < 128 && lazyBundleBytes+len(body) <= 4<<20 {
			lazyBundleBytes += len(body)
			lazyBundles[id] = b
			b.Facts, b.Features = slices.Clone(b.Facts), slices.Clone(b.Features)
		}
		return b, true
	}
	// The due-only transaction reconstructs the original cutoff history even
	// after it has aged out of the current acquisition window. Arms sharing a
	// cohort consume disjoint cutoff views of one bounded retained window.
	type cutoffRange struct{ first, last time.Time }
	deadlines := make(map[string]cutoffRange)
	if historical || selectNow {
		dueThrough := at
		if selectNow {
			dueThrough = at.Add(750 * time.Millisecond)
		}
		for _, c := range e.Candidates {
			if c.Phase != "OBSERVING" || c.DueAt.After(dueThrough) {
				continue
			}
			r := deadlines[c.Asset]
			if r.first.IsZero() || c.DueAt.Before(r.first) {
				r.first = c.DueAt
			}
			if c.DueAt.After(r.last) {
				r.last = c.DueAt
			}
			deadlines[c.Asset] = r
		}
	}
	loaded, loadedBytes := 0, 0
	// Each bounded lookback is staged in full. A capacity witness suppresses
	// only that asset; no partial history can support a category result.
	for _, asset := range s.config.Assets {
		if forced != "" {
			break
		}
		from, through := at.Add(-900*time.Second), at
		r, due := deadlines[asset.EntityKey]
		current := !historical && (!selectNow || slices.Contains(snap.selected, asset.EntityKey))
		if !current {
			if !due {
				continue
			}
			from, through = r.first.Add(-900*time.Second), r.last
			if through.After(at) {
				through = at
			}
		} else if due && r.first.Add(-900*time.Second).Before(from) {
			from = r.first.Add(-900 * time.Second)
		}
		en := e.Enrollments[asset.EntityKey]
		rows, err = tx.Query(ctx, assessmentRetainedLookbackSQL, s.config.RunID, asset.EntityKey, from, en.Active, en.DiscoveryFloor, through)
		if err != nil {
			return nil, snap, err
		}
		var window []a.Fact
		windowBytes := 0
		overflowed := false
		for rows.Next() {
			var body []byte
			if err = rows.Scan(&body); err != nil {
				rows.Close()
				return nil, snap, err
			}
			windowBytes += len(body)
			if len(window) >= a.MaxFacts || loaded+len(window) >= 8192 || loadedBytes+windowBytes > a.MaxInputBytes {
				overflowed = true
				break
			}
			f, decodeErr := decodeAssessmentFact(body, 65536)
			if decodeErr != nil {
				rows.Close()
				return nil, snap, decodeErr
			}
			h, fe := a.FactIdentity(s.config.Category, f)
			if fe != nil || h != f.ID || f.Asset != asset.EntityKey {
				rows.Close()
				return nil, snap, a.ErrInvalid
			}
			window = append(window, f)
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return nil, snap, err
		}
		if overflowed {
			e.SuppressAsset(asset.EntityKey, "CAPACITY")
			continue
		}
		loaded += len(window)
		loadedBytes += windowBytes
		for _, f := range window {
			e.Facts[f.ID] = f
			snap.facts[f.ID] = true
		}
	}
	if err = loadAssessmentFaults(ctx, tx, e); err != nil {
		return nil, snap, err
	}
	for _, f := range e.Failures {
		snap.failureCount[f.ID] = f.Count
	}
	return e, snap, nil
}

// The three indexed sources are disjoint. Only IDs/timestamps are sorted;
// immutable bodies are fetched after the 1,024-row limit and overflow witness.
const assessmentRetainedLookbackSQL = `
WITH recent AS MATERIALIZED (
 SELECT id,available_at FROM assessment_facts WHERE run_id=$1 AND asset=$2 AND available_at BETWEEN $3 AND $6
 ORDER BY available_at,id LIMIT 1025
), delayed AS MATERIALIZED (
 SELECT id,available_at FROM assessment_facts WHERE run_id=$1 AND asset=$2 AND kind='SAMPLE'
  AND public.assessment_sample_source(body)>=$3 AND available_at<$3
 ORDER BY public.assessment_sample_source(body),id LIMIT 1025
), qualified AS MATERIALIZED (
 SELECT id,available_at FROM assessment_facts WHERE $4::boolean AND run_id=$1 AND asset=$2
  AND kind='QUALIFIED' AND available_at >= $5 AND available_at<$3
  AND convert_from(body,'UTF8')::jsonb #>> '{body,transition}'='OPEN'
  AND convert_from(body,'UTF8')::jsonb #>> '{body,severity}'='CRITICAL'
  AND convert_from(body,'UTF8')::jsonb #>> '{body,rule}' IN ('gpu_thermal','hbm_thermal')
 ORDER BY available_at,id LIMIT 1025
), selected AS MATERIALIZED (
 SELECT * FROM recent UNION ALL SELECT * FROM delayed UNION ALL SELECT * FROM qualified
 ORDER BY available_at,id LIMIT 1025
)
SELECT f.body FROM selected s JOIN assessment_facts f ON f.run_id=$1 AND f.id=s.id
ORDER BY s.available_at,s.id`

const assessmentWriteBatch = 64

// Cache exact admission identities in one snapshot query. On-demand frozen
// references and newly derived IDs still use the normal fact resolver.
func prefetchAssessmentAdmissions(ctx context.Context, tx pgx.Tx, e *a.Engine, facts []a.Fact) error {
	if len(facts) > 2*a.MaxFacts {
		return ErrAssessmentCapacity
	}
	checked := make(map[string]string, len(facts))
	ids := make([]string, 0, len(facts))
	for _, f := range facts {
		if _, current := e.Facts[f.ID]; current {
			continue
		}
		if _, duplicate := checked[f.ID]; !duplicate {
			checked[f.ID] = f.Asset
			ids = append(ids, f.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT incoming.id,f.body FROM unnest($2::text[]) AS incoming(id)
 CROSS JOIN LATERAL (SELECT body FROM assessment_facts WHERE run_id=$1 AND id=incoming.id LIMIT 1) f`, e.Config.RunID, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	stored := make(map[string]a.Fact)
	bytes := 0
	for rows.Next() {
		var id string
		var body []byte
		if err := rows.Scan(&id, &body); err != nil {
			return err
		}
		bytes += len(body)
		if bytes > a.MaxInputBytes {
			return ErrAssessmentCapacity
		}
		f, err := decodeAssessmentFact(body, 65536)
		if err != nil {
			return err
		}
		hash, err := a.FactIdentity(e.Config.Category, f)
		if err != nil || f.Run != e.Config.RunID || f.Asset != checked[id] || hash != id || f.ID != id {
			return a.ErrInvalid
		}
		stored[id] = f
	}
	if err := rows.Err(); err != nil {
		return err
	}
	previous := e.LookupFact
	e.LookupFact = func(id string) (a.Fact, bool) {
		if _, checked := checked[id]; checked {
			f, ok := stored[id]
			return f, ok
		}
		if previous != nil {
			return previous(id)
		}
		return a.Fact{}, false
	}
	return nil
}

func saveAssessmentFacts(ctx context.Context, tx pgx.Tx, e *a.Engine, snap assessmentSnapshot) error {
	ids := make([]string, 0, len(e.Facts))
	for id := range e.Facts {
		if !snap.facts[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for chunk := range slices.Chunk(ids, assessmentWriteBatch) {
		assets, kinds := make([]string, 0, len(chunk)), make([]string, 0, len(chunk))
		times, bodies := make([]time.Time, 0, len(chunk)), make([][]byte, 0, len(chunk))
		for _, id := range chunk {
			f := e.Facts[id]
			body, err := encodeAssessmentFact(f)
			if err != nil {
				return err
			}
			assets, kinds, times, bodies = append(assets, f.Asset), append(kinds, f.Kind), append(times, f.AvailableAt), append(bodies, body)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO assessment_facts(run_id,id,asset,kind,available_at,body)
 SELECT $1,* FROM unnest($2::text[],$3::text[],$4::text[],$5::timestamptz[],$6::bytea[])
 ON CONFLICT(run_id,id) DO NOTHING`, e.Config.RunID, chunk, assets, kinds, times, bodies); err != nil {
			return err
		}
	}
	return nil
}

func saveAssessmentBundles(ctx context.Context, tx pgx.Tx, e *a.Engine, snap assessmentSnapshot) error {
	ids := make([]string, 0, len(e.Bundles))
	for id := range e.Bundles {
		if !snap.bundles[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for chunk := range slices.Chunk(ids, assessmentWriteBatch) {
		assets := make([]string, 0, len(chunk))
		logical, cutoff := make([]time.Time, 0, len(chunk)), make([]time.Time, 0, len(chunk))
		bodies := make([][]byte, 0, len(chunk))
		for _, id := range chunk {
			b := e.Bundles[id]
			body, err := a.Canonical(b)
			if err != nil {
				return err
			}
			assets, logical, cutoff, bodies = append(assets, b.Asset), append(logical, b.LogicalAt), append(cutoff, b.AvailabilityCutoff), append(bodies, body)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO assessment_bundles(run_id,id,asset,logical_at,availability_cutoff,body)
 SELECT $1,* FROM unnest($2::text[],$3::text[],$4::timestamptz[],$5::timestamptz[],$6::bytea[])
 ON CONFLICT(run_id,id) DO NOTHING`, e.Config.RunID, chunk, assets, logical, cutoff, bodies); err != nil {
			return err
		}
	}
	return nil
}

func (s *AssessmentStore) saveEngine(ctx context.Context, tx pgx.Tx, e *a.Engine, snap assessmentSnapshot, at time.Time, selected []string) error {
	if err := saveAssessmentFacts(ctx, tx, e, snap); err != nil {
		return err
	}
	if err := saveAssessmentBundles(ctx, tx, e, snap); err != nil {
		return err
	}
	for _, c := range e.Candidates {
		var entry []byte
		var err error
		if _, exists := snap.candidateRevision[c.ID]; !exists {
			entry, err = a.Canonical(c.Entry)
			if err != nil {
				return err
			}
		}
		var terminal []byte
		var terminalID *string
		if c.Terminal != nil {
			terminal, err = a.Canonical(*c.Terminal)
			if err != nil {
				return err
			}
			terminalID = &c.Terminal.DecisionID
		}
		revision, exists := snap.candidateRevision[c.ID]
		if exists {
			if c.Revision == revision {
				continue
			}
			tag, err := tx.Exec(ctx, `UPDATE assessment_candidates SET revision=$3,phase=$4,state=$5,state_hash=$6,terminal_id=$7,terminal=$8,reserved_codes=$9 WHERE run_id=$1 AND id=$2 AND revision=$10`, s.config.RunID, c.ID, c.Revision, c.Phase, c.State.Body, c.State.Hash, terminalID, terminal, c.ReservedCodes, revision)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("HOST_STATE")
			}
		} else {
			if _, err = tx.Exec(ctx, `INSERT INTO assessment_candidates(run_id,id,category,asset,sequence,budget_ms,revision,phase,entered_at,due_at,entry_bundle,entry,initial_state,initial_hash,state,state_hash,terminal_id,terminal,reserved_codes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`, s.config.RunID, c.ID, s.config.Category, c.Asset, c.Sequence, c.BudgetMS, c.Revision, c.Phase, c.EnteredAt, c.DueAt, c.Entry.BundleID, entry, c.InitialState.Body, c.InitialState.Hash, c.State.Body, c.State.Hash, terminalID, terminal, c.ReservedCodes); err != nil {
				return err
			}
		}
	}
	for _, d := range e.Decisions {
		var details []byte
		var detailsHash *string
		if d.Details != nil {
			details = d.Details.Body
			detailsHash = &d.Details.Hash
		}
		route := "none"
		if d.Action != "NONE" {
			route = s.config.Routes.Investigate
		}
		metadata := map[string]any{"schema": int64(1), "route": route, "urgent_occurrences": d.UrgentOccurrences}
		if d.TerminalEndpoint != nil {
			metadata["terminal_endpoint"] = *d.TerminalEndpoint
		}
		meta, err := a.Canonical(metadata)
		if err != nil {
			return err
		}
		// Shadow decision time accounts for previous fact/bundle writes. Stored
		// replay rows retain the explicit original execution and commit times.
		if _, err = tx.Exec(ctx, `WITH stamp AS MATERIALIZED (SELECT date_trunc('microseconds',clock_timestamp()) AS ts)
 INSERT INTO assessment_decisions(run_id,id,candidate_id,kind,logical_at,executed_at,committed_at,lateness_us,action,decision_source,outcome,host_cause,failure_code,bundle_id,codes,reasons,support,summary,details,details_hash,metadata)
 SELECT $1,$2,$3,$4,$5,$6,CASE WHEN $22 THEN stamp.ts ELSE $7 END,
        CASE WHEN NOT $22 THEN $8 WHEN $4='TERMINAL' THEN greatest(0,(extract(epoch FROM stamp.ts-c.due_at)*1000000)::bigint) ELSE 0 END,
        $9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21
 FROM stamp,assessment_candidates c WHERE c.run_id=$1 AND c.id=$3 ON CONFLICT(run_id,id) DO NOTHING`, s.config.RunID, d.ID, d.CandidateID, d.Kind, d.LogicalAt, d.ExecutedAt, d.CommittedAt, d.LatenessUS, d.Action, d.DecisionSource, assessmentNullable(d.Outcome), assessmentNullable(d.HostCause), assessmentNullable(d.FailureCode), d.BundleID, d.Codes, d.Reasons, d.Support, d.Summary, details, detailsHash, meta, e.Shadow); err != nil {
			return err
		}
	}
	for _, asset := range s.config.Assets {
		en := e.Enrollments[asset.EntityKey]
		chosen := false
		for _, key := range selected {
			chosen = chosen || key == en.Asset
		}
		if !chosen && en.Revision == snap.enrollmentRevision[en.Asset] {
			continue
		}
		var tracker []byte
		var hash *string
		if en.Tracker != nil {
			tracker = en.Tracker.Body
			hash = &en.Tracker.Hash
		}
		next := at.Add(time.Second)
		if en.NextLogicalAt != nil && en.NextLogicalAt.After(at) && en.NextLogicalAt.Before(next) {
			next = *en.NextLogicalAt
		}
		attempted := en.ProcessedAt
		if attempted.IsZero() {
			attempted = at
		}
		if _, err := tx.Exec(ctx, `UPDATE assessment_enrollments SET discovery_floor=$3,next_due_at=$4,last_attempt_at=$5,sequence=$6,revision=$7,rearm_eligible=$8,tracker=$9,tracker_hash=$10 WHERE run_id=$1 AND asset=$2 AND revision=$11`, s.config.RunID, en.Asset, en.DiscoveryFloor, next, attempted, en.Sequence, en.Revision, !en.Active, tracker, hash, snap.enrollmentRevision[en.Asset]); err != nil {
			return err
		}
	}
	for _, f := range e.Failures {
		if snap.failureCount[f.ID] == f.Count {
			continue
		}
		from, through := f.FirstAt, f.At
		if f.LogicalFrom != nil {
			from = *f.LogicalFrom
		}
		if f.LogicalThrough != nil {
			through = *f.LogicalThrough
		}
		bodyValue := map[string]any{"schema": int64(1), "fact_ids": f.FactIDs, "message": f.Code, "from": from, "through": through}
		if f.BundleID != "" {
			bodyValue["bundle_id"] = f.BundleID
		}
		body, err := a.Canonical(bodyValue)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO assessment_failures(run_id,id,category,asset,kind,code,scope_key,first_at,last_at,count,body) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(run_id,id) DO UPDATE SET last_at=greatest(assessment_failures.last_at,EXCLUDED.last_at),count=EXCLUDED.count`, s.config.RunID, f.ID, s.config.Category, assessmentNullable(f.Asset), f.Kind, f.Code, f.ScopeKey, f.FirstAt, f.At, f.Count, body); err != nil {
			return err
		}
	}
	for _, r := range e.Telemetry {
		bodyValue := map[string]any{"schema": int64(1), "policy_id": r.PolicyID, "occurrence": r.Occurrence, "disposition": r.Disposition, "open_fact": r.OpenFact, "bundle_id": r.BundleID, "summary": r.Summary}
		if r.PhysicalSequence > 0 {
			bodyValue["physical_sequence"] = r.PhysicalSequence
		}
		if r.RecoverFact != "" {
			bodyValue["recover_fact"] = r.RecoverFact
		}
		if r.PreviewID != "" {
			bodyValue["preview_id"] = r.PreviewID
		}
		body, err := a.Canonical(bodyValue)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO assessment_failures(run_id,id,category,asset,kind,code,scope_key,first_at,last_at,count,body) VALUES($1,$2,$3,$4,'QUALIFIED_TELEMETRY','QUALIFIED_TELEMETRY',$2,$5,$6,$7,$8) ON CONFLICT(run_id,id) DO UPDATE SET last_at=greatest(assessment_failures.last_at,EXCLUDED.last_at),count=EXCLUDED.count,body=EXCLUDED.body`, s.config.RunID, r.ID, s.config.Category, r.Asset, r.FirstAt, r.LastAt, r.Count, body); err != nil {
			return err
		}
	}
	var closed, stopped *time.Time
	var reason *string
	if e.State != "ACTIVE" {
		stopped = &at
		value := e.StopReason
		if value == "" {
			value = "DURATION"
		}
		reason = &value
	}
	if e.State == "CLOSED" {
		closed = &e.ClosedAt
	}
	coverage, err := a.Canonical(e.CoverageIntervals)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `WITH stamp AS MATERIALIZED (SELECT date_trunc('microseconds',clock_timestamp()) AS ts),
 closure AS (SELECT CASE WHEN $2='CLOSED' AND $9 THEN stamp.ts ELSE $5::timestamptz END AS closed_at FROM stamp)
 UPDATE assessment_runs SET state=$2,
 stopped_at=coalesce(stopped_at,CASE WHEN $2='CLOSED' THEN least($3::timestamptz,closure.closed_at) ELSE $3 END),
 stop_reason=coalesce(stop_reason,$4),closed_at=closure.closed_at,last_success_at=$6,overflow_count=$7,followup_truncated=$8,coverage=$10,unknown_from=$11,unknown_through=$12
 FROM closure WHERE run_id=$1`, s.config.RunID, e.State, stopped, reason, closed, at, e.FailureOverflow, e.FollowupTruncated, e.Shadow, coverage, e.UnknownFrom, e.UnknownThrough)
	return err
}
func assessmentNullable(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

// OpenAssessmentArchive owns an independent read-only repeatable-read snapshot.
// The first SELECT establishes age eligibility using clock_timestamp, never the
// transaction's earlier start time. Source observations are never reread.
type assessmentArchive struct {
	conn       *pgx.Conn
	tx         pgx.Tx
	cancel     context.CancelFunc
	ctx        context.Context
	meta       a.ArchiveMetadata
	section    int
	rows       pgx.Rows
	closed     bool
	cursorOpen bool
	batchRows  int
}

func OpenAssessmentArchive(ctx context.Context, dsn, runID string) (a.ArchiveSource, error) {
	if dsn == "" || !a.ValidID(runID, 128) {
		return nil, a.ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Minute)
	conn, err := pgx.Connect(bounded, dsn)
	if err != nil {
		cancel()
		return nil, errors.New("assessment export connection failed")
	}
	tx, err := conn.BeginTx(bounded, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		_ = conn.Close(bounded)
		cancel()
		return nil, errors.New("assessment export snapshot failed")
	}
	source := &assessmentArchive{conn: conn, tx: tx, cancel: cancel, ctx: bounded}
	var state, mode string
	var closed *time.Time
	var now time.Time
	err = tx.QueryRow(bounded, `SELECT state,mode,closed_at,config_hash,payload_bytes,record_count,clock_timestamp() FROM assessment_runs WHERE run_id=$1`, runID).Scan(&state, &mode, &closed, &source.meta.ConfigHash, &source.meta.SourcePayloadBytes, &source.meta.RecordCount, &now)
	if err != nil {
		_ = source.Close(context.Background())
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &a.ReplayError{Code: "RUN_NOT_FOUND"}
		}
		return nil, errors.New("assessment export run unavailable")
	}
	if state != "CLOSED" || closed == nil {
		_ = source.Close(context.Background())
		return nil, &a.ReplayError{Code: "RUN_NOT_CLOSED"}
	}
	if !now.Before(closed.Add(7 * 24 * time.Hour)) {
		_ = source.Close(context.Background())
		return nil, &a.ReplayError{Code: "RUN_EXPIRED"}
	}
	source.meta.RunID = runID
	source.meta.Provenance = "OBSERVED_AVAILABILITY"
	if mode == "replay" {
		source.meta.Provenance = "SYNTHETIC"
	}
	return source, nil
}
func (s *assessmentArchive) Metadata() a.ArchiveMetadata { return s.meta }

var assessmentArchiveSections = []string{"run", "enrollments", "facts", "bundles", "candidates", "decisions", "failures"}
var assessmentArchiveByteColumns = map[string][]string{"run": {"config", "descriptor", "coverage"}, "enrollments": {"bindings", "tracker"}, "facts": {"body"}, "bundles": {"body"}, "candidates": {"entry", "initial_state", "state", "terminal"}, "decisions": {"details", "metadata"}, "failures": {"body"}}
var assessmentArchiveTimeColumns = map[string][]string{"run": {"start_at", "admission_end_at", "stopped_at", "closed_at", "last_success_at", "unknown_from", "unknown_through"}, "enrollments": {"discovery_floor", "next_due_at", "last_attempt_at"}, "facts": {"available_at"}, "bundles": {"logical_at", "availability_cutoff"}, "candidates": {"entered_at", "due_at"}, "decisions": {"logical_at", "executed_at", "committed_at"}, "failures": {"first_at", "last_at"}}

func (s *assessmentArchive) Next(ctx context.Context) (a.ArchiveRow, error) {
	if s.closed {
		return a.ArchiveRow{}, io.EOF
	}
	if err := ctx.Err(); err != nil {
		return a.ArchiveRow{}, err
	}
	if err := s.ctx.Err(); err != nil {
		return a.ArchiveRow{}, err
	}
	for s.section < len(assessmentArchiveSections) {
		section := assessmentArchiveSections[s.section]
		table := "assessment_" + section
		key := "id"
		order := "id"
		if section == "run" {
			table = "assessment_runs"
			key = "run_id"
			order = key
		}
		if section == "enrollments" {
			key = "asset"
			order = "category,asset"
		}
		if section == "facts" {
			order = "available_at,id"
		}
		if !s.cursorOpen {
			projections := []string{}
			for _, col := range assessmentArchiveByteColumns[section] {
				projections = append(projections, fmt.Sprintf("'%s',replace(encode(t.%s,'base64'),E'\\n','')", col, col))
			}
			for _, col := range assessmentArchiveTimeColumns[section] {
				projections = append(projections, fmt.Sprintf("'%s',to_char(t.%s AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')", col, col))
			}
			query := fmt.Sprintf("SELECT %s,jsonb_strip_nulls(to_jsonb(t)||jsonb_build_object(%s)) FROM %s t WHERE run_id=$1 ORDER BY %s", key, strings.Join(projections, ","), table, order)
			_, err := s.tx.Exec(s.ctx, "DECLARE assessment_export_cursor NO SCROLL CURSOR FOR "+query, s.meta.RunID)
			if err != nil {
				return a.ArchiveRow{}, errors.New("assessment export cursor failed")
			}
			s.cursorOpen = true
		}
		if s.rows == nil {
			rows, err := s.tx.Query(s.ctx, "FETCH FORWARD 32 FROM assessment_export_cursor")
			if err != nil {
				return a.ArchiveRow{}, errors.New("assessment export read failed")
			}
			s.rows = rows
			s.batchRows = 0
		}
		if s.rows.Next() {
			s.batchRows++
			var key string
			var body []byte
			if err := s.rows.Scan(&key, &body); err != nil {
				return a.ArchiveRow{}, err
			}
			var v map[string]json.RawMessage
			if err := json.Unmarshal(body, &v); err != nil {
				return a.ArchiveRow{}, err
			}
			for _, col := range assessmentArchiveTimeColumns[section] {
				raw, exists := v[col]
				if !exists {
					continue
				}
				var str string
				if err := json.Unmarshal(raw, &str); err != nil {
					return a.ArchiveRow{}, err
				}
				at, err := time.Parse(time.RFC3339Nano, str)
				if err != nil {
					return a.ArchiveRow{}, err
				}
				v[col], err = json.Marshal(at.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano))
				if err != nil {
					return a.ArchiveRow{}, err
				}
			}
			normalized, err := json.Marshal(v)
			if err != nil {
				return a.ArchiveRow{}, err
			}
			return a.ArchiveRow{Table: section, Key: key, Body: normalized}, nil
		}
		err := s.rows.Err()
		s.rows.Close()
		s.rows = nil
		if err != nil {
			return a.ArchiveRow{}, errors.New("assessment export read failed")
		}
		if s.batchRows == 32 {
			continue
		}
		if _, err = s.tx.Exec(s.ctx, "CLOSE assessment_export_cursor"); err != nil {
			return a.ArchiveRow{}, err
		}
		s.cursorOpen = false
		s.section++
	}
	return a.ArchiveRow{}, io.EOF
}
func (s *assessmentArchive) Close(ctx context.Context) error {
	if s.closed {
		return nil
	}
	s.closed = true
	if s.rows != nil {
		s.rows.Close()
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_ = s.tx.Rollback(bounded)
	err := s.conn.Close(bounded)
	s.cancel()
	return err
}
