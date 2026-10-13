//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// snapshotSeed enrolls four durable Prometheus schedules with current-revision
// execution grants. It deliberately reports no heartbeat and no capabilities:
// the snapshot is a schedule-state view and must not gate on either.
func snapshotSeed(t *testing.T, f durableFixture, cluster, source string) []domain.DesiredSchedule {
	t.Helper()
	ctx := context.Background()
	id := domain.ClusterID(cluster)
	src := domain.SourceID(source)
	collector := domain.CollectorID(cluster + "-collector")
	if err := f.s.EnsureSource(ctx, id, cluster+"-name", src, source+"-name"); err != nil {
		t.Fatal(err)
	}
	if err := f.c.RegisterCollector(ctx, storepg.CollectorRegistration{CollectorID: collector, ClusterID: id, DisplayName: cluster, Version: "fixture", ProtocolMin: 1, ProtocolMax: 2, OperatingSystem: "linux", Architecture: "amd64"}); err != nil {
		t.Fatal(err)
	}
	seeds := application.LegacyPrometheusSchedules(id, src, domain.SchedulingDurable, 30*time.Second, 10*time.Second, 100, 100000)
	if err := f.s.ImportLegacyPrometheusSchedules(ctx, seeds, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	for i, seed := range seeds {
		d, err := f.s.DesiredSchedule(ctx, seed.ScheduleKey)
		if err != nil {
			t.Fatal(err)
		}
		seeds[i] = d
		if err := f.s.ConfigureDurableExecution(ctx, domain.DurableExecution{ScheduleKey: d.ScheduleKey, Revision: d.Revision, CollectorID: collector}); err != nil {
			t.Fatal(err)
		}
	}
	return seeds
}

func snapshotKeys(schedules []domain.DesiredSchedule) []domain.ScheduleKey {
	keys := make([]domain.ScheduleKey, 0, len(schedules))
	for _, schedule := range schedules {
		keys = append(keys, schedule.ScheduleKey)
	}
	return keys
}

func snapshotState(t *testing.T, f durableFixture, cluster string) (state string, work, occurrences int) {
	t.Helper()
	ctx := context.Background()
	var encoded string
	if err := f.p.QueryRow(ctx, `SELECT coalesce(string_agg(cluster_id||'/'||source_id||'/'||operation||'/'||next_due_at::text||'/'||occurrence::text||'/'||coalesced_intervals::text, ',' ORDER BY cluster_id,source_id,operation),'') FROM durable_schedule_state WHERE cluster_id=$1`, cluster).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	if err := f.p.QueryRow(ctx, `SELECT count(*) FROM collector_work_items WHERE cluster_id=$1`, cluster).Scan(&work); err != nil {
		t.Fatal(err)
	}
	if err := f.p.QueryRow(ctx, `SELECT count(*) FROM durable_schedule_occurrences WHERE cluster_id=$1`, cluster).Scan(&occurrences); err != nil {
		t.Fatal(err)
	}
	return encoded, work, occurrences
}

func TestReadDurableScheduleSnapshot(t *testing.T) {
	p := durableTestDatabase(t)
	s, _ := storepg.NewCollectionStore(p)
	c, _ := storepg.NewCollectorControlStore(p)
	ctx := context.Background()
	isolated := func(t *testing.T) durableFixture {
		f := durableFixture{p: p, s: s, c: c}
		f.exec(t, `TRUNCATE clusters CASCADE`)
		return f
	}

	t.Run("exact mapping, order and timestamp", func(t *testing.T) {
		f := isolated(t)
		seeds := snapshotSeed(t, f, "snap-a", "snap-a-source")
		due := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
		for i, seed := range seeds {
			f.exec(t, `UPDATE durable_schedule_state SET next_due_at=$1, coalesced_intervals=$2 WHERE cluster_id=$3 AND source_id=$4 AND operation=$5`,
				due.Add(time.Duration(i)*time.Second), int64(i*3), seed.ClusterID, seed.SourceID, seed.Operation)
		}
		// Scrambled enrollment must still return deterministic row order.
		keys := snapshotKeys(seeds)
		for i, j := 0, len(keys)-1; i < j; i, j = i+1, j-1 {
			keys[i], keys[j] = keys[j], keys[i]
		}
		var before, after time.Time
		if err := p.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		snap, err := s.ReadDurableScheduleSnapshot(ctx, keys)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if snap.ObservedAt.Before(before) || snap.ObservedAt.After(after) {
			t.Fatalf("observation %v outside database window [%v,%v]", snap.ObservedAt, before, after)
		}
		if len(snap.Rows) != len(seeds) {
			t.Fatalf("rows=%d want %d", len(snap.Rows), len(seeds))
		}
		for i, row := range snap.Rows {
			if i > 0 {
				prev := snap.Rows[i-1].Key
				if prev.ClusterID > row.Key.ClusterID ||
					(prev.ClusterID == row.Key.ClusterID && prev.SourceID > row.Key.SourceID) ||
					(prev.ClusterID == row.Key.ClusterID && prev.SourceID == row.Key.SourceID && prev.Operation >= row.Key.Operation) {
					t.Fatalf("rows not ordered at %d: %+v then %+v", i, prev, row.Key)
				}
			}
			var want *domain.DesiredSchedule
			for j := range seeds {
				if seeds[j].ScheduleKey == row.Key {
					want = &seeds[j]
					break
				}
			}
			if want == nil {
				t.Fatalf("unexpected row key %+v", row.Key)
			}
		}
		byKey := map[domain.ScheduleKey]domain.DurableSchedulerSnapshotRow{}
		for _, row := range snap.Rows {
			byKey[row.Key] = row
		}
		for i, seed := range seeds {
			row := byKey[seed.ScheduleKey]
			if !row.NextDue.Equal(due.Add(time.Duration(i) * time.Second)) {
				t.Fatalf("next-due for %+v is %v", seed.ScheduleKey, row.NextDue)
			}
			if row.CoalescedIntervals != int64(i*3) {
				t.Fatalf("coalesced for %+v is %d", seed.ScheduleKey, row.CoalescedIntervals)
			}
		}
	})

	t.Run("cross-cluster exact identities without cross-product leakage", func(t *testing.T) {
		f := isolated(t)
		first := snapshotSeed(t, f, "snap-b1", "snap-b1-source")
		second := snapshotSeed(t, f, "snap-b2", "snap-b2-source")
		// Source IDs are globally unique in the store, so identical sources
		// across clusters cannot exist there; label separation for that case
		// is covered at the metrics layer. Here the discriminating case is a
		// per-column match, which would leak the non-enrolled combinations
		// (b1,s1,opB) and (b2,s2,opA) that exist as schedules.
		keys := []domain.ScheduleKey{first[0].ScheduleKey, second[1].ScheduleKey}
		snap, err := s.ReadDurableScheduleSnapshot(ctx, keys)
		if err != nil {
			t.Fatal(err)
		}
		if len(snap.Rows) != 2 {
			t.Fatalf("rows=%d want exactly the 2 enrolled identities", len(snap.Rows))
		}
		for _, row := range snap.Rows {
			if row.Key != keys[0] && row.Key != keys[1] {
				t.Fatalf("leaked non-enrolled identity %+v", row.Key)
			}
		}
		if snap.Rows[0].Key.ClusterID != "snap-b1" || snap.Rows[1].Key.ClusterID != "snap-b2" {
			t.Fatalf("rows not cluster-ordered: %+v", snap.Rows)
		}
	})

	t.Run("stale grants omitted until re-granted", func(t *testing.T) {
		f := isolated(t)
		seeds := snapshotSeed(t, f, "snap-c", "snap-c-source")
		stale := seeds[0].ScheduleKey
		f.exec(t, `UPDATE desired_schedules SET revision=revision+1 WHERE cluster_id=$1 AND source_id=$2 AND operation=$3`, stale.ClusterID, stale.SourceID, stale.Operation)
		snap, err := s.ReadDurableScheduleSnapshot(ctx, snapshotKeys(seeds))
		if err != nil {
			t.Fatal(err)
		}
		if len(snap.Rows) != len(seeds)-1 {
			t.Fatalf("rows=%d want %d with the stale grant omitted", len(snap.Rows), len(seeds)-1)
		}
		for _, row := range snap.Rows {
			if row.Key == stale {
				t.Fatalf("stale-grant schedule %+v still exported", stale)
			}
		}
		current, err := s.DesiredSchedule(ctx, stale)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.ConfigureDurableExecution(ctx, domain.DurableExecution{ScheduleKey: stale, Revision: current.Revision, CollectorID: "snap-c-collector"}); err != nil {
			t.Fatal(err)
		}
		snap, err = s.ReadDurableScheduleSnapshot(ctx, snapshotKeys(seeds))
		if err != nil {
			t.Fatal(err)
		}
		if len(snap.Rows) != len(seeds) {
			t.Fatalf("rows=%d want %d after re-grant", len(snap.Rows), len(seeds))
		}
	})

	t.Run("disabled, legacy, removed and missing schedules omitted", func(t *testing.T) {
		f := isolated(t)
		seeds := snapshotSeed(t, f, "snap-d", "snap-d-source")
		f.exec(t, `UPDATE desired_schedules SET enabled=false WHERE cluster_id='snap-d' AND operation=$1`, seeds[0].Operation)
		f.exec(t, `UPDATE desired_schedules SET mode='legacy' WHERE cluster_id='snap-d' AND operation=$1`, seeds[1].Operation)
		snapshotSeed(t, f, "snap-e", "snap-e-source")
		f.exec(t, `UPDATE clusters SET removed_at=clock_timestamp() WHERE cluster_id='snap-e'`)
		keys := snapshotKeys(seeds)
		keys = append(keys, domain.ScheduleKey{ClusterID: "snap-d", SourceID: "snap-d-source", Operation: domain.OperationPrometheusGPUTemperature})
		snap, err := s.ReadDurableScheduleSnapshot(ctx, keys)
		if err != nil {
			t.Fatal(err)
		}
		if len(snap.Rows) != len(seeds)-2 {
			t.Fatalf("rows=%d want %d enabled durable schedules", len(snap.Rows), len(seeds)-2)
		}
		for _, row := range snap.Rows {
			if row.Key == seeds[0].ScheduleKey || row.Key == seeds[1].ScheduleKey {
				t.Fatalf("excluded schedule %+v still exported", row.Key)
			}
		}
		removed, err := s.ReadDurableScheduleSnapshot(ctx, []domain.ScheduleKey{{ClusterID: "snap-e", SourceID: "snap-e-source", Operation: domain.OperationPrometheusGPUXID}})
		if err != nil {
			t.Fatal(err)
		}
		if len(removed.Rows) != 0 || removed.ObservedAt.IsZero() {
			t.Fatalf("removed-cluster result rows=%d timestamp-zero=%v", len(removed.Rows), removed.ObservedAt.IsZero())
		}
	})

	t.Run("empty input and empty result carry a database timestamp", func(t *testing.T) {
		isolated(t)
		var before, after time.Time
		if err := p.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		empty, err := s.ReadDurableScheduleSnapshot(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		missing, err := s.ReadDurableScheduleSnapshot(ctx, []domain.ScheduleKey{{ClusterID: "snap-absent", SourceID: "snap-absent", Operation: domain.OperationPrometheusGPUXID}})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&after); err != nil {
			t.Fatal(err)
		}
		for name, snap := range map[string]domain.DurableSchedulerSnapshot{"empty": empty, "missing": missing} {
			if len(snap.Rows) != 0 {
				t.Fatalf("%s snapshot has %d rows", name, len(snap.Rows))
			}
			if snap.ObservedAt.IsZero() || snap.ObservedAt.Before(before) || snap.ObservedAt.After(after) {
				t.Fatalf("%s observation %v outside database window [%v,%v]", name, snap.ObservedAt, before, after)
			}
		}
	})

	t.Run("invalid inputs rejected", func(t *testing.T) {
		isolated(t)
		key := domain.ScheduleKey{ClusterID: "snap-x", SourceID: "snap-x", Operation: domain.OperationPrometheusGPUXID}
		over := make([]domain.ScheduleKey, 0, domain.MaxDurableSchedulerSnapshotKeys+1)
		for i := 0; i <= domain.MaxDurableSchedulerSnapshotKeys; i++ {
			over = append(over, domain.ScheduleKey{ClusterID: domain.ClusterID(fmt.Sprintf("snap-over-%d", i)), SourceID: "s", Operation: domain.OperationPrometheusGPUUtilization})
		}
		for name, keys := range map[string][]domain.ScheduleKey{
			"duplicate":         {key, key},
			"empty cluster":     {{SourceID: "s", Operation: domain.OperationPrometheusGPUXID}},
			"empty source":      {{ClusterID: "c", Operation: domain.OperationPrometheusGPUXID}},
			"empty operation":   {{ClusterID: "c", SourceID: "s"}},
			"unreviewed":        {{ClusterID: "c", SourceID: "s", Operation: "example.unreviewed.v9"}},
			"over 64-key limit": over,
		} {
			if _, err := s.ReadDurableScheduleSnapshot(ctx, keys); err == nil {
				t.Fatalf("%s input accepted", name)
			}
		}
	})

	t.Run("context cancellation fails the read", func(t *testing.T) {
		f := isolated(t)
		seeds := snapshotSeed(t, f, "snap-g", "snap-g-source")
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := s.ReadDurableScheduleSnapshot(cancelled, snapshotKeys(seeds)); err == nil {
			t.Fatal("cancelled context accepted")
		}
	})

	t.Run("reads leave schedule state and work unchanged", func(t *testing.T) {
		f := isolated(t)
		seeds := snapshotSeed(t, f, "snap-h", "snap-h-source")
		keys := snapshotKeys(seeds)
		before, workBefore, occurrencesBefore := snapshotState(t, f, "snap-h")
		for range 3 {
			if _, err := s.ReadDurableScheduleSnapshot(ctx, keys); err != nil {
				t.Fatal(err)
			}
		}
		after, workAfter, occurrencesAfter := snapshotState(t, f, "snap-h")
		if before != after || workBefore != workAfter || occurrencesBefore != occurrencesAfter {
			t.Fatalf("read mutated state: %q/%d/%d then %q/%d/%d", before, workBefore, occurrencesBefore, after, workAfter, occurrencesAfter)
		}
	})
}

// snapshotAdmissionReady adds collector heartbeat and capabilities so the
// real AdmitDueSchedule and ClaimWork paths below execute. Snapshot reads
// need neither, which the earlier subtests prove by omitting both.
func snapshotAdmissionReady(t *testing.T, f durableFixture, cluster, source string, seeds []domain.DesiredSchedule) {
	t.Helper()
	caps := map[string]string{}
	for _, seed := range seeds {
		op, _ := domain.ReviewedCollectionOperation(seed.Operation)
		caps[string(op.Query)] = "1"
	}
	collector := domain.CollectorID(cluster + "-collector")
	if err := f.c.ReplaceCapabilities(context.Background(), collector, caps); err != nil {
		t.Fatal(err)
	}
	f.report(t, collector, domain.SourceID(source))
}

// expireSnapshotWork shifts a work window into the past, preserving the
// deadline/expires-after-start constraints, so the next admission or claim
// reconciles it through the real expiry path.
func expireSnapshotWork(t *testing.T, f durableFixture, workID domain.WorkID) {
	t.Helper()
	past := time.Now().UTC().Add(-time.Hour)
	end := past.Add(30 * time.Second)
	f.exec(t, `UPDATE collector_work_items SET scheduled_for=$1, available_at=$1, deadline=$2, work_expires_at=$2 WHERE work_id=$3`, past, end, string(workID))
}

func TestReadDurableScheduleSnapshotDroppedIntervals(t *testing.T) {
	p := durableTestDatabase(t)
	s, _ := storepg.NewCollectionStore(p)
	c, _ := storepg.NewCollectorControlStore(p)
	ctx := context.Background()
	policy := domain.DurableAdmissionPolicy{GlobalLimit: 16, ClusterLimit: 4}
	isolated := func(t *testing.T) durableFixture {
		f := durableFixture{p: p, s: s, c: c, policy: policy}
		f.exec(t, `TRUNCATE clusters CASCADE`)
		return f
	}
	admit := func(t *testing.T, f durableFixture) (domain.ScheduleAdmission, bool) {
		t.Helper()
		a, found, err := f.s.AdmitDueSchedule(ctx, policy)
		if err != nil {
			t.Fatalf("admit: %v", err)
		}
		return a, found
	}
	// dueOnly leaves exactly one operation due so each admission is
	// deterministic under the one-outstanding-operation-per-source rule.
	dueOnly := func(t *testing.T, f durableFixture, seeds []domain.DesiredSchedule, operation domain.CollectionOperationID) domain.ScheduleKey {
		t.Helper()
		now := time.Now().UTC()
		var key domain.ScheduleKey
		for _, seed := range seeds {
			due := now.Add(time.Hour)
			if seed.Operation == operation {
				due = now.Add(-time.Second)
				key = seed.ScheduleKey
			}
			f.exec(t, `UPDATE durable_schedule_state SET next_due_at=$1 WHERE cluster_id=$2 AND source_id=$3 AND operation=$4`, due, seed.ClusterID, seed.SourceID, seed.Operation)
		}
		return key
	}
	readDropped := func(t *testing.T, f durableFixture, keys []domain.ScheduleKey) map[domain.ScheduleKey]domain.DurableSchedulerSnapshotRow {
		t.Helper()
		snap, err := f.s.ReadDurableScheduleSnapshot(ctx, keys)
		if err != nil {
			t.Fatal(err)
		}
		rows := map[domain.ScheduleKey]domain.DurableSchedulerSnapshotRow{}
		for _, row := range snap.Rows {
			rows[row.Key] = row
		}
		return rows
	}

	t.Run("unclaimed expiry contributes one", func(t *testing.T) {
		f := isolated(t)
		seeds := snapshotSeed(t, f, "snap-drop-a", "snap-drop-a-source")
		snapshotAdmissionReady(t, f, "snap-drop-a", "snap-drop-a-source", seeds)
		key := dueOnly(t, f, seeds, domain.OperationPrometheusGPUXID)
		a, found := admit(t, f)
		if !found || a.ScheduleKey != key {
			t.Fatalf("admitted %+v found=%t, want %+v", a.ScheduleKey, found, key)
		}
		expireSnapshotWork(t, f, a.WorkID)
		if _, found := admit(t, f); found {
			t.Fatal("unexpected second admission while nothing is due")
		}
		rows := readDropped(t, f, snapshotKeys(seeds))
		if len(rows) != len(seeds) {
			t.Fatalf("rows=%d want %d", len(rows), len(seeds))
		}
		for _, seed := range seeds {
			want := int64(0)
			if seed.ScheduleKey == key {
				want = 1
			}
			if rows[seed.ScheduleKey].DroppedIntervals != want {
				t.Fatalf("dropped for %+v is %d, want %d", seed.ScheduleKey, rows[seed.ScheduleKey].DroppedIntervals, want)
			}
		}
		if again := readDropped(t, f, snapshotKeys(seeds)); again[key].DroppedIntervals != 1 {
			t.Fatal("repeated read changed the dropped count")
		}
	})

	t.Run("coalescing stays separate from dropped", func(t *testing.T) {
		f := isolated(t)
		seeds := snapshotSeed(t, f, "snap-drop-b", "snap-drop-b-source")
		snapshotAdmissionReady(t, f, "snap-drop-b", "snap-drop-b-source", seeds)
		key := dueOnly(t, f, seeds, domain.OperationPrometheusGPUXID)
		f.exec(t, `UPDATE durable_schedule_state SET next_due_at=$1 WHERE cluster_id=$2 AND source_id=$3 AND operation=$4`,
			time.Now().UTC().Add(-300*time.Second), key.ClusterID, key.SourceID, key.Operation)
		a, found := admit(t, f)
		if !found || a.ScheduleKey != key {
			t.Fatalf("admitted %+v found=%t, want %+v", a.ScheduleKey, found, key)
		}
		expireSnapshotWork(t, f, a.WorkID)
		if _, found := admit(t, f); found {
			t.Fatal("unexpected second admission while nothing is due")
		}
		rows := readDropped(t, f, snapshotKeys(seeds))
		if rows[key].DroppedIntervals != 1 {
			t.Fatalf("dropped=%d, want exactly one for ten coalesced intervals", rows[key].DroppedIntervals)
		}
		if rows[key].CoalescedIntervals != 10 {
			t.Fatalf("coalesced=%d, want 10 retained separately", rows[key].CoalescedIntervals)
		}
	})

	t.Run("claimed occurrence contributes zero", func(t *testing.T) {
		f := isolated(t)
		seeds := snapshotSeed(t, f, "snap-drop-c", "snap-drop-c-source")
		snapshotAdmissionReady(t, f, "snap-drop-c", "snap-drop-c-source", seeds)
		key := dueOnly(t, f, seeds, domain.OperationPrometheusGPUXID)
		a, found := admit(t, f)
		if !found || a.ScheduleKey != key {
			t.Fatalf("admitted %+v found=%t, want %+v", a.ScheduleKey, found, key)
		}
		lease, found, err := f.c.ClaimWork(ctx, "snap-drop-c-collector", "snapshot-drop-claim-token", time.Minute)
		if err != nil || !found || lease.Work.WorkID != a.WorkID {
			t.Fatalf("claim work=%s found=%t err=%v", lease.Work.WorkID, found, err)
		}
		f.exec(t, `UPDATE collector_work_attempts SET claimed_at=$1, started_at=$1, lease_expires_at=$2 WHERE work_id=$3`,
			time.Now().UTC().Add(-2*time.Minute), time.Now().UTC().Add(-time.Second), string(a.WorkID))
		expireSnapshotWork(t, f, a.WorkID)
		if _, found := admit(t, f); found {
			t.Fatal("unexpected second admission while nothing is due")
		}
		if rows := readDropped(t, f, snapshotKeys(seeds)); rows[key].DroppedIntervals != 0 {
			t.Fatalf("claimed-then-failed occurrence dropped=%d, want 0", rows[key].DroppedIntervals)
		}
	})

	t.Run("pending, manual and other-schedule work excluded", func(t *testing.T) {
		f := isolated(t)
		seeds := snapshotSeed(t, f, "snap-drop-d", "snap-drop-d-source")
		snapshotAdmissionReady(t, f, "snap-drop-d", "snap-drop-d-source", seeds)
		key := dueOnly(t, f, seeds, domain.OperationPrometheusGPUXID)
		if _, found := admit(t, f); !found {
			t.Fatal("expected the due admission")
		}
		now := time.Now().UTC()
		manual := domain.CollectorWork{
			WorkID: "snap-drop-d-manual", Status: domain.WorkAvailable, AvailableAt: now, WorkExpiresAt: now.Add(5 * time.Minute),
			Task: domain.CollectionTask{RunID: "snap-drop-d-manual-run", ClusterID: "snap-drop-d", SourceID: "snap-drop-d-source",
				Query: domain.QueryGPUUtilization, ScheduledFor: now, Deadline: now.Add(5 * time.Minute),
				MaxSeries: 100, MaxBytes: 1000, IdempotencyKey: "snap-drop-d-manual"},
		}
		if inserted, err := f.c.EnqueueCollectionWork(ctx, manual); err != nil || !inserted {
			t.Fatalf("enqueue manual inserted=%t err=%v", inserted, err)
		}
		expireSnapshotWork(t, f, manual.WorkID)
		// The admission reconcile terminally fails the expired manual work,
		// which has no occurrence and must never count; the pending
		// occurrence stays available.
		if _, found := admit(t, f); found {
			t.Fatal("unexpected second admission while nothing is due")
		}
		other := snapshotSeed(t, f, "snap-drop-e", "snap-drop-e-source")
		snapshotAdmissionReady(t, f, "snap-drop-e", "snap-drop-e-source", other)
		otherKey := dueOnly(t, f, other, domain.OperationPrometheusGPUXID)
		otherAdmission, found := admit(t, f)
		if !found || otherAdmission.ScheduleKey != otherKey {
			t.Fatalf("admitted %+v found=%t, want %+v", otherAdmission.ScheduleKey, found, otherKey)
		}
		expireSnapshotWork(t, f, otherAdmission.WorkID)
		if _, found := admit(t, f); found {
			t.Fatal("unexpected admission while nothing is due")
		}
		rows := readDropped(t, f, append(snapshotKeys(seeds), snapshotKeys(other)...))
		if rows[key].DroppedIntervals != 0 {
			t.Fatalf("pending occurrence dropped=%d, want 0", rows[key].DroppedIntervals)
		}
		if rows[otherKey].DroppedIntervals != 1 {
			t.Fatalf("other schedule dropped=%d, want 1", rows[otherKey].DroppedIntervals)
		}
	})

	t.Run("historical revisions accumulate", func(t *testing.T) {
		f := isolated(t)
		seeds := snapshotSeed(t, f, "snap-drop-f", "snap-drop-f-source")
		snapshotAdmissionReady(t, f, "snap-drop-f", "snap-drop-f-source", seeds)
		key := dueOnly(t, f, seeds, domain.OperationPrometheusGPUXID)
		first, found := admit(t, f)
		if !found || first.ScheduleKey != key {
			t.Fatalf("admitted %+v found=%t, want %+v", first.ScheduleKey, found, key)
		}
		f.exec(t, `UPDATE desired_schedules SET revision=revision+1 WHERE cluster_id=$1 AND source_id=$2 AND operation=$3`, key.ClusterID, key.SourceID, key.Operation)
		current, err := f.s.DesiredSchedule(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.s.ConfigureDurableExecution(ctx, domain.DurableExecution{ScheduleKey: key, Revision: current.Revision, CollectorID: "snap-drop-f-collector"}); err != nil {
			t.Fatal(err)
		}
		f.exec(t, `UPDATE durable_schedule_state SET next_due_at=$1 WHERE cluster_id=$2 AND source_id=$3 AND operation=$4`, time.Now().UTC().Add(-time.Second), key.ClusterID, key.SourceID, key.Operation)
		second, found := admit(t, f)
		if !found || second.WorkID == first.WorkID {
			t.Fatalf("second revision admission found=%t work=%s", found, second.WorkID)
		}
		expireSnapshotWork(t, f, first.WorkID)
		expireSnapshotWork(t, f, second.WorkID)
		if _, found := admit(t, f); found {
			t.Fatal("unexpected admission while nothing is due")
		}
		if rows := readDropped(t, f, snapshotKeys(seeds)); rows[key].DroppedIntervals != 2 {
			t.Fatalf("dropped=%d across two revisions, want 2", rows[key].DroppedIntervals)
		}
	})
}
