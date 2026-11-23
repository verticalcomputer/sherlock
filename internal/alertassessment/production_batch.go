package alertassessment

import (
	"context"
	"slices"
	"time"
)

// AdvanceProductionBatch consumes one asset's newly visible facts in receipt
// order. The caller persists the resulting snapshot, decision proofs and input
// progress in one transaction and discards the engine if that transaction fails.
func (e *Engine) AdvanceProductionBatch(ctx context.Context, asset string, now time.Time, facts []Fact) error {
	now = clock(now)
	if !e.Config.production || len(e.Config.Assets) != 1 || e.Enrollments[asset] == nil || now.Before(e.StartAt) || now.Before(e.lastPass) {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, ShadowGPUBudget)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx = withFactValidationCache(ctx)
	category := e.visibleReplayCategory()
	if category == nil {
		if err := e.AdvanceAssets(ctx, now, now, now, facts, nil, []string{asset}); err != nil {
			return err
		}
		return ctx.Err()
	}
	history, freshness := category.ReplaySampleWindows(ctx, e.policy)
	if history <= 0 || freshness <= 0 {
		return ErrInvalid
	}

	// After a prolonged outage, the acquisition and snapshot contracts retain
	// only one host history window. Keep older observing deadlines actionable.
	cursor := maxTime(e.StartAt, now.Add(-requestFactWindow)).Add(-time.Microsecond)
	cursor = maxTime(cursor, e.lastPass)
	receipts := map[time.Time][]Fact{}
	windowChanges := map[time.Time]bool{}
	times := map[time.Time]bool{now: true}
	schedule := func(f Fact, visible time.Time) {
		source := rawBoundaryWithSamples(f, e.Config.Category, checkedSamples(ctx))
		// A clock-qualified source may be slightly ahead of the receipt.
		if source.After(cursor) && source.After(visible) && !source.After(now) {
			times[source] = true
			windowChanges[source] = true
		}
		boundary := historyBoundary(f, source)
		if boundary.IsZero() {
			return
		}
		expire := func(age time.Duration) {
			// A sample exactly on an inclusive window edge is still usable.
			at := boundary.Add(age + time.Microsecond)
			if at.After(cursor) && at.After(visible) && !at.After(now) {
				times[at] = true
				windowChanges[at] = true
			}
		}
		expire(requestFactWindow)
		if f.Kind == "SAMPLE" {
			expire(history)
			expire(freshness)
		}
	}
	for _, f := range e.Facts {
		if err := ctx.Err(); err != nil {
			return err
		}
		schedule(f, f.AvailableAt)
	}
	for _, f := range facts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if f.Asset != asset || f.AvailableAt.IsZero() || f.AvailableAt.After(now) {
			return ErrInvalid
		}
		at := clock(f.AvailableAt)
		if !at.After(cursor) {
			// First seen behind an already processed frontier. It can change
			// the current view, but cannot justify a decision in the past.
			at = now
			f.AvailableAt = now
		}
		times[at] = true
		receipts[at] = append(receipts[at], f)
		schedule(f, at)
	}

	agenda := make([]time.Time, 0, len(times))
	for at := range times {
		agenda = append(agenda, at)
	}
	slices.SortFunc(agenda, time.Time.Compare)
	agenda = e.coalesceStalePrefix(ctx, category, asset, cursor, freshness, agenda, receipts)
	e.orderedBatch = true
	defer func() {
		e.orderedBatch = false
		e.batchWindowChanged = false
	}()
	for len(agenda) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		at := agenda[0]
		wake := func(t time.Time) {
			if t.After(cursor) && t.Before(at) {
				at = t
			}
		}
		en := e.Enrollments[asset]
		if en.NextLogicalAt != nil {
			wake(*en.NextLogicalAt)
		}
		for _, c := range e.Candidates {
			if c.Phase == "OBSERVING" {
				wake(maxTime(c.DueAt, cursor.Add(time.Microsecond)))
				if c.NextLogicalAt != nil {
					wake(*c.NextLogicalAt)
				}
			}
		}
		if at.Equal(agenda[0]) {
			agenda = agenda[1:]
		}
		e.batchWindowChanged = windowChanges[at]
		if err := e.AdvanceAssets(ctx, at, now, now, receipts[at], nil, []string{asset}); err != nil {
			return err
		}
		cursor = at
		if e.State == "CLOSED" {
			break
		}
	}
	return ctx.Err()
}

// The first potentially effective event receives all preceding stale facts in
// their original visibility order. This avoids materializing identical tracker
// and final-arm requests for each stale receipt in a delayed upload burst.
func (e *Engine) coalesceStalePrefix(ctx context.Context, category VisibleInputReplay, asset string, cursor time.Time, freshness time.Duration, agenda []time.Time, receipts map[time.Time][]Fact) []time.Time {
	capability, ok := category.(StaleSampleReplay)
	en := e.Enrollments[asset]
	if !ok || !capability.CoalescesStaleFinalSamples() || !en.Active || en.NextLogicalAt != nil || len(e.Candidates) != 1 || e.Candidates[0].Phase != "FINAL" || len(agenda) < 2 {
		return agenda
	}
	type sampleKey struct {
		metric string
		at     time.Time
	}
	seen := map[sampleKey]bool{}
	isStale := func(f Fact, at time.Time) bool {
		if f.Kind != "SAMPLE" {
			return false
		}
		s, err := checkedSamples(ctx).decodeForSelection(e.Config.Category, f)
		if err != nil || !s.SourceAt.Add(freshness).Before(at) {
			return false
		}
		key := sampleKey{s.Metric, s.SourceAt}
		if seen[key] {
			return false
		}
		seen[key] = true
		return true
	}
	for _, f := range e.Facts {
		switch f.Kind {
		case "SAMPLE":
			if !isStale(f, cursor) {
				return agenda
			}
		case "TRACKER_CONTEXT", "FEATURE", "PROVENANCE":
		default:
			return agenda
		}
	}
	for i, at := range agenda {
		barrier := i == len(agenda)-1
		for _, f := range receipts[at] {
			if !isStale(f, at) {
				barrier = true
				break
			}
		}
		if barrier {
			// Keep the last stale instant distinct from the barrier, so that
			// conflicts and independent events enter against the prior state.
			if i < 2 {
				return agenda
			}
			last := agenda[i-1]
			for _, earlier := range agenda[:i-1] {
				receipts[last] = append(receipts[last], receipts[earlier]...)
				delete(receipts, earlier)
			}
			return agenda[i-1:]
		}
	}
	return agenda
}
