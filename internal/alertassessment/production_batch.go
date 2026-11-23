package alertassessment

import (
	"bytes"
	"context"
	"slices"
	"time"
)

// AdvanceProductionBatch consumes one asset's newly visible facts in receipt
// order. The caller persists the resulting snapshot, decision proofs and input
// progress in one transaction and discards the engine if that transaction fails.
func (e *Engine) AdvanceProductionBatch(ctx context.Context, asset string, now time.Time, facts []Fact) error {
	return e.AdvanceProductionSlice(ctx, asset, now, facts, time.Time{}, 0)
}

// A frozen agenda separates the physical time of a retry from the logical time
// when its evidence was first seen. Dynamic candidate wakes are picked afresh
// from the restored enrollment before each static step.
type productionReplayStep struct {
	At            time.Time `json:"at"`
	WindowChanged bool      `json:"window_changed,omitempty"`
	Facts         []Fact    `json:"facts,omitempty"`
}
type productionReplayBatch struct {
	Through time.Time              `json:"through"`
	Steps   []productionReplayStep `json:"steps"`
}

func (e *Engine) ProductionBatchPending() bool { return e.pendingReplay != nil }

// ProductionSliceFailure reports the latest failure raised in this transaction.
func (e *Engine) ProductionSliceFailure() *Failure { return e.productionSliceFailure }

// RestrictProductionDiscovery reserves remaining publication capacity for
// already admitted occurrences and their recovery. This applies to one engine
// transaction and is deliberately omitted from the durable checkpoint.
func (e *Engine) RestrictProductionDiscovery() { e.productionDiscoveryRestricted = e.Config.production }

// AdvanceProductionSlice processes complete logical timestamps. A successful
// soft yield must be committed with the pending agenda. A hard error requires
// discarding the engine. Zero limits allow a caller to process the full batch.
func (e *Engine) AdvanceProductionSlice(ctx context.Context, asset string, now time.Time, facts []Fact, stopBefore time.Time, maxSteps int) error {
	e.productionSliceFailure = nil
	now = clock(now)
	if !e.Config.production || len(e.Config.Assets) != 1 || e.Enrollments[asset] == nil || now.Before(e.StartAt) || now.Before(e.lastPass) || maxSteps < 0 {
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
		if e.pendingReplay != nil {
			return ErrInvalid
		}
		if err := e.AdvanceAssets(ctx, now, now, now, facts, nil, []string{asset}); err != nil {
			return err
		}
		return ctx.Err()
	}
	batch := e.pendingReplay
	resuming := batch != nil
	if !resuming {
		var err error
		batch, err = e.prepareProductionReplay(ctx, category, asset, now, facts, maxSteps > 0 || !stopBefore.IsZero())
		if err != nil {
			return err
		}
		e.pendingReplay = batch
	} else if len(facts) != 0 || now.Before(batch.Through) {
		return ErrInvalid
	}
	cursor := maxTime(e.StartAt, batch.Through.Add(-requestFactWindow)).Add(-time.Microsecond)
	cursor = maxTime(cursor, e.lastPass)
	e.orderedBatch = true
	defer func() {
		e.orderedBatch = false
		e.batchWindowChanged = false
	}()
	for steps := 0; len(batch.Steps) > 0; steps++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if maxSteps > 0 && steps >= maxSteps || !stopBefore.IsZero() && !time.Now().Before(stopBefore) {
			if resuming && steps == 0 {
				return context.DeadlineExceeded
			}
			return nil
		}
		step := batch.Steps[0]
		at := step.At
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
		var input []Fact
		e.batchWindowChanged = false
		if at.Equal(step.At) {
			input = step.Facts
			e.batchWindowChanged = step.WindowChanged
			batch.Steps = batch.Steps[1:]
		}
		if err := e.AdvanceAssets(ctx, at, now, now, input, nil, []string{asset}); err != nil {
			return err
		}
		cursor = at
		if e.State == "CLOSED" {
			break
		}
	}
	e.pendingReplay = nil
	return ctx.Err()
}

func (e *Engine) prepareProductionReplay(ctx context.Context, category VisibleInputReplay, asset string, now time.Time, facts []Fact, mayYield bool) (*productionReplayBatch, error) {
	history, freshness := category.ReplaySampleWindows(ctx, e.policy)
	if history <= 0 || freshness <= 0 {
		return nil, ErrInvalid
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
			return nil, err
		}
		schedule(f, f.AvailableAt)
	}
	if len(facts) > MaxFacts {
		return nil, ErrInvalid
	}
	var frozen []Fact
	if mayYield {
		frozen = make([]Fact, 0, len(facts))
	}
	inputBytes := 0
	for _, f := range facts {
		inputBytes += len(f.Body)
		if inputBytes > MaxInputBytes {
			return nil, ErrInvalid
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if f.Run != e.Config.RunID || f.Asset != asset || f.AvailableAt.IsZero() || f.AvailableAt.After(now) {
			return nil, ErrInvalid
		}
		at := clock(f.AvailableAt)
		if !at.After(cursor) {
			// First seen behind an already processed frontier. It can change
			// the current view, but cannot justify a decision in the past.
			at = now
			f.AvailableAt = now
		}
		if mayYield {
			f.Body = bytes.Clone(f.Body)
			frozen = append(frozen, f)
		}
		times[at] = true
		receipts[at] = append(receipts[at], f)
		schedule(f, at)
	}

	if mayYield {
		if _, err := e.checkAdmission(ctx, now, frozen, true); err != nil {
			return nil, err
		}
	}
	agenda := make([]time.Time, 0, len(times))
	for at := range times {
		agenda = append(agenda, at)
	}
	slices.SortFunc(agenda, time.Time.Compare)
	agenda = e.coalesceStalePrefix(ctx, category, asset, cursor, freshness, agenda, receipts)
	batch := &productionReplayBatch{Through: now, Steps: make([]productionReplayStep, 0, len(agenda))}
	for _, at := range agenda {
		batch.Steps = append(batch.Steps, productionReplayStep{At: at, WindowChanged: windowChanges[at], Facts: receipts[at]})
	}
	return batch, ctx.Err()
}

// Admit stale facts together at the last stale instant, preserving every
// original availability. This avoids materializing unchanged tracker and
// final-arm requests for each stale receipt in a delayed upload burst.
func (e *Engine) coalesceStalePrefix(ctx context.Context, category VisibleInputReplay, asset string, cursor time.Time, freshness time.Duration, agenda []time.Time, receipts map[time.Time][]Fact) []time.Time {
	capability, ok := category.(StaleSampleReplay)
	en := e.Enrollments[asset]
	if !ok || !e.Shadow || e.State != "ACTIVE" || !capability.CoalescesStaleFinalSamples() || !en.Active || en.NextLogicalAt != nil || len(e.Candidates) != 1 || e.Candidates[0].Phase != "FINAL" || len(agenda) < 2 {
		return agenda
	}
	// Replaying near a host capacity guard can itself produce a transition
	// at the first overflowing receipt. Preserve individual admission there.
	count := len(e.Facts)
	for _, group := range receipts {
		count += len(group)
	}
	if int64(count) > e.Config.Limits.FactCount || count > MaxFacts {
		return agenda
	}
	type sampleKey struct {
		metric string
		at     time.Time
	}
	seen := map[sampleKey]bool{}
	isStale := func(f Fact, at time.Time) bool {
		if ctx.Err() != nil || f.Kind != "SAMPLE" {
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
