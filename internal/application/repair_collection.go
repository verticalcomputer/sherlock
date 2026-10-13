package application

import (
	"context"
	"fmt"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// RepairCollectionClaim is an immutable, already-bound collection occurrence.
// Its task must be passed unchanged to Collector.Collect: the collector queue
// idempotency key is the repair effect's key, so restart only resumes the same
// work rather than creating another occurrence.
type RepairCollectionClaim struct {
	RequestID  string
	Generation int64
	Task       domain.CollectionTask
}

type RepairCollectionStore interface {
	ClaimRepairCollection(context.Context, domain.ClusterID, domain.SourceID, string, time.Duration) (RepairCollectionClaim, bool, error)
	FinishRepairCollection(context.Context, RepairCollectionClaim, string) error
}

// RepairCollectionWorker bridges a live repair request into the existing
// collector path. It owns no scheduling state and never talks to a source;
// Collector.Collect performs the normal local or remote collection protocol.
type RepairCollectionWorker struct {
	store     RepairCollectionStore
	collector *Collector
	owner     string
	cluster   domain.ClusterID
	source    domain.SourceID
	lease     time.Duration
}

func NewRepairCollectionWorker(store RepairCollectionStore, collector *Collector, cluster domain.ClusterID, source domain.SourceID, owner string, lease time.Duration) (*RepairCollectionWorker, error) {
	if store == nil || collector == nil || cluster == "" || source == "" || owner == "" || lease <= 0 || lease > 5*time.Minute {
		return nil, fmt.Errorf("repair collection worker dependencies are invalid")
	}
	return &RepairCollectionWorker{store: store, collector: collector, cluster: cluster, source: source, owner: owner, lease: lease}, nil
}

// RunOnce claims at most one request so a poisoned or slow remote collection
// cannot starve ordinary worker maintenance. Completion is durable in the same
// request lifecycle; a process loss leaves the lease reclaimable.
func (w *RepairCollectionWorker) RunOnce(ctx context.Context) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, w.lease)
	defer cancel()
	claim, found, err := w.store.ClaimRepairCollection(ctx, w.cluster, w.source, w.owner, w.lease)
	if err != nil || !found {
		return found, err
	}
	if _, err := w.collector.Collect(ctx, claim.Task); err != nil {
		return true, err
	}
	if err := w.store.FinishRepairCollection(ctx, claim, w.owner); err != nil {
		return true, err
	}
	return true, nil
}
