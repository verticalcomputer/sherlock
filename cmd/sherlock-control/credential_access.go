package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// configureCredentialAccessTests builds the keyring-backed store and mounts
// the opt-in credential-test endpoint family on the collector transport.
func configureCredentialAccessTests(cfg config.Control, pool *pgxpool.Pool, transport *collectorcontrol.Transport) error {
	ring, err := adminmanage.NewCredentialKeyring(cfg.CredentialKeyring.ActiveVersion, cfg.CredentialKeyring.Keys)
	if err != nil {
		return fmt.Errorf("configure credential keyring: %w", err)
	}
	defer ring.Destroy()
	for _, key := range cfg.CredentialKeyring.Keys {
		clear(key)
	}
	store, err := adminmanage.NewPostgresStore(pool, adminmanage.WithCredentialKeyring(ring))
	if err != nil {
		return err
	}
	return transport.ConfigureCredentialAccessTests(credentialAccessTestAdapter{store: store})
}

// credentialAccessTestAdapter maps the store's errors onto the transport's
// vocabulary. It adds no authorization of its own: every check lives in the
// store transaction.
type credentialAccessTestAdapter struct {
	store *adminmanage.PostgresStore
}

func (adapter credentialAccessTestAdapter) ClaimCredentialAccessTest(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, token string, leaseFor time.Duration) (collectorcontrol.CredentialAccessTestLease, bool, error) {
	lease, found, err := adapter.store.ClaimCredentialAccessTest(ctx, cluster, collector, token, leaseFor)
	if err != nil {
		return collectorcontrol.CredentialAccessTestLease{}, false, mapCredentialAccessTestError(err)
	}
	if !found {
		return collectorcontrol.CredentialAccessTestLease{}, false, nil
	}
	return collectorcontrol.CredentialAccessTestLease{TestID: lease.Plan.TestID, Attempt: lease.Attempt, LeaseToken: lease.LeaseToken, LeaseExpires: lease.LeaseExpires, Plan: lease.Plan}, true, nil
}

func (adapter credentialAccessTestAdapter) StartCredentialAccessTest(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, ref collectorcontrol.CredentialAccessTestRef, leaseFor time.Duration) (time.Time, error) {
	expires, err := adapter.store.StartCredentialAccessTest(ctx, cluster, collector, storeRef(ref), leaseFor)
	return expires, mapCredentialAccessTestError(err)
}

func (adapter credentialAccessTestAdapter) RenewCredentialAccessTestLease(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, ref collectorcontrol.CredentialAccessTestRef, leaseFor time.Duration) (time.Time, error) {
	expires, err := adapter.store.RenewCredentialAccessTestLease(ctx, cluster, collector, storeRef(ref), leaseFor)
	return expires, mapCredentialAccessTestError(err)
}

func (adapter credentialAccessTestAdapter) DeliverCredentialForAccessTest(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, ref collectorcontrol.CredentialAccessTestRef, digest domain.SHA256) (collectorcontrol.CredentialDelivery, error) {
	delivery, err := adapter.store.DeliverCredentialForAccessTest(ctx, cluster, collector, storeRef(ref), digest)
	if err != nil {
		return collectorcontrol.CredentialDelivery{}, mapCredentialAccessTestError(err)
	}
	return collectorcontrol.CredentialDelivery{Host: delivery.Host, Username: delivery.Username, CredentialVersion: delivery.CredentialVersion, SudoPassword: delivery.SudoPassword}, nil
}

func (adapter credentialAccessTestAdapter) CompleteCredentialAccessTest(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, ref collectorcontrol.CredentialAccessTestRef, result domain.CredentialAccessTestResult) (collectorcontrol.CredentialTestCompletion, error) {
	completion, err := adapter.store.CompleteCredentialAccessTest(ctx, cluster, collector, storeRef(ref), result)
	if err != nil {
		return collectorcontrol.CredentialTestCompletion{}, mapCredentialAccessTestError(err)
	}
	return collectorcontrol.CredentialTestCompletion{Status: completion.Status, Outcome: completion.Outcome, Rejected: completion.Rejected}, nil
}

func storeRef(ref collectorcontrol.CredentialAccessTestRef) adminmanage.CredentialAccessTestLeaseRef {
	return adminmanage.CredentialAccessTestLeaseRef{TestID: ref.TestID, Attempt: ref.Attempt, LeaseToken: ref.LeaseToken}
}

func mapCredentialAccessTestError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, adminmanage.ErrAccessTestCollectorIncompatible):
		return collectorcontrol.ErrCredentialTestNotPermitted
	case errors.Is(err, adminmanage.ErrAccessTestLeaseInvalid), errors.Is(err, adminmanage.ErrConflict):
		return collectorcontrol.ErrWorkLeaseInvalid
	case errors.Is(err, adminmanage.ErrInvalid):
		return collectorcontrol.ErrWorkLeaseInvalid
	default:
		// Database and key failures are deliberately opaque to the collector.
		return errors.New("credential access test operation failed")
	}
}
