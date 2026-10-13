package adminmanage

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// Audit kinds for the expected-inventory proposal and approval.
const (
	EventExpectedInventoryPreviewed = "EXPECTED_INVENTORY_PREVIEWED"
	EventExpectedInventoryImported  = "EXPECTED_INVENTORY_IMPORTED"

	// expectedInventoryPreviewTTL bounds how long an operator may approve a
	// reconciliation that was computed from a particular moment's telemetry.
	expectedInventoryPreviewTTL = 24 * time.Hour
	// expectedInventoryContentLimit is deliberately below the schema's
	// 256 KiB CHECK. The CHECK measures octet_length(content::text), which
	// is Postgres's own jsonb re-serialization and is larger than the
	// compact JSON measured here (jsonb inserts a space after every ':' and
	// ',' and re-encodes escapes). Bounding the Go side at 192 KiB keeps a
	// 25% margin, so an oversized preview is always refused here as a clean
	// ErrInvalid and the database CHECK can never be the first failure an
	// operator sees.
	expectedInventoryContentLimit = 192 << 10
	// observedInventoryQueryLimit reads one row past each domain bound so an
	// oversized target inventory is refused rather than silently truncated.
	observedInventoryNodeLimit = domain.ExpectedInventoryMaxObservedNodes + 1
	observedInventoryGPULimit  = domain.ExpectedInventoryMaxObservedGPUs + 1
)

// ErrExpectedInventoryUnavailable means no goodput store was configured, so
// the canonical expected-inventory write path does not exist in this process.
var ErrExpectedInventoryUnavailable = errors.New("expected inventory import is not configured")

// ErrExpectedInventoryAmbiguousSource means the cluster declares more than
// one Prometheus source, so the caller must name the exact one. It is a
// distinct sentinel because the API turns it into its own operator message
// rather than the generic unprocessable-preview refusal.
var ErrExpectedInventoryAmbiguousSource = errors.New("the cluster declares several Prometheus sources")

// WithGoodputStore injects the canonical GP-02 fact writer. Expected
// inventory is only ever recorded through RecordExpectedInventoryRevision;
// this package never writes the goodput tables itself and keeps no parallel
// registry of nodes or GPU identities.
func WithGoodputStore(store application.GoodputStore) PostgresOption {
	return func(target *PostgresStore) error {
		if store == nil {
			return fmt.Errorf("%w: goodput store is required", ErrInvalid)
		}
		target.goodput = store
		return nil
	}
}

// ExpectedInventoryRevisionSummary is the redacted header of the expected
// revision currently in force for one cluster and source.
type ExpectedInventoryRevisionSummary struct {
	RevisionID  string
	SourceAt    time.Time
	EffectiveAt time.Time
	ObservedAt  time.Time
	NodeCount   int
	GPUCount    int
}

// ExpectedInventoryPreviewRecord is one persisted proposal with its import
// state. DigestHex is what an operator approves by; it binds the approval to
// exactly this reconciliation and nothing else.
type ExpectedInventoryPreviewRecord struct {
	PreviewID          string
	ClusterID          string
	SourceID           string
	DigestHex          string
	Blocking           bool
	GeneratedBy        string
	GeneratedAt        time.Time
	ExpiresAt          time.Time
	ImportedRevisionID string
	ImportedBy         string
	ImportedAt         *time.Time
	Preview            domain.ExpectedInventoryPreview
	// Superseded is true when the stored content's SchemaVersion is not the
	// current one. Such a record's digest is never re-derived: the canonical
	// encoding changed, so an older content would re-hash to a different
	// digest even though nothing about the stored bytes is corrupt. It is
	// reported to the operator, never imported, and never treated as a
	// conflict.
	Superseded bool
	// SupersededReason is the fixed, redacted operator text explaining why.
	SupersededReason string
}

// Expired reports whether the proposal may still be approved.
func (record ExpectedInventoryPreviewRecord) Expired(now time.Time) bool {
	return !record.ExpiresAt.After(now.UTC())
}

// Imported reports whether this exact proposal already produced a revision.
func (record ExpectedInventoryPreviewRecord) Imported() bool { return record.ImportedAt != nil }

// ExpectedInventoryState is the cluster's expected-inventory view: what is in
// force, what is proposed, and whether a discovery exists to propose from.
type ExpectedInventoryState struct {
	ClusterID            string
	SourceID             string
	Current              *ExpectedInventoryRevisionSummary
	LatestPreview        *ExpectedInventoryPreviewRecord
	DiscoveryAvailable   bool
	DiscoveryTestID      string
	DiscoveryCompletedAt time.Time
}

// ExpectedInventoryImport is the outcome of approving one exact proposal.
// AlreadyImported is idempotency, not a new write.
type ExpectedInventoryImport struct {
	PreviewID       string
	RevisionID      string
	AlreadyImported bool
}

// GenerateExpectedInventoryPreview reconciles the newest SUCCEEDED BCM
// inventory discovery with the observed collection target inventory and
// persists the result as a digest-bound proposal. It writes no inventory
// fact: approval is a separate, explicit operator action.
func (store *PostgresStore) GenerateExpectedInventoryPreview(ctx context.Context, clusterID, subject, sourceID string, excludeNodes, excludeCategories []string, audit MutationAudit) (ExpectedInventoryPreviewRecord, error) {
	if !store.credentialsEnabled() {
		return ExpectedInventoryPreviewRecord{}, ErrCredentialKeyUnavailable
	}
	if validateClusterID(clusterID) != nil || !validAccessSubject(subject) || !validExpectedInventorySource(sourceID) {
		return ExpectedInventoryPreviewRecord{}, fmt.Errorf("%w: expected inventory preview request is invalid", ErrInvalid)
	}
	// The exclusion list is an operator decision that travels into the
	// digest-bound content; nothing about it is stored separately, so there
	// is no second copy that could disagree with the approved preview.
	excluded, err := validateExpectedInventoryExclusions(excludeNodes)
	if err != nil {
		return ExpectedInventoryPreviewRecord{}, err
	}
	excludedCategories, err := validateExpectedInventoryCategoryExclusions(excludeCategories)
	if err != nil {
		return ExpectedInventoryPreviewRecord{}, err
	}
	if err := validateMutationAudit(audit, EventExpectedInventoryPreviewed); err != nil {
		return ExpectedInventoryPreviewRecord{}, err
	}
	// The grant check is the same one ListCredentialAccessTests uses: a
	// preview exposes the retained BCM listing, so it is credential-scoped.
	allowed, err := store.CredentialAdminAllowed(ctx, clusterID, subject)
	if err != nil {
		return ExpectedInventoryPreviewRecord{}, err
	}
	if !allowed {
		return ExpectedInventoryPreviewRecord{}, ErrCredentialAccessDenied
	}
	resolvedSource, err := store.resolveExpectedInventorySource(ctx, clusterID, sourceID)
	if err != nil {
		return ExpectedInventoryPreviewRecord{}, err
	}
	discovery, found, err := store.loadLatestInventoryDiscovery(ctx, clusterID)
	if err != nil {
		return ExpectedInventoryPreviewRecord{}, err
	}
	if !found {
		return ExpectedInventoryPreviewRecord{}, fmt.Errorf("%w: no inventory discovery has succeeded for this cluster", ErrNotFound)
	}
	observedNodes, observedGPUs, err := store.loadObservedTargets(ctx, clusterID, resolvedSource)
	if err != nil {
		return ExpectedInventoryPreviewRecord{}, err
	}
	current, err := store.loadCurrentExpectedRevision(ctx, clusterID, resolvedSource)
	if err != nil {
		return ExpectedInventoryPreviewRecord{}, err
	}
	generatedAt := audit.OccurredAt.UTC()
	preview, err := domain.BuildExpectedInventoryPreview(domain.ExpectedInventoryPreviewInput{
		ClusterID: domain.ClusterID(clusterID), SourceID: domain.SourceID(resolvedSource),
		Discovery: domain.InventoryDiscoveryEvidence{
			TestID: discovery.TestID, CredentialID: discovery.CredentialID, CredentialVersion: discovery.CredentialVersion,
			CredentialCurrent: discovery.CredentialCurrent, Host: discovery.Host, BCMVersion: discovery.BCMVersion,
			CompletedAt: discovery.CompletedAt, Devices: discovery.Devices,
		},
		ObservedNodes: observedNodes, ObservedGPUs: observedGPUs, Current: current, GeneratedAt: generatedAt,
		ExcludeNodes: excluded, ExcludeCategories: excludedCategories,
	})
	if err != nil {
		return ExpectedInventoryPreviewRecord{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	digest, err := domain.ExpectedInventoryPreviewDigest(preview)
	if err != nil {
		return ExpectedInventoryPreviewRecord{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	content, err := encodeExpectedInventoryPreview(preview)
	if err != nil {
		return ExpectedInventoryPreviewRecord{}, err
	}
	previewID, err := newExpectedInventoryPreviewID()
	if err != nil {
		return ExpectedInventoryPreviewRecord{}, err
	}
	record := ExpectedInventoryPreviewRecord{
		PreviewID: previewID, ClusterID: clusterID, SourceID: resolvedSource,
		DigestHex: hex.EncodeToString(digest[:]), Blocking: preview.Blocking, GeneratedBy: subject,
		GeneratedAt: generatedAt, ExpiresAt: generatedAt.Add(expectedInventoryPreviewTTL), Preview: preview,
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ExpectedInventoryPreviewRecord{}, fmt.Errorf("begin expected inventory preview: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO expected_inventory_previews
		(preview_id,cluster_id,source_id,discovery_test_id,digest,content,blocking,node_count,gpu_count,generated_by,generated_at,expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		record.PreviewID, clusterID, resolvedSource, discovery.TestID, digest[:], content, preview.Blocking,
		preview.NodeCount, preview.GPUCount, subject, record.GeneratedAt, record.ExpiresAt); err != nil {
		return ExpectedInventoryPreviewRecord{}, classifyMutationError("store expected inventory preview", err)
	}
	if err := insertAccessTestEvent(ctx, tx, accessTestEvent{
		Kind: EventExpectedInventoryPreviewed, Outcome: "SUCCEEDED", Reason: audit.ReasonCode,
		ActorKind: "ACCESS_SUBJECT", Actor: subject, ClusterID: clusterID, TestID: discovery.TestID,
		CredentialID: discovery.CredentialID, CredentialVersion: discovery.CredentialVersion,
		RequestID: audit.RequestID, OccurredAt: generatedAt,
	}); err != nil {
		return ExpectedInventoryPreviewRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ExpectedInventoryPreviewRecord{}, classifyMutationError("commit expected inventory preview", err)
	}
	return record, nil
}

// GetExpectedInventory reports the revision in force and the newest proposal
// for a cluster. It never generates a preview as a side effect of reading.
func (store *PostgresStore) GetExpectedInventory(ctx context.Context, clusterID, subject, sourceID string) (ExpectedInventoryState, error) {
	if !store.credentialsEnabled() {
		return ExpectedInventoryState{}, ErrCredentialKeyUnavailable
	}
	if validateClusterID(clusterID) != nil || !validAccessSubject(subject) || !validExpectedInventorySource(sourceID) {
		return ExpectedInventoryState{}, fmt.Errorf("%w: expected inventory request is invalid", ErrInvalid)
	}
	allowed, err := store.CredentialAdminAllowed(ctx, clusterID, subject)
	if err != nil {
		return ExpectedInventoryState{}, err
	}
	if !allowed {
		return ExpectedInventoryState{}, ErrCredentialAccessDenied
	}
	resolvedSource, err := store.resolveExpectedInventorySource(ctx, clusterID, sourceID)
	if err != nil {
		return ExpectedInventoryState{}, err
	}
	state := ExpectedInventoryState{ClusterID: clusterID, SourceID: resolvedSource}
	current, err := store.loadCurrentExpectedRevision(ctx, clusterID, resolvedSource)
	if err != nil {
		return ExpectedInventoryState{}, err
	}
	if current != nil {
		summary := ExpectedInventoryRevisionSummary{
			RevisionID: string(current.ID), SourceAt: current.SourceAt.UTC(),
			EffectiveAt: current.EffectiveAt.UTC(), ObservedAt: current.ObservedAt.UTC(),
		}
		for _, entity := range current.Entities {
			switch entity.Kind {
			case domain.EntityNode:
				summary.NodeCount++
			case domain.EntityGPU:
				summary.GPUCount++
			}
		}
		state.Current = &summary
	}
	discovery, found, err := store.loadLatestInventoryDiscovery(ctx, clusterID)
	if err != nil {
		return ExpectedInventoryState{}, err
	}
	if found {
		state.DiscoveryAvailable, state.DiscoveryTestID, state.DiscoveryCompletedAt = true, discovery.TestID, discovery.CompletedAt
	}
	record, found, err := store.loadLatestExpectedInventoryPreview(ctx, clusterID, resolvedSource)
	if err != nil {
		// The latest preview is a proposal, not the state itself: a stored
		// digest conflict on that one record must not hide the current
		// revision or discovery availability the operator needs in order to
		// generate a replacement preview.
		if !errors.Is(err, ErrConflict) {
			return ExpectedInventoryState{}, err
		}
		record.Superseded, record.SupersededReason = true, "stored digest does not match its content"
		found = true
	}
	if found {
		state.LatestPreview = &record
	}
	return state, nil
}

// ImportExpectedInventoryPreview approves exactly one stored proposal, by
// digest, and records it through the canonical RecordExpectedInventoryRevision
// path. It never re-queries BCM or telemetry: the revision is built from the
// stored content, so approval and import cannot disagree.
//
// The goodput store owns its own transaction, so the revision is recorded
// first and the preview row is marked afterwards. A crash between the two
// leaves a durable revision and an unmarked preview. The repair is explicit
// and runs before every other gate: the deterministic revision identifier is
// looked up, and a revision that is already durable completes the marking and
// reports AlreadyImported. Without that ordering the retry would meet the
// expiry or supersede gate first and refuse forever, leaving a recorded
// revision whose preview claims it was never imported.
func (store *PostgresStore) ImportExpectedInventoryPreview(ctx context.Context, clusterID, subject, previewID, digestHex string, audit MutationAudit) (ExpectedInventoryImport, error) {
	if !store.credentialsEnabled() {
		return ExpectedInventoryImport{}, ErrCredentialKeyUnavailable
	}
	if store.goodput == nil {
		return ExpectedInventoryImport{}, ErrExpectedInventoryUnavailable
	}
	if validateClusterID(clusterID) != nil || !validAccessSubject(subject) || !validExpectedInventoryPreviewID(previewID) {
		return ExpectedInventoryImport{}, fmt.Errorf("%w: expected inventory import request is invalid", ErrInvalid)
	}
	approved, err := hex.DecodeString(strings.TrimSpace(digestHex))
	if err != nil || len(approved) != len(domain.SHA256{}) {
		return ExpectedInventoryImport{}, fmt.Errorf("%w: the approved preview digest is invalid", ErrInvalid)
	}
	if err := validateMutationAudit(audit, EventExpectedInventoryImported); err != nil {
		return ExpectedInventoryImport{}, err
	}
	allowed, err := store.CredentialAdminAllowed(ctx, clusterID, subject)
	if err != nil {
		return ExpectedInventoryImport{}, err
	}
	if !allowed {
		return ExpectedInventoryImport{}, ErrCredentialAccessDenied
	}
	record, stored, err := store.lockExpectedInventoryPreview(ctx, clusterID, previewID, approved)
	if err != nil {
		return ExpectedInventoryImport{}, err
	}
	if record.Imported() {
		return ExpectedInventoryImport{PreviewID: previewID, RevisionID: record.ImportedRevisionID, AlreadyImported: true}, nil
	}
	now := audit.OccurredAt.UTC()
	revisionID := domain.InventoryRevisionID("exp_" + strings.TrimPrefix(previewID, "ipv_"))
	// Crash repair, before any gate that could refuse: the revision this
	// exact preview would produce is already durable, so the only work left
	// is the marking that did not survive.
	existing, found, err := store.goodput.GetInventoryRevision(ctx, domain.ClusterID(clusterID), revisionID)
	if err != nil {
		return ExpectedInventoryImport{}, fmt.Errorf("load recorded expected inventory revision: %w", err)
	}
	if found && existing.Class == application.InventoryExpected {
		if err := store.markExpectedInventoryPreviewImported(ctx, clusterID, previewID, string(revisionID), subject, now, audit, record); err != nil {
			return ExpectedInventoryImport{}, err
		}
		return ExpectedInventoryImport{PreviewID: previewID, RevisionID: string(revisionID), AlreadyImported: true}, nil
	}
	// The stored Blocking column is a cached summary of the stored content.
	// The content is digest-bound and the column is not, so the refusal is
	// re-derived from the findings and a disagreement is a conflict, never a
	// preview whose cheaper flag is believed over what the operator saw.
	blocking := stored.DerivedBlocking()
	if blocking != record.Blocking || blocking != stored.Blocking {
		return ExpectedInventoryImport{}, fmt.Errorf("%w: the stored preview's blocking state does not match its discrepancies", ErrConflict)
	}
	if blocking {
		return ExpectedInventoryImport{}, fmt.Errorf("%w: the preview has blocking discrepancies and cannot be imported", ErrInvalid)
	}
	if record.Expired(now) {
		return ExpectedInventoryImport{}, fmt.Errorf("%w: the preview has expired and must be regenerated", ErrInvalid)
	}
	revision, err := domain.ExpectedInventoryRevisionFromPreview(stored, revisionID, now)
	if err != nil {
		return ExpectedInventoryImport{}, fmt.Errorf("%w: the preview does not describe a valid inventory revision", ErrInvalid)
	}
	// The freshness precondition and canonical write share the goodput fact
	// stream lock. Separate preview approvals can therefore never both pass
	// against the same current revision and commit in reverse order.
	recorded, accepted, err := store.goodput.RecordExpectedInventoryRevisionIfCurrentBefore(ctx, revision, stored.GeneratedAt)
	if err != nil {
		// The store's own message can name an immutable revision; the caller
		// receives a fixed conflict instead of durable-state detail.
		return ExpectedInventoryImport{}, fmt.Errorf("%w: the expected inventory revision conflicts with durable state", ErrConflict)
	}
	if !accepted {
		return ExpectedInventoryImport{}, fmt.Errorf("%w: a newer expected inventory revision is already in force for this source; regenerate the preview", ErrConflict)
	}
	if err := store.markExpectedInventoryPreviewImported(ctx, clusterID, previewID, string(revisionID), subject, now, audit, record); err != nil {
		return ExpectedInventoryImport{}, err
	}
	// recorded==false means the identical revision was already durable, which
	// is the repair path for a crash between the two writes above.
	return ExpectedInventoryImport{PreviewID: previewID, RevisionID: string(revisionID), AlreadyImported: !recorded}, nil
}

func (store *PostgresStore) markExpectedInventoryPreviewImported(ctx context.Context, clusterID, previewID, revisionID, subject string, now time.Time, audit MutationAudit, record ExpectedInventoryPreviewRecord) error {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin expected inventory import: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The lock released before this transaction began, so a concurrent
	// import of the same preview may already have marked the row. The audit
	// event records an approval that was applied here; emitting it for an
	// update that matched nothing would record the same import twice.
	marked, err := tx.Exec(ctx, `UPDATE expected_inventory_previews
		SET imported_revision_id=$3, imported_by=$4, imported_at=$5
		WHERE preview_id=$1 AND cluster_id=$2 AND imported_at IS NULL`,
		previewID, clusterID, revisionID, subject, now)
	if err != nil {
		return classifyMutationError("record expected inventory import", err)
	}
	if marked.RowsAffected() == 0 {
		return nil
	}
	if err := insertAccessTestEvent(ctx, tx, accessTestEvent{
		Kind: EventExpectedInventoryImported, Outcome: "SUCCEEDED", Reason: audit.ReasonCode,
		ActorKind: "ACCESS_SUBJECT", Actor: subject, ClusterID: clusterID, TestID: record.Preview.DiscoveryTestID,
		CredentialID: record.Preview.CredentialID, CredentialVersion: record.Preview.CredentialVersion,
		RequestID: audit.RequestID, OccurredAt: now,
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return classifyMutationError("commit expected inventory import", err)
	}
	return nil
}

// lockExpectedInventoryPreview loads one proposal FOR UPDATE and proves that
// the approved digest is the digest of exactly the stored content.
func (store *PostgresStore) lockExpectedInventoryPreview(ctx context.Context, clusterID, previewID string, approved []byte) (ExpectedInventoryPreviewRecord, domain.ExpectedInventoryPreview, error) {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ExpectedInventoryPreviewRecord{}, domain.ExpectedInventoryPreview{}, fmt.Errorf("begin expected inventory preview lock: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	record, err := scanExpectedInventoryPreview(tx.QueryRow(ctx, expectedInventoryPreviewColumns+` WHERE preview_id=$1 FOR UPDATE`, previewID))
	if errors.Is(err, pgx.ErrNoRows) {
		return ExpectedInventoryPreviewRecord{}, domain.ExpectedInventoryPreview{}, fmt.Errorf("%w: the expected inventory preview was not found", ErrNotFound)
	}
	if err != nil {
		return ExpectedInventoryPreviewRecord{}, domain.ExpectedInventoryPreview{}, err
	}
	if record.ClusterID != clusterID {
		// A preview belongs to one cluster; a grant for another cluster must
		// not resolve it, so absence and foreign ownership read alike.
		return ExpectedInventoryPreviewRecord{}, domain.ExpectedInventoryPreview{}, fmt.Errorf("%w: the expected inventory preview was not found", ErrNotFound)
	}
	// A superseded preview's content was persisted under an earlier schema
	// version and was never re-hashed against its stored digest (see
	// scanExpectedInventoryPreview), so there is no trustworthy digest to
	// compare the operator's approval against. The refusal is checked before
	// that comparison, not folded into it.
	if record.Superseded {
		return ExpectedInventoryPreviewRecord{}, domain.ExpectedInventoryPreview{}, fmt.Errorf("%w: the preview was generated by an earlier format; generate a new preview", ErrInvalid)
	}
	storedDigest, err := hex.DecodeString(record.DigestHex)
	if err != nil {
		return ExpectedInventoryPreviewRecord{}, domain.ExpectedInventoryPreview{}, fmt.Errorf("%w: the stored preview digest is unreadable", ErrConflict)
	}
	if subtle.ConstantTimeCompare(storedDigest, approved) != 1 {
		return ExpectedInventoryPreviewRecord{}, domain.ExpectedInventoryPreview{}, fmt.Errorf("%w: the approved digest does not identify this preview", ErrInvalid)
	}
	if err := tx.Commit(ctx); err != nil {
		return ExpectedInventoryPreviewRecord{}, domain.ExpectedInventoryPreview{}, classifyMutationError("commit expected inventory preview lock", err)
	}
	return record, record.Preview, nil
}

const expectedInventoryPreviewColumns = `SELECT preview_id,cluster_id,source_id,encode(digest,'hex'),content,blocking,
	generated_by,generated_at,expires_at,imported_revision_id,imported_by,imported_at
	FROM expected_inventory_previews`

type expectedInventoryRow interface {
	Scan(destinations ...any) error
}

// supersededPreviewReason is the fixed operator text for a preview whose
// stored content was persisted under an earlier schema version. It names no
// durable state and no host response.
const supersededPreviewReason = "generated by an earlier preview format"

// scanExpectedInventoryPreview decodes the stored content and, for a preview
// whose content is still the current schema version, re-derives its digest.
// A row whose current-version content no longer hashes to its stored digest
// is a conflict, never a preview an operator may approve.
//
// A row whose content carries an earlier SchemaVersion is never re-hashed:
// the canonical encoding changed with the schema, so an older content's
// digest would legitimately differ from a digest computed under today's
// encoding even though the stored bytes are exactly what was written. Such a
// row is reported back as Superseded instead of as a conflict.
func scanExpectedInventoryPreview(row expectedInventoryRow) (ExpectedInventoryPreviewRecord, error) {
	var record ExpectedInventoryPreviewRecord
	var content []byte
	var revisionID, importedBy *string
	if err := row.Scan(&record.PreviewID, &record.ClusterID, &record.SourceID, &record.DigestHex, &content,
		&record.Blocking, &record.GeneratedBy, &record.GeneratedAt, &record.ExpiresAt,
		&revisionID, &importedBy, &record.ImportedAt); err != nil {
		return ExpectedInventoryPreviewRecord{}, err
	}
	if err := json.Unmarshal(content, &record.Preview); err != nil {
		return record, fmt.Errorf("%w: the stored preview content is unreadable", ErrConflict)
	}
	if record.Preview.SchemaVersion != domain.ExpectedInventoryPreviewSchemaVersion {
		record.Superseded, record.SupersededReason = true, supersededPreviewReason
		if revisionID != nil {
			record.ImportedRevisionID = *revisionID
		}
		if importedBy != nil {
			record.ImportedBy = *importedBy
		}
		record.GeneratedAt, record.ExpiresAt = record.GeneratedAt.UTC(), record.ExpiresAt.UTC()
		if record.ImportedAt != nil {
			imported := record.ImportedAt.UTC()
			record.ImportedAt = &imported
		}
		return record, nil
	}
	digest, err := domain.ExpectedInventoryPreviewDigest(record.Preview)
	if err != nil {
		return record, fmt.Errorf("%w: the stored preview content is unreadable", ErrConflict)
	}
	if hex.EncodeToString(digest[:]) != record.DigestHex {
		return record, fmt.Errorf("%w: the stored preview content does not match its digest", ErrConflict)
	}
	if revisionID != nil {
		record.ImportedRevisionID = *revisionID
	}
	if importedBy != nil {
		record.ImportedBy = *importedBy
	}
	record.GeneratedAt, record.ExpiresAt = record.GeneratedAt.UTC(), record.ExpiresAt.UTC()
	if record.ImportedAt != nil {
		imported := record.ImportedAt.UTC()
		record.ImportedAt = &imported
	}
	return record, nil
}

// loadLatestExpectedInventoryPreview returns the record even when it also
// returns an error: a caller such as GetExpectedInventory that must not fail
// its whole read on a stored digest conflict needs the row's own identifying
// fields (PreviewID, GeneratedAt, …) to build a Superseded projection from.
func (store *PostgresStore) loadLatestExpectedInventoryPreview(ctx context.Context, clusterID, sourceID string) (ExpectedInventoryPreviewRecord, bool, error) {
	record, err := scanExpectedInventoryPreview(store.pool.QueryRow(ctx,
		expectedInventoryPreviewColumns+` WHERE cluster_id=$1 AND source_id=$2 ORDER BY generated_at DESC, preview_id DESC LIMIT 1`, clusterID, sourceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return ExpectedInventoryPreviewRecord{}, false, nil
	}
	if err != nil {
		return record, false, err
	}
	return record, true, nil
}

// resolveExpectedInventorySource accepts an explicit source or, when the
// cluster declares exactly one Prometheus source, that one. It never guesses
// between several: an expected inventory is scoped to one exact source.
func (store *PostgresStore) resolveExpectedInventorySource(ctx context.Context, clusterID, sourceID string) (string, error) {
	if sourceID != "" {
		var resolved string
		err := store.pool.QueryRow(ctx, `SELECT source_id FROM sources WHERE cluster_id=$1 AND source_id=$2`, clusterID, sourceID).Scan(&resolved)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("%w: the source is not declared for this cluster", ErrNotFound)
		}
		if err != nil {
			return "", fmt.Errorf("resolve expected inventory source: %w", err)
		}
		return resolved, nil
	}
	rows, err := store.pool.Query(ctx, `SELECT source_id FROM sources WHERE cluster_id=$1 AND kind='prometheus' ORDER BY source_id LIMIT 2`, clusterID)
	if err != nil {
		return "", fmt.Errorf("resolve expected inventory source: %w", err)
	}
	defer rows.Close()
	candidates := make([]string, 0, 2)
	for rows.Next() {
		var candidate string
		if err := rows.Scan(&candidate); err != nil {
			return "", fmt.Errorf("scan expected inventory source: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("resolve expected inventory source: %w", err)
	}
	switch len(candidates) {
	case 0:
		return "", fmt.Errorf("%w: the cluster declares no Prometheus source", ErrNotFound)
	case 1:
		return candidates[0], nil
	default:
		return "", fmt.Errorf("%w: %w; name the exact source", ErrInvalid, ErrExpectedInventoryAmbiguousSource)
	}
}

// loadObservedTargets reads the observed collection target inventory. It is
// the identity evidence the DCGM mapper will later join on, not a claim that
// any node is healthy.
func (store *PostgresStore) loadObservedTargets(ctx context.Context, clusterID, sourceID string) ([]domain.ObservedNodeTarget, []domain.ObservedGPUTarget, error) {
	nodeRows, err := store.pool.Query(ctx, `SELECT target_id,last_observed_at FROM collection_target_inventory
		WHERE cluster_id=$1 AND source_id=$2 AND target_kind='NODE' ORDER BY target_id LIMIT $3`, clusterID, sourceID, observedInventoryNodeLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("load observed node targets: %w", err)
	}
	defer nodeRows.Close()
	nodes := make([]domain.ObservedNodeTarget, 0)
	for nodeRows.Next() {
		var node domain.ObservedNodeTarget
		if err := nodeRows.Scan(&node.NodeID, &node.LastObservedAt); err != nil {
			return nil, nil, fmt.Errorf("scan observed node target: %w", err)
		}
		nodes = append(nodes, node)
	}
	if err := nodeRows.Err(); err != nil {
		return nil, nil, fmt.Errorf("load observed node targets: %w", err)
	}
	nodeRows.Close()
	gpuRows, err := store.pool.Query(ctx, `SELECT node_id,target_id,last_observed_at FROM collection_target_inventory
		WHERE cluster_id=$1 AND source_id=$2 AND target_kind='GPU' ORDER BY node_id,target_id LIMIT $3`, clusterID, sourceID, observedInventoryGPULimit)
	if err != nil {
		return nil, nil, fmt.Errorf("load observed GPU targets: %w", err)
	}
	defer gpuRows.Close()
	gpus := make([]domain.ObservedGPUTarget, 0)
	for gpuRows.Next() {
		var gpu domain.ObservedGPUTarget
		if err := gpuRows.Scan(&gpu.NodeID, &gpu.UUID, &gpu.LastObservedAt); err != nil {
			return nil, nil, fmt.Errorf("scan observed GPU target: %w", err)
		}
		gpus = append(gpus, gpu)
	}
	if err := gpuRows.Err(); err != nil {
		return nil, nil, fmt.Errorf("load observed GPU targets: %w", err)
	}
	return nodes, gpus, nil
}

func (store *PostgresStore) loadCurrentExpectedRevision(ctx context.Context, clusterID, sourceID string) (*domain.InventoryRevision, error) {
	if store.goodput == nil {
		return nil, nil
	}
	projection, found, err := store.goodput.GetCurrentInventoryRevision(ctx, domain.ClusterID(clusterID), domain.SourceID(sourceID), application.InventoryExpected)
	if err != nil {
		return nil, fmt.Errorf("load current expected inventory revision: %w", err)
	}
	if !found {
		return nil, nil
	}
	revision := projection.Revision
	return &revision, nil
}

// encodeExpectedInventoryPreview encodes the proposal for storage and applies
// the Go-side content bound. The bound is enforced here, before the insert,
// so an oversized preview is always an ErrInvalid the caller can act on and
// never a database CHECK violation surfacing as an opaque conflict.
func encodeExpectedInventoryPreview(preview domain.ExpectedInventoryPreview) ([]byte, error) {
	content, err := json.Marshal(preview)
	if err != nil {
		return nil, fmt.Errorf("%w: expected inventory preview cannot be encoded", ErrInvalid)
	}
	if len(content) > expectedInventoryContentLimit {
		return nil, fmt.Errorf("%w: expected inventory preview exceeds the stored content bound", ErrInvalid)
	}
	return content, nil
}

// validateExpectedInventoryExclusions bounds and shapes the operator's
// exclusion list before the domain sees it, so a mistyped request is a clean
// ErrInvalid here rather than a domain refusal the caller cannot classify.
func validateExpectedInventoryExclusions(nodes []string) ([]domain.StableNodeID, error) {
	if len(nodes) > domain.ExpectedInventoryMaxExcludedNodes {
		return nil, fmt.Errorf("%w: more than %d nodes were excluded", ErrInvalid, domain.ExpectedInventoryMaxExcludedNodes)
	}
	excluded := make([]domain.StableNodeID, 0, len(nodes))
	for _, node := range nodes {
		trimmed := strings.TrimSpace(node)
		if trimmed == "" || len(trimmed) > 128 || strings.ContainsAny(trimmed, "\x00\r\n\t ") {
			return nil, fmt.Errorf("%w: an excluded node is not a hostname-shaped identifier", ErrInvalid)
		}
		excluded = append(excluded, domain.StableNodeID(trimmed))
	}
	return excluded, nil
}

// validateExpectedInventoryCategoryExclusions applies the same shaping to the
// category list. A category name is BCM configuration, matched against the
// retained listing exactly, so a value that could not be one is a typo.
func validateExpectedInventoryCategoryExclusions(categories []string) ([]string, error) {
	if len(categories) > domain.ExpectedInventoryMaxExcludedCategories {
		return nil, fmt.Errorf("%w: more than %d categories were excluded", ErrInvalid, domain.ExpectedInventoryMaxExcludedCategories)
	}
	excluded := make([]string, 0, len(categories))
	for _, category := range categories {
		trimmed := strings.TrimSpace(category)
		if trimmed == "" || len(trimmed) > 128 || strings.ContainsAny(trimmed, "\x00\r\n\t ") {
			return nil, fmt.Errorf("%w: an excluded category is not a category-shaped identifier", ErrInvalid)
		}
		excluded = append(excluded, trimmed)
	}
	return excluded, nil
}

func validExpectedInventorySource(sourceID string) bool {
	return len(sourceID) <= 128 && !strings.ContainsAny(sourceID, "\x00\r\n")
}

func validExpectedInventoryPreviewID(id string) bool {
	return len(id) >= 5 && len(id) <= 128 && strings.HasPrefix(id, "ipv_") && !strings.ContainsAny(id, "\x00\r\n/\\")
}

func newExpectedInventoryPreviewID() (string, error) {
	raw := make([]byte, 18)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return "ipv_" + base64.RawURLEncoding.EncodeToString(raw), nil
}
