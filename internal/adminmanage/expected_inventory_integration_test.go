//go:build integration

package adminmanage_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

type expectedInventoryFixture struct {
	credentialFixture
	store      *adminmanage.PostgresStore
	goodput    *storepg.GoodputStore
	subject    string
	sourceID   string
	credential adminmanage.CredentialMetadata
	testID     string
}

// coordinatedExpectedInventoryStore pauses approvals immediately before the
// real canonical store operation. Tests use it to prove that two requests
// which have both completed their admin-side validation are serialized by the
// database store rather than by goroutine scheduling in this package.
type coordinatedExpectedInventoryStore struct {
	application.GoodputStore
	arrived chan domain.InventoryRevisionID
	release map[domain.InventoryRevisionID]chan struct{}
}

func (store *coordinatedExpectedInventoryStore) RecordExpectedInventoryRevisionIfCurrentBefore(ctx context.Context, revision domain.InventoryRevision, generatedAt time.Time) (bool, bool, error) {
	store.arrived <- revision.ID
	select {
	case <-ctx.Done():
		return false, false, ctx.Err()
	case <-store.release[revision.ID]:
	}
	return store.GoodputStore.RecordExpectedInventoryRevisionIfCurrentBefore(ctx, revision, generatedAt)
}

// newExpectedInventoryFixture seeds one cluster, one Prometheus source, one
// active credential and one SUCCEEDED inventory discovery with its retained
// listing. Identifiers are unique per run: these tests are not idempotent.
func newExpectedInventoryFixture(t *testing.T, devices []domain.CredentialAccessDevice) expectedInventoryFixture {
	t.Helper()
	base := newCredentialFixture(t, 0)
	goodput, err := storepg.NewGoodputStore(base.pool)
	if err != nil {
		t.Fatal(err)
	}
	store, err := adminmanage.NewPostgresStore(base.pool,
		adminmanage.WithCredentialKeyring(credentialRing(t, "v1", 0x11)),
		adminmanage.WithGoodputStore(goodput))
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	fixture := expectedInventoryFixture{
		credentialFixture: base, store: store, goodput: goodput,
		subject: "inventory-admin-" + suffix, sourceID: "head-prometheus-" + suffix,
	}
	// The grant is recorded through the base store, which shares the pool.
	grantCredentialAdmin(t, base, fixture.subject)
	mustExec(t, base.pool, `INSERT INTO sources(source_id,cluster_id,kind,display_name) VALUES($1,$2,'prometheus',$1)`, fixture.sourceID, base.clusterID)
	credential, err := putCredential(base, context.Background(), base.clusterID, fixture.subject, "fixture1-zone1-headnode", "fixture_user_1", "ssh-"+accessTestCanary, accessTestCanary, 0, "", "inv-create-"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	fixture.credential = credential
	fixture.testID = seedInventoryDiscovery(t, fixture, "ctest_inv"+suffix, devices, time.Now().UTC().Add(-time.Minute))
	return fixture
}

// seedInventoryDiscovery writes a terminal discovery row directly, exactly as
// the completion path would leave it: SUCCEEDED, with its sanitized listing.
func seedInventoryDiscovery(t *testing.T, fixture expectedInventoryFixture, testID string, devices []domain.CredentialAccessDevice, completedAt time.Time) string {
	t.Helper()
	requestedAt := completedAt.Add(-time.Minute)
	mustExec(t, fixture.pool, `INSERT INTO credential_access_tests
		(test_id,cluster_id,credential_id,credential_version,host,purpose,username,operation,plan,plan_digest,
		 requested_by,requested_at,deadline,status,max_attempts,outcome_code,outcome_summary,bcm_version,devices_listed,completed_at)
		VALUES ($1,$2,$3,$4,'fixture1-zone1-headnode','BCM_READ_ONLY','fixture_user_1',$5,'{}'::jsonb,$6,$7,$8,$9,'SUCCEEDED',1,
			'BCM_INVENTORY_LISTED','cmsh listed devices read-only.','10.0',$10,$11)`,
		testID, fixture.clusterID, fixture.credential.ID, fixture.credential.Version,
		domain.CredentialInventoryDiscoveryOperation, make([]byte, 32), fixture.subject,
		requestedAt, requestedAt.Add(15*time.Minute), len(devices), completedAt)
	for ordinal, device := range devices {
		mustExec(t, fixture.pool, `INSERT INTO credential_access_test_devices(test_id,ordinal,device_type,hostname,category,status) VALUES($1,$2,$3,$4,$5,$6)`,
			testID, ordinal, device.Type, device.Hostname, device.Category, device.Status)
	}
	return testID
}

func observeTarget(t *testing.T, fixture expectedInventoryFixture, kind, targetID, nodeID string, observedAt time.Time) {
	t.Helper()
	mustExec(t, fixture.pool, `INSERT INTO collection_target_inventory(cluster_id,source_id,target_kind,target_id,node_id,last_observed_at)
		VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (cluster_id,source_id,target_kind,target_id) DO UPDATE SET node_id=EXCLUDED.node_id, last_observed_at=EXCLUDED.last_observed_at`,
		fixture.clusterID, fixture.sourceID, kind, targetID, nodeID, observedAt)
}

// pilotComputeNodes and pilotLoginNode mirror the pilot listing: ten GPU
// compute nodes and one login node, which BCM types PhysicalNode exactly as
// it types a compute node and which reports no GPU telemetry at all. The
// statuses are the shapes the head really returned.
var pilotComputeNodes = []int{1, 2, 3, 4, 5, 6, 7, 8, 10, 11}

const pilotLoginNode = "fixture1-zone1-loginnode"

// The categories the head reports alongside the devices. They are what tells
// the login node apart from a compute node; the head node carries none.
const (
	pilotComputeCategory = "asus-h100-compute-category"
	pilotLoginCategory   = "login-default-category"
)

func pilotListing() []domain.CredentialAccessDevice {
	devices := []domain.CredentialAccessDevice{{Type: "HeadNode", Hostname: "fixture1-zone1-headnode", Status: "[ UP ]"}}
	for _, index := range pilotComputeNodes {
		devices = append(devices, domain.CredentialAccessDevice{
			Type: "PhysicalNode", Hostname: fmt.Sprintf("fixture1-zone1-comp%03d", index), Category: pilotComputeCategory,
			Status: "[ UP ], health check failed, restart required (initialize, interface:ipmi0)",
		})
	}
	devices = append(devices, domain.CredentialAccessDevice{
		Type: "PhysicalNode", Hostname: pilotLoginNode, Category: pilotLoginCategory,
		Status: "[ UP ], restart required (interface:ipmi0)",
	})
	return devices
}

// excludeLoginNode is the operator decision the pilot needs: the login node
// is listed, has no GPU telemetry, and is not a GPU compute node.
func excludeLoginNode() []string { return []string{pilotLoginNode} }

// excludeLoginCategory is the same decision made once about the grouping.
func excludeLoginCategory() []string { return []string{pilotLoginCategory} }

// seedPilotTelemetry mirrors the pilot: ten reporting nodes with eight GPUs
// each; the login node reports nothing at all.
func seedPilotTelemetry(t *testing.T, fixture expectedInventoryFixture) {
	t.Helper()
	observedAt := time.Now().UTC().Add(-30 * time.Second)
	for _, index := range pilotComputeNodes {
		node := fmt.Sprintf("fixture1-zone1-comp%03d", index)
		observeTarget(t, fixture, "NODE", node, node, observedAt)
		for slot := 0; slot < 8; slot++ {
			observeTarget(t, fixture, "GPU", fmt.Sprintf("GPU-377d585f-%04d-%04d", index, slot), node, observedAt)
		}
	}
}

func inventoryAudit(kind string) adminmanage.MutationAudit {
	return credentialAudit(fmt.Sprintf("inv-audit-%d", time.Now().UnixNano()), kind, "test", "actor", time.Now().UTC())
}

func TestExpectedInventoryPreviewToApprovedImportThroughTheStore(t *testing.T) {
	fixture := newExpectedInventoryFixture(t, pilotListing())
	ctx := context.Background()
	seedPilotTelemetry(t, fixture)

	if _, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, "stranger", "", nil, nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed)); !errors.Is(err, adminmanage.ErrCredentialAccessDenied) {
		t.Fatalf("ungranted subject err=%v", err)
	}

	record, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", excludeLoginNode(), nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed))
	if err != nil {
		t.Fatal(err)
	}
	if record.SourceID != fixture.sourceID {
		t.Fatalf("the single Prometheus source was not resolved: %q", record.SourceID)
	}
	if record.Blocking {
		t.Fatalf("pilot shape blocked: %+v", record.Preview.Discrepancies)
	}
	if record.Preview.NodeCount != 10 || record.Preview.GPUCount != 80 {
		t.Fatalf("nodes=%d gpus=%d", record.Preview.NodeCount, record.Preview.GPUCount)
	}
	codes := map[domain.InventoryDiscrepancyCode]int{}
	for _, finding := range record.Preview.Discrepancies {
		codes[finding.Code]++
	}
	if codes[domain.DiscrepancyUnmanagedDevice] != 1 || codes[domain.DiscrepancyNodeExcludedByOperator] != 1 {
		t.Fatalf("expected the head node unmanaged and the login node excluded: %v", codes)
	}
	// Every device reported health text after an "[ UP ]" token: that is a
	// health warning, never "the device is not up".
	if codes[domain.DiscrepancyDeviceHealthWarning] != 11 || codes[domain.DiscrepancyDeviceNotUp] != 0 {
		t.Fatalf("status token parsing: %v", codes)
	}
	if codes[domain.DiscrepancyNodeUnclassified] != 0 || codes[domain.DiscrepancyNodeMissingTelemetry] != 0 {
		t.Fatalf("the excluded login node was still reported as a node finding: %v", codes)
	}
	if record.Preview.DiscoveryTestID != fixture.testID {
		t.Fatalf("preview did not bind the discovery: %q", record.Preview.DiscoveryTestID)
	}
	digest, err := domain.ExpectedInventoryPreviewDigest(record.Preview)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(digest[:]) != record.DigestHex {
		t.Fatalf("stored digest %q does not describe the stored preview", record.DigestHex)
	}

	wrong := otherDigest(record.DigestHex)
	if _, err := fixture.store.ImportExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, record.PreviewID, wrong, inventoryAudit(adminmanage.EventExpectedInventoryImported)); !errors.Is(err, adminmanage.ErrInvalid) {
		t.Fatalf("wrong digest err=%v", err)
	}
	if _, err := fixture.store.ImportExpectedInventoryPreview(ctx, fixture.clusterID, "stranger", record.PreviewID, record.DigestHex, inventoryAudit(adminmanage.EventExpectedInventoryImported)); !errors.Is(err, adminmanage.ErrCredentialAccessDenied) {
		t.Fatalf("ungranted import err=%v", err)
	}
	if _, err := fixture.store.ImportExpectedInventoryPreview(ctx, fixture.foreignID, fixture.subject, record.PreviewID, record.DigestHex, inventoryAudit(adminmanage.EventExpectedInventoryImported)); err == nil {
		t.Fatal("a preview was importable from another cluster")
	}

	imported, err := fixture.store.ImportExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, record.PreviewID, record.DigestHex, inventoryAudit(adminmanage.EventExpectedInventoryImported))
	if err != nil || imported.AlreadyImported || imported.RevisionID == "" {
		t.Fatalf("import: %v %+v", err, imported)
	}
	projection, found, err := fixture.goodput.GetCurrentInventoryRevision(ctx, domain.ClusterID(fixture.clusterID), domain.SourceID(fixture.sourceID), application.InventoryExpected)
	if err != nil || !found {
		t.Fatalf("current expected revision: %v found=%v", err, found)
	}
	if string(projection.Revision.ID) != imported.RevisionID || len(projection.Revision.Entities) != 90 {
		t.Fatalf("recorded revision %+v", projection.Revision)
	}
	if !projection.Revision.SourceAt.Equal(record.Preview.DiscoveryCompletedAt) {
		t.Fatalf("source time %s is not the head listing time %s", projection.Revision.SourceAt, record.Preview.DiscoveryCompletedAt)
	}

	// A repeated approval of the same preview records no second revision.
	repeat, err := fixture.store.ImportExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, record.PreviewID, record.DigestHex, inventoryAudit(adminmanage.EventExpectedInventoryImported))
	if err != nil || !repeat.AlreadyImported || repeat.RevisionID != imported.RevisionID {
		t.Fatalf("re-import: %v %+v", err, repeat)
	}
	var revisions int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM goodput_inventory_revisions WHERE cluster_id=$1 AND source_id=$2 AND inventory_class='EXPECTED'`, fixture.clusterID, fixture.sourceID).Scan(&revisions); err != nil {
		t.Fatal(err)
	}
	if revisions != 1 {
		t.Fatalf("re-import recorded %d revisions", revisions)
	}

	state, err := fixture.store.GetExpectedInventory(ctx, fixture.clusterID, fixture.subject, "")
	if err != nil || state.Current == nil || state.Current.RevisionID != imported.RevisionID {
		t.Fatalf("state: %v %+v", err, state)
	}
	if state.Current.NodeCount != 10 || state.Current.GPUCount != 80 {
		t.Fatalf("state counts: %+v", state.Current)
	}
	if state.LatestPreview == nil || !state.LatestPreview.Imported() || state.LatestPreview.ImportedRevisionID != imported.RevisionID {
		t.Fatalf("latest preview import state: %+v", state.LatestPreview)
	}
	if !state.DiscoveryAvailable || state.DiscoveryTestID != fixture.testID {
		t.Fatalf("state discovery: %+v", state)
	}
	if _, err := fixture.store.GetExpectedInventory(ctx, fixture.clusterID, "stranger", ""); !errors.Is(err, adminmanage.ErrCredentialAccessDenied) {
		t.Fatalf("ungranted state read err=%v", err)
	}

	// Removing an observed GPU makes the next preview propose a removal
	// against the revision that is now in force.
	mustExec(t, fixture.pool, `DELETE FROM collection_target_inventory WHERE cluster_id=$1 AND source_id=$2 AND target_kind='GPU' AND target_id=$3`,
		fixture.clusterID, fixture.sourceID, "GPU-377d585f-0001-0000")
	second, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, fixture.sourceID, excludeLoginNode(), nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Preview.Removals) != 1 || string(second.Preview.Removals[0].PhysicalGPUUUID) != "GPU-377d585f-0001-0000" {
		t.Fatalf("proposed removals=%+v", second.Preview.Removals)
	}
	var removalReported bool
	for _, finding := range second.Preview.Discrepancies {
		removalReported = removalReported || finding.Code == domain.DiscrepancyProposedRemoval
	}
	if !removalReported || second.Blocking {
		t.Fatalf("removal discrepancy reported=%v blocking=%v", removalReported, second.Blocking)
	}
	if second.DigestHex == record.DigestHex {
		t.Fatal("a different reconciliation produced the same digest")
	}
	assertNoCanaryInDatabase(t, fixture.credentialFixture)
}

func TestExpectedInventoryBlockingPreviewRefusesImport(t *testing.T) {
	fixture := newExpectedInventoryFixture(t, pilotListing())
	ctx := context.Background()
	seedPilotTelemetry(t, fixture)
	// A MIG-shaped identity is not a physical GPU, and an observed node that
	// only case-insensitively resembles a managed hostname is not an alias:
	// the DCGM mapper joins on the exact exporter hostname label. Both are
	// blocking ambiguities an operator must resolve, not approve away.
	// (A single UUID on two nodes cannot be represented in
	// collection_target_inventory, whose key is the target identifier;
	// DUPLICATE_GPU remains a domain guard covered by the unit tests.)
	now := time.Now().UTC()
	observeTarget(t, fixture, "GPU", "MIG-GPU-377d585f-0001-0000/1/0", "fixture1-zone1-comp001", now)
	observeTarget(t, fixture, "NODE", "fixture1-zone1-COMP001", "fixture1-zone1-COMP001", now)

	record, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", excludeLoginNode(), nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed))
	if err != nil {
		t.Fatal(err)
	}
	if !record.Blocking {
		t.Fatalf("ambiguous identities did not block: %+v", record.Preview.Discrepancies)
	}
	codes := map[domain.InventoryDiscrepancyCode]bool{}
	for _, finding := range record.Preview.Discrepancies {
		codes[finding.Code] = codes[finding.Code] || finding.Blocking
	}
	if !codes[domain.DiscrepancyAmbiguousMIGIdentity] || !codes[domain.DiscrepancyHostnameMismatch] {
		t.Fatalf("blocking codes=%v", codes)
	}
	if _, err := fixture.store.ImportExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, record.PreviewID, record.DigestHex, inventoryAudit(adminmanage.EventExpectedInventoryImported)); !errors.Is(err, adminmanage.ErrInvalid) {
		t.Fatalf("blocking import err=%v", err)
	}
	var revisions int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM goodput_inventory_revisions WHERE cluster_id=$1`, fixture.clusterID).Scan(&revisions); err != nil {
		t.Fatal(err)
	}
	if revisions != 0 {
		t.Fatalf("a blocking preview recorded %d revisions", revisions)
	}
}

func TestExpectedInventoryPreviewRequiresASucceededDiscovery(t *testing.T) {
	base := newCredentialFixture(t, 0)
	goodput, err := storepg.NewGoodputStore(base.pool)
	if err != nil {
		t.Fatal(err)
	}
	store, err := adminmanage.NewPostgresStore(base.pool,
		adminmanage.WithCredentialKeyring(credentialRing(t, "v1", 0x11)),
		adminmanage.WithGoodputStore(goodput))
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	subject := "inventory-admin-" + suffix
	grantCredentialAdmin(t, base, subject)
	mustExec(t, base.pool, `INSERT INTO sources(source_id,cluster_id,kind,display_name) VALUES($1,$2,'prometheus',$1)`, "only-source-"+suffix, base.clusterID)
	ctx := context.Background()
	if _, err := store.GenerateExpectedInventoryPreview(ctx, base.clusterID, subject, "", nil, nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed)); !errors.Is(err, adminmanage.ErrNotFound) {
		t.Fatalf("missing discovery err=%v", err)
	}
	if _, err := store.GenerateExpectedInventoryPreview(ctx, base.clusterID, subject, "no-such-source-"+suffix, nil, nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed)); !errors.Is(err, adminmanage.ErrNotFound) {
		t.Fatalf("undeclared source err=%v", err)
	}
	mustExec(t, base.pool, `INSERT INTO sources(source_id,cluster_id,kind,display_name) VALUES($1,$2,'prometheus',$1)`, "second-source-"+suffix, base.clusterID)
	if _, err := store.GenerateExpectedInventoryPreview(ctx, base.clusterID, subject, "", nil, nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed)); !errors.Is(err, adminmanage.ErrInvalid) {
		t.Fatalf("ambiguous source err=%v", err)
	}
}

func TestExpectedInventoryImportIsUnavailableWithoutTheGoodputStore(t *testing.T) {
	fixture := newExpectedInventoryFixture(t, pilotListing())
	ctx := context.Background()
	seedPilotTelemetry(t, fixture)
	record, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", excludeLoginNode(), nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed))
	if err != nil {
		t.Fatal(err)
	}
	// The base fixture store has no goodput writer, so it has no way to
	// record an expected revision and must refuse rather than improvise one.
	if _, err := fixture.credentialFixture.store.ImportExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, record.PreviewID, record.DigestHex, inventoryAudit(adminmanage.EventExpectedInventoryImported)); !errors.Is(err, adminmanage.ErrExpectedInventoryUnavailable) {
		t.Fatalf("unconfigured import err=%v", err)
	}
}

// TestExpectedInventoryImportRefusesASupersededPreview: an approval takes
// effect when it is approved, so approving an older preview after a newer one
// has already been imported would record a reconciliation of older facts
// behind the revision in force and silently supersede it.
func TestExpectedInventoryImportRefusesASupersededPreview(t *testing.T) {
	fixture := newExpectedInventoryFixture(t, pilotListing())
	ctx := context.Background()
	seedPilotTelemetry(t, fixture)

	older, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", excludeLoginNode(), nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed))
	if err != nil {
		t.Fatal(err)
	}
	// A second reconciliation of the same facts must differ, or the two
	// previews would be the same proposal: drop one observed GPU.
	mustExec(t, fixture.pool, `DELETE FROM collection_target_inventory WHERE cluster_id=$1 AND source_id=$2 AND target_kind='GPU' AND target_id=$3`,
		fixture.clusterID, fixture.sourceID, "GPU-377d585f-0011-0007")
	newer, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", excludeLoginNode(), nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed))
	if err != nil {
		t.Fatal(err)
	}
	if newer.PreviewID == older.PreviewID || !newer.GeneratedAt.After(older.GeneratedAt) {
		t.Fatalf("the second preview is not newer: %s vs %s", newer.GeneratedAt, older.GeneratedAt)
	}

	// The newer preview is approved first, at approval time.
	approvedAt := time.Now().UTC().Truncate(time.Microsecond)
	imported, err := fixture.store.ImportExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, newer.PreviewID, newer.DigestHex,
		credentialAudit("inv-audit-newer-"+fmt.Sprint(time.Now().UnixNano()), adminmanage.EventExpectedInventoryImported, "test", "actor", approvedAt))
	if err != nil || imported.AlreadyImported {
		t.Fatalf("import newer: %v %+v", err, imported)
	}
	projection, found, err := fixture.goodput.GetCurrentInventoryRevision(ctx, domain.ClusterID(fixture.clusterID), domain.SourceID(fixture.sourceID), application.InventoryExpected)
	if err != nil || !found {
		t.Fatalf("current revision: %v found=%v", err, found)
	}
	// EffectiveAt and ObservedAt are the approval time, not the generation
	// time: the revision must not be backdated to when it was reconciled.
	if !projection.Revision.EffectiveAt.Equal(approvedAt) || !projection.Revision.ObservedAt.Equal(approvedAt) {
		t.Fatalf("effective=%s observed=%s want the approval time %s", projection.Revision.EffectiveAt, projection.Revision.ObservedAt, approvedAt)
	}
	if projection.Revision.EffectiveAt.Equal(newer.GeneratedAt) {
		t.Fatalf("the revision was backdated to the preview generation time %s", newer.GeneratedAt)
	}
	// SourceAt stays the head's listing time.
	if !projection.Revision.SourceAt.Equal(newer.Preview.DiscoveryCompletedAt) {
		t.Fatalf("source time %s is not the head listing time", projection.Revision.SourceAt)
	}

	// The older preview is not expired, is not blocking and still carries a
	// valid digest, and is refused only because it is superseded.
	if older.Expired(time.Now().UTC()) || older.Blocking {
		t.Fatalf("the older preview is not the superseded-only case: %+v", older)
	}
	if _, err := fixture.store.ImportExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, older.PreviewID, older.DigestHex, inventoryAudit(adminmanage.EventExpectedInventoryImported)); !errors.Is(err, adminmanage.ErrConflict) {
		t.Fatalf("superseded import err=%v, want ErrConflict", err)
	}
	var revisions int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM goodput_inventory_revisions WHERE cluster_id=$1 AND source_id=$2 AND inventory_class='EXPECTED'`, fixture.clusterID, fixture.sourceID).Scan(&revisions); err != nil {
		t.Fatal(err)
	}
	if revisions != 1 {
		t.Fatalf("the superseded import recorded a revision: %d total", revisions)
	}
	// The refused preview is still unimported: a refusal marks nothing.
	var importedAt *time.Time
	if err := fixture.pool.QueryRow(ctx, `SELECT imported_at FROM expected_inventory_previews WHERE preview_id=$1`, older.PreviewID).Scan(&importedAt); err != nil {
		t.Fatal(err)
	}
	if importedAt != nil {
		t.Fatalf("a refused import marked the preview at %s", importedAt)
	}
}

func TestExpectedInventoryConcurrentImportCannotReplaceNewerApprovalWithOlderPreview(t *testing.T) {
	fixture := newExpectedInventoryFixture(t, pilotListing())
	seedPilotTelemetry(t, fixture)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	older, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", excludeLoginNode(), nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed))
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, fixture.pool, `DELETE FROM collection_target_inventory WHERE cluster_id=$1 AND source_id=$2 AND target_kind='GPU' AND target_id=$3`,
		fixture.clusterID, fixture.sourceID, "GPU-377d585f-0011-0007")
	newer, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", excludeLoginNode(), nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed))
	if err != nil {
		t.Fatal(err)
	}
	if !newer.GeneratedAt.After(older.GeneratedAt) {
		t.Fatalf("newer preview generated at %s, older at %s", newer.GeneratedAt, older.GeneratedAt)
	}

	olderRevisionID := domain.InventoryRevisionID("exp_" + strings.TrimPrefix(older.PreviewID, "ipv_"))
	newerRevisionID := domain.InventoryRevisionID("exp_" + strings.TrimPrefix(newer.PreviewID, "ipv_"))
	coordinated := &coordinatedExpectedInventoryStore{
		GoodputStore: fixture.goodput,
		arrived:      make(chan domain.InventoryRevisionID, 2),
		release: map[domain.InventoryRevisionID]chan struct{}{
			olderRevisionID: make(chan struct{}),
			newerRevisionID: make(chan struct{}),
		},
	}
	manager, err := adminmanage.NewPostgresStore(fixture.pool,
		adminmanage.WithCredentialKeyring(credentialRing(t, "v1", 0x11)),
		adminmanage.WithGoodputStore(coordinated))
	if err != nil {
		t.Fatal(err)
	}
	type importResult struct {
		result adminmanage.ExpectedInventoryImport
		err    error
	}
	newerResult := make(chan importResult, 1)
	olderResult := make(chan importResult, 1)
	go func() {
		result, err := manager.ImportExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, newer.PreviewID, newer.DigestHex, inventoryAudit(adminmanage.EventExpectedInventoryImported))
		newerResult <- importResult{result: result, err: err}
	}()
	if arrived := <-coordinated.arrived; arrived != newerRevisionID {
		t.Fatalf("first approval reached the store for %s, want newer %s", arrived, newerRevisionID)
	}
	go func() {
		result, err := manager.ImportExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, older.PreviewID, older.DigestHex, inventoryAudit(adminmanage.EventExpectedInventoryImported))
		olderResult <- importResult{result: result, err: err}
	}()
	if arrived := <-coordinated.arrived; arrived != olderRevisionID {
		t.Fatalf("second approval reached the store for %s, want older %s", arrived, olderRevisionID)
	}

	// Both requests have passed all admin-side checks. Commit the newer one,
	// then let the older request acquire the same database fact-stream lock.
	close(coordinated.release[newerRevisionID])
	approved := <-newerResult
	if approved.err != nil || approved.result.RevisionID != string(newerRevisionID) {
		t.Fatalf("newer approval: result=%+v err=%v", approved.result, approved.err)
	}
	close(coordinated.release[olderRevisionID])
	refused := <-olderResult
	if !errors.Is(refused.err, adminmanage.ErrConflict) {
		t.Fatalf("older concurrent approval result=%+v err=%v, want ErrConflict", refused.result, refused.err)
	}

	current, found, err := fixture.goodput.GetCurrentInventoryRevision(ctx, domain.ClusterID(fixture.clusterID), domain.SourceID(fixture.sourceID), application.InventoryExpected)
	if err != nil || !found {
		t.Fatalf("current expected inventory: found=%t err=%v", found, err)
	}
	if current.Revision.ID != newerRevisionID {
		t.Fatalf("older preview replaced the newer approval: current=%s newer=%s", current.Revision.ID, newerRevisionID)
	}
}

// TestExpectedInventoryImportRepairsACrashBeforeMarking: the revision commit
// and the preview marking are separate transactions. A crash between them
// leaves a durable revision and an unmarked preview, and the retry may well
// arrive after the preview's 24 hour window. The repair must therefore run
// before the expiry and blocking gates, or the preview would claim forever
// that a revision recorded from it was never imported.
func TestExpectedInventoryImportRepairsACrashBeforeMarking(t *testing.T) {
	fixture := newExpectedInventoryFixture(t, pilotListing())
	ctx := context.Background()
	seedPilotTelemetry(t, fixture)

	record, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", excludeLoginNode(), nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed))
	if err != nil {
		t.Fatal(err)
	}
	// Record the revision directly, exactly as the crashed attempt would
	// have left it: durable, under the deterministic identifier, with the
	// preview row still unmarked.
	revisionID := domain.InventoryRevisionID("exp_" + strings.TrimPrefix(record.PreviewID, "ipv_"))
	revision, err := domain.ExpectedInventoryRevisionFromPreview(record.Preview, revisionID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := fixture.goodput.RecordExpectedInventoryRevision(ctx, revision)
	if err != nil || !recorded {
		t.Fatalf("seed revision: %v recorded=%v", err, recorded)
	}

	// Expire the preview, so the retry would meet the expiry gate first if
	// the repair were ordered after it.
	expirePreview(t, fixture, record.PreviewID)
	expired, found, err := loadPreviewRow(ctx, fixture, record.PreviewID)
	if err != nil || !found {
		t.Fatalf("reload preview: %v found=%v", err, found)
	}
	if !expired.Expired(time.Now().UTC()) {
		t.Fatalf("the preview did not expire: %s", expired.ExpiresAt)
	}

	result, err := fixture.store.ImportExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, record.PreviewID, record.DigestHex, inventoryAudit(adminmanage.EventExpectedInventoryImported))
	if err != nil {
		t.Fatalf("crash repair refused: %v", err)
	}
	if !result.AlreadyImported || result.RevisionID != string(revisionID) {
		t.Fatalf("crash repair result %+v", result)
	}
	// The preview now names the revision that is durable.
	var importedRevision string
	var importedAt *time.Time
	if err := fixture.pool.QueryRow(ctx, `SELECT imported_revision_id,imported_at FROM expected_inventory_previews WHERE preview_id=$1`, record.PreviewID).Scan(&importedRevision, &importedAt); err != nil {
		t.Fatal(err)
	}
	if importedAt == nil || importedRevision != string(revisionID) {
		t.Fatalf("the preview was not marked: revision=%q at=%v", importedRevision, importedAt)
	}
	var revisions int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM goodput_inventory_revisions WHERE cluster_id=$1 AND source_id=$2 AND inventory_class='EXPECTED'`, fixture.clusterID, fixture.sourceID).Scan(&revisions); err != nil {
		t.Fatal(err)
	}
	if revisions != 1 {
		t.Fatalf("the repair recorded a second revision: %d", revisions)
	}
	// Exactly one IMPORTED event: the marking happened once, so it is
	// audited once.
	var events int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM credential_access_test_events WHERE cluster_id=$1 AND event_kind=$2`,
		fixture.clusterID, adminmanage.EventExpectedInventoryImported).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("the repair emitted %d import events", events)
	}
	// A further retry is plain idempotency off the marked row.
	again, err := fixture.store.ImportExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, record.PreviewID, record.DigestHex, inventoryAudit(adminmanage.EventExpectedInventoryImported))
	if err != nil || !again.AlreadyImported || again.RevisionID != string(revisionID) {
		t.Fatalf("second retry: %v %+v", err, again)
	}
}

// TestExpectedInventoryExpiredPreviewIsRefused is the plain expiry case, with
// no revision recorded from it: an operator cannot approve a reconciliation
// of telemetry that is a day old.
func TestExpectedInventoryExpiredPreviewIsRefused(t *testing.T) {
	fixture := newExpectedInventoryFixture(t, pilotListing())
	ctx := context.Background()
	seedPilotTelemetry(t, fixture)

	record, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", excludeLoginNode(), nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed))
	if err != nil {
		t.Fatal(err)
	}
	expirePreview(t, fixture, record.PreviewID)

	if _, err := fixture.store.ImportExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, record.PreviewID, record.DigestHex, inventoryAudit(adminmanage.EventExpectedInventoryImported)); !errors.Is(err, adminmanage.ErrInvalid) {
		t.Fatalf("expired import err=%v, want ErrInvalid", err)
	}
	var revisions int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM goodput_inventory_revisions WHERE cluster_id=$1`, fixture.clusterID).Scan(&revisions); err != nil {
		t.Fatal(err)
	}
	if revisions != 0 {
		t.Fatalf("an expired preview recorded %d revisions", revisions)
	}
	var importedAt *time.Time
	if err := fixture.pool.QueryRow(ctx, `SELECT imported_at FROM expected_inventory_previews WHERE preview_id=$1`, record.PreviewID).Scan(&importedAt); err != nil {
		t.Fatal(err)
	}
	if importedAt != nil {
		t.Fatalf("an expired preview was marked imported at %s", importedAt)
	}
	// No IMPORTED event is recorded for a refusal.
	var events int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM credential_access_test_events WHERE cluster_id=$1 AND event_kind=$2`,
		fixture.clusterID, adminmanage.EventExpectedInventoryImported).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 0 {
		t.Fatalf("a refused import emitted %d import events", events)
	}
}

// loadPreviewRow reads the stored expiry back, so a test can assert on the
// row the store will actually lock rather than on its own fixture value.
func loadPreviewRow(ctx context.Context, fixture expectedInventoryFixture, previewID string) (adminmanage.ExpectedInventoryPreviewRecord, bool, error) {
	var record adminmanage.ExpectedInventoryPreviewRecord
	err := fixture.pool.QueryRow(ctx, `SELECT preview_id,generated_at,expires_at FROM expected_inventory_previews WHERE preview_id=$1`, previewID).
		Scan(&record.PreviewID, &record.GeneratedAt, &record.ExpiresAt)
	if err != nil {
		return adminmanage.ExpectedInventoryPreviewRecord{}, false, err
	}
	return record, true, nil
}

// expirePreview moves the whole row into the past. The schema requires
// expires_at > generated_at, so the expiry cannot be moved back on its own.
func expirePreview(t *testing.T, fixture expectedInventoryFixture, previewID string) {
	t.Helper()
	mustExec(t, fixture.pool, `UPDATE expected_inventory_previews
		SET generated_at=generated_at - interval '48 hours', expires_at=expires_at - interval '48 hours'
		WHERE preview_id=$1`, previewID)
}

// otherDigest returns a digest that is never equal to the one given. Deriving
// the fixture by overwriting a fixed prefix collides whenever the real digest
// already begins with that prefix.
func otherDigest(digest string) string {
	if strings.HasPrefix(digest, "0") {
		return "1" + digest[1:]
	}
	return "0" + digest[1:]
}

// TestExpectedInventoryLoginNodeNeedsAnOperatorDecision is the pilot's first
// real discovery end to end: BCM lists a login node as a PhysicalNode exactly
// as it lists the GPU compute nodes, and nothing in the listing distinguishes
// them. Without an operator decision the preview must refuse; with the
// exclusion it is approvable and records only the GPU nodes.
func TestExpectedInventoryLoginNodeNeedsAnOperatorDecision(t *testing.T) {
	fixture := newExpectedInventoryFixture(t, pilotListing())
	ctx := context.Background()
	seedPilotTelemetry(t, fixture)

	unresolved, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", nil, nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed))
	if err != nil {
		t.Fatal(err)
	}
	if !unresolved.Blocking {
		t.Fatalf("a first-seen node with no GPU evidence did not block: %+v", unresolved.Preview.Discrepancies)
	}
	var unclassified domain.InventoryDiscrepancy
	for _, finding := range unresolved.Preview.Discrepancies {
		if finding.Code == domain.DiscrepancyCategoryUnclassified {
			unclassified = finding
		}
	}
	if !strings.HasSuffix(unclassified.Detail, ": "+pilotLoginCategory) || !unclassified.Blocking {
		t.Fatalf("unclassified category finding: %+v", unclassified)
	}
	// The retained category reached the preview through the store.
	var loginDevice domain.PreviewDevice
	for _, device := range unresolved.Preview.Devices {
		if device.Hostname == pilotLoginNode {
			loginDevice = device
		}
	}
	if loginDevice.Category != pilotLoginCategory || !loginDevice.Managed || loginDevice.Included {
		t.Fatalf("login device: %+v", loginDevice)
	}
	if unresolved.Preview.NodeCount != 10 || unresolved.Preview.GPUCount != 80 {
		t.Fatalf("nodes=%d gpus=%d", unresolved.Preview.NodeCount, unresolved.Preview.GPUCount)
	}
	if _, err := fixture.store.ImportExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, unresolved.PreviewID, unresolved.DigestHex, inventoryAudit(adminmanage.EventExpectedInventoryImported)); !errors.Is(err, adminmanage.ErrInvalid) {
		t.Fatalf("blocking import err=%v", err)
	}

	// A mistyped exclusion is refused rather than silently ignored: it must
	// not leave the operator approving the node they meant to leave out.
	typo, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", []string{"fixture1-zone1-loginnode1"}, nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed))
	if err != nil {
		t.Fatal(err)
	}
	if !typo.Blocking {
		t.Fatalf("a mistyped exclusion did not block: %+v", typo.Preview.Discrepancies)
	}
	var unmatched bool
	for _, finding := range typo.Preview.Discrepancies {
		if finding.Code == domain.DiscrepancyExclusionUnmatched && finding.NodeID == "fixture1-zone1-loginnode1" && finding.Blocking {
			unmatched = true
		}
	}
	if !unmatched {
		t.Fatalf("EXCLUSION_UNMATCHED was not reported: %+v", typo.Preview.Discrepancies)
	}
	if _, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", []string{"fixture1 bom"}, nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed)); !errors.Is(err, adminmanage.ErrInvalid) {
		t.Fatalf("an exclusion with whitespace err=%v", err)
	}
	// The same rule for a mistyped category exclusion.
	categoryTypo, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", nil, []string{"login-defualt-category"}, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed))
	if err != nil {
		t.Fatal(err)
	}
	var categoryUnmatched bool
	for _, finding := range categoryTypo.Preview.Discrepancies {
		if finding.Code == domain.DiscrepancyExclusionUnmatched && finding.Blocking && strings.HasSuffix(finding.Detail, ": login-defualt-category") {
			categoryUnmatched = true
		}
	}
	if !categoryTypo.Blocking || !categoryUnmatched {
		t.Fatalf("a mistyped category exclusion did not block: %+v", categoryTypo.Preview.Discrepancies)
	}
	if _, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", nil, []string{"login default"}, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed)); !errors.Is(err, adminmanage.ErrInvalid) {
		t.Fatalf("a category exclusion with whitespace err=%v", err)
	}

	// Excluding the category is the decision the pilot actually makes: it
	// resolves the same refusal, and the imported revision is the ten GPU
	// nodes and their eighty identities.
	byCategory, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", nil, excludeLoginCategory(), inventoryAudit(adminmanage.EventExpectedInventoryPreviewed))
	if err != nil {
		t.Fatal(err)
	}
	if byCategory.Blocking {
		t.Fatalf("excluding the category left the preview blocking: %+v", byCategory.Preview.Discrepancies)
	}
	if byCategory.Preview.NodeCount != 10 || byCategory.Preview.GPUCount != 80 {
		t.Fatalf("nodes=%d gpus=%d", byCategory.Preview.NodeCount, byCategory.Preview.GPUCount)
	}
	if len(byCategory.Preview.ExcludedCategories) != 1 || byCategory.Preview.ExcludedCategories[0] != pilotLoginCategory {
		t.Fatalf("excluded categories=%+v", byCategory.Preview.ExcludedCategories)
	}
	var excludedByCategory bool
	for _, finding := range byCategory.Preview.Discrepancies {
		if finding.Code == domain.DiscrepancyNodeExcludedByOperator && string(finding.NodeID) == pilotLoginNode &&
			strings.HasSuffix(finding.Detail, ": "+pilotLoginCategory) {
			excludedByCategory = true
		}
	}
	if !excludedByCategory {
		t.Fatalf("the login node was not reported as excluded by category: %+v", byCategory.Preview.Discrepancies)
	}
	// The two decisions are different reconciliations, so they are different
	// approvals: a category exclusion is not the same document as the same
	// nodes named one by one.
	if byCategory.DigestHex == unresolved.DigestHex {
		t.Fatal("the category exclusion did not change the preview digest")
	}

	resolved, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", excludeLoginNode(), nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed))
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Blocking {
		t.Fatalf("the resolved preview blocked: %+v", resolved.Preview.Discrepancies)
	}
	if resolved.Preview.NodeCount != 10 || resolved.Preview.GPUCount != 80 || len(resolved.Preview.Entities) != 90 {
		t.Fatalf("nodes=%d gpus=%d entities=%d", resolved.Preview.NodeCount, resolved.Preview.GPUCount, len(resolved.Preview.Entities))
	}
	if len(resolved.Preview.ExcludedNodes) != 1 || string(resolved.Preview.ExcludedNodes[0]) != pilotLoginNode {
		t.Fatalf("excluded nodes=%+v", resolved.Preview.ExcludedNodes)
	}
	// The exclusion is part of the reconciliation, so it is part of the
	// digest an approval names.
	if resolved.DigestHex == unresolved.DigestHex {
		t.Fatal("the exclusion did not change the preview digest")
	}
	counts := map[domain.InventoryDiscrepancyCode]int{}
	for _, finding := range resolved.Preview.Discrepancies {
		counts[finding.Code]++
	}
	if counts[domain.DiscrepancyNodeExcludedByOperator] != 1 || counts[domain.DiscrepancyNodeUnclassified] != 0 {
		t.Fatalf("exclusion findings: %v", counts)
	}
	if counts[domain.DiscrepancyDeviceHealthWarning] != 11 || counts[domain.DiscrepancyDeviceNotUp] != 0 {
		t.Fatalf("the real pilot statuses were misread: %v", counts)
	}
	for _, entity := range resolved.Preview.Entities {
		if string(entity.NodeID) == pilotLoginNode {
			t.Fatalf("the excluded login node was proposed: %+v", entity)
		}
	}

	imported, err := fixture.store.ImportExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, resolved.PreviewID, resolved.DigestHex, inventoryAudit(adminmanage.EventExpectedInventoryImported))
	if err != nil || imported.AlreadyImported {
		t.Fatalf("import: %v %+v", err, imported)
	}
	projection, found, err := fixture.goodput.GetCurrentInventoryRevision(ctx, domain.ClusterID(fixture.clusterID), domain.SourceID(fixture.sourceID), application.InventoryExpected)
	if err != nil || !found || len(projection.Revision.Entities) != 90 {
		t.Fatalf("recorded revision: %v found=%v %+v", err, found, projection.Revision)
	}
	for _, entity := range projection.Revision.Entities {
		if string(entity.NodeID) == pilotLoginNode {
			t.Fatalf("the excluded login node reached the expected revision: %+v", entity)
		}
	}
}

// TestExpectedInventoryCategoryExclusionImportsThroughTheStore approves the
// category-scoped decision end to end: the login category is excluded once and
// the recorded expected revision is the ten GPU nodes and their eighty
// physical identities, with nothing from the excluded category in it.
func TestExpectedInventoryCategoryExclusionImportsThroughTheStore(t *testing.T) {
	fixture := newExpectedInventoryFixture(t, pilotListing())
	ctx := context.Background()
	seedPilotTelemetry(t, fixture)

	record, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", nil, excludeLoginCategory(), inventoryAudit(adminmanage.EventExpectedInventoryPreviewed))
	if err != nil {
		t.Fatal(err)
	}
	if record.Blocking || record.Preview.NodeCount != 10 || record.Preview.GPUCount != 80 {
		t.Fatalf("preview: blocking=%v nodes=%d gpus=%d %+v", record.Blocking, record.Preview.NodeCount, record.Preview.GPUCount, record.Preview.Discrepancies)
	}
	imported, err := fixture.store.ImportExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, record.PreviewID, record.DigestHex, inventoryAudit(adminmanage.EventExpectedInventoryImported))
	if err != nil || imported.AlreadyImported {
		t.Fatalf("import: %v %+v", err, imported)
	}
	projection, found, err := fixture.goodput.GetCurrentInventoryRevision(ctx, domain.ClusterID(fixture.clusterID), domain.SourceID(fixture.sourceID), application.InventoryExpected)
	if err != nil || !found || len(projection.Revision.Entities) != 90 {
		t.Fatalf("recorded revision: %v found=%v %+v", err, found, projection.Revision)
	}
	for _, entity := range projection.Revision.Entities {
		if string(entity.NodeID) == pilotLoginNode {
			t.Fatalf("a device from the excluded category reached the expected revision: %+v", entity)
		}
	}
	// The stored proposal round-trips with its category decision intact.
	state, err := fixture.store.GetExpectedInventory(ctx, fixture.clusterID, fixture.subject, "")
	if err != nil || state.LatestPreview == nil {
		t.Fatalf("state: %v %+v", err, state)
	}
	if len(state.LatestPreview.Preview.ExcludedCategories) != 1 ||
		state.LatestPreview.Preview.ExcludedCategories[0] != pilotLoginCategory {
		t.Fatalf("excluded categories did not survive storage: %+v", state.LatestPreview.Preview.ExcludedCategories)
	}
	var loginDevice domain.PreviewDevice
	for _, device := range state.LatestPreview.Preview.Devices {
		if device.Hostname == pilotLoginNode {
			loginDevice = device
		}
	}
	if loginDevice.Category != pilotLoginCategory {
		t.Fatalf("the retained category did not survive storage: %+v", loginDevice)
	}
}

// seedV1ShapedPreviewRow inserts one preview row whose content is exactly the
// shape the previous build persisted: schema version 1, no ExcludedNodes or
// ExcludedCategories field at all, and no Category on its one device. This is
// not a corrupted row — it is a row nothing has touched since before 43218bc
// widened the canonical content — so it must never be reported as a digest
// conflict. The stored digest is a valid 32-byte value but is deliberately
// never checked against this content: schema-version 1 content is read
// without digest re-derivation.
func seedV1ShapedPreviewRow(t *testing.T, fixture expectedInventoryFixture, previewID string, generatedAt time.Time) {
	t.Helper()
	content := fmt.Sprintf(`{
		"SchemaVersion": 1,
		"ClusterID": %q,
		"SourceID": %q,
		"GeneratedAt": %q,
		"DiscoveryTestID": %q,
		"DiscoveryCompletedAt": %q,
		"CredentialID": %q,
		"CredentialVersion": 1,
		"BCMVersion": "10.0",
		"Entities": [
			{"Kind":"NODE","ClusterID":%q,"NodeID":"fixture1-zone1-comp001"},
			{"Kind":"GPU","ClusterID":%q,"NodeID":"fixture1-zone1-comp001","PhysicalGPUUUID":"GPU-377d585f-0001-0000"}
		],
		"Devices": [
			{"Type":"PhysicalNode","Hostname":"fixture1-zone1-comp001","Status":"[ UP ]","Managed":true,"ObservedGPUs":1,"Included":true}
		],
		"Discrepancies": [],
		"Removals": [],
		"Additions": 2,
		"Blocking": false,
		"NodeCount": 1,
		"GPUCount": 1
	}`, fixture.clusterID, fixture.sourceID, generatedAt.UTC().Format(time.RFC3339Nano), fixture.testID,
		generatedAt.Add(-time.Hour).UTC().Format(time.RFC3339Nano), fixture.credential.ID, fixture.clusterID, fixture.clusterID)
	digest := sha256.Sum256([]byte(content))
	mustExec(t, fixture.pool, `INSERT INTO expected_inventory_previews
		(preview_id,cluster_id,source_id,discovery_test_id,digest,content,blocking,node_count,gpu_count,generated_by,generated_at,expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,false,1,1,$7,$8,$9)`,
		previewID, fixture.clusterID, fixture.sourceID, fixture.testID, digest[:], content,
		fixture.subject, generatedAt.UTC(), generatedAt.Add(24*time.Hour).UTC())
}

// TestExpectedInventoryV1ShapedPreviewIsSupersededNotConflict is the
// production defect this change fixes: a preview persisted by the previous
// build, before 43218bc widened the canonical content with per-device
// Category and the exclusion lists, must not fail digest re-derivation and
// must not take the rest of the cluster's expected-inventory state down with
// it. The row is reported as superseded, the current revision and discovery
// availability still render, a fresh preview can still be generated, and the
// superseded preview itself can never be imported.
func TestExpectedInventoryV1ShapedPreviewIsSupersededNotConflict(t *testing.T) {
	fixture := newExpectedInventoryFixture(t, pilotListing())
	ctx := context.Background()
	seedPilotTelemetry(t, fixture)

	previewID := "ipv_v1shaped" + fmt.Sprint(time.Now().UnixNano())
	seedV1ShapedPreviewRow(t, fixture, previewID, time.Now().UTC().Add(-time.Minute))

	state, err := fixture.store.GetExpectedInventory(ctx, fixture.clusterID, fixture.subject, "")
	if err != nil {
		t.Fatalf("a v1-shaped preview failed the whole state read: %v", err)
	}
	if state.LatestPreview == nil || !state.LatestPreview.Superseded {
		t.Fatalf("the v1-shaped preview was not reported as superseded: %+v", state.LatestPreview)
	}
	if state.LatestPreview.SupersededReason == "" {
		t.Fatal("a superseded preview carries no reason")
	}
	if !state.DiscoveryAvailable || state.DiscoveryTestID != fixture.testID {
		t.Fatalf("discovery availability did not survive a superseded latest preview: %+v", state)
	}

	// Generating a fresh preview still works, and the new record is current
	// and not superseded.
	fresh, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", excludeLoginNode(), nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed))
	if err != nil {
		t.Fatalf("generate after a superseded latest preview: %v", err)
	}
	if fresh.Superseded {
		t.Fatalf("a freshly generated preview was reported as superseded: %+v", fresh)
	}
	if fresh.Preview.SchemaVersion != domain.ExpectedInventoryPreviewSchemaVersion {
		t.Fatalf("fresh preview schema version %d, want %d", fresh.Preview.SchemaVersion, domain.ExpectedInventoryPreviewSchemaVersion)
	}

	// The superseded preview itself is never importable, whatever digest is
	// submitted for it, and the refusal names the fixed reason rather than
	// treating it as a digest mismatch.
	if _, err := fixture.store.ImportExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, previewID, hex.EncodeToString(make([]byte, 32)), inventoryAudit(adminmanage.EventExpectedInventoryImported)); !errors.Is(err, adminmanage.ErrInvalid) ||
		!strings.Contains(err.Error(), "generated by an earlier format") {
		t.Fatalf("import of a v1-shaped preview err=%v, want ErrInvalid naming the earlier format", err)
	}
}

// TestExpectedInventoryDigestMismatchStaysAConflictForACurrentVersionRecord
// proves the read-back digest re-derivation this change narrows is not
// removed for a current-schema-version row: GetExpectedInventory still must
// not fail its whole read (point 3 of the fix applies to every ErrConflict
// from the latest preview, not only the schema-version case), but it reports
// the record as superseded for the digest-mismatch reason specifically, and
// an approval attempt against that exact record still fails as ErrConflict,
// exactly as before this change. Only a schema-version mismatch skips the
// digest re-derivation itself; a current-version record is always re-hashed.
func TestExpectedInventoryDigestMismatchStaysAConflictForACurrentVersionRecord(t *testing.T) {
	fixture := newExpectedInventoryFixture(t, pilotListing())
	ctx := context.Background()
	seedPilotTelemetry(t, fixture)

	record, err := fixture.store.GenerateExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, "", excludeLoginNode(), nil, inventoryAudit(adminmanage.EventExpectedInventoryPreviewed))
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the stored content without touching its digest column: the
	// content no longer hashes to what was stored alongside it.
	mustExec(t, fixture.pool, `UPDATE expected_inventory_previews SET content = content || '{"BCMVersion":"tampered"}'::jsonb WHERE preview_id=$1`, record.PreviewID)

	state, err := fixture.store.GetExpectedInventory(ctx, fixture.clusterID, fixture.subject, "")
	if err != nil {
		t.Fatalf("a tampered current-version preview failed the whole state read: %v", err)
	}
	if state.LatestPreview == nil || !state.LatestPreview.Superseded || state.LatestPreview.SupersededReason != "stored digest does not match its content" {
		t.Fatalf("the tampered record was not reported with the digest-mismatch reason: %+v", state.LatestPreview)
	}

	if _, err := fixture.store.ImportExpectedInventoryPreview(ctx, fixture.clusterID, fixture.subject, record.PreviewID, record.DigestHex, inventoryAudit(adminmanage.EventExpectedInventoryImported)); !errors.Is(err, adminmanage.ErrConflict) {
		t.Fatalf("import of a tampered current-version preview err=%v, want ErrConflict", err)
	}
}
