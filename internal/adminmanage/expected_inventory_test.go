package adminmanage

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// TestExpectedInventoryContentBoundIsTheFirstFailure proves the Go bound is
// strictly below the schema's 256 KiB CHECK on octet_length(content::text).
// Postgres re-serializes jsonb with a space after every ':' and ',', so the
// text it measures is always larger than the compact encoding measured here;
// a Go bound at the same number would let a preview through that the database
// then refuses, turning an operator-actionable ErrInvalid into a constraint
// violation from the insert.
func TestExpectedInventoryContentBoundIsTheFirstFailure(t *testing.T) {
	if expectedInventoryContentLimit != 192<<10 {
		t.Fatalf("content limit %d is not the documented 192 KiB", expectedInventoryContentLimit)
	}
	if expectedInventoryContentLimit >= 256<<10 {
		t.Fatal("the Go bound is not below the schema CHECK, so the database can fail first")
	}

	// A synthetic preview just under the bound stores cleanly.
	under, err := encodeExpectedInventoryPreview(syntheticPreview(t, 520))
	if err != nil {
		t.Fatalf("a preview within the bound was refused: %v", err)
	}
	if len(under) > expectedInventoryContentLimit {
		t.Fatalf("fixture is not under the bound: %d bytes", len(under))
	}

	// One just over it is refused as ErrInvalid, and the compact encoding the
	// bound measured is still smaller than the jsonb text the CHECK would.
	over := syntheticPreview(t, 620)
	raw, err := json.Marshal(over)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= expectedInventoryContentLimit {
		t.Fatalf("fixture is not over the bound: %d bytes", len(raw))
	}
	if len(raw) >= 256<<10 {
		t.Fatalf("fixture %d bytes is not a near-limit case below the schema CHECK", len(raw))
	}
	if _, err := encodeExpectedInventoryPreview(over); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an oversized preview was not refused as ErrInvalid: %v", err)
	}
}

// syntheticPreview builds a preview whose encoded size grows with the entity
// count. It is not a reconciliation; it exists only to exercise the bound.
func syntheticPreview(t *testing.T, entities int) domain.ExpectedInventoryPreview {
	t.Helper()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	preview := domain.ExpectedInventoryPreview{
		SchemaVersion: domain.ExpectedInventoryPreviewSchemaVersion,
		ClusterID:     "bound-cluster", SourceID: "bound-source", GeneratedAt: now,
		DiscoveryTestID: "ctest_bound", DiscoveryCompletedAt: now.Add(-time.Hour),
		CredentialID: "cred_bound", CredentialVersion: 1, BCMVersion: "10.0",
	}
	for index := 0; index < entities; index++ {
		node := domain.StableNodeID(fmt.Sprintf("fixture1-zone1-compute-node-with-a-long-name-%06d", index))
		preview.Entities = append(preview.Entities, domain.EntityIdentity{
			ClusterID: preview.ClusterID, Kind: domain.EntityGPU, NodeID: node,
			PhysicalGPUUUID: domain.PhysicalGPUUUID(fmt.Sprintf("GPU-377d585f-1f2e-4a3b-9c8d-%012d", index)),
		})
		preview.Devices = append(preview.Devices, domain.PreviewDevice{
			Type: "PhysicalNode", Hostname: string(node), Category: "asus-h100-compute-category",
			Status: "UP", Managed: true, ObservedGPUs: 8, Included: true,
		})
	}
	preview.GPUCount = len(preview.Entities)
	return preview
}

// fakeExpectedInventoryRow implements expectedInventoryRow over fixed values,
// in exactly the column order expectedInventoryPreviewColumns selects, so
// scanExpectedInventoryPreview can be exercised without a database.
type fakeExpectedInventoryRow struct {
	previewID, clusterID, sourceID, digestHex string
	content                                   []byte
	blocking                                  bool
	generatedBy                               string
	generatedAt, expiresAt                    time.Time
	revisionID, importedBy                    *string
	importedAt                                *time.Time
}

func (row fakeExpectedInventoryRow) Scan(destinations ...any) error {
	*destinations[0].(*string) = row.previewID
	*destinations[1].(*string) = row.clusterID
	*destinations[2].(*string) = row.sourceID
	*destinations[3].(*string) = row.digestHex
	*destinations[4].(*[]byte) = row.content
	*destinations[5].(*bool) = row.blocking
	*destinations[6].(*string) = row.generatedBy
	*destinations[7].(*time.Time) = row.generatedAt
	*destinations[8].(*time.Time) = row.expiresAt
	*destinations[9].(**string) = row.revisionID
	*destinations[10].(**string) = row.importedBy
	*destinations[11].(**time.Time) = row.importedAt
	return nil
}

// v1ShapedPreviewContent is exactly the content shape the previous build
// persisted: schema version 1, no ExcludedNodes or ExcludedCategories key at
// all, and no Category key on its one device. It is built from the field
// list a production row actually carried, not by marshaling today's struct,
// because the point of the fixture is that these keys are simply absent.
const v1ShapedPreviewContent = `{
	"SchemaVersion": 1,
	"ClusterID": "fixture1",
	"SourceID": "head-prometheus",
	"GeneratedAt": "2026-09-01T00:00:00Z",
	"DiscoveryTestID": "ctest_v1",
	"DiscoveryCompletedAt": "2026-08-31T23:00:00Z",
	"CredentialID": "cred_v1",
	"CredentialVersion": 1,
	"BCMVersion": "10.0",
	"Entities": [
		{"Kind":"NODE","ClusterID":"fixture1","NodeID":"fixture1-zone1-comp001"},
		{"Kind":"GPU","ClusterID":"fixture1","NodeID":"fixture1-zone1-comp001","PhysicalGPUUUID":"GPU-377d585f-0001-0000"}
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
}`

// TestScanExpectedInventoryPreviewV1ContentIsSupersededNotConflict is the
// unit-level proof of the production defect: a row whose content predates
// the widened canonical shape (43218bc) decodes cleanly, is never re-hashed
// against its stored digest, and comes back Superseded rather than as an
// ErrConflict the caller would have to fail its whole read over.
func TestScanExpectedInventoryPreviewV1ContentIsSupersededNotConflict(t *testing.T) {
	row := fakeExpectedInventoryRow{
		previewID: "ipv_v1", clusterID: "fixture1", sourceID: "head-prometheus",
		// A digest that does not describe this content at all: it must never
		// be compared, since schema-version-1 content skips re-derivation.
		digestHex:   "00000000000000000000000000000000000000000000000000000000000000",
		content:     []byte(v1ShapedPreviewContent),
		blocking:    false,
		generatedBy: "operator", generatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		expiresAt: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC),
	}
	record, err := scanExpectedInventoryPreview(row)
	if err != nil {
		t.Fatalf("a v1-shaped preview failed to scan: %v", err)
	}
	if !record.Superseded {
		t.Fatal("a v1-shaped preview was not reported as superseded")
	}
	if record.SupersededReason != supersededPreviewReason {
		t.Fatalf("superseded reason = %q, want %q", record.SupersededReason, supersededPreviewReason)
	}
	if record.Preview.SchemaVersion != 1 {
		t.Fatalf("decoded schema version = %d, want 1", record.Preview.SchemaVersion)
	}
	if record.PreviewID != "ipv_v1" || record.ClusterID != "fixture1" {
		t.Fatalf("row identity did not survive: %+v", record)
	}
	if len(record.Preview.Entities) != 2 || record.Preview.NodeCount != 1 || record.Preview.GPUCount != 1 {
		t.Fatalf("decoded content: %+v", record.Preview)
	}
	if record.Preview.ExcludedNodes != nil || record.Preview.ExcludedCategories != nil {
		t.Fatalf("v1 content should decode with no exclusions at all: %+v", record.Preview)
	}
}

// TestScanExpectedInventoryPreviewCurrentVersionDigestMismatchIsAConflict
// proves the narrower re-derivation this change makes is still applied to a
// current-schema-version row: a content that does not hash to its stored
// digest is still refused as ErrConflict, exactly as before.
func TestScanExpectedInventoryPreviewCurrentVersionDigestMismatchIsAConflict(t *testing.T) {
	preview := domain.ExpectedInventoryPreview{
		SchemaVersion: domain.ExpectedInventoryPreviewSchemaVersion,
		ClusterID:     "fixture1", SourceID: "head-prometheus",
		GeneratedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), DiscoveryTestID: "ctest_v2",
		DiscoveryCompletedAt: time.Date(2026, 8, 31, 23, 0, 0, 0, time.UTC),
		CredentialID:         "cred_v2", CredentialVersion: 1, BCMVersion: "10.0",
	}
	content, err := json.Marshal(preview)
	if err != nil {
		t.Fatal(err)
	}
	row := fakeExpectedInventoryRow{
		previewID: "ipv_v2", clusterID: "fixture1", sourceID: "head-prometheus",
		// Any digest works here as long as it does not describe the content:
		// a current-version record is always re-hashed and compared.
		digestHex:   "00000000000000000000000000000000000000000000000000000000000000",
		content:     content,
		generatedBy: "operator", generatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		expiresAt: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC),
	}
	_, err = scanExpectedInventoryPreview(row)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("a tampered current-version preview err=%v, want ErrConflict", err)
	}
}
