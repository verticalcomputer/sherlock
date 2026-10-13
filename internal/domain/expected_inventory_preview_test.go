package domain_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	previewCluster = domain.ClusterID("pilot-cluster")
	previewSource  = domain.SourceID("head-prometheus")
)

var previewNow = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

// The pilot listing as BCM reported it: ten GPU compute nodes, one login
// node with no GPU telemetry at all, and the head node. Every device carries
// a bracketed state token, which is the only part of the status that says
// whether the device is up.
var pilotComputeNodes = []int{1, 2, 3, 4, 5, 6, 7, 8, 10, 11}

const pilotLoginNode = domain.StableNodeID("fixture1-zone1-loginnode")

// The two categories the head reports for the pilot. The head node itself
// carries none, which is the empty-category case.
const (
	pilotComputeCategory = "asus-h100-compute-category"
	pilotLoginCategory   = "login-default-category"
)

func pilotDevices() []domain.CredentialAccessDevice {
	devices := make([]domain.CredentialAccessDevice, 0, 12)
	devices = append(devices, domain.CredentialAccessDevice{Type: "HeadNode", Hostname: "fixture1-zone1-headnode", Status: "[ UP ]"})
	for _, index := range pilotComputeNodes {
		devices = append(devices, domain.CredentialAccessDevice{
			Type: "PhysicalNode", Hostname: fmt.Sprintf("fixture1-zone1-comp%03d", index),
			Category: pilotComputeCategory, Status: "[ UP ]",
		})
	}
	devices = append(devices, domain.CredentialAccessDevice{
		Type: "PhysicalNode", Hostname: string(pilotLoginNode), Category: pilotLoginCategory, Status: "[ UP ]",
	})
	return devices
}

func pilotObservedNodes() []domain.ObservedNodeTarget {
	nodes := make([]domain.ObservedNodeTarget, 0, len(pilotComputeNodes))
	for _, index := range pilotComputeNodes {
		nodes = append(nodes, domain.ObservedNodeTarget{
			NodeID:         domain.StableNodeID(fmt.Sprintf("fixture1-zone1-comp%03d", index)),
			LastObservedAt: previewNow.Add(-30 * time.Second),
		})
	}
	return nodes
}

func pilotObservedGPUs() []domain.ObservedGPUTarget {
	gpus := make([]domain.ObservedGPUTarget, 0, 80)
	for _, index := range pilotComputeNodes {
		for slot := 0; slot < 8; slot++ {
			gpus = append(gpus, domain.ObservedGPUTarget{
				NodeID:         domain.StableNodeID(fmt.Sprintf("fixture1-zone1-comp%03d", index)),
				UUID:           domain.PhysicalGPUUUID(fmt.Sprintf("GPU-377d585f-%04d-%04d", index, slot)),
				LastObservedAt: previewNow.Add(-30 * time.Second),
			})
		}
	}
	return gpus
}

// pilotListingInput is the reconciliation with no operator decision applied:
// the login node is a first-seen PhysicalNode with no GPU evidence, so the
// preview blocks until the operator says what it is.
func pilotListingInput() domain.ExpectedInventoryPreviewInput {
	return domain.ExpectedInventoryPreviewInput{
		ClusterID: previewCluster, SourceID: previewSource,
		Discovery: domain.InventoryDiscoveryEvidence{
			TestID: "ctest_pilot", CredentialID: "cred_pilot", CredentialVersion: 1, CredentialCurrent: true,
			Host: "fixture1-zone1-headnode", BCMVersion: "10.0", CompletedAt: previewNow.Add(-time.Hour),
			Devices: pilotDevices(),
		},
		ObservedNodes: pilotObservedNodes(), ObservedGPUs: pilotObservedGPUs(), GeneratedAt: previewNow,
	}
}

// pilotInput is the resolved pilot: the operator has excluded the login node,
// which is the decision that makes the reconciliation approvable.
func pilotInput() domain.ExpectedInventoryPreviewInput {
	in := pilotListingInput()
	in.ExcludeNodes = []domain.StableNodeID{pilotLoginNode}
	return in
}

func codes(preview domain.ExpectedInventoryPreview) map[domain.InventoryDiscrepancyCode]int {
	counts := map[domain.InventoryDiscrepancyCode]int{}
	for _, finding := range preview.Discrepancies {
		counts[finding.Code]++
	}
	return counts
}

func mustBuild(t *testing.T, in domain.ExpectedInventoryPreviewInput) domain.ExpectedInventoryPreview {
	t.Helper()
	preview, err := domain.BuildExpectedInventoryPreview(in)
	if err != nil {
		t.Fatalf("build preview: %v", err)
	}
	return preview
}

func TestBuildExpectedInventoryPreviewReconcilesPilotShape(t *testing.T) {
	preview := mustBuild(t, pilotInput())
	if preview.SchemaVersion != domain.ExpectedInventoryPreviewSchemaVersion {
		t.Fatalf("schema version %d", preview.SchemaVersion)
	}
	if preview.NodeCount != 10 || preview.GPUCount != 80 || len(preview.Entities) != 90 {
		t.Fatalf("nodes=%d gpus=%d entities=%d", preview.NodeCount, preview.GPUCount, len(preview.Entities))
	}
	if preview.Blocking {
		t.Fatalf("the resolved pilot shape must not block: %+v", preview.Discrepancies)
	}
	if preview.Additions != 90 || len(preview.Removals) != 0 {
		t.Fatalf("additions=%d removals=%d", preview.Additions, len(preview.Removals))
	}
	counts := codes(preview)
	if counts[domain.DiscrepancyUnmanagedDevice] != 1 {
		t.Fatalf("expected the head node to be reported as unmanaged: %v", counts)
	}
	// Every device reported "[ UP ]" with no trailing text, so neither status
	// code appears at all.
	if counts[domain.DiscrepancyDeviceNotUp] != 0 || counts[domain.DiscrepancyDeviceHealthWarning] != 0 {
		t.Fatalf("an unqualified [ UP ] raised a status finding: %v", counts)
	}
	if counts[domain.DiscrepancyNodeMissingTelemetry] != 0 || counts[domain.DiscrepancyNodeUnclassified] != 0 {
		t.Fatalf("the excluded login node was also reported as a telemetry finding: %v", counts)
	}
	// The login node is excluded once as a node; it has no observed GPU, so
	// no identity is named alongside it.
	if counts[domain.DiscrepancyNodeExcludedByOperator] != 1 {
		t.Fatalf("operator exclusion not reported once: %v", counts)
	}
	for _, finding := range preview.Discrepancies {
		if finding.Code == domain.DiscrepancyNodeExcludedByOperator && finding.NodeID != pilotLoginNode {
			t.Fatalf("exclusion reported for %q", finding.NodeID)
		}
		if finding.Detail == "" {
			t.Fatalf("discrepancy %q has no fixed detail", finding.Code)
		}
	}
	if len(preview.ExcludedNodes) != 1 || preview.ExcludedNodes[0] != pilotLoginNode {
		t.Fatalf("excluded nodes=%+v", preview.ExcludedNodes)
	}
	for _, entity := range preview.Entities {
		if entity.NodeID == pilotLoginNode {
			t.Fatalf("an excluded node produced an entity: %+v", entity)
		}
	}
	for index := 1; index < len(preview.Entities); index++ {
		previous, current := preview.Entities[index-1], preview.Entities[index]
		if previous.Key() >= current.Key() && previous.NodeID > current.NodeID {
			t.Fatalf("entities are not deterministically ordered at %d", index)
		}
	}
	if len(preview.Devices) != 12 {
		t.Fatalf("devices=%d", len(preview.Devices))
	}
	for _, device := range preview.Devices {
		switch {
		case device.Type == "HeadNode":
			if device.Managed || device.Included || device.ObservedGPUs != 0 {
				t.Fatalf("head node classified as managed: %+v", device)
			}
		case device.Hostname == string(pilotLoginNode):
			// The excluded node stays a listed, managed device: it is shown
			// and not proposed, which is not the same as not existing.
			if !device.Managed || device.Included || device.ObservedGPUs != 0 {
				t.Fatalf("excluded login node: %+v", device)
			}
		default:
			if !device.Managed || !device.Included || device.ObservedGPUs != 8 {
				t.Fatalf("compute node: %+v", device)
			}
		}
	}
}

// TestBuildExpectedInventoryPreviewBlocksAnUnclassifiedCategory: BCM types the
// login node PhysicalNode exactly as it types a GPU compute node, but it does
// put the two in different categories. With no GPU evidence anywhere in the
// login category and no member in the current expected revision, promoting
// that category into the denominator would be a guess, so the preview refuses
// until an operator decides — once, about the category.
func TestBuildExpectedInventoryPreviewBlocksAnUnclassifiedCategory(t *testing.T) {
	preview := mustBuild(t, pilotListingInput())
	if !preview.Blocking {
		t.Fatalf("a category with no GPU evidence did not block: %+v", preview.Discrepancies)
	}
	counts := codes(preview)
	if counts[domain.DiscrepancyCategoryUnclassified] != 1 || counts[domain.DiscrepancyNodeUnclassified] != 0 ||
		counts[domain.DiscrepancyNodeMissingTelemetry] != 0 {
		t.Fatalf("unclassified category reported wrongly: %v", counts)
	}
	finding, found := findFindingByCode(preview, domain.DiscrepancyCategoryUnclassified)
	if !found || !finding.Blocking || !strings.HasSuffix(finding.Detail, ": "+pilotLoginCategory) {
		t.Fatalf("unclassified category finding: %+v", finding)
	}
	// The finding is about the category, so it names no node: an operator
	// excludes the grouping, not each of its members.
	if finding.NodeID != "" {
		t.Fatalf("a category finding named a node: %+v", finding)
	}
	if preview.NodeCount != 10 || preview.GPUCount != 80 {
		t.Fatalf("nodes=%d gpus=%d", preview.NodeCount, preview.GPUCount)
	}
	for _, entity := range preview.Entities {
		if entity.NodeID == pilotLoginNode {
			t.Fatal("an unclassified node was proposed as an entity")
		}
	}
	// It is still listed as a managed device: the operator has to see the
	// node they are being asked about.
	var listed bool
	for _, device := range preview.Devices {
		if device.Hostname == string(pilotLoginNode) {
			listed = true
			if !device.Managed || device.Included {
				t.Fatalf("unclassified device: %+v", device)
			}
		}
	}
	if !listed {
		t.Fatal("the unclassified node was dropped from the device listing")
	}
}

func findFindingByCode(preview domain.ExpectedInventoryPreview, code domain.InventoryDiscrepancyCode) (domain.InventoryDiscrepancy, bool) {
	for _, finding := range preview.Discrepancies {
		if finding.Code == code {
			return finding, true
		}
	}
	return domain.InventoryDiscrepancy{}, false
}

// TestBuildExpectedInventoryPreviewExcludesACategory is the pilot's actual
// resolution: one decision about "the login category" drops every device in
// it and clears the refusal, and the compute category is proposed whole.
func TestBuildExpectedInventoryPreviewExcludesACategory(t *testing.T) {
	in := pilotListingInput()
	in.ExcludeCategories = []string{pilotLoginCategory}
	preview := mustBuild(t, in)

	if preview.Blocking {
		t.Fatalf("excluding the category left the preview blocking: %+v", preview.Discrepancies)
	}
	if preview.NodeCount != 10 || preview.GPUCount != 80 {
		t.Fatalf("nodes=%d gpus=%d", preview.NodeCount, preview.GPUCount)
	}
	counts := codes(preview)
	if counts[domain.DiscrepancyCategoryUnclassified] != 0 {
		t.Fatalf("an excluded category was still reported as unclassified: %v", counts)
	}
	finding, found := findNodeFinding(preview, domain.DiscrepancyNodeExcludedByOperator, pilotLoginNode)
	if !found || finding.Blocking || !strings.HasSuffix(finding.Detail, ": "+pilotLoginCategory) {
		t.Fatalf("category exclusion finding: %+v", finding)
	}
	for _, entity := range preview.Entities {
		if entity.NodeID == pilotLoginNode {
			t.Fatal("a device in an excluded category was proposed")
		}
	}
	for _, device := range preview.Devices {
		if device.Hostname == string(pilotLoginNode) && (!device.Managed || device.Included || device.Category != pilotLoginCategory) {
			t.Fatalf("excluded device: %+v", device)
		}
	}
	if len(preview.ExcludedCategories) != 1 || preview.ExcludedCategories[0] != pilotLoginCategory {
		t.Fatalf("excluded categories %v", preview.ExcludedCategories)
	}
}

// TestBuildExpectedInventoryPreviewProposesAFirstSeenNodeInAComputeCategory is
// the first-seen-member rule the category restores: comp009 is racked into the
// known GPU category and has not reported a single DCGM row yet. It is
// proposed with its GPUs explicitly unknown, and that is not blocking: the
// category is evidence about the node, and a missing member is exactly what an
// operator needs to see rather than have silently dropped.
func TestBuildExpectedInventoryPreviewProposesAFirstSeenNodeInAComputeCategory(t *testing.T) {
	in := pilotListingInput()
	in.ExcludeCategories = []string{pilotLoginCategory}
	const firstSeen = domain.StableNodeID("fixture1-zone1-comp009")
	in.Discovery.Devices = append(in.Discovery.Devices, domain.CredentialAccessDevice{
		Type: "PhysicalNode", Hostname: string(firstSeen), Category: pilotComputeCategory, Status: "[ UP ]",
	})
	preview := mustBuild(t, in)

	if preview.Blocking {
		t.Fatalf("a first-seen node in a known GPU category blocked: %+v", preview.Discrepancies)
	}
	if preview.NodeCount != 11 || preview.GPUCount != 80 {
		t.Fatalf("nodes=%d gpus=%d", preview.NodeCount, preview.GPUCount)
	}
	finding, found := findNodeFinding(preview, domain.DiscrepancyNodeMissingTelemetry, firstSeen)
	if !found || finding.Blocking {
		t.Fatalf("missing-telemetry finding: %+v (found=%v)", finding, found)
	}
	var proposed bool
	for _, entity := range preview.Entities {
		if entity.NodeID == firstSeen {
			if entity.Kind != domain.EntityNode {
				t.Fatalf("a node with no telemetry contributed a GPU identity: %+v", entity)
			}
			proposed = true
		}
	}
	if !proposed {
		t.Fatal("the first-seen node was not proposed")
	}
	// A device with no category at all keeps the per-node refusal: there is
	// no grouping to classify it by.
	uncategorized := pilotListingInput()
	uncategorized.ExcludeCategories = []string{pilotLoginCategory}
	uncategorized.Discovery.Devices = append(uncategorized.Discovery.Devices, domain.CredentialAccessDevice{
		Type: "PhysicalNode", Hostname: "fixture1-zone1-spare001", Status: "[ UP ]",
	})
	bare := mustBuild(t, uncategorized)
	if !bare.Blocking {
		t.Fatalf("an uncategorized first-seen device did not block: %+v", bare.Discrepancies)
	}
	if _, found := findNodeFinding(bare, domain.DiscrepancyNodeUnclassified, "fixture1-zone1-spare001"); !found {
		t.Fatalf("the uncategorized device was not reported per node: %+v", bare.Discrepancies)
	}
}

// TestBuildExpectedInventoryPreviewReportsInstallerFailedButStillProposes is
// comp004 as the head actually reported it. An INSTALLER_FAILED state token is
// informative: BCM's own state is not a telemetry fact, and the node's eight
// GPU identities are observed regardless, so it stays proposed.
func TestBuildExpectedInventoryPreviewReportsInstallerFailedButStillProposes(t *testing.T) {
	in := pilotInput()
	const failed = domain.StableNodeID("fixture1-zone1-comp004")
	for index := range in.Discovery.Devices {
		if in.Discovery.Devices[index].Hostname == string(failed) {
			in.Discovery.Devices[index].Status = "[ INSTALLER_FAILED ] (This n…)"
		}
	}
	preview := mustBuild(t, in)

	if preview.Blocking {
		t.Fatalf("an INSTALLER_FAILED state token blocked the import: %+v", preview.Discrepancies)
	}
	finding, found := findNodeFinding(preview, domain.DiscrepancyDeviceNotUp, failed)
	if !found || finding.Blocking {
		t.Fatalf("not-up finding: %+v (found=%v)", finding, found)
	}
	if preview.NodeCount != 10 || preview.GPUCount != 80 {
		t.Fatalf("nodes=%d gpus=%d", preview.NodeCount, preview.GPUCount)
	}
	var proposed int
	for _, entity := range preview.Entities {
		if entity.NodeID == failed {
			proposed++
		}
	}
	if proposed != 9 {
		t.Fatalf("the node and its eight GPUs were not proposed: %d entities", proposed)
	}
}

// TestBuildExpectedInventoryPreviewBlocksAnUnmatchedCategoryExclusion: a
// mistyped category that was silently ignored would leave the operator
// approving exactly the devices they meant to leave out.
func TestBuildExpectedInventoryPreviewBlocksAnUnmatchedCategoryExclusion(t *testing.T) {
	in := pilotListingInput()
	in.ExcludeCategories = []string{pilotLoginCategory, "login-defualt-category"}
	preview := mustBuild(t, in)

	if !preview.Blocking {
		t.Fatalf("a category exclusion that matched nothing did not block: %+v", preview.Discrepancies)
	}
	var unmatched int
	for _, finding := range preview.Discrepancies {
		if finding.Code == domain.DiscrepancyExclusionUnmatched {
			unmatched++
			if !finding.Blocking || !strings.HasSuffix(finding.Detail, ": login-defualt-category") {
				t.Fatalf("unmatched exclusion finding: %+v", finding)
			}
		}
	}
	if unmatched != 1 {
		t.Fatalf("unmatched exclusions reported: %d", unmatched)
	}
}

// TestNormalizeExcludedCategoriesIsTotal: the list is part of the digest, so
// order and duplication must not change the reconciliation, and a value that
// could not be a category name is refused rather than ignored.
func TestNormalizeExcludedCategoriesIsTotal(t *testing.T) {
	first := pilotListingInput()
	first.ExcludeCategories = []string{pilotLoginCategory, pilotComputeCategory}
	second := pilotListingInput()
	second.ExcludeCategories = []string{pilotComputeCategory, pilotLoginCategory, pilotLoginCategory}
	firstDigest, err := domain.ExpectedInventoryPreviewDigest(mustBuild(t, first))
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := domain.ExpectedInventoryPreviewDigest(mustBuild(t, second))
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatal("reordering or repeating the category exclusions changed the preview")
	}
	for name, categories := range map[string][]string{
		"empty":      {""},
		"whitespace": {"login default"},
		"oversized":  {strings.Repeat("c", 129)},
		"too many":   make([]string, domain.ExpectedInventoryMaxExcludedCategories+1),
	} {
		bad := pilotListingInput()
		bad.ExcludeCategories = categories
		if _, err := domain.BuildExpectedInventoryPreview(bad); err == nil {
			t.Fatalf("%s category exclusion was accepted", name)
		}
	}
}

// TestBuildExpectedInventoryPreviewPreservesAnExpectedSilentNode is the other
// half of the same rule: a node that is already an expected member and has
// gone silent is preserved, because losing a member is a different decision
// from promoting a stranger.
func TestBuildExpectedInventoryPreviewPreservesAnExpectedSilentNode(t *testing.T) {
	in := pilotListingInput()
	current, err := domain.CreateInventoryRevision(domain.InventoryRevision{
		SchemaVersion: domain.InventoryContractSchemaVersion, ID: "exp_previous",
		ClusterID: previewCluster, SourceID: previewSource,
		SourceAt: previewNow.Add(-4 * time.Hour), EffectiveAt: previewNow.Add(-4 * time.Hour), ObservedAt: previewNow.Add(-4 * time.Hour),
		Entities: []domain.EntityIdentity{{ClusterID: previewCluster, Kind: domain.EntityNode, NodeID: pilotLoginNode}},
	})
	if err != nil {
		t.Fatal(err)
	}
	in.Current = &current
	preview := mustBuild(t, in)

	counts := codes(preview)
	if counts[domain.DiscrepancyNodeMissingTelemetry] != 1 || counts[domain.DiscrepancyNodeUnclassified] != 0 {
		t.Fatalf("an expected silent node was not preserved: %v", counts)
	}
	finding, found := findNodeFinding(preview, domain.DiscrepancyNodeMissingTelemetry, pilotLoginNode)
	if !found || finding.Blocking {
		t.Fatalf("preserving an expected member must not block: %+v", finding)
	}
	if preview.Blocking {
		t.Fatalf("preview blocked: %+v", preview.Discrepancies)
	}
	var nodeSeen, gpuSeen bool
	for _, entity := range preview.Entities {
		if entity.NodeID != pilotLoginNode {
			continue
		}
		nodeSeen = nodeSeen || entity.Kind == domain.EntityNode
		gpuSeen = gpuSeen || entity.Kind == domain.EntityGPU
	}
	if !nodeSeen || gpuSeen {
		t.Fatalf("preserved node=%v gpu=%v", nodeSeen, gpuSeen)
	}
	if preview.NodeCount != 11 || preview.GPUCount != 80 {
		t.Fatalf("nodes=%d gpus=%d", preview.NodeCount, preview.GPUCount)
	}
}

// TestBuildExpectedInventoryPreviewParsesTheBracketedStateToken: BCM reports
// a state token in brackets followed by optional health text. Comparing the
// whole status string to "UP" reported every device in the pilot as not up,
// which is exactly the noise that hides a device that really is down.
func TestBuildExpectedInventoryPreviewParsesTheBracketedStateToken(t *testing.T) {
	cases := []struct {
		name   string
		status string
		notUp  bool
		health bool
	}{
		{"plain up", "[ UP ]", false, false},
		{"up with failed health check", "[ UP ], health check failed", false, true},
		{"up with health check and restart", "[ UP ], health check failed, restart required (initialize, interface:ipmi0)", false, true},
		{"up with restart required", "[ UP ], restart required (interface:ipmi0)", false, true},
		{"spaced down", "[ DOWN ]", true, false},
		{"tight down", "[DOWN]", true, false},
		{"empty", "", true, false},
		{"garbage", "not a status at all", true, false},
		{"empty bracket", "[]", true, false},
		{"unterminated bracket", "[ UP", true, false},
		{"installing with text", "[ INSTALLING ], restart required", true, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			in := pilotInput()
			in.Discovery.Devices[1].Status = testCase.status
			preview := mustBuild(t, in)
			node := domain.StableNodeID(in.Discovery.Devices[1].Hostname)
			_, notUp := findNodeFinding(preview, domain.DiscrepancyDeviceNotUp, node)
			health, healthFound := findNodeFinding(preview, domain.DiscrepancyDeviceHealthWarning, node)
			if notUp != testCase.notUp {
				t.Fatalf("DEVICE_NOT_UP=%v want %v for %q", notUp, testCase.notUp, testCase.status)
			}
			if healthFound != testCase.health {
				t.Fatalf("DEVICE_HEALTH_WARNING=%v want %v for %q", healthFound, testCase.health, testCase.status)
			}
			// Neither code is blocking, and the health detail never echoes
			// the free text: the status column already shows it verbatim.
			if healthFound {
				if health.Blocking || strings.Contains(health.Detail, "ipmi0") || strings.Contains(health.Detail, "health check failed") {
					t.Fatalf("health finding leaked host text or blocked: %+v", health)
				}
			}
			if preview.Blocking {
				t.Fatalf("a status token blocked the import: %+v", preview.Discrepancies)
			}
			// A device that is not up is still proposed: BCM status is not a
			// telemetry fact.
			if preview.NodeCount != 10 {
				t.Fatalf("nodes=%d", preview.NodeCount)
			}
		})
	}
}

// TestBuildExpectedInventoryPreviewAppliesOperatorExclusions covers the two
// halves of an exclusion: a matched hostname is excluded with its GPUs, and
// an unmatched one is a blocking typo.
func TestBuildExpectedInventoryPreviewAppliesOperatorExclusions(t *testing.T) {
	t.Run("matched node with GPUs", func(t *testing.T) {
		in := pilotInput()
		in.ExcludeNodes = append(in.ExcludeNodes, "fixture1-zone1-comp003")
		preview := mustBuild(t, in)
		if preview.Blocking {
			t.Fatalf("an exclusion blocked the import: %+v", preview.Discrepancies)
		}
		if preview.NodeCount != 9 || preview.GPUCount != 72 {
			t.Fatalf("nodes=%d gpus=%d", preview.NodeCount, preview.GPUCount)
		}
		for _, entity := range preview.Entities {
			if entity.NodeID == "fixture1-zone1-comp003" {
				t.Fatalf("an excluded node kept an entity: %+v", entity)
			}
		}
		// The node and each of its eight identities are named, so an
		// exclusion can never read as a node that simply has no GPU.
		named := 0
		for _, finding := range preview.Discrepancies {
			if finding.Code == domain.DiscrepancyNodeExcludedByOperator && finding.NodeID == "fixture1-zone1-comp003" {
				named++
				if finding.Blocking {
					t.Fatalf("an exclusion was blocking: %+v", finding)
				}
			}
		}
		if named != 9 {
			t.Fatalf("exclusion findings for comp003=%d", named)
		}
		for _, device := range preview.Devices {
			if device.Hostname == "fixture1-zone1-comp003" && (!device.Managed || device.Included || device.ObservedGPUs != 8) {
				t.Fatalf("excluded device: %+v", device)
			}
		}
	})
	t.Run("unmatched exclusion blocks", func(t *testing.T) {
		in := pilotInput()
		in.ExcludeNodes = append(in.ExcludeNodes, "fixture1-zone1-cmop003")
		preview := mustBuild(t, in)
		if !preview.Blocking {
			t.Fatal("a mistyped exclusion was silently ignored")
		}
		finding, found := findNodeFinding(preview, domain.DiscrepancyExclusionUnmatched, "fixture1-zone1-cmop003")
		if !found || !finding.Blocking {
			t.Fatalf("unmatched exclusion: %+v", finding)
		}
		if preview.NodeCount != 10 {
			t.Fatalf("a typo changed the proposal: nodes=%d", preview.NodeCount)
		}
	})
	t.Run("an excluded expected member is an ordinary removal", func(t *testing.T) {
		in := pilotInput()
		in.ExcludeNodes = append(in.ExcludeNodes, "fixture1-zone1-comp003")
		current, err := domain.CreateInventoryRevision(domain.InventoryRevision{
			SchemaVersion: domain.InventoryContractSchemaVersion, ID: "exp_previous",
			ClusterID: previewCluster, SourceID: previewSource,
			SourceAt: previewNow.Add(-4 * time.Hour), EffectiveAt: previewNow.Add(-4 * time.Hour), ObservedAt: previewNow.Add(-4 * time.Hour),
			Entities: []domain.EntityIdentity{{ClusterID: previewCluster, Kind: domain.EntityNode, NodeID: "fixture1-zone1-comp003"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		in.Current = &current
		preview := mustBuild(t, in)
		if len(preview.Removals) != 1 || preview.Removals[0].NodeID != "fixture1-zone1-comp003" {
			t.Fatalf("removals=%+v", preview.Removals)
		}
		// comp003 reports fresh telemetry, so retiring it deliberately is an
		// informative proposal and not a refusal.
		if preview.Blocking {
			t.Fatalf("a deliberate retirement blocked: %+v", preview.Discrepancies)
		}
	})
	t.Run("normalization and bounds", func(t *testing.T) {
		in := pilotInput()
		in.ExcludeNodes = []domain.StableNodeID{"fixture1-zone1-comp003", pilotLoginNode, "fixture1-zone1-comp003"}
		preview := mustBuild(t, in)
		if len(preview.ExcludedNodes) != 2 || preview.ExcludedNodes[0] != "fixture1-zone1-comp003" || preview.ExcludedNodes[1] != pilotLoginNode {
			t.Fatalf("excluded nodes=%+v", preview.ExcludedNodes)
		}
		for _, invalid := range []domain.StableNodeID{"", "fixture1 bom", "fixture1\tbom", "fixture1\nbom", domain.StableNodeID(strings.Repeat("n", 129))} {
			bad := pilotInput()
			bad.ExcludeNodes = []domain.StableNodeID{invalid}
			if _, err := domain.BuildExpectedInventoryPreview(bad); err == nil {
				t.Fatalf("an invalid exclusion %q was accepted", invalid)
			}
		}
		tooMany := pilotInput()
		tooMany.ExcludeNodes = make([]domain.StableNodeID, domain.ExpectedInventoryMaxExcludedNodes+1)
		for index := range tooMany.ExcludeNodes {
			tooMany.ExcludeNodes[index] = domain.StableNodeID(fmt.Sprintf("node%04d", index))
		}
		if _, err := domain.BuildExpectedInventoryPreview(tooMany); err == nil {
			t.Fatal("an oversized exclusion list was accepted")
		}
	})
}

func TestBuildExpectedInventoryPreviewDiscrepancyTable(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*domain.ExpectedInventoryPreviewInput)
		code     domain.InventoryDiscrepancyCode
		blocking bool
		assert   func(*testing.T, domain.ExpectedInventoryPreview)
	}{
		{
			name: "duplicate uuid",
			mutate: func(in *domain.ExpectedInventoryPreviewInput) {
				in.ObservedGPUs = append(in.ObservedGPUs, domain.ObservedGPUTarget{
					NodeID: "fixture1-zone1-comp002", UUID: "GPU-377d585f-0001-0000", LastObservedAt: previewNow,
				})
			},
			code: domain.DiscrepancyDuplicateGPU, blocking: true,
			assert: func(t *testing.T, preview domain.ExpectedInventoryPreview) {
				for _, entity := range preview.Entities {
					if entity.PhysicalGPUUUID == "GPU-377d585f-0001-0000" {
						t.Fatal("a duplicated UUID was still proposed as an entity")
					}
				}
			},
		},
		{
			name: "foreign node telemetry",
			mutate: func(in *domain.ExpectedInventoryPreviewInput) {
				in.ObservedNodes = append(in.ObservedNodes, domain.ObservedNodeTarget{NodeID: "other-site-node01", LastObservedAt: previewNow})
				in.ObservedGPUs = append(in.ObservedGPUs, domain.ObservedGPUTarget{NodeID: "other-site-node01", UUID: "GPU-foreign-0001", LastObservedAt: previewNow})
			},
			code: domain.DiscrepancyForeignNodeTelemetry, blocking: false,
			assert: func(t *testing.T, preview domain.ExpectedInventoryPreview) {
				for _, entity := range preview.Entities {
					if entity.NodeID == "other-site-node01" {
						t.Fatal("a foreign node produced an entity")
					}
				}
			},
		},
		{
			name: "hostname case mismatch",
			mutate: func(in *domain.ExpectedInventoryPreviewInput) {
				in.ObservedNodes = append(in.ObservedNodes, domain.ObservedNodeTarget{NodeID: "fixture1-zone1-COMP001", LastObservedAt: previewNow})
				in.ObservedGPUs = append(in.ObservedGPUs, domain.ObservedGPUTarget{NodeID: "fixture1-zone1-COMP001", UUID: "GPU-377d585f-0001-0099", LastObservedAt: previewNow})
			},
			code: domain.DiscrepancyHostnameMismatch, blocking: true,
			assert: func(t *testing.T, preview domain.ExpectedInventoryPreview) {
				for _, entity := range preview.Entities {
					if entity.NodeID == "fixture1-zone1-COMP001" {
						t.Fatal("a case-insensitive near match was adopted as an alias")
					}
				}
			},
		},
		{
			name: "fqdn mismatch",
			mutate: func(in *domain.ExpectedInventoryPreviewInput) {
				in.ObservedNodes = append(in.ObservedNodes, domain.ObservedNodeTarget{NodeID: "fixture1-zone1-comp001.example.test", LastObservedAt: previewNow})
			},
			code: domain.DiscrepancyHostnameMismatch, blocking: true,
		},
		{
			name: "stale discovery",
			mutate: func(in *domain.ExpectedInventoryPreviewInput) {
				in.Discovery.CompletedAt = previewNow.Add(-48 * time.Hour)
			},
			code: domain.DiscrepancyDiscoveryStale, blocking: true,
		},
		{
			name: "stale credential",
			mutate: func(in *domain.ExpectedInventoryPreviewInput) {
				in.Discovery.CredentialCurrent = false
			},
			code: domain.DiscrepancyDiscoveryCredentialStale, blocking: true,
		},
		{
			name: "MIG identity",
			mutate: func(in *domain.ExpectedInventoryPreviewInput) {
				in.ObservedGPUs = append(in.ObservedGPUs, domain.ObservedGPUTarget{
					NodeID: "fixture1-zone1-comp001", UUID: "MIG-GPU-377d585f-0001-0000/1/0", LastObservedAt: previewNow,
				})
			},
			code: domain.DiscrepancyAmbiguousMIGIdentity, blocking: true,
		},
		{
			name: "stale telemetry keeps identities and blocks",
			mutate: func(in *domain.ExpectedInventoryPreviewInput) {
				for index := range in.ObservedGPUs {
					if in.ObservedGPUs[index].NodeID == "fixture1-zone1-comp001" {
						in.ObservedGPUs[index].LastObservedAt = previewNow.Add(-time.Hour)
					}
				}
				for index := range in.ObservedNodes {
					if in.ObservedNodes[index].NodeID == "fixture1-zone1-comp001" {
						in.ObservedNodes[index].LastObservedAt = previewNow.Add(-time.Hour)
					}
				}
			},
			// The identities stay in the preview so the operator sees what
			// they are being asked about, and the import is refused because
			// the exporter has confirmed none of them inside the window.
			code: domain.DiscrepancyNodeStaleTelemetry, blocking: true,
			assert: func(t *testing.T, preview domain.ExpectedInventoryPreview) {
				if preview.GPUCount != 80 {
					t.Fatalf("stale telemetry dropped GPU identities: %d", preview.GPUCount)
				}
			},
		},
		{
			name: "device not up",
			mutate: func(in *domain.ExpectedInventoryPreviewInput) {
				in.Discovery.Devices[3].Status = "[ DOWN ]"
			},
			code: domain.DiscrepancyDeviceNotUp, blocking: false,
			assert: func(t *testing.T, preview domain.ExpectedInventoryPreview) {
				if preview.NodeCount != 10 {
					t.Fatalf("a DOWN device was dropped from the expected inventory: %d", preview.NodeCount)
				}
			},
		},
		{
			name: "no managed nodes",
			mutate: func(in *domain.ExpectedInventoryPreviewInput) {
				in.Discovery.Devices = []domain.CredentialAccessDevice{{Type: "HeadNode", Hostname: "fixture1-zone1-headnode", Status: "[ UP ]"}}
				in.ExcludeNodes = nil
			},
			code: domain.DiscrepancyNoManagedNodes, blocking: true,
		},
		{
			name: "observed inventory unavailable",
			mutate: func(in *domain.ExpectedInventoryPreviewInput) {
				in.ObservedGPUs = nil
			},
			code: domain.DiscrepancyObservedInventoryUnavailable, blocking: true,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			in := pilotInput()
			testCase.mutate(&in)
			preview := mustBuild(t, in)
			if codes(preview)[testCase.code] == 0 {
				t.Fatalf("missing %s: %+v", testCase.code, preview.Discrepancies)
			}
			if preview.Blocking != testCase.blocking {
				t.Fatalf("blocking=%v want %v", preview.Blocking, testCase.blocking)
			}
			for _, finding := range preview.Discrepancies {
				if finding.Code == testCase.code && finding.Blocking != testCase.blocking && testCase.blocking {
					t.Fatalf("%s reported as non-blocking", testCase.code)
				}
			}
			if testCase.assert != nil {
				testCase.assert(t, preview)
			}
		})
	}
}

func TestBuildExpectedInventoryPreviewReportsProposedRemovals(t *testing.T) {
	in := pilotInput()
	current := domain.InventoryRevision{
		SchemaVersion: domain.InventoryContractSchemaVersion, ID: "exp_previous",
		ClusterID: previewCluster, SourceID: previewSource,
		SourceAt: previewNow.Add(-4 * time.Hour), EffectiveAt: previewNow.Add(-4 * time.Hour), ObservedAt: previewNow.Add(-4 * time.Hour),
		Entities: []domain.EntityIdentity{
			{ClusterID: previewCluster, Kind: domain.EntityNode, NodeID: "fixture1-zone1-comp001"},
			{ClusterID: previewCluster, Kind: domain.EntityGPU, NodeID: "fixture1-zone1-comp001", PhysicalGPUUUID: "GPU-377d585f-0001-0000"},
			{ClusterID: previewCluster, Kind: domain.EntityNode, NodeID: "fixture1-zone1-retired"},
			{ClusterID: previewCluster, Kind: domain.EntityGPU, NodeID: "fixture1-zone1-retired", PhysicalGPUUUID: "GPU-retired-0000"},
		},
	}
	validated, err := domain.CreateInventoryRevision(current)
	if err != nil {
		t.Fatal(err)
	}
	in.Current = &validated
	preview := mustBuild(t, in)
	if len(preview.Removals) != 2 {
		t.Fatalf("removals=%+v", preview.Removals)
	}
	for _, removal := range preview.Removals {
		if removal.NodeID != "fixture1-zone1-retired" {
			t.Fatalf("unexpected removal %+v", removal)
		}
	}
	if codes(preview)[domain.DiscrepancyProposedRemoval] != 2 {
		t.Fatalf("proposed removals not reported: %+v", preview.Discrepancies)
	}
	if preview.Blocking {
		t.Fatal("a proposed removal must not block by itself")
	}
	if preview.Additions != 88 {
		t.Fatalf("additions=%d", preview.Additions)
	}
}

func TestBuildExpectedInventoryPreviewRefusesBoundsInsteadOfTruncating(t *testing.T) {
	t.Run("devices", func(t *testing.T) {
		in := pilotInput()
		devices := make([]domain.CredentialAccessDevice, 0, domain.ExpectedInventoryMaxDevices+1)
		for index := 0; index <= domain.ExpectedInventoryMaxDevices; index++ {
			devices = append(devices, domain.CredentialAccessDevice{Type: "PhysicalNode", Hostname: fmt.Sprintf("node%04d", index), Status: "[ UP ]"})
		}
		in.Discovery.Devices = devices
		if _, err := domain.BuildExpectedInventoryPreview(in); err == nil {
			t.Fatal("expected a refusal above the device bound")
		}
	})
	t.Run("observed gpus", func(t *testing.T) {
		in := pilotInput()
		gpus := make([]domain.ObservedGPUTarget, 0, domain.ExpectedInventoryMaxObservedGPUs+1)
		for index := 0; index <= domain.ExpectedInventoryMaxObservedGPUs; index++ {
			gpus = append(gpus, domain.ObservedGPUTarget{NodeID: "fixture1-zone1-comp001", UUID: domain.PhysicalGPUUUID(fmt.Sprintf("GPU-%06d", index)), LastObservedAt: previewNow})
		}
		in.ObservedGPUs = gpus
		if _, err := domain.BuildExpectedInventoryPreview(in); err == nil {
			t.Fatal("expected a refusal above the observed GPU bound")
		}
	})
	t.Run("observed nodes", func(t *testing.T) {
		in := pilotInput()
		nodes := make([]domain.ObservedNodeTarget, 0, domain.ExpectedInventoryMaxObservedNodes+1)
		for index := 0; index <= domain.ExpectedInventoryMaxObservedNodes; index++ {
			nodes = append(nodes, domain.ObservedNodeTarget{NodeID: domain.StableNodeID(fmt.Sprintf("node%04d", index)), LastObservedAt: previewNow})
		}
		in.ObservedNodes = nodes
		if _, err := domain.BuildExpectedInventoryPreview(in); err == nil {
			t.Fatal("expected a refusal above the observed node bound")
		}
	})
	t.Run("entities", func(t *testing.T) {
		in := pilotInput()
		devices := make([]domain.CredentialAccessDevice, 0, 200)
		gpus := make([]domain.ObservedGPUTarget, 0, 1600)
		for node := 0; node < 200; node++ {
			hostname := fmt.Sprintf("node%04d", node)
			devices = append(devices, domain.CredentialAccessDevice{Type: "PhysicalNode", Hostname: hostname, Status: "[ UP ]"})
			for slot := 0; slot < 8; slot++ {
				gpus = append(gpus, domain.ObservedGPUTarget{
					NodeID: domain.StableNodeID(hostname), UUID: domain.PhysicalGPUUUID(fmt.Sprintf("GPU-%04d-%02d", node, slot)), LastObservedAt: previewNow,
				})
			}
		}
		in.Discovery.Devices, in.ObservedGPUs, in.ObservedNodes = devices, gpus, nil
		if _, err := domain.BuildExpectedInventoryPreview(in); err == nil {
			t.Fatal("expected a refusal above the entity bound")
		}
	})
}

func TestExpectedInventoryPreviewDigestIsStableAndSensitive(t *testing.T) {
	first := mustBuild(t, pilotInput())
	second := mustBuild(t, pilotInput())
	firstDigest, err := domain.ExpectedInventoryPreviewDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := domain.ExpectedInventoryPreviewDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatal("the same reconciliation produced different digests")
	}
	mutations := []struct {
		name   string
		mutate func(*domain.ExpectedInventoryPreview)
	}{
		{"cluster", func(p *domain.ExpectedInventoryPreview) { p.ClusterID = "other" }},
		{"source", func(p *domain.ExpectedInventoryPreview) { p.SourceID = "other" }},
		{"generated at", func(p *domain.ExpectedInventoryPreview) { p.GeneratedAt = p.GeneratedAt.Add(time.Nanosecond) }},
		{"discovery", func(p *domain.ExpectedInventoryPreview) { p.DiscoveryTestID = "ctest_other" }},
		{"discovery time", func(p *domain.ExpectedInventoryPreview) {
			p.DiscoveryCompletedAt = p.DiscoveryCompletedAt.Add(time.Second)
		}},
		{"credential", func(p *domain.ExpectedInventoryPreview) { p.CredentialID = "cred_other" }},
		{"credential version", func(p *domain.ExpectedInventoryPreview) { p.CredentialVersion = 2 }},
		{"bcm version", func(p *domain.ExpectedInventoryPreview) { p.BCMVersion = "10.1" }},
		{"entity", func(p *domain.ExpectedInventoryPreview) { p.Entities[0].NodeID = "fixture1-zone1-comp999" }},
		{"entity removed", func(p *domain.ExpectedInventoryPreview) { p.Entities = p.Entities[1:] }},
		{"device status", func(p *domain.ExpectedInventoryPreview) { p.Devices[0].Status = "DOWN" }},
		{"device gpu count", func(p *domain.ExpectedInventoryPreview) { p.Devices[1].ObservedGPUs = 7 }},
		{"discrepancy", func(p *domain.ExpectedInventoryPreview) { p.Discrepancies[0].NodeID = "changed" }},
		{"removals", func(p *domain.ExpectedInventoryPreview) {
			p.Removals = append(p.Removals, domain.EntityIdentity{ClusterID: previewCluster, Kind: domain.EntityNode, NodeID: "gone"})
		}},
		{"additions", func(p *domain.ExpectedInventoryPreview) { p.Additions++ }},
		// The exclusion list is an operator decision the approval is bound
		// to: approving a preview must approve the exclusions it was made
		// with, so the digest has to cover them.
		{"excluded nodes added", func(p *domain.ExpectedInventoryPreview) {
			p.ExcludedNodes = append(p.ExcludedNodes, "fixture1-zone1-comp003")
		}},
		{"excluded nodes cleared", func(p *domain.ExpectedInventoryPreview) { p.ExcludedNodes = nil }},
		{"excluded categories added", func(p *domain.ExpectedInventoryPreview) {
			p.ExcludedCategories = append(p.ExcludedCategories, pilotLoginCategory)
		}},
		{"device category", func(p *domain.ExpectedInventoryPreview) { p.Devices[1].Category = "other-category" }},
		{"blocking", func(p *domain.ExpectedInventoryPreview) { p.Blocking = true }},
		{"node count", func(p *domain.ExpectedInventoryPreview) { p.NodeCount++ }},
		{"gpu count", func(p *domain.ExpectedInventoryPreview) { p.GPUCount++ }},
		{"schema version", func(p *domain.ExpectedInventoryPreview) { p.SchemaVersion++ }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := mustBuild(t, pilotInput())
			mutation.mutate(&changed)
			digest, err := domain.ExpectedInventoryPreviewDigest(changed)
			if err != nil {
				t.Fatal(err)
			}
			if digest == firstDigest {
				t.Fatalf("changing %s did not change the digest", mutation.name)
			}
		})
	}
}

func TestExpectedInventoryRevisionFromPreview(t *testing.T) {
	preview := mustBuild(t, pilotInput())
	approvedAt := previewNow.Add(2 * time.Hour)
	revision, err := domain.ExpectedInventoryRevisionFromPreview(preview, "exp_pilot", approvedAt)
	if err != nil {
		t.Fatal(err)
	}
	if revision.SchemaVersion != domain.InventoryContractSchemaVersion || revision.ID != "exp_pilot" {
		t.Fatalf("unexpected revision header: %+v", revision)
	}
	if revision.ClusterID != previewCluster || revision.SourceID != previewSource {
		t.Fatalf("unexpected revision scope: %+v", revision)
	}
	if !revision.SourceAt.Equal(preview.DiscoveryCompletedAt) {
		t.Fatalf("source time %s", revision.SourceAt)
	}
	// A declaration takes effect when it is approved, not when it was
	// reconciled: otherwise an older preview approved later backdates itself
	// behind the revision already in force.
	if !revision.EffectiveAt.Equal(approvedAt) || !revision.ObservedAt.Equal(approvedAt) {
		t.Fatalf("effective/observed times %s %s", revision.EffectiveAt, revision.ObservedAt)
	}
	if revision.EffectiveAt.Equal(preview.GeneratedAt) {
		t.Fatal("the revision was backdated to the preview generation time")
	}
	if len(revision.Entities) != len(preview.Entities) {
		t.Fatalf("entities=%d", len(revision.Entities))
	}

	blocking := mustBuild(t, func() domain.ExpectedInventoryPreviewInput {
		in := pilotInput()
		in.Discovery.CredentialCurrent = false
		return in
	}())
	if _, err := domain.ExpectedInventoryRevisionFromPreview(blocking, "exp_blocked", approvedAt); err == nil {
		t.Fatal("a blocking preview must not convert to a revision")
	}
	if _, err := domain.ExpectedInventoryRevisionFromPreview(preview, "exp pilot\n", approvedAt); err == nil {
		t.Fatal("an invalid revision identifier must be refused")
	}
	if _, err := domain.ExpectedInventoryRevisionFromPreview(preview, "exp_pilot", time.Time{}); err == nil {
		t.Fatal("a revision without an approval time must be refused")
	}
	// A preview whose cached flag was cleared but whose findings still block
	// must not convert: the findings are the reconciliation, the flag is a
	// summary of it.
	tampered := mustBuild(t, pilotInput())
	tampered.Discrepancies = append(tampered.Discrepancies, domain.InventoryDiscrepancy{
		Code: domain.DiscrepancyDuplicateGPU, Blocking: true,
	})
	tampered.Blocking = false
	if _, err := domain.ExpectedInventoryRevisionFromPreview(tampered, "exp_tampered", approvedAt); err == nil {
		t.Fatal("a preview with blocking findings and a cleared flag must not convert")
	}
	if !tampered.DerivedBlocking() {
		t.Fatal("DerivedBlocking ignored a blocking finding")
	}
}

// findNodeFinding returns the one finding with this code and node, if any.
func findNodeFinding(preview domain.ExpectedInventoryPreview, code domain.InventoryDiscrepancyCode, node domain.StableNodeID) (domain.InventoryDiscrepancy, bool) {
	for _, finding := range preview.Discrepancies {
		if finding.Code == code && finding.NodeID == node && finding.GPUUUID == "" {
			return finding, true
		}
	}
	return domain.InventoryDiscrepancy{}, false
}

// findFinding returns the one finding with this code and GPU UUID, if any.
func findFinding(preview domain.ExpectedInventoryPreview, code domain.InventoryDiscrepancyCode, uuid domain.PhysicalGPUUUID) (domain.InventoryDiscrepancy, bool) {
	for _, finding := range preview.Discrepancies {
		if finding.Code == code && finding.GPUUUID == uuid {
			return finding, true
		}
	}
	return domain.InventoryDiscrepancy{}, false
}

// TestExpectedInventoryStaleGPUOnAFreshNodeBlocks is the decommissioned-GPU
// shape: collection_target_inventory is never pruned, so the removed card's
// last row stays durable while the node keeps exporting the rest. Judging
// freshness per node alone would let that identity into an approved expected
// inventory with no discrepancy at all.
func TestExpectedInventoryStaleGPUOnAFreshNodeBlocks(t *testing.T) {
	in := pilotInput()
	stale := domain.PhysicalGPUUUID("GPU-377d585f-0001-0003")
	for index := range in.ObservedGPUs {
		if in.ObservedGPUs[index].UUID == stale {
			in.ObservedGPUs[index].LastObservedAt = previewNow.Add(-72 * time.Hour)
		}
	}
	preview := mustBuild(t, in)

	finding, found := findFinding(preview, domain.DiscrepancyGPUStaleTelemetry, stale)
	if !found {
		t.Fatalf("the stale GPU was not reported: %+v", preview.Discrepancies)
	}
	if !finding.Blocking || finding.NodeID != "fixture1-zone1-comp001" || finding.Detail == "" {
		t.Fatalf("unexpected stale GPU finding: %+v", finding)
	}
	if !preview.Blocking {
		t.Fatal("a stale GPU identity did not block the import")
	}
	// Exactly one GPU is stale; its node reports nine other fresh rows, so
	// the node itself is not reported as stale.
	if counts := codes(preview); counts[domain.DiscrepancyGPUStaleTelemetry] != 1 || counts[domain.DiscrepancyNodeStaleTelemetry] != 0 {
		t.Fatalf("staleness reported at the wrong scope: %v", counts)
	}
	// The row is shown, never filtered away: the operator must see the
	// identity they are being asked not to approve.
	var retained bool
	for _, entity := range preview.Entities {
		retained = retained || entity.PhysicalGPUUUID == stale
	}
	if !retained || preview.GPUCount != 80 {
		t.Fatalf("the stale identity was dropped from the preview: retained=%v gpus=%d", retained, preview.GPUCount)
	}
}

// TestExpectedInventoryFullyStaleNodeBlocks covers the other half: when every
// row a node has is stale, the node is reported once and the refusal is the
// same. An operator cannot approve GPUs the exporter has not confirmed.
func TestExpectedInventoryFullyStaleNodeBlocks(t *testing.T) {
	in := pilotInput()
	for index := range in.ObservedGPUs {
		if in.ObservedGPUs[index].NodeID == "fixture1-zone1-comp002" {
			in.ObservedGPUs[index].LastObservedAt = previewNow.Add(-72 * time.Hour)
		}
	}
	for index := range in.ObservedNodes {
		if in.ObservedNodes[index].NodeID == "fixture1-zone1-comp002" {
			in.ObservedNodes[index].LastObservedAt = previewNow.Add(-72 * time.Hour)
		}
	}
	preview := mustBuild(t, in)

	counts := codes(preview)
	if counts[domain.DiscrepancyNodeStaleTelemetry] != 1 {
		t.Fatalf("the fully stale node was not reported once: %v", counts)
	}
	// The node-level finding stands alone; the eight identities under it are
	// not restated one by one.
	if counts[domain.DiscrepancyGPUStaleTelemetry] != 0 {
		t.Fatalf("a fully stale node also raised per-GPU findings: %v", counts)
	}
	var nodeFinding domain.InventoryDiscrepancy
	for _, finding := range preview.Discrepancies {
		if finding.Code == domain.DiscrepancyNodeStaleTelemetry {
			nodeFinding = finding
		}
	}
	if !nodeFinding.Blocking || nodeFinding.NodeID != "fixture1-zone1-comp002" {
		t.Fatalf("unexpected stale node finding: %+v", nodeFinding)
	}
	if !preview.Blocking || preview.GPUCount != 80 {
		t.Fatalf("blocking=%v gpus=%d", preview.Blocking, preview.GPUCount)
	}
}

// TestExpectedInventoryInvalidGPUIdentityIsNotAMIGAmbiguity keeps the two
// refusals distinct: reporting a malformed identifier as a MIG ambiguity
// sends the operator looking for a partition that does not exist.
func TestExpectedInventoryInvalidGPUIdentityIsNotAMIGAmbiguity(t *testing.T) {
	in := pilotInput()
	in.ObservedGPUs = append(in.ObservedGPUs,
		domain.ObservedGPUTarget{NodeID: "fixture1-zone1-comp001", UUID: "GPU-377d585f\t0001", LastObservedAt: previewNow},
		domain.ObservedGPUTarget{NodeID: "fixture1-zone1-comp001", UUID: "MIG-GPU-377d585f-0001-0000/1/0", LastObservedAt: previewNow},
	)
	preview := mustBuild(t, in)

	invalid, found := findFinding(preview, domain.DiscrepancyInvalidGPUIdentity, "GPU-377d585f\t0001")
	if !found || !invalid.Blocking || invalid.NodeID != "fixture1-zone1-comp001" {
		t.Fatalf("the malformed identity was not reported as INVALID_GPU_IDENTITY: %+v", preview.Discrepancies)
	}
	if _, mig := findFinding(preview, domain.DiscrepancyAmbiguousMIGIdentity, "GPU-377d585f\t0001"); mig {
		t.Fatal("a malformed identity was reported as a MIG ambiguity")
	}
	if _, mig := findFinding(preview, domain.DiscrepancyAmbiguousMIGIdentity, "MIG-GPU-377d585f-0001-0000/1/0"); !mig {
		t.Fatal("a genuine MIG identity stopped being reported as one")
	}
}

// TestExpectedInventoryProposedRemovalBlocksOnUnconfirmedTelemetry: a node
// whose exporter is down must not lose its GPUs from the denominator by one
// click, while a removal on a node that is reporting normally stays an
// informative proposal.
func TestExpectedInventoryProposedRemovalBlocksOnUnconfirmedTelemetry(t *testing.T) {
	// The current revision holds the silent login node as an expected member
	// with one GPU, and one GPU on a healthy node that the exporter no longer
	// lists. The login node is therefore preserved, not unclassified, and its
	// removal is the silent-exporter case.
	current := domain.InventoryRevision{
		ClusterID: previewCluster, SourceID: previewSource,
		Entities: []domain.EntityIdentity{
			{ClusterID: previewCluster, Kind: domain.EntityNode, NodeID: pilotLoginNode},
			{ClusterID: previewCluster, Kind: domain.EntityGPU, NodeID: pilotLoginNode, PhysicalGPUUUID: "GPU-377d585f-0009-0000"},
			{ClusterID: previewCluster, Kind: domain.EntityGPU, NodeID: "fixture1-zone1-comp003", PhysicalGPUUUID: "GPU-377d585f-0003-0099"},
		},
	}
	in := pilotListingInput()
	in.Current = &current
	preview := mustBuild(t, in)

	silent, found := findFinding(preview, domain.DiscrepancyProposedRemoval, "GPU-377d585f-0009-0000")
	if !found {
		t.Fatalf("the silent node's removal was not reported: %+v", preview.Discrepancies)
	}
	if !silent.Blocking {
		t.Fatal("a removal from a node with no telemetry was not blocking")
	}
	healthy, found := findFinding(preview, domain.DiscrepancyProposedRemoval, "GPU-377d585f-0003-0099")
	if !found {
		t.Fatalf("the healthy node's removal was not reported: %+v", preview.Discrepancies)
	}
	if healthy.Blocking {
		t.Fatal("a removal from a node reporting fresh telemetry was blocking")
	}
	if !preview.Blocking || len(preview.Removals) != 2 {
		t.Fatalf("blocking=%v removals=%d", preview.Blocking, len(preview.Removals))
	}

	// A stale GPU elsewhere on the node has the same effect as no telemetry
	// at all: the node's rows are not a current statement of what it holds.
	stale := pilotListingInput()
	stale.Current = &current
	for index := range stale.ObservedGPUs {
		if stale.ObservedGPUs[index].NodeID == "fixture1-zone1-comp003" && stale.ObservedGPUs[index].UUID == "GPU-377d585f-0003-0000" {
			stale.ObservedGPUs[index].LastObservedAt = previewNow.Add(-72 * time.Hour)
		}
	}
	stalePreview := mustBuild(t, stale)
	nowBlocking, found := findFinding(stalePreview, domain.DiscrepancyProposedRemoval, "GPU-377d585f-0003-0099")
	if !found || !nowBlocking.Blocking {
		t.Fatalf("a removal from a node with a stale identity was not blocking: %+v", nowBlocking)
	}
}
