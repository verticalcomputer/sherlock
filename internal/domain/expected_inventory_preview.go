package domain

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ExpectedInventoryPreviewSchemaVersion versions the reconciliation contract
// between a BCM inventory discovery, observed collection targets, and the
// GP-02 expected inventory revision an operator may approve from it.
//
// Version 2 added per-device Category and the ExcludedNodes/ExcludedCategories
// fields to the canonical content (43218bc, 86b5a47). A version 1 preview
// persisted before that change re-derives to a different digest under the
// new canonical shape; it is never re-hashed against its stored digest and is
// reported to the operator as superseded instead. See
// loadLatestExpectedInventoryPreview and ImportExpectedInventoryPreview.
const ExpectedInventoryPreviewSchemaVersion = 2

// Bounds are refusals, never truncations: a preview that silently dropped a
// managed node or an observed GPU would be approved as if it were complete.
// The four bounds are coherent on purpose. A discovery listing is refused
// past 512 device rows, which is also the bound the head collector enforces
// before it retains anything. The observed bounds are read bounds on the
// collection target inventory, and ExpectedInventoryMaxEntities is the
// governing ceiling: a preview proposes one entity per managed node plus one
// per included GPU, so 1024 entities is reached long before 4096 observed GPU
// rows are. A larger observed bound would only let a read succeed that the
// entity ceiling then refuses, which is the same refusal one step later.
const (
	ExpectedInventoryMaxDevices       = 512
	ExpectedInventoryMaxObservedNodes = 1024
	ExpectedInventoryMaxObservedGPUs  = 4096
	ExpectedInventoryMaxEntities      = 1024
	ExpectedInventoryMaxExcludedNodes = 256
	// ExpectedInventoryMaxExcludedCategories bounds the category exclusion
	// list. A head has a handful of device categories, not hundreds, so the
	// bound is deliberately far below the node bound: a request naming more
	// categories than a head could plausibly have is a mistake, not a policy.
	ExpectedInventoryMaxExcludedCategories = 64
)

// Default policy values. DiscoveryMaxAge bounds how old the BCM listing may
// be; ObservedMaxAge bounds how old telemetry may be before it is reported as
// stale. Staleness of telemetry never removes a GPU identity: a UUID is an
// identity, not a freshness claim.
const (
	ExpectedInventoryDefaultDiscoveryMaxAge = 24 * time.Hour
	ExpectedInventoryDefaultObservedMaxAge  = 10 * time.Minute
)

// ExpectedInventoryDefaultManagedDeviceType is the only BCM device type that
// is treated as a managed compute node by default. Head nodes, switches and
// every other listed type are reported and excluded, never guessed at.
const ExpectedInventoryDefaultManagedDeviceType = "PhysicalNode"

// InventoryDiscoveryEvidence is the redacted provenance of one SUCCEEDED
// bcm.inventory_discovery.v1 test. It carries no secret and no command text.
type InventoryDiscoveryEvidence struct {
	TestID            string
	CredentialID      string
	CredentialVersion int64
	CredentialCurrent bool
	Host              string
	BCMVersion        string
	CompletedAt       time.Time
	Devices           []CredentialAccessDevice
}

// ObservedGPUTarget is one physical GPU identity currently reported by the
// collection target inventory for a cluster and source.
type ObservedGPUTarget struct {
	NodeID         StableNodeID
	UUID           PhysicalGPUUUID
	LastObservedAt time.Time
}

// ObservedNodeTarget is one node currently reported by the collection target
// inventory for a cluster and source.
type ObservedNodeTarget struct {
	NodeID         StableNodeID
	LastObservedAt time.Time
}

// ExpectedInventoryPolicy holds the reviewed thresholds. A zero value is
// replaced with the documented defaults so a caller cannot accidentally
// disable an age bound by leaving a field unset.
type ExpectedInventoryPolicy struct {
	ManagedDeviceTypes []string
	DiscoveryMaxAge    time.Duration
	ObservedMaxAge     time.Duration
}

func (policy ExpectedInventoryPolicy) withDefaults() ExpectedInventoryPolicy {
	if len(policy.ManagedDeviceTypes) == 0 {
		policy.ManagedDeviceTypes = []string{ExpectedInventoryDefaultManagedDeviceType}
	}
	if policy.DiscoveryMaxAge <= 0 {
		policy.DiscoveryMaxAge = ExpectedInventoryDefaultDiscoveryMaxAge
	}
	if policy.ObservedMaxAge <= 0 {
		policy.ObservedMaxAge = ExpectedInventoryDefaultObservedMaxAge
	}
	return policy
}

// ExpectedInventoryPreviewInput is everything the reconciliation reads. It is
// a value: BuildExpectedInventoryPreview performs no I/O and no clock read,
// so the same input always produces the same preview and the same digest.
type ExpectedInventoryPreviewInput struct {
	ClusterID     ClusterID
	SourceID      SourceID
	Discovery     InventoryDiscoveryEvidence
	ObservedNodes []ObservedNodeTarget
	ObservedGPUs  []ObservedGPUTarget
	Current       *InventoryRevision
	GeneratedAt   time.Time
	Policy        ExpectedInventoryPolicy
	// ExcludeNodes names the hostnames the operator has decided this preview
	// must not propose. It is part of the preview and therefore of its
	// digest: an approval names the exclusions it was made with.
	ExcludeNodes []StableNodeID
	// ExcludeCategories names the BCM device categories the operator has
	// decided this preview must not propose. It is the same decision one
	// level up: a login category is excluded once, rather than once per login
	// node, and a node later added to that category is excluded with it. It
	// is part of the digest for the same reason ExcludeNodes is.
	ExcludeCategories []string
}

// InventoryDiscrepancyCode names one explicit reconciliation finding. Codes
// are stable identifiers an operator and an audit record can both refer to.
type InventoryDiscrepancyCode string

const (
	// DiscrepancyUnmanagedDevice reports a listed device whose type is not a
	// managed compute node. It is excluded, never silently adopted.
	DiscrepancyUnmanagedDevice InventoryDiscrepancyCode = "UNMANAGED_DEVICE"
	// DiscrepancyDeviceNotUp reports a listed device whose BCM status is not
	// UP. It is informative: BCM status is not a telemetry fact.
	DiscrepancyDeviceNotUp InventoryDiscrepancyCode = "DEVICE_NOT_UP"
	// DiscrepancyDeviceHealthWarning reports that a listed device's status
	// carries text after its bracketed state token — a failed health check,
	// a required restart. It is informative: BCM health text is not a
	// telemetry fact and says nothing about the identities being proposed.
	DiscrepancyDeviceHealthWarning InventoryDiscrepancyCode = "DEVICE_HEALTH_WARNING"
	// DiscrepancyNodeMissingTelemetry reports a managed node with no observed
	// GPU rows that is already a NODE entity in the current expected
	// revision. The node is preserved as expected; its GPUs remain unknown.
	// A node that is not already expected is DiscrepancyNodeUnclassified
	// instead: preserving a member and promoting a stranger are different
	// decisions.
	DiscrepancyNodeMissingTelemetry InventoryDiscrepancyCode = "NODE_MISSING_TELEMETRY"
	// DiscrepancyNodeUnclassified reports a managed device with no observed
	// GPU identity at all that is not in the current expected revision. BCM's
	// device type cannot distinguish a login or service node from a GPU
	// compute node, so a first-seen node with no GPU evidence cannot be
	// promoted into the denominator without an explicit operator decision.
	DiscrepancyNodeUnclassified InventoryDiscrepancyCode = "NODE_UNCLASSIFIED"
	// DiscrepancyCategoryUnclassified reports a BCM device category in which
	// no device reports a physical GPU identity and no device is a member of
	// the current expected revision. The category as a whole cannot be told
	// apart from a login or service grouping, so it is blocking: an operator
	// either excludes the category or supplies the telemetry that classifies
	// it. It is reported once per category, not once per device, because the
	// decision an operator makes is about the category.
	DiscrepancyCategoryUnclassified InventoryDiscrepancyCode = "CATEGORY_UNCLASSIFIED"
	// DiscrepancyNodeExcludedByOperator reports a managed device the operator
	// named in this preview's exclusion list, by hostname or by category. It
	// is listed and not proposed.
	DiscrepancyNodeExcludedByOperator InventoryDiscrepancyCode = "NODE_EXCLUDED_BY_OPERATOR"
	// DiscrepancyExclusionUnmatched reports an excluded hostname that no
	// listed device matches. It is blocking: a typo in an exclusion must not
	// be silently ignored, or the operator would approve an inventory that
	// still contains the node they meant to leave out.
	DiscrepancyExclusionUnmatched InventoryDiscrepancyCode = "EXCLUSION_UNMATCHED"
	// DiscrepancyNodeStaleTelemetry reports a managed node whose newest
	// observed row is older than the policy window: every row the node has
	// is stale, so the exporter has confirmed nothing inside the window.
	DiscrepancyNodeStaleTelemetry InventoryDiscrepancyCode = "NODE_STALE_TELEMETRY"
	// DiscrepancyGPUStaleTelemetry reports one physical GPU whose own
	// observed row is older than the policy window while its node still
	// reports fresher rows. The collection target inventory is never pruned,
	// so a decommissioned GPU's last row would otherwise enter a preview
	// with no discrepancy at all and be approved as expected inventory.
	DiscrepancyGPUStaleTelemetry InventoryDiscrepancyCode = "GPU_STALE_TELEMETRY"
	// DiscrepancyForeignNodeTelemetry reports observed telemetry for a node
	// the head does not manage. It is excluded from the expected inventory.
	DiscrepancyForeignNodeTelemetry InventoryDiscrepancyCode = "FOREIGN_NODE_TELEMETRY"
	// DiscrepancyHostnameMismatch reports an observed node identifier that
	// resembles a managed hostname but is not equal to it. The DCGM mapper
	// joins on the exact exporter hostname label, so a case-insensitive or
	// short/FQDN near-match is a blocking ambiguity, never an alias.
	DiscrepancyHostnameMismatch InventoryDiscrepancyCode = "HOSTNAME_MISMATCH"
	// DiscrepancyDuplicateGPU reports one physical GPU UUID observed on more
	// than one managed node.
	DiscrepancyDuplicateGPU InventoryDiscrepancyCode = "DUPLICATE_GPU"
	// DiscrepancyAmbiguousMIGIdentity reports a MIG-shaped identity in the
	// observed physical GPU set. MIG identities are not physical GPUs.
	DiscrepancyAmbiguousMIGIdentity InventoryDiscrepancyCode = "AMBIGUOUS_MIG_IDENTITY"
	// DiscrepancyInvalidGPUIdentity reports an observed identity that is not
	// MIG-shaped and is still not a usable stable identifier. Reporting it as
	// a MIG ambiguity would send the operator looking for a partition that
	// does not exist.
	DiscrepancyInvalidGPUIdentity InventoryDiscrepancyCode = "INVALID_GPU_IDENTITY"
	// DiscrepancyDiscoveryStale reports a BCM listing older than the policy.
	DiscrepancyDiscoveryStale InventoryDiscrepancyCode = "DISCOVERY_STALE"
	// DiscrepancyDiscoveryCredentialStale reports that the credential version
	// the listing was produced with is no longer the current active version.
	DiscrepancyDiscoveryCredentialStale InventoryDiscrepancyCode = "DISCOVERY_CREDENTIAL_STALE"
	// DiscrepancyNoManagedNodes reports a listing with no managed node.
	DiscrepancyNoManagedNodes InventoryDiscrepancyCode = "NO_MANAGED_NODES"
	// DiscrepancyObservedInventoryUnavailable reports that no physical GPU
	// identity was observed at all, so no GPU entity can be proposed.
	DiscrepancyObservedInventoryUnavailable InventoryDiscrepancyCode = "OBSERVED_INVENTORY_UNAVAILABLE"
	// DiscrepancyProposedRemoval reports an entity present in the current
	// expected revision that this preview would not carry forward.
	DiscrepancyProposedRemoval InventoryDiscrepancyCode = "PROPOSED_REMOVAL"
)

// discrepancyDetails holds the fixed, redacted operator text for each code.
// Detail never contains a host response, a command, or any value read from a
// credential-bearing path.
var discrepancyDetails = map[InventoryDiscrepancyCode]string{
	DiscrepancyUnmanagedDevice:              "listed device is not a managed compute node type and is excluded",
	DiscrepancyDeviceNotUp:                  "listed device state token is not UP",
	DiscrepancyDeviceHealthWarning:          "listed device reports a health or restart condition alongside its state; see the device status column",
	DiscrepancyNodeMissingTelemetry:         "managed node reports no physical GPU identity while its BCM category or the current expected revision classifies it as a compute node; the node is proposed and its GPUs remain unknown",
	DiscrepancyNodeUnclassified:             "managed device reports no physical GPU identity, reports no BCM category, and is not in the current expected revision; the listed device type cannot distinguish a GPU node from a login or service node, so it is excluded until an operator decides",
	DiscrepancyCategoryUnclassified:         categoryUnclassifiedDetailPrefix,
	DiscrepancyNodeExcludedByOperator:       "node was excluded by the operator for this preview and is not proposed as expected inventory",
	DiscrepancyExclusionUnmatched:           "the operator excluded a hostname that no listed device matches",
	DiscrepancyNodeStaleTelemetry:           "every observed row for this managed node is older than the freshness window; identities are retained and cannot be approved until the exporter confirms them",
	DiscrepancyGPUStaleTelemetry:            "physical GPU telemetry is older than the freshness window while its node reports fresher rows; the identity is retained and cannot be approved until the exporter confirms it",
	DiscrepancyForeignNodeTelemetry:         "observed node is not managed by this head listing and is excluded",
	DiscrepancyHostnameMismatch:             "observed node identifier resembles a managed hostname but is not equal to it",
	DiscrepancyDuplicateGPU:                 "physical GPU UUID is observed on more than one managed node",
	DiscrepancyAmbiguousMIGIdentity:         "observed identity is MIG-shaped and is not a physical GPU identity",
	DiscrepancyInvalidGPUIdentity:           "observed identity is not a usable stable physical GPU identifier",
	DiscrepancyDiscoveryStale:               "inventory discovery is older than the allowed age",
	DiscrepancyDiscoveryCredentialStale:     "inventory discovery was produced with a credential version that is no longer current",
	DiscrepancyNoManagedNodes:               "the listing contains no managed compute node",
	DiscrepancyObservedInventoryUnavailable: "no physical GPU identity was observed for this cluster and source",
	DiscrepancyProposedRemoval:              "entity is in the current expected revision and is not in this preview",
}

// The category-scoped findings name the category itself. A BCM category name
// is head configuration an operator chose, not a host response and not a
// value read from a credential-bearing path, so naming it is what makes the
// finding actionable: "one category is unclassified" without saying which is
// an instruction to guess. The name is sanitized and bounded exactly like
// every other retained device field before it reaches a Detail.
const (
	categoryUnclassifiedDetailPrefix = "no device in this BCM category reports a physical GPU identity and no device in it is in the current expected revision; the category is not proposed until an operator classifies or excludes it; category: "
	categoryExcludedDetail           = "the node's BCM category was excluded by the operator for this preview, so the node is not proposed as expected inventory; category: "
	categoryExclusionUnmatchedDetail = "the operator excluded a BCM category that no listed device reports; category: "
)

// blockingDiscrepancies names the codes that refuse an import outright. The
// two staleness codes are blocking because an operator cannot approve an
// identity the exporter has not confirmed inside the freshness window: the
// collection target inventory is never pruned, so a stale row is exactly as
// durable as a live one and says nothing about whether the hardware is still
// there. PROPOSED_REMOVAL is the one code whose blocking is not fixed by the
// code alone; see the removal loop in BuildExpectedInventoryPreview.
var blockingDiscrepancies = map[InventoryDiscrepancyCode]bool{
	DiscrepancyHostnameMismatch:             true,
	DiscrepancyDuplicateGPU:                 true,
	DiscrepancyAmbiguousMIGIdentity:         true,
	DiscrepancyInvalidGPUIdentity:           true,
	DiscrepancyNodeStaleTelemetry:           true,
	DiscrepancyGPUStaleTelemetry:            true,
	DiscrepancyNodeUnclassified:             true,
	DiscrepancyCategoryUnclassified:         true,
	DiscrepancyExclusionUnmatched:           true,
	DiscrepancyDiscoveryStale:               true,
	DiscrepancyDiscoveryCredentialStale:     true,
	DiscrepancyNoManagedNodes:               true,
	DiscrepancyObservedInventoryUnavailable: true,
}

// InventoryDiscrepancy is one explicit finding. Blocking is derived from the
// code so a caller cannot construct a non-blocking duplicate-UUID finding.
type InventoryDiscrepancy struct {
	Code       InventoryDiscrepancyCode
	Blocking   bool
	NodeID     StableNodeID
	GPUUUID    PhysicalGPUUUID
	DeviceType string
	Detail     string
}

// PreviewDevice is one listed BCM device as the preview classified it.
// Category is the BCM device category the head reported, empty when the
// device has none or when the discovery predates the category column.
type PreviewDevice struct {
	Type         string
	Hostname     string
	Category     string
	Status       string
	Managed      bool
	ObservedGPUs int
	Included     bool
}

// ExpectedInventoryPreview is a durable, digest-bound proposal. It is not an
// inventory revision and is not hardware verification: it states exactly
// which identities an operator would be approving and what is unresolved.
type ExpectedInventoryPreview struct {
	SchemaVersion        int
	ClusterID            ClusterID
	SourceID             SourceID
	GeneratedAt          time.Time
	DiscoveryTestID      string
	DiscoveryCompletedAt time.Time
	CredentialID         string
	CredentialVersion    int64
	BCMVersion           string
	Entities             []EntityIdentity
	Devices              []PreviewDevice
	Discrepancies        []InventoryDiscrepancy
	Removals             []EntityIdentity
	ExcludedNodes        []StableNodeID
	ExcludedCategories   []string
	Additions            int
	Blocking             bool
	NodeCount            int
	GPUCount             int
}

// BuildExpectedInventoryPreview reconciles a BCM listing with observed
// physical GPU identities. It is pure: every decision is a function of the
// input, so the resulting digest identifies exactly this reconciliation.
func BuildExpectedInventoryPreview(in ExpectedInventoryPreviewInput) (ExpectedInventoryPreview, error) {
	policy := in.Policy.withDefaults()
	if in.ClusterID == "" || in.SourceID == "" {
		return ExpectedInventoryPreview{}, fmt.Errorf("expected inventory preview requires cluster and source identifiers")
	}
	if in.GeneratedAt.IsZero() {
		return ExpectedInventoryPreview{}, fmt.Errorf("expected inventory preview requires a generation time")
	}
	if in.Discovery.TestID == "" || in.Discovery.CompletedAt.IsZero() {
		return ExpectedInventoryPreview{}, fmt.Errorf("expected inventory preview requires a completed inventory discovery")
	}
	if len(in.Discovery.Devices) > ExpectedInventoryMaxDevices {
		return ExpectedInventoryPreview{}, fmt.Errorf("inventory discovery lists more than %d devices", ExpectedInventoryMaxDevices)
	}
	if len(in.ObservedNodes) > ExpectedInventoryMaxObservedNodes {
		return ExpectedInventoryPreview{}, fmt.Errorf("observed node inventory exceeds %d rows", ExpectedInventoryMaxObservedNodes)
	}
	if len(in.ObservedGPUs) > ExpectedInventoryMaxObservedGPUs {
		return ExpectedInventoryPreview{}, fmt.Errorf("observed GPU inventory exceeds %d rows", ExpectedInventoryMaxObservedGPUs)
	}
	if in.Current != nil && (in.Current.ClusterID != in.ClusterID || in.Current.SourceID != in.SourceID) {
		return ExpectedInventoryPreview{}, fmt.Errorf("current inventory revision belongs to another cluster or source")
	}
	if err := ValidateCredentialAccessDevices(in.Discovery.Devices); err != nil {
		return ExpectedInventoryPreview{}, fmt.Errorf("inventory discovery devices: %w", err)
	}
	excludedNodes, err := normalizeExcludedNodes(in.ExcludeNodes)
	if err != nil {
		return ExpectedInventoryPreview{}, err
	}
	excludedCategories, err := normalizeExcludedCategories(in.ExcludeCategories)
	if err != nil {
		return ExpectedInventoryPreview{}, err
	}

	preview := ExpectedInventoryPreview{
		SchemaVersion: ExpectedInventoryPreviewSchemaVersion, ClusterID: in.ClusterID, SourceID: in.SourceID,
		GeneratedAt: in.GeneratedAt.UTC(), DiscoveryTestID: in.Discovery.TestID,
		DiscoveryCompletedAt: in.Discovery.CompletedAt.UTC(), CredentialID: in.Discovery.CredentialID,
		CredentialVersion: in.Discovery.CredentialVersion, BCMVersion: in.Discovery.BCMVersion,
		ExcludedNodes: excludedNodes, ExcludedCategories: excludedCategories,
	}
	findings := newDiscrepancySet()
	excluded := make(map[StableNodeID]struct{}, len(excludedNodes))
	for _, node := range excludedNodes {
		excluded[node] = struct{}{}
	}
	excludedCategory := make(map[string]struct{}, len(excludedCategories))
	for _, category := range excludedCategories {
		excludedCategory[category] = struct{}{}
	}

	// Managed nodes come from the listing's hostname exactly as reported,
	// trimmed only of surrounding whitespace. The DCGM mapper joins on the
	// exporter hostname label, so any other transformation would invent an
	// identity that the metric path can never match.
	managed := make(map[StableNodeID]struct{}, len(in.Discovery.Devices))
	managedOrder := make([]StableNodeID, 0, len(in.Discovery.Devices))
	listedHostnames := make(map[StableNodeID]struct{}, len(in.Discovery.Devices))
	listedCategories := make(map[string]struct{}, len(in.Discovery.Devices))
	// nodeCategory is the BCM category of each managed hostname, taken from
	// the first row that names it, and categoryOrder is the order the
	// categories were first listed in. Both are what the classification below
	// groups on; neither is ever derived from telemetry.
	nodeCategory := make(map[StableNodeID]string, len(in.Discovery.Devices))
	categoryMembers := make(map[string][]StableNodeID, len(in.Discovery.Devices))
	categoryOrder := make([]string, 0, len(in.Discovery.Devices))
	preview.Devices = make([]PreviewDevice, 0, len(in.Discovery.Devices))
	for _, device := range in.Discovery.Devices {
		hostname := strings.TrimSpace(device.Hostname)
		category := strings.TrimSpace(device.Category)
		listedHostnames[StableNodeID(hostname)] = struct{}{}
		if category != "" {
			listedCategories[category] = struct{}{}
		}
		isManaged := managedDeviceType(device.Type, policy.ManagedDeviceTypes) && validGoodputIdentifier(hostname)
		entry := PreviewDevice{Type: device.Type, Hostname: hostname, Category: category, Status: device.Status, Managed: isManaged, Included: isManaged}
		if !isManaged {
			findings.add(DiscrepancyUnmanagedDevice, "", "", device.Type)
		} else if _, seen := managed[StableNodeID(hostname)]; !seen {
			managed[StableNodeID(hostname)] = struct{}{}
			managedOrder = append(managedOrder, StableNodeID(hostname))
			nodeCategory[StableNodeID(hostname)] = category
			if category != "" {
				if _, known := categoryMembers[category]; !known {
					categoryOrder = append(categoryOrder, category)
				}
				categoryMembers[category] = append(categoryMembers[category], StableNodeID(hostname))
			}
		}
		// BCM reports a state token in brackets followed by optional health
		// text: "[ UP ], health check failed, restart required (…)". Only the
		// token answers whether the device is up; the text after it is a
		// separate, informational fact and is never echoed into a finding.
		state, bracketed, health := parseDeviceStatus(device.Status)
		if !bracketed || state != "UP" {
			findings.add(DiscrepancyDeviceNotUp, StableNodeID(hostname), "", device.Type)
		}
		if health {
			findings.add(DiscrepancyDeviceHealthWarning, StableNodeID(hostname), "", device.Type)
		}
		preview.Devices = append(preview.Devices, entry)
	}
	// An exclusion that matches no listed device at all is a typo, and a typo
	// that was silently ignored would leave the operator approving exactly the
	// inventory they meant to change.
	for _, node := range excludedNodes {
		if _, listed := listedHostnames[node]; !listed {
			findings.add(DiscrepancyExclusionUnmatched, node, "", "")
		}
	}
	// The same rule one level up: a category exclusion that matches nothing is
	// a typo, and a typo that was ignored would leave every device of the
	// category the operator meant to drop still proposed.
	for _, category := range excludedCategories {
		if _, listed := listedCategories[category]; !listed {
			findings.addWithDetail(DiscrepancyExclusionUnmatched, "", "", "", categoryExclusionUnmatchedDetail+category)
		}
	}

	// An observed node the head does not manage is either a near-match of a
	// managed hostname (blocking, because the operator must resolve which
	// identity the exporter really uses) or plainly foreign (excluded).
	observedNodeNames := make(map[StableNodeID]struct{}, len(in.ObservedNodes))
	freshest := make(map[StableNodeID]time.Time, len(in.ObservedNodes))
	for _, node := range in.ObservedNodes {
		observedNodeNames[node.NodeID] = struct{}{}
		if current, ok := freshest[node.NodeID]; !ok || node.LastObservedAt.After(current) {
			freshest[node.NodeID] = node.LastObservedAt
		}
	}
	for _, gpu := range in.ObservedGPUs {
		observedNodeNames[gpu.NodeID] = struct{}{}
		if current, ok := freshest[gpu.NodeID]; !ok || gpu.LastObservedAt.After(current) {
			freshest[gpu.NodeID] = gpu.LastObservedAt
		}
	}
	for node := range observedNodeNames {
		if _, ok := managed[node]; ok {
			continue
		}
		if nearMatchesManagedNode(node, managedOrder) {
			findings.add(DiscrepancyHostnameMismatch, node, "", "")
			continue
		}
		findings.add(DiscrepancyForeignNodeTelemetry, node, "", "")
	}

	// Per-GPU checks apply to the GPUs whose node identifier matches a
	// managed hostname exactly. A foreign node's rows are already excluded,
	// so they never block an import for inventory the head does not own.
	holders := make(map[PhysicalGPUUUID]map[StableNodeID]struct{})
	// gpuFreshest carries each retained GPU's own newest observation so that
	// staleness can be judged per identity, not only per node.
	gpuFreshest := make(map[StableNodeID]map[PhysicalGPUUUID]time.Time)
	for _, gpu := range in.ObservedGPUs {
		if _, ok := managed[gpu.NodeID]; !ok {
			continue
		}
		if isMIGIdentity(string(gpu.UUID)) {
			findings.add(DiscrepancyAmbiguousMIGIdentity, gpu.NodeID, gpu.UUID, "")
			continue
		}
		if !validGoodputIdentifier(string(gpu.UUID)) {
			findings.add(DiscrepancyInvalidGPUIdentity, gpu.NodeID, gpu.UUID, "")
			continue
		}
		if holders[gpu.UUID] == nil {
			holders[gpu.UUID] = map[StableNodeID]struct{}{}
		}
		holders[gpu.UUID][gpu.NodeID] = struct{}{}
		if gpuFreshest[gpu.NodeID] == nil {
			gpuFreshest[gpu.NodeID] = map[PhysicalGPUUUID]time.Time{}
		}
		if current, ok := gpuFreshest[gpu.NodeID][gpu.UUID]; !ok || gpu.LastObservedAt.After(current) {
			gpuFreshest[gpu.NodeID][gpu.UUID] = gpu.LastObservedAt
		}
	}
	duplicate := make(map[PhysicalGPUUUID]bool, len(holders))
	for uuid, nodes := range holders {
		if len(nodes) > 1 {
			duplicate[uuid] = true
			findings.add(DiscrepancyDuplicateGPU, "", uuid, "")
		}
	}

	includedGPUs := make(map[StableNodeID]map[PhysicalGPUUUID]struct{}, len(managed))
	for uuid, nodes := range holders {
		if duplicate[uuid] {
			continue
		}
		for node := range nodes {
			if includedGPUs[node] == nil {
				includedGPUs[node] = map[PhysicalGPUUUID]struct{}{}
			}
			includedGPUs[node][uuid] = struct{}{}
		}
	}

	// unconfirmed names the nodes whose telemetry an operator cannot treat as
	// a current statement of what is installed: no rows at all, every row
	// stale, or at least one individually stale GPU identity. A proposed
	// removal on such a node is a removal decided by a silent exporter.
	// observedAnyGPU records whether a managed node has any physical GPU row
	// at all, fresh or stale, valid or not. It is the evidence that separates
	// a GPU node that has gone silent from a device that was never a GPU node.
	observedAnyGPU := make(map[StableNodeID]bool, len(managed))
	for _, gpu := range in.ObservedGPUs {
		if _, ok := managed[gpu.NodeID]; ok {
			observedAnyGPU[gpu.NodeID] = true
		}
	}
	currentNodes := make(map[StableNodeID]bool)
	if in.Current != nil {
		for _, entity := range in.Current.Entities {
			if entity.Kind == EntityNode {
				currentNodes[entity.NodeID] = true
			}
		}
	}

	// Classification is by BCM category, not per node. BCM's device type says
	// PhysicalNode for a login node and for a GPU compute node alike, but the
	// head's own category tells them apart, and it is the same grouping the
	// operator already administers. A category is a compute category when at
	// least one of its devices has physical GPU rows (fresh or stale) or is
	// already a NODE entity in the current expected revision: one member's
	// evidence classifies the grouping, which is what lets a first-seen node
	// in a known GPU category be proposed with its GPUs simply unknown,
	// instead of being refused as a stranger.
	computeCategory := make(map[string]bool, len(categoryMembers))
	for category, members := range categoryMembers {
		for _, member := range members {
			if observedAnyGPU[member] || currentNodes[member] {
				computeCategory[category] = true
				break
			}
		}
	}
	// A category with no evidence at all is reported once, against the
	// category, because that is the shape of the decision: an operator
	// excludes "the login category", not eleven separate login nodes. An
	// excluded category is already decided and is not reported again, and a
	// category whose every member was excluded by hostname has nothing left
	// to classify.
	for _, category := range categoryOrder {
		if computeCategory[category] {
			continue
		}
		if _, dropped := excludedCategory[category]; dropped {
			continue
		}
		remaining := false
		for _, member := range categoryMembers[category] {
			if _, byName := excluded[member]; !byName {
				remaining = true
				break
			}
		}
		if remaining {
			findings.addWithDetail(DiscrepancyCategoryUnclassified, "", "", "", categoryUnclassifiedDetailPrefix+category)
		}
	}

	unconfirmed := make(map[StableNodeID]bool, len(managed))
	included := make(map[StableNodeID]bool, len(managed))
	entities := make([]EntityIdentity, 0, len(managed)+len(in.ObservedGPUs))
	for _, node := range managedOrder {
		gpus := includedGPUs[node]
		category := nodeCategory[node]
		_, nameExcluded := excluded[node]
		_, categoryExcluded := excludedCategory[category]
		operatorExcluded := nameExcluded || categoryExcluded
		// unconfirmed is judged the same way whatever the node's fate, so an
		// excluded or unclassified node that is in the current revision keeps
		// the removal rule it would have had: a silent exporter must not
		// decide a removal by itself.
		if len(gpus) == 0 {
			unconfirmed[node] = true
		}
		nodeStale := false
		if last, ok := freshest[node]; ok && !last.IsZero() && preview.GeneratedAt.Sub(last.UTC()) > policy.ObservedMaxAge {
			nodeStale, unconfirmed[node] = true, true
		}
		if operatorExcluded {
			// Which list dropped the node is part of the finding: an operator
			// re-reading the preview must be able to tell a hostname they
			// typed from a category decision that will also drop every node
			// added to that category later.
			detail := discrepancyDetails[DiscrepancyNodeExcludedByOperator]
			if !nameExcluded {
				detail = categoryExcludedDetail + category
			}
			findings.addWithDetail(DiscrepancyNodeExcludedByOperator, node, "", "", detail)
			// The node's identities are named too: an exclusion that dropped
			// eight GPUs silently would be read as a node that has none.
			for uuid := range gpus {
				findings.addWithDetail(DiscrepancyNodeExcludedByOperator, node, uuid, "", detail)
			}
			continue
		}
		// A device with no GPU evidence of its own is still proposed when its
		// category is a compute category; its GPUs are simply unknown. Only a
		// device that has no evidence, no compute category and no current
		// membership is left unclassified, and a device with no category at
		// all is the one case that is still reported per node: there is no
		// grouping to report it against.
		if len(gpus) == 0 && !observedAnyGPU[node] && !currentNodes[node] && !computeCategory[category] {
			if category == "" {
				findings.add(DiscrepancyNodeUnclassified, node, "", "")
			}
			continue
		}
		included[node] = true
		entities = append(entities, EntityIdentity{ClusterID: in.ClusterID, Kind: EntityNode, NodeID: node})
		if len(gpus) == 0 {
			findings.add(DiscrepancyNodeMissingTelemetry, node, "", "")
		}
		// A node whose newest row is stale has nothing fresh at all, so it is
		// reported once against the node. Only when the node still reports
		// fresher rows is an individual GPU's own staleness a separate fact:
		// that is the decommissioned-GPU shape, where the node keeps
		// exporting and one identity simply stopped being confirmed.
		if nodeStale {
			findings.add(DiscrepancyNodeStaleTelemetry, node, "", "")
		}
		for uuid := range gpus {
			if !nodeStale {
				if last, ok := gpuFreshest[node][uuid]; ok && !last.IsZero() && preview.GeneratedAt.Sub(last.UTC()) > policy.ObservedMaxAge {
					findings.add(DiscrepancyGPUStaleTelemetry, node, uuid, "")
					unconfirmed[node] = true
				}
			}
			entities = append(entities, EntityIdentity{ClusterID: in.ClusterID, Kind: EntityGPU, NodeID: node, PhysicalGPUUUID: uuid})
		}
	}
	sortEntities(entities)
	preview.Entities = entities
	for index := range preview.Devices {
		if !preview.Devices[index].Managed {
			continue
		}
		hostname := StableNodeID(preview.Devices[index].Hostname)
		preview.Devices[index].ObservedGPUs = len(includedGPUs[hostname])
		preview.Devices[index].Included = included[hostname]
	}

	if len(managed) == 0 {
		findings.add(DiscrepancyNoManagedNodes, "", "", "")
	}
	if len(in.ObservedGPUs) == 0 {
		findings.add(DiscrepancyObservedInventoryUnavailable, "", "", "")
	}
	if preview.GeneratedAt.Sub(preview.DiscoveryCompletedAt) > policy.DiscoveryMaxAge {
		findings.add(DiscrepancyDiscoveryStale, "", "", "")
	}
	if !in.Discovery.CredentialCurrent {
		findings.add(DiscrepancyDiscoveryCredentialStale, "", "", "")
	}

	proposed := make(map[string]struct{}, len(entities))
	for _, entity := range entities {
		proposed[entity.Key()] = struct{}{}
		if entity.Kind == EntityNode {
			preview.NodeCount++
		} else {
			preview.GPUCount++
		}
	}
	if in.Current != nil {
		removals := make([]EntityIdentity, 0)
		for _, entity := range in.Current.Entities {
			if _, kept := proposed[entity.Key()]; kept {
				continue
			}
			removals = append(removals, entity)
			// A removal is ordinarily an informative proposal. It becomes
			// blocking when the node it is removed from has no confirmed
			// telemetry inside the window: a node whose exporter is down or
			// stale must not lose its GPUs from the denominator by one click.
			findings.addWithBlocking(DiscrepancyProposedRemoval, entity.NodeID, entity.PhysicalGPUUUID, "", unconfirmed[entity.NodeID])
		}
		sortEntities(removals)
		preview.Removals = removals
		existing := make(map[string]struct{}, len(in.Current.Entities))
		for _, entity := range in.Current.Entities {
			existing[entity.Key()] = struct{}{}
		}
		for _, entity := range entities {
			if _, known := existing[entity.Key()]; !known {
				preview.Additions++
			}
		}
	} else {
		preview.Removals = []EntityIdentity{}
		preview.Additions = len(entities)
	}

	if len(entities) > ExpectedInventoryMaxEntities {
		return ExpectedInventoryPreview{}, fmt.Errorf("expected inventory preview proposes more than %d entities", ExpectedInventoryMaxEntities)
	}
	preview.Discrepancies = findings.sorted()
	preview.Blocking = preview.DerivedBlocking()
	return preview, nil
}

// DerivedBlocking re-derives the refusal from the findings themselves. The
// stored Blocking flag is a cached summary; an import re-derives it here and
// refuses a stored preview whose flag and findings disagree, so a row that
// was written or migrated with a stale summary cannot approve findings the
// operator was shown as blocking.
func (preview ExpectedInventoryPreview) DerivedBlocking() bool {
	for _, finding := range preview.Discrepancies {
		if finding.Blocking {
			return true
		}
	}
	return false
}

// ExpectedInventoryPreviewDigest binds an approval to exactly one preview.
// The encoding is canonical JSON with sorted object keys and RFC3339Nano UTC
// timestamps, so any change to any field changes the digest.
func ExpectedInventoryPreviewDigest(preview ExpectedInventoryPreview) (SHA256, error) {
	encoded, err := json.Marshal(canonicalExpectedInventoryPreview(preview))
	if err != nil {
		return SHA256{}, fmt.Errorf("encode expected inventory preview: %w", err)
	}
	// Re-encoding through a generic value sorts every object key: Go emits
	// map keys in sorted order, so the digest does not depend on the order
	// Go struct fields happen to be declared in.
	var generic any
	if err := json.Unmarshal(encoded, &generic); err != nil {
		return SHA256{}, fmt.Errorf("canonicalize expected inventory preview: %w", err)
	}
	canonical, err := json.Marshal(generic)
	if err != nil {
		return SHA256{}, fmt.Errorf("canonicalize expected inventory preview: %w", err)
	}
	return sha256.Sum256(canonical), nil
}

// ExpectedInventoryRevisionFromPreview converts an approved preview into the
// GP-02 revision that RecordExpectedInventoryRevision will persist.
//
// SourceAt is the head's listing time, which is a fact about the discovery.
// EffectiveAt and ObservedAt are approvedAt — the moment the operator
// approved — and never the preview's generation time: a declaration takes
// effect when it is declared. Using the generation time would let an older
// preview, approved after a newer one, backdate itself behind the revision
// already in force and silently supersede it. The generation time stays on
// the preview record, which is where the provenance question is asked.
func ExpectedInventoryRevisionFromPreview(preview ExpectedInventoryPreview, revisionID InventoryRevisionID, approvedAt time.Time) (InventoryRevision, error) {
	if preview.SchemaVersion != ExpectedInventoryPreviewSchemaVersion {
		return InventoryRevision{}, fmt.Errorf("unsupported expected inventory preview schema version %d", preview.SchemaVersion)
	}
	if preview.Blocking || preview.DerivedBlocking() {
		return InventoryRevision{}, fmt.Errorf("expected inventory preview has blocking discrepancies")
	}
	if approvedAt.IsZero() {
		return InventoryRevision{}, fmt.Errorf("expected inventory revision requires the approval time")
	}
	entities := make([]EntityIdentity, len(preview.Entities))
	copy(entities, preview.Entities)
	return CreateInventoryRevision(InventoryRevision{
		SchemaVersion: InventoryContractSchemaVersion, ID: revisionID,
		ClusterID: preview.ClusterID, SourceID: preview.SourceID,
		SourceAt: preview.DiscoveryCompletedAt, EffectiveAt: approvedAt.UTC(),
		ObservedAt: approvedAt.UTC(), Entities: entities,
	})
}

type discrepancySet struct {
	seen  map[InventoryDiscrepancy]struct{}
	items []InventoryDiscrepancy
}

func newDiscrepancySet() *discrepancySet {
	return &discrepancySet{seen: map[InventoryDiscrepancy]struct{}{}}
}

func (set *discrepancySet) add(code InventoryDiscrepancyCode, node StableNodeID, uuid PhysicalGPUUUID, deviceType string) {
	set.addWithBlocking(code, node, uuid, deviceType, blockingDiscrepancies[code])
}

// addWithBlocking is the one escape from the code-derived blocking table, for
// the single code whose severity depends on the rest of the reconciliation.
// It can only ever raise severity: a code that is blocking by its own nature
// stays blocking whatever the caller passes.
func (set *discrepancySet) addWithBlocking(code InventoryDiscrepancyCode, node StableNodeID, uuid PhysicalGPUUUID, deviceType string, blocking bool) {
	set.appendFinding(InventoryDiscrepancy{
		Code: code, Blocking: blocking || blockingDiscrepancies[code], NodeID: node, GPUUUID: uuid,
		DeviceType: deviceType, Detail: discrepancyDetails[code],
	})
}

// addWithDetail carries a Detail the fixed table cannot hold because it names
// the BCM category the finding is about. The text is still built here from a
// fixed prefix and one sanitized, bounded configuration value; nothing read
// from a credential-bearing path or from a host response reaches it, and
// blocking stays derived from the code.
func (set *discrepancySet) addWithDetail(code InventoryDiscrepancyCode, node StableNodeID, uuid PhysicalGPUUUID, deviceType, detail string) {
	set.appendFinding(InventoryDiscrepancy{
		Code: code, Blocking: blockingDiscrepancies[code], NodeID: node, GPUUUID: uuid,
		DeviceType: deviceType, Detail: detail,
	})
}

func (set *discrepancySet) appendFinding(finding InventoryDiscrepancy) {
	if _, duplicate := set.seen[finding]; duplicate {
		return
	}
	set.seen[finding] = struct{}{}
	set.items = append(set.items, finding)
}

func (set *discrepancySet) sorted() []InventoryDiscrepancy {
	items := make([]InventoryDiscrepancy, len(set.items))
	copy(items, set.items)
	sort.Slice(items, func(first, second int) bool {
		left, right := items[first], items[second]
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		if left.NodeID != right.NodeID {
			return left.NodeID < right.NodeID
		}
		if left.GPUUUID != right.GPUUUID {
			return left.GPUUUID < right.GPUUUID
		}
		if left.DeviceType != right.DeviceType {
			return left.DeviceType < right.DeviceType
		}
		// Detail is the last tiebreak so the ordering is total. Two findings
		// that differ only in Detail — the category-scoped codes, which carry
		// the category name there — would otherwise compare equal and be left
		// in whatever order an unstable sort produced, which would make the
		// digest of one reconciliation depend on nothing at all.
		return left.Detail < right.Detail
	})
	return items
}

func managedDeviceType(value string, managed []string) bool {
	for _, candidate := range managed {
		if value == candidate {
			return true
		}
	}
	return false
}

// isMIGIdentity recognizes the MIG identity shapes NVIDIA emits. A MIG
// instance is a partition, never a physical GPU identity.
func isMIGIdentity(value string) bool {
	trimmed := strings.TrimSpace(value)
	upper := strings.ToUpper(trimmed)
	return strings.HasPrefix(upper, "MIG-") || strings.Contains(upper, "/MIG") ||
		strings.Contains(upper, "MIG-GPU-") || strings.Contains(trimmed, "/")
}

// nearMatchesManagedNode reports whether an unmanaged observed identifier is
// close enough to a managed hostname that adopting it would be a guess:
// equal ignoring case, or a short/FQDN prefix relationship.
func nearMatchesManagedNode(observed StableNodeID, managed []StableNodeID) bool {
	candidate := strings.TrimSpace(string(observed))
	if candidate == "" {
		return false
	}
	for _, node := range managed {
		name := string(node)
		if strings.EqualFold(candidate, name) {
			return true
		}
		if shortNameOf(candidate) != "" && strings.EqualFold(shortNameOf(candidate), shortNameOf(name)) {
			return true
		}
	}
	return false
}

func shortNameOf(value string) string {
	if index := strings.Index(value, "."); index > 0 {
		return value[:index]
	}
	return value
}

func entityKindRank(kind EntityKind) int {
	switch kind {
	case EntityNode:
		return 0
	case EntityGPU:
		return 1
	default:
		return 2
	}
}

func sortEntities(entities []EntityIdentity) {
	sort.Slice(entities, func(first, second int) bool {
		left, right := entities[first], entities[second]
		if left.NodeID != right.NodeID {
			return left.NodeID < right.NodeID
		}
		if leftRank, rightRank := entityKindRank(left.Kind), entityKindRank(right.Kind); leftRank != rightRank {
			return leftRank < rightRank
		}
		if left.PhysicalGPUUUID != right.PhysicalGPUUUID {
			return left.PhysicalGPUUUID < right.PhysicalGPUUUID
		}
		return left.MIGIdentity < right.MIGIdentity
	})
}

// The canonical encoding is separate from any transport DTO on purpose: a
// later wire field must not silently change an approved preview's digest.
type canonicalEntity struct {
	Kind    string `json:"kind"`
	NodeID  string `json:"node_id"`
	GPUUUID string `json:"physical_gpu_uuid"`
	MIG     string `json:"mig_identity"`
}

type canonicalDevice struct {
	Type         string `json:"type"`
	Hostname     string `json:"hostname"`
	Category     string `json:"category"`
	Status       string `json:"status"`
	Managed      bool   `json:"managed"`
	ObservedGPUs int    `json:"observed_gpus"`
	Included     bool   `json:"included"`
}

type canonicalDiscrepancy struct {
	Code       string `json:"code"`
	Blocking   bool   `json:"blocking"`
	NodeID     string `json:"node_id"`
	GPUUUID    string `json:"physical_gpu_uuid"`
	DeviceType string `json:"device_type"`
	Detail     string `json:"detail"`
}

type canonicalPreview struct {
	SchemaVersion        int                    `json:"schema_version"`
	ClusterID            string                 `json:"cluster_id"`
	SourceID             string                 `json:"source_id"`
	GeneratedAt          string                 `json:"generated_at"`
	DiscoveryTestID      string                 `json:"discovery_test_id"`
	DiscoveryCompletedAt string                 `json:"discovery_completed_at"`
	CredentialID         string                 `json:"credential_id"`
	CredentialVersion    int64                  `json:"credential_version"`
	BCMVersion           string                 `json:"bcm_version"`
	Entities             []canonicalEntity      `json:"entities"`
	Devices              []canonicalDevice      `json:"devices"`
	Discrepancies        []canonicalDiscrepancy `json:"discrepancies"`
	Removals             []canonicalEntity      `json:"removals"`
	ExcludedNodes        []string               `json:"excluded_nodes"`
	ExcludedCategories   []string               `json:"excluded_categories"`
	Additions            int                    `json:"additions"`
	Blocking             bool                   `json:"blocking"`
	NodeCount            int                    `json:"node_count"`
	GPUCount             int                    `json:"gpu_count"`
}

func canonicalExpectedInventoryPreview(preview ExpectedInventoryPreview) canonicalPreview {
	canonical := canonicalPreview{
		SchemaVersion: preview.SchemaVersion, ClusterID: string(preview.ClusterID), SourceID: string(preview.SourceID),
		GeneratedAt: canonicalTime(preview.GeneratedAt), DiscoveryTestID: preview.DiscoveryTestID,
		DiscoveryCompletedAt: canonicalTime(preview.DiscoveryCompletedAt), CredentialID: preview.CredentialID,
		CredentialVersion: preview.CredentialVersion, BCMVersion: preview.BCMVersion,
		Entities: canonicalEntities(preview.Entities), Devices: make([]canonicalDevice, 0, len(preview.Devices)),
		Discrepancies: make([]canonicalDiscrepancy, 0, len(preview.Discrepancies)),
		Removals:      canonicalEntities(preview.Removals), ExcludedNodes: canonicalNodeIDs(preview.ExcludedNodes),
		ExcludedCategories: append([]string{}, preview.ExcludedCategories...),
		Additions:          preview.Additions,
		Blocking:           preview.Blocking, NodeCount: preview.NodeCount, GPUCount: preview.GPUCount,
	}
	// The two shapes are identical by construction: a new preview device
	// field must be added to the canonical encoding, or the digest would
	// stop covering it.
	for _, device := range preview.Devices {
		canonical.Devices = append(canonical.Devices, canonicalDevice(device))
	}
	for _, finding := range preview.Discrepancies {
		canonical.Discrepancies = append(canonical.Discrepancies, canonicalDiscrepancy{
			Code: string(finding.Code), Blocking: finding.Blocking, NodeID: string(finding.NodeID),
			GPUUUID: string(finding.GPUUUID), DeviceType: finding.DeviceType, Detail: finding.Detail,
		})
	}
	return canonical
}

func canonicalEntities(entities []EntityIdentity) []canonicalEntity {
	canonical := make([]canonicalEntity, 0, len(entities))
	for _, entity := range entities {
		canonical = append(canonical, canonicalEntity{
			Kind: string(entity.Kind), NodeID: string(entity.NodeID),
			GPUUUID: string(entity.PhysicalGPUUUID), MIG: string(entity.MIGIdentity),
		})
	}
	return canonical
}

func canonicalTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func canonicalNodeIDs(nodes []StableNodeID) []string {
	canonical := make([]string, 0, len(nodes))
	for _, node := range nodes {
		canonical = append(canonical, string(node))
	}
	return canonical
}

// normalizeExcludedNodes sorts and deduplicates the operator's exclusion list
// and refuses anything that is not a hostname-shaped identifier. The list is
// part of the digest, so the normalization has to be total: two requests that
// name the same hostnames in a different order are the same decision and must
// produce the same preview.
func normalizeExcludedNodes(nodes []StableNodeID) ([]StableNodeID, error) {
	if len(nodes) > ExpectedInventoryMaxExcludedNodes {
		return nil, fmt.Errorf("expected inventory preview excludes more than %d nodes", ExpectedInventoryMaxExcludedNodes)
	}
	seen := make(map[StableNodeID]struct{}, len(nodes))
	normalized := make([]StableNodeID, 0, len(nodes))
	for _, node := range nodes {
		if !validExcludedNodeIdentifier(string(node)) {
			return nil, fmt.Errorf("expected inventory preview exclusion is not a hostname-shaped identifier")
		}
		if _, duplicate := seen[node]; duplicate {
			continue
		}
		seen[node] = struct{}{}
		normalized = append(normalized, node)
	}
	sort.Slice(normalized, func(first, second int) bool { return normalized[first] < normalized[second] })
	return normalized, nil
}

// normalizeExcludedCategories applies the same total normalization to the
// category exclusion list. The list is part of the digest, so two requests
// that name the same categories in a different order must produce the same
// preview, exactly as for hostnames.
func normalizeExcludedCategories(categories []string) ([]string, error) {
	if len(categories) > ExpectedInventoryMaxExcludedCategories {
		return nil, fmt.Errorf("expected inventory preview excludes more than %d categories", ExpectedInventoryMaxExcludedCategories)
	}
	seen := make(map[string]struct{}, len(categories))
	normalized := make([]string, 0, len(categories))
	for _, category := range categories {
		if !validExcludedNodeIdentifier(category) {
			return nil, fmt.Errorf("expected inventory preview exclusion is not a category-shaped identifier")
		}
		if _, duplicate := seen[category]; duplicate {
			continue
		}
		seen[category] = struct{}{}
		normalized = append(normalized, category)
	}
	sort.Strings(normalized)
	return normalized, nil
}

// validExcludedNodeIdentifier accepts a bounded identifier with no whitespace
// and no control character. It is deliberately stricter than the goodput
// identifier rule: an exclusion is matched against a hostname exactly, so a
// value that could not be a hostname can only ever be a typo.
func validExcludedNodeIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character <= ' ' || character == 0x7f {
			return false
		}
	}
	return true
}

// parseDeviceStatus reads a BCM device status of the shape
// "[ UP ], health check failed, restart required (interface:ipmi0)". It
// returns the bracketed state token with its inner whitespace collapsed and
// upper-cased, whether a bracket token was present at all, and whether any
// text follows the bracket. The trailing text itself is never returned into a
// finding: the status column already shows it verbatim.
func parseDeviceStatus(status string) (state string, bracketed bool, health bool) {
	trimmed := strings.TrimSpace(status)
	if !strings.HasPrefix(trimmed, "[") {
		return "", false, false
	}
	end := strings.Index(trimmed, "]")
	if end < 0 {
		return "", false, false
	}
	state = strings.ToUpper(strings.Join(strings.Fields(trimmed[1:end]), " "))
	rest := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(trimmed[end+1:]), ","))
	return state, true, rest != ""
}
