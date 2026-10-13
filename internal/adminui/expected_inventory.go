package adminui

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ExpectedInventoryEntity is one stable identity the preview proposes.
type ExpectedInventoryEntity struct {
	Kind    string
	NodeID  string
	GPUUUID string
}

// ExpectedInventoryDevice is one listed BCM device as the preview classified
// it. Listing a device is not verification of anything about that device.
type ExpectedInventoryDevice struct {
	Type         string
	Hostname     string
	Category     string
	Status       string
	Managed      bool
	ObservedGPUs int
	Included     bool
}

// ExpectedInventoryDiscrepancy is one explicit finding with fixed text.
type ExpectedInventoryDiscrepancy struct {
	Code       string
	Blocking   bool
	NodeID     string
	GPUUUID    string
	DeviceType string
	Detail     string
}

// ExpectedInventoryPreview is the dashboard projection of one proposal.
type ExpectedInventoryPreview struct {
	PreviewID            string
	ClusterID            string
	SourceID             string
	Digest               string
	Blocking             bool
	GeneratedBy          string
	GeneratedAt          time.Time
	ExpiresAt            time.Time
	DiscoveryTestID      string
	DiscoveryCompletedAt time.Time
	CredentialID         string
	CredentialVersion    int64
	BCMVersion           string
	NodeCount            int
	GPUCount             int
	Additions            int
	Entities             []ExpectedInventoryEntity
	Devices              []ExpectedInventoryDevice
	Discrepancies        []ExpectedInventoryDiscrepancy
	Removals             []ExpectedInventoryEntity
	ExcludedNodes        []string
	ExcludedCategories   []string
	ImportedRevisionID   string
	ImportedBy           string
	ImportedAt           *time.Time
	// Superseded is true when this preview's stored content was persisted
	// under an earlier schema version. It is never importable: the operator
	// must generate a fresh preview instead.
	Superseded       bool
	SupersededReason string
}

// Imported reports whether this exact proposal already produced a revision.
func (preview ExpectedInventoryPreview) Imported() bool { return preview.ImportedAt != nil }

// ImportedAtTime is the template-safe import time; the zero value renders as
// "Not observed" rather than as a pointer.
func (preview ExpectedInventoryPreview) ImportedAtTime() time.Time {
	if preview.ImportedAt == nil {
		return time.Time{}
	}
	return *preview.ImportedAt
}

// ShortDigest is the operator-facing abbreviation. The full value stays
// available in the element title so an approval can be checked by eye.
func (preview ExpectedInventoryPreview) ShortDigest() string {
	if len(preview.Digest) <= 16 {
		return preview.Digest
	}
	return preview.Digest[:16]
}

// BlockingDiscrepancies returns only the findings that refuse an import.
func (preview ExpectedInventoryPreview) BlockingDiscrepancies() []ExpectedInventoryDiscrepancy {
	blocking := []ExpectedInventoryDiscrepancy{}
	for _, finding := range preview.Discrepancies {
		if finding.Blocking {
			blocking = append(blocking, finding)
		}
	}
	return blocking
}

// ExpectedInventoryNodeSummary is one proposed node with its GPU count and
// the codes that were reported against it.
type ExpectedInventoryNodeSummary struct {
	NodeID string
	GPUs   int
	Flags  []string
	// GPUsUnknown is true when the node reported no physical GPU identity at
	// all. Its GPU count is then not zero GPUs, it is no statement.
	GPUsUnknown bool
}

// NodeSummaries groups the proposed entities per node, in entity order, and
// attaches every discrepancy code reported against the node — including the
// GPU-scoped ones, whose node is named on the finding. A stale or invalid
// identity on a node is a fact about that node's row: leaving it only in the
// separate discrepancy list would let a node read as clean in the table an
// operator scans before approving.
func (preview ExpectedInventoryPreview) NodeSummaries() []ExpectedInventoryNodeSummary {
	order := make([]string, 0, preview.NodeCount)
	counts := map[string]int{}
	for _, entity := range preview.Entities {
		switch entity.Kind {
		case "NODE":
			if _, seen := counts[entity.NodeID]; !seen {
				counts[entity.NodeID] = 0
				order = append(order, entity.NodeID)
			}
		case "GPU":
			counts[entity.NodeID]++
		}
	}
	flags := map[string][]string{}
	seen := map[string]bool{}
	for _, finding := range preview.Discrepancies {
		if finding.NodeID == "" || seen[finding.NodeID+"\x00"+finding.Code] {
			continue
		}
		seen[finding.NodeID+"\x00"+finding.Code] = true
		flags[finding.NodeID] = append(flags[finding.NodeID], finding.Code)
	}
	summaries := make([]ExpectedInventoryNodeSummary, 0, len(order))
	for _, node := range order {
		summaries = append(summaries, ExpectedInventoryNodeSummary{
			NodeID: node, GPUs: counts[node], Flags: flags[node],
			GPUsUnknown: preview.NodeGPUsUnknown(node),
		})
	}
	return summaries
}

// NodeGPUsUnknown reports whether the node's GPU count is unknown rather than
// zero. A managed node whose exporter reported nothing has no GPU statement
// at all; rendering that as "0" would read as a node that is installed and
// genuinely has no GPU, which is a different and approvable claim.
func (preview ExpectedInventoryPreview) NodeGPUsUnknown(nodeID string) bool {
	if nodeID == "" {
		return false
	}
	for _, finding := range preview.Discrepancies {
		if finding.NodeID == nodeID && finding.Code == "NODE_MISSING_TELEMETRY" {
			return true
		}
	}
	return false
}

// NodeExcluded reports whether the operator excluded this device from the
// proposal. Its GPU count is then not a claim about the inventory at all.
func (preview ExpectedInventoryPreview) NodeExcluded(nodeID string) bool {
	return preview.nodeHasCode(nodeID, "NODE_EXCLUDED_BY_OPERATOR")
}

// NodeUnclassified reports whether the device was listed with no GPU evidence
// and is not an expected member, so the preview refuses to guess what it is.
func (preview ExpectedInventoryPreview) NodeUnclassified(nodeID string) bool {
	return preview.nodeHasCode(nodeID, "NODE_UNCLASSIFIED")
}

func (preview ExpectedInventoryPreview) nodeHasCode(nodeID, code string) bool {
	if nodeID == "" {
		return false
	}
	for _, finding := range preview.Discrepancies {
		if finding.NodeID == nodeID && finding.Code == code {
			return true
		}
	}
	return false
}

// ExpectedInventoryRevision is the redacted header of the revision in force.
type ExpectedInventoryRevision struct {
	RevisionID  string
	SourceAt    time.Time
	EffectiveAt time.Time
	ObservedAt  time.Time
	NodeCount   int
	GPUCount    int
}

// ExpectedInventoryState is what the cluster edit page renders.
type ExpectedInventoryState struct {
	ClusterID            string
	SourceID             string
	Current              *ExpectedInventoryRevision
	LatestPreview        *ExpectedInventoryPreview
	DiscoveryAvailable   bool
	DiscoveryTestID      string
	DiscoveryCompletedAt time.Time
}

// ExpectedInventoryImport is the outcome of approving one exact proposal.
type ExpectedInventoryImport struct {
	PreviewID       string
	RevisionID      string
	AlreadyImported bool
}

// ExpectedInventoryProvider is optional and separate from the credential
// providers, so the expected-inventory section appears only when the private
// API offers it.
type ExpectedInventoryProvider interface {
	GetExpectedInventory(context.Context, string, string) (ExpectedInventoryState, error)
	GenerateExpectedInventoryPreview(context.Context, string, string, string, []string, []string, MutationContext) (ExpectedInventoryPreview, error)
	ImportExpectedInventoryPreview(context.Context, string, string, string, string, MutationContext) (ExpectedInventoryImport, error)
}

// expectedInventorySection is the rendered state of the page section. Enabled
// is false when the identity has no grant or the feature is not configured,
// in which case no inventory detail is shown at all.
type expectedInventorySection struct {
	Enabled       bool
	Status        string
	Message       string
	SourceID      string
	Current       *ExpectedInventoryRevision
	Preview       *ExpectedInventoryPreview
	Discovery     bool
	DiscoveryText string
	CanGenerate   bool
	CanImport     bool
}

// loadExpectedInventorySection reads the cluster's expected-inventory state
// for the page. A failure is reported as an unavailable section, never as a
// claim that a cluster has no expected inventory.
func (server *Server) loadExpectedInventorySection(request *http.Request, clusterID string) expectedInventorySection {
	section := expectedInventorySection{Message: expectedInventoryMessage(request)}
	if server.expectedInventoryProvider == nil {
		return section
	}
	identity := requestIdentity(request)
	state, err := server.expectedInventoryProvider.GetExpectedInventory(request.Context(), clusterID, identity.Subject)
	if err != nil {
		section.Status = "Expected inventory is unavailable or this Access identity has no cluster grant."
		return section
	}
	section.Enabled = true
	section.SourceID, section.Current = state.SourceID, state.Current
	section.Discovery, section.CanGenerate = state.DiscoveryAvailable, state.DiscoveryAvailable && clusterAccess(request.Context(), clusterID).CanManagePolicy
	if !state.DiscoveryAvailable {
		section.DiscoveryText = "No successful BCM inventory discovery is listed for this cluster. Run \"Discover BCM inventory\" on an active credential first."
	}
	if state.LatestPreview != nil {
		preview := *state.LatestPreview
		section.Preview = &preview
		section.CanImport = clusterAccess(request.Context(), clusterID).CanManagePolicy && !preview.Superseded && !preview.Blocking && !preview.Imported() && preview.ExpiresAt.After(server.clock.Now().UTC())
	}
	return section
}

func expectedInventoryMessage(request *http.Request) string {
	switch request.URL.Query().Get("inventory") {
	case "previewed":
		return "Expected-inventory preview generated. Review the devices, entities and discrepancies below before approving."
	case "preview_error":
		return "The preview was not generated. A successful BCM inventory discovery and a cluster grant are required."
	case "imported":
		return "Expected inventory imported. The approved preview is now the expected revision for this source."
	case "already_imported":
		return "This preview had already been imported. No new revision was recorded."
	case "import_error":
		return "The import was not applied. The preview may be blocking, expired, already superseded, or the approved digest may not match."
	}
	return ""
}

// generateExpectedInventoryPreview posts the reconciliation request. It uses
// the same CSRF, same-origin and grant handling as the credential buttons.
func (server *Server) generateExpectedInventoryPreview(writer http.ResponseWriter, request *http.Request) {
	key, csrfToken, ok := server.requireAccess(writer, request)
	if !ok {
		return
	}
	if server.expectedInventoryProvider == nil {
		http.Error(writer, "expected inventory management is not configured", http.StatusServiceUnavailable)
		return
	}
	if !server.parseAndVerifyCSRF(writer, request, csrfToken) {
		return
	}
	clusterID := strings.TrimSpace(request.PathValue("id"))
	if !validAdminToken(clusterID) {
		http.Error(writer, "invalid cluster reference", http.StatusBadRequest)
		return
	}
	sourceID := strings.TrimSpace(request.PostForm.Get("source_id"))
	if sourceID != "" && !validAdminToken(sourceID) {
		http.Error(writer, "invalid source reference", http.StatusBadRequest)
		return
	}
	excludeNodes, ok := parseExcludedNodes(request.PostForm.Get("exclude_nodes"))
	if !ok {
		http.Error(writer, "invalid node exclusion list", http.StatusBadRequest)
		return
	}
	excludeCategories, ok := parseExcludedCategories(request.PostForm.Get("exclude_categories"))
	if !ok {
		http.Error(writer, "invalid category exclusion list", http.StatusBadRequest)
		return
	}
	identity := requestIdentity(request)
	if _, err := server.expectedInventoryProvider.GenerateExpectedInventoryPreview(request.Context(), clusterID, identity.Subject, sourceID, excludeNodes, excludeCategories, server.mutationContext(request, key)); err != nil {
		server.redirectExpectedInventory(writer, request, clusterID, "preview_error")
		return
	}
	server.redirectExpectedInventory(writer, request, clusterID, "previewed")
}

// importExpectedInventoryPreview approves exactly the preview the operator
// saw: the posted digest is forwarded unchanged and is what the store
// compares against the stored content.
func (server *Server) importExpectedInventoryPreview(writer http.ResponseWriter, request *http.Request) {
	key, csrfToken, ok := server.requireAccess(writer, request)
	if !ok {
		return
	}
	if server.expectedInventoryProvider == nil {
		http.Error(writer, "expected inventory management is not configured", http.StatusServiceUnavailable)
		return
	}
	if !server.parseAndVerifyCSRF(writer, request, csrfToken) {
		return
	}
	clusterID := strings.TrimSpace(request.PathValue("id"))
	previewID := strings.TrimSpace(request.PostForm.Get("preview_id"))
	digest := strings.TrimSpace(request.PostForm.Get("digest"))
	if !validAdminToken(clusterID) || !validPreviewIdentifier(previewID) || !validPreviewDigest(digest) {
		http.Error(writer, "invalid expected inventory approval", http.StatusBadRequest)
		return
	}
	identity := requestIdentity(request)
	result, err := server.expectedInventoryProvider.ImportExpectedInventoryPreview(request.Context(), clusterID, identity.Subject, previewID, digest, server.mutationContext(request, key))
	if err != nil {
		server.redirectExpectedInventory(writer, request, clusterID, "import_error")
		return
	}
	outcome := "imported"
	if result.AlreadyImported {
		outcome = "already_imported"
	}
	server.redirectExpectedInventory(writer, request, clusterID, outcome)
}

func (server *Server) redirectExpectedInventory(writer http.ResponseWriter, request *http.Request, clusterID, outcome string) {
	http.Redirect(writer, request, "/admin/clusters/"+url.PathEscape(clusterID)+"/edit?inventory="+outcome+"#expected-inventory", http.StatusSeeOther)
}

// parseExcludedNodes splits the operator's free-text field on commas and
// whitespace. An entry that cannot be a hostname is refused rather than
// dropped: a silently ignored exclusion would leave the operator approving
// the node they meant to leave out.
func parseExcludedNodes(value string) ([]string, bool) {
	fields := strings.FieldsFunc(value, func(character rune) bool {
		return character == ',' || character == ';' || character <= ' '
	})
	if len(fields) > 256 {
		return nil, false
	}
	nodes := make([]string, 0, len(fields))
	for _, field := range fields {
		if len(field) > 128 {
			return nil, false
		}
		nodes = append(nodes, field)
	}
	return nodes, true
}

// parseExcludedCategories applies the same splitting to the category field.
// A BCM category name has no whitespace, so the same separators are safe and
// an entry that cannot be one is refused rather than dropped.
func parseExcludedCategories(value string) ([]string, bool) {
	fields := strings.FieldsFunc(value, func(character rune) bool {
		return character == ',' || character == ';' || character <= ' '
	})
	if len(fields) > 64 {
		return nil, false
	}
	categories := make([]string, 0, len(fields))
	for _, field := range fields {
		if len(field) > 128 {
			return nil, false
		}
		categories = append(categories, field)
	}
	return categories, true
}

// CategoryUnclassified reports whether this device's BCM category was left
// unclassified, so the device is listed but not proposed. The finding is
// reported against the category, so the device row is matched by its own
// category value rather than by hostname.
func (preview ExpectedInventoryPreview) CategoryUnclassified(category string) bool {
	if category == "" {
		return false
	}
	for _, finding := range preview.Discrepancies {
		if finding.Code == "CATEGORY_UNCLASSIFIED" && strings.HasSuffix(finding.Detail, ": "+category) {
			return true
		}
	}
	return false
}

func validPreviewDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

// validPreviewIdentifier accepts the preview identifier shape only. It is
// deliberately not the cluster-token validator: a preview identifier carries
// base64url characters ("_" and "-") that a cluster identifier never has.
func validPreviewIdentifier(value string) bool {
	if len(value) < 5 || len(value) > 128 || !strings.HasPrefix(value, "ipv_") {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("_-", character) {
			continue
		}
		return false
	}
	return true
}
