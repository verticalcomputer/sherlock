package adminui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const uiPreviewDigest = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"

type expectedInventoryUIProvider struct {
	*credentialUIProvider
	state      ExpectedInventoryState
	stateErr   error
	subject    string
	sourceID   string
	previewID  string
	digest     string
	exclusions []string
	categories []string
	mutation   MutationContext
	importErr  error
	already    bool
}

func (provider *expectedInventoryUIProvider) GetExpectedInventory(_ context.Context, _ string, subject string) (ExpectedInventoryState, error) {
	provider.subject = subject
	return provider.state, provider.stateErr
}

func (provider *expectedInventoryUIProvider) GenerateExpectedInventoryPreview(_ context.Context, _ string, subject, sourceID string, excludeNodes, excludeCategories []string, mutation MutationContext) (ExpectedInventoryPreview, error) {
	provider.subject, provider.sourceID, provider.exclusions, provider.categories, provider.mutation = subject, sourceID, excludeNodes, excludeCategories, mutation
	return ExpectedInventoryPreview{PreviewID: "ipv_new"}, nil
}

func (provider *expectedInventoryUIProvider) ImportExpectedInventoryPreview(_ context.Context, _ string, subject, previewID, digest string, mutation MutationContext) (ExpectedInventoryImport, error) {
	provider.subject, provider.previewID, provider.digest, provider.mutation = subject, previewID, digest, mutation
	if provider.importErr != nil {
		return ExpectedInventoryImport{}, provider.importErr
	}
	return ExpectedInventoryImport{PreviewID: previewID, RevisionID: "exp_new", AlreadyImported: provider.already}, nil
}

func samplePreview(now time.Time) *ExpectedInventoryPreview {
	return &ExpectedInventoryPreview{
		PreviewID: "ipv_abc", ClusterID: "cluster-1", SourceID: "head-prometheus", Digest: uiPreviewDigest,
		GeneratedBy: "access-user-1", GeneratedAt: now, ExpiresAt: now.Add(24 * time.Hour),
		DiscoveryTestID: "ctest_inv", DiscoveryCompletedAt: now.Add(-time.Hour),
		CredentialID: "cred_active", CredentialVersion: 1, BCMVersion: "10.0",
		NodeCount: 2, GPUCount: 8, Additions: 10,
		Entities: []ExpectedInventoryEntity{
			{Kind: "NODE", NodeID: "fixture1-zone1-comp001"},
			{Kind: "GPU", NodeID: "fixture1-zone1-comp001", GPUUUID: "GPU-1"},
			{Kind: "NODE", NodeID: "fixture1-zone1-comp009"},
		},
		Devices: []ExpectedInventoryDevice{
			{Type: "HeadNode", Hostname: "fixture1-zone1-headnode", Status: "UP"},
			{Type: "PhysicalNode", Hostname: "fixture1-zone1-comp001", Category: "asus-h100-compute-category", Status: "UP", Managed: true, ObservedGPUs: 8, Included: true},
		},
		Discrepancies: []ExpectedInventoryDiscrepancy{
			{Code: "UNMANAGED_DEVICE", DeviceType: "HeadNode", Detail: "listed device is not a managed compute node type and is excluded"},
			{Code: "NODE_MISSING_TELEMETRY", NodeID: "fixture1-zone1-comp009", Detail: "managed node reports no physical GPU identity"},
		},
		Removals:           []ExpectedInventoryEntity{{Kind: "NODE", NodeID: "fixture1-zone1-retired"}},
		ExcludedNodes:      []string{"fixture1-zone1-loginnode"},
		ExcludedCategories: []string{"login-default-category"},
	}
}

func newExpectedInventoryUI(t *testing.T, provider *expectedInventoryUIProvider, clock *fakeClock) *Server {
	t.Helper()
	server, err := New(Options{Provider: provider, AccessVerifier: fakeAccessVerifier{}, Auditor: &fakeAuditor{}, ErrorReporter: &fakeErrorReporter{}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func renderEditPage(t *testing.T, server *Server, query string) string {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "https://admin.example/admin/clusters/cluster-1/edit"+query, nil)
	request.Header.Set(accessAssertionHeader, testAssertion)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("edit page code=%d", response.Code)
	}
	return response.Body.String()
}

func TestExpectedInventoryUIShowsPreviewAndNeverClaimsVerification(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	provider := &expectedInventoryUIProvider{credentialUIProvider: &credentialUIProvider{fakeProvider: sampleProvider()}}
	provider.state = ExpectedInventoryState{ClusterID: "cluster-1", SourceID: "head-prometheus"}
	server := newExpectedInventoryUI(t, provider, clock)

	empty := renderEditPage(t, server, "")
	if !strings.Contains(empty, "Expected inventory") || !strings.Contains(empty, "No expected inventory revision is in force") {
		t.Fatalf("empty section:\n%s", empty)
	}
	if !strings.Contains(empty, "No successful BCM inventory discovery is listed") ||
		!strings.Contains(empty, "<button type=\"button\" disabled>Generate preview from BCM discovery</button>") {
		t.Fatalf("generate button should be disabled without a discovery:\n%s", empty)
	}
	if provider.subject != "access-user-1" {
		t.Fatalf("state read used subject %q", provider.subject)
	}

	provider.state.DiscoveryAvailable, provider.state.DiscoveryTestID = true, "ctest_inv"
	provider.state.Current = &ExpectedInventoryRevision{RevisionID: "exp_old", SourceAt: now, EffectiveAt: now, ObservedAt: now, NodeCount: 11, GPUCount: 80}
	provider.state.LatestPreview = samplePreview(now)
	ready := renderEditPage(t, server, "")
	for _, fragment := range []string{
		"EXPECTED REVISION", "exp_old", "Generate preview from BCM discovery</button>",
		"ctest_inv", uiPreviewDigest[:16], "UNMANAGED_DEVICE", "NODE_MISSING_TELEMETRY",
		"fixture1-zone1-retired", "Approve and import this exact preview",
		`name="digest" value="` + uiPreviewDigest + `"`, `name="preview_id" value="ipv_abc"`,
	} {
		if !strings.Contains(ready, fragment) {
			t.Fatalf("ready preview missing %q:\n%s", fragment, ready)
		}
	}
	if strings.Contains(ready, "VERIFIED") || strings.Contains(strings.ToLower(ready), "hardware verified") {
		t.Fatalf("the expected-inventory section must never claim verification:\n%s", ready)
	}
}

func TestExpectedInventoryUIDisablesImportWhenBlockingExpiredOrImported(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		mutate   func(*ExpectedInventoryPreview)
		fragment string
	}{
		{"blocking", func(preview *ExpectedInventoryPreview) {
			preview.Blocking = true
			preview.Discrepancies = append(preview.Discrepancies, ExpectedInventoryDiscrepancy{Code: "DUPLICATE_GPU", Blocking: true, GPUUUID: "GPU-1", Detail: "physical GPU UUID is observed on more than one managed node"})
		}, "BLOCKING"},
		{"expired", func(preview *ExpectedInventoryPreview) { preview.ExpiresAt = now.Add(-time.Minute) }, "can no longer be approved"},
		{"imported", func(preview *ExpectedInventoryPreview) {
			imported := now
			preview.ImportedAt, preview.ImportedBy, preview.ImportedRevisionID = &imported, "access-user-1", "exp_done"
		}, "exp_done"},
		{"superseded", func(preview *ExpectedInventoryPreview) {
			preview.Superseded, preview.SupersededReason = true, "generated by an earlier preview format"
		}, "SUPERSEDED"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			provider := &expectedInventoryUIProvider{credentialUIProvider: &credentialUIProvider{fakeProvider: sampleProvider()}}
			preview := samplePreview(now)
			testCase.mutate(preview)
			provider.state = ExpectedInventoryState{ClusterID: "cluster-1", SourceID: "head-prometheus", DiscoveryAvailable: true, LatestPreview: preview}
			server := newExpectedInventoryUI(t, provider, &fakeClock{now: now})
			page := renderEditPage(t, server, "")
			if strings.Contains(page, "<button type=\"submit\">Approve and import this exact preview</button>") {
				t.Fatalf("%s preview offered an enabled import button:\n%s", testCase.name, page)
			}
			if !strings.Contains(page, testCase.fragment) {
				t.Fatalf("%s preview missing %q:\n%s", testCase.name, testCase.fragment, page)
			}
		})
	}
}

// TestExpectedInventoryUISupersededPreviewStillOffersGenerate proves the
// admin dashboard degradation this change fixes: a superseded latest
// preview, from a row the previous build persisted, must never hide the
// generate form. The operator's only way out of a superseded preview is to
// generate a fresh one, so the form has to render whenever a discovery is
// available, superseded preview or not.
func TestExpectedInventoryUISupersededPreviewStillOffersGenerate(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	provider := &expectedInventoryUIProvider{credentialUIProvider: &credentialUIProvider{fakeProvider: sampleProvider()}}
	preview := samplePreview(now)
	preview.Superseded, preview.SupersededReason = true, "generated by an earlier preview format"
	provider.state = ExpectedInventoryState{
		ClusterID: "cluster-1", SourceID: "head-prometheus", DiscoveryAvailable: true,
		DiscoveryTestID: "ctest_inv", LatestPreview: preview,
	}
	server := newExpectedInventoryUI(t, provider, &fakeClock{now: now})
	page := renderEditPage(t, server, "")
	if !strings.Contains(page, `<button type="submit">Generate preview from BCM discovery</button>`) {
		t.Fatalf("the generate form was not offered alongside a superseded preview:\n%s", page)
	}
	if !strings.Contains(page, "SUPERSEDED") || !strings.Contains(page, preview.SupersededReason) {
		t.Fatalf("the superseded badge or reason was not rendered:\n%s", page)
	}
	if strings.Contains(page, `<button type="submit">Approve and import this exact preview</button>`) {
		t.Fatalf("a superseded preview offered an enabled import button:\n%s", page)
	}
}

func TestExpectedInventoryUIRejectsUnverifiedMutations(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	provider := &expectedInventoryUIProvider{credentialUIProvider: &credentialUIProvider{fakeProvider: sampleProvider()}}
	provider.state = ExpectedInventoryState{ClusterID: "cluster-1", SourceID: "head-prometheus", DiscoveryAvailable: true, LatestPreview: samplePreview(now)}
	server := newExpectedInventoryUI(t, provider, &fakeClock{now: now})
	token := server.csrfToken(testAssertion)

	post := func(path string, form url.Values, origin string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "https://admin.example"+path, strings.NewReader(form.Encode()))
		request.Header.Set(accessAssertionHeader, testAssertion)
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		return response
	}

	approval := url.Values{"csrf_token": {token}, "preview_id": {"ipv_abc"}, "digest": {uiPreviewDigest}, "actor_subject": {"forged"}}
	accepted := post("/admin/clusters/cluster-1/expected-inventory/import", approval, "https://admin.example")
	if accepted.Code != http.StatusSeeOther || !strings.Contains(accepted.Header().Get("Location"), "inventory=imported") {
		t.Fatalf("import code=%d location=%q", accepted.Code, accepted.Header().Get("Location"))
	}
	if provider.previewID != "ipv_abc" || provider.digest != uiPreviewDigest {
		t.Fatalf("the approval was not forwarded unchanged: preview=%q digest=%q", provider.previewID, provider.digest)
	}
	if provider.subject != "access-user-1" || provider.mutation.ActorSubject != "access-user-1" {
		t.Fatalf("a form field overrode the verified identity: %+v", provider)
	}

	noCSRF := post("/admin/clusters/cluster-1/expected-inventory/import", url.Values{"preview_id": {"ipv_abc"}, "digest": {uiPreviewDigest}}, "https://admin.example")
	if noCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF token accepted: %d", noCSRF.Code)
	}
	crossOrigin := post("/admin/clusters/cluster-1/expected-inventory/import", approval, "https://evil.example")
	if crossOrigin.Code != http.StatusForbidden {
		t.Fatalf("cross-origin approval accepted: %d", crossOrigin.Code)
	}
	badDigest := post("/admin/clusters/cluster-1/expected-inventory/import", url.Values{"csrf_token": {token}, "preview_id": {"ipv_abc"}, "digest": {"abcd"}}, "https://admin.example")
	if badDigest.Code != http.StatusBadRequest {
		t.Fatalf("short digest accepted: %d", badDigest.Code)
	}
	badPreview := post("/admin/clusters/cluster-1/expected-inventory/import", url.Values{"csrf_token": {token}, "preview_id": {"exp_abc"}, "digest": {uiPreviewDigest}}, "https://admin.example")
	if badPreview.Code != http.StatusBadRequest {
		t.Fatalf("foreign preview identifier accepted: %d", badPreview.Code)
	}

	generate := post("/admin/clusters/cluster-1/expected-inventory/previews", url.Values{
		"csrf_token": {token}, "source_id": {"head-prometheus"},
		"exclude_nodes":      {"fixture1-zone1-loginnode, fixture1-zone1-comp003\n fixture1-zone1-comp004"},
		"exclude_categories": {"login-default-category other-category"},
	}, "https://admin.example")
	if generate.Code != http.StatusSeeOther || !strings.Contains(generate.Header().Get("Location"), "inventory=previewed") || provider.sourceID != "head-prometheus" {
		t.Fatalf("generate code=%d location=%q source=%q", generate.Code, generate.Header().Get("Location"), provider.sourceID)
	}
	// Commas and whitespace both separate; nothing is silently dropped.
	if strings.Join(provider.exclusions, "|") != "fixture1-zone1-loginnode|fixture1-zone1-comp003|fixture1-zone1-comp004" {
		t.Fatalf("the exclusion field was not forwarded: %+v", provider.exclusions)
	}
	if strings.Join(provider.categories, "|") != "login-default-category|other-category" {
		t.Fatalf("the category exclusion field was not forwarded: %+v", provider.categories)
	}
	tooLong := post("/admin/clusters/cluster-1/expected-inventory/previews", url.Values{
		"csrf_token": {token}, "exclude_nodes": {strings.Repeat("n", 129)},
	}, "https://admin.example")
	if tooLong.Code != http.StatusBadRequest {
		t.Fatalf("an oversized exclusion was accepted: %d", tooLong.Code)
	}
	tooLongCategory := post("/admin/clusters/cluster-1/expected-inventory/previews", url.Values{
		"csrf_token": {token}, "exclude_categories": {strings.Repeat("c", 129)},
	}, "https://admin.example")
	if tooLongCategory.Code != http.StatusBadRequest {
		t.Fatalf("an oversized category exclusion was accepted: %d", tooLongCategory.Code)
	}

	provider.already = true
	repeat := post("/admin/clusters/cluster-1/expected-inventory/import", approval, "https://admin.example")
	if !strings.Contains(repeat.Header().Get("Location"), "inventory=already_imported") {
		t.Fatalf("idempotent import location=%q", repeat.Header().Get("Location"))
	}
	provider.importErr = errors.New("refused")
	failed := post("/admin/clusters/cluster-1/expected-inventory/import", approval, "https://admin.example")
	if !strings.Contains(failed.Header().Get("Location"), "inventory=import_error") {
		t.Fatalf("refused import location=%q", failed.Header().Get("Location"))
	}
}

func TestExpectedInventoryUIReportsUnavailableRatherThanEmpty(t *testing.T) {
	provider := &expectedInventoryUIProvider{credentialUIProvider: &credentialUIProvider{fakeProvider: sampleProvider()}, stateErr: errors.New("no grant")}
	server := newExpectedInventoryUI(t, provider, &fakeClock{now: time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)})
	page := renderEditPage(t, server, "")
	if !strings.Contains(page, "Expected inventory is unavailable or this Access identity has no cluster grant.") {
		t.Fatalf("unavailable section:\n%s", page)
	}
	if strings.Contains(page, "No expected inventory revision is in force") {
		t.Fatalf("an unavailable read must not read as an empty inventory:\n%s", page)
	}
}

func TestExpectedInventoryPreviewNodeSummariesGroupEntities(t *testing.T) {
	preview := samplePreview(time.Now().UTC())
	summaries := preview.NodeSummaries()
	if len(summaries) != 2 || summaries[0].NodeID != "fixture1-zone1-comp001" || summaries[0].GPUs != 1 {
		t.Fatalf("summaries=%+v", summaries)
	}
	if summaries[1].NodeID != "fixture1-zone1-comp009" || summaries[1].GPUs != 0 || len(summaries[1].Flags) != 1 || summaries[1].Flags[0] != "NODE_MISSING_TELEMETRY" {
		t.Fatalf("missing-telemetry node summary=%+v", summaries[1])
	}
	preview.Blocking = true
	preview.Discrepancies = append(preview.Discrepancies, ExpectedInventoryDiscrepancy{Code: "DUPLICATE_GPU", Blocking: true})
	if blocking := preview.BlockingDiscrepancies(); len(blocking) != 1 || blocking[0].Code != "DUPLICATE_GPU" {
		t.Fatalf("blocking=%+v", blocking)
	}
	if preview.ShortDigest() != uiPreviewDigest[:16] {
		t.Fatalf("short digest %q", preview.ShortDigest())
	}
}

// TestExpectedInventoryNodeSummariesCarryGPUScopedFindings: a GPU-scoped
// finding names the node it was observed on, and the node table is what an
// operator scans before approving. Leaving those codes only in the separate
// discrepancy list would let a node with a stale or invalid identity read as
// clean in that table.
func TestExpectedInventoryNodeSummariesCarryGPUScopedFindings(t *testing.T) {
	preview := samplePreview(time.Now().UTC())
	preview.Discrepancies = append(preview.Discrepancies,
		ExpectedInventoryDiscrepancy{Code: "GPU_STALE_TELEMETRY", Blocking: true, NodeID: "fixture1-zone1-comp001", GPUUUID: "GPU-1", Detail: "stale"},
		ExpectedInventoryDiscrepancy{Code: "INVALID_GPU_IDENTITY", Blocking: true, NodeID: "fixture1-zone1-comp001", GPUUUID: "GPU-2", Detail: "invalid"},
		// A second stale identity on the same node is the same fact about
		// the node and is listed once.
		ExpectedInventoryDiscrepancy{Code: "GPU_STALE_TELEMETRY", Blocking: true, NodeID: "fixture1-zone1-comp001", GPUUUID: "GPU-3", Detail: "stale"},
	)
	summaries := preview.NodeSummaries()
	if len(summaries) != 2 {
		t.Fatalf("summaries=%+v", summaries)
	}
	if strings.Join(summaries[0].Flags, ",") != "GPU_STALE_TELEMETRY,INVALID_GPU_IDENTITY" {
		t.Fatalf("comp001 flags=%v", summaries[0].Flags)
	}
	if len(summaries[1].Flags) != 1 || summaries[1].Flags[0] != "NODE_MISSING_TELEMETRY" {
		t.Fatalf("comp009 flags=%v", summaries[1].Flags)
	}
}

// TestExpectedInventoryUIRendersUnknownGPUsForSilentNodes: a managed node
// whose exporter reported nothing has no GPU statement at all. Rendering that
// as "0" would read as a node that is installed and genuinely holds no GPU,
// which is a different and approvable claim.
func TestExpectedInventoryUIRendersUnknownGPUsForSilentNodes(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	provider := &expectedInventoryUIProvider{credentialUIProvider: &credentialUIProvider{fakeProvider: sampleProvider()}}
	preview := samplePreview(now)
	// comp009 is listed and managed by the head but reports no telemetry.
	preview.Devices = append(preview.Devices, ExpectedInventoryDevice{
		Type: "PhysicalNode", Hostname: "fixture1-zone1-comp009", Category: "asus-h100-compute-category",
		Status: "UP", Managed: true, ObservedGPUs: 0, Included: true,
	})
	provider.state = ExpectedInventoryState{
		ClusterID: "cluster-1", SourceID: "head-prometheus",
		DiscoveryAvailable: true, DiscoveryTestID: "ctest_inv", LatestPreview: preview,
	}
	server := newExpectedInventoryUI(t, provider, clock)
	page := renderEditPage(t, server, "")

	if !preview.NodeGPUsUnknown("fixture1-zone1-comp009") || preview.NodeGPUsUnknown("fixture1-zone1-comp001") {
		t.Fatal("NodeGPUsUnknown did not follow NODE_MISSING_TELEMETRY")
	}
	// The silent node's row carries the badge, never a zero count.
	deviceRow := `<td class="mono">fixture1-zone1-comp009</td><td class="mono">asus-h100-compute-category</td><td>UP</td><td>yes</td><td><span class="badge">unknown</span></td>`
	if !strings.Contains(page, deviceRow) {
		t.Fatalf("silent node device row did not render as unknown:\n%s", page)
	}
	summaryRow := `<td class="mono">fixture1-zone1-comp009</td><td><span class="badge">unknown</span></td>`
	if !strings.Contains(page, summaryRow) {
		t.Fatalf("silent node summary row did not render as unknown:\n%s", page)
	}
	if strings.Contains(page, `<td class="mono">fixture1-zone1-comp009</td><td>0</td>`) {
		t.Fatalf("a node with no telemetry rendered as 0 GPUs:\n%s", page)
	}
	// A node that is genuinely reporting still shows its count.
	if !strings.Contains(page, `<td class="mono">fixture1-zone1-comp001</td><td class="mono">asus-h100-compute-category</td><td>UP</td><td>yes</td><td>8</td>`) {
		t.Fatalf("a reporting node lost its GPU count:\n%s", page)
	}
}

// TestExpectedInventoryUIRendersOperatorDecisionsOnDeviceRows: an excluded or
// unclassified device is still listed, and its GPU column carries the reason
// it is not being proposed rather than a count. A count there would read as a
// claim about inventory the preview is deliberately not making.
func TestExpectedInventoryUIRendersOperatorDecisionsOnDeviceRows(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	provider := &expectedInventoryUIProvider{credentialUIProvider: &credentialUIProvider{fakeProvider: sampleProvider()}}
	preview := samplePreview(now)
	preview.Devices = append(preview.Devices,
		ExpectedInventoryDevice{Type: "PhysicalNode", Hostname: "fixture1-zone1-loginnode", Category: "login-default-category", Status: "[ UP ], health check failed", Managed: true},
		ExpectedInventoryDevice{Type: "PhysicalNode", Hostname: "fixture1-zone1-comp012", Status: "[ UP ]", Managed: true},
		ExpectedInventoryDevice{Type: "PhysicalNode", Hostname: "fixture1-zone1-svc001", Category: "service-default-category", Status: "[ UP ]", Managed: true},
	)
	preview.Discrepancies = append(preview.Discrepancies,
		ExpectedInventoryDiscrepancy{Code: "NODE_EXCLUDED_BY_OPERATOR", NodeID: "fixture1-zone1-loginnode", Detail: "excluded by the operator"},
		ExpectedInventoryDiscrepancy{Code: "DEVICE_HEALTH_WARNING", NodeID: "fixture1-zone1-loginnode", DeviceType: "PhysicalNode", Detail: "health or restart condition"},
		ExpectedInventoryDiscrepancy{Code: "NODE_UNCLASSIFIED", Blocking: true, NodeID: "fixture1-zone1-comp012", Detail: "not classifiable without an operator decision"},
		ExpectedInventoryDiscrepancy{Code: "CATEGORY_UNCLASSIFIED", Blocking: true, Detail: "no device in this BCM category reports a physical GPU identity; category: service-default-category"},
	)
	preview.Blocking = true
	provider.state = ExpectedInventoryState{
		ClusterID: "cluster-1", SourceID: "head-prometheus", DiscoveryAvailable: true, LatestPreview: preview,
	}
	server := newExpectedInventoryUI(t, provider, &fakeClock{now: now})
	page := renderEditPage(t, server, "")

	if !strings.Contains(page, `name="exclude_nodes"`) || !strings.Contains(page, "Exclude nodes (comma or whitespace separated hostnames)") {
		t.Fatalf("the exclusion field is missing from the generate form:\n%s", page)
	}
	if !strings.Contains(page, `name="exclude_categories"`) || !strings.Contains(page, "Exclude categories (comma or whitespace separated BCM device categories)") {
		t.Fatalf("the category exclusion field is missing from the generate form:\n%s", page)
	}
	if !strings.Contains(page, "Excluded categories: ") || !strings.Contains(page, `<span class="mono">login-default-category</span>`) {
		t.Fatalf("the category exclusion list was not shown:\n%s", page)
	}
	if !strings.Contains(page, "Excluded by operator: ") || !strings.Contains(page, `<span class="mono">fixture1-zone1-loginnode</span>`) {
		t.Fatalf("the exclusion list was not shown:\n%s", page)
	}
	if !strings.Contains(page, `<td class="mono">fixture1-zone1-loginnode</td><td class="mono">login-default-category</td><td>[ UP ], health check failed</td><td>yes</td><td><span class="badge">EXCLUDED</span></td>`) {
		t.Fatalf("the excluded device row did not render as EXCLUDED:\n%s", page)
	}
	if !strings.Contains(page, `<td class="mono">fixture1-zone1-comp012</td><td class="mono">—</td><td>[ UP ]</td><td>yes</td><td><span class="badge">UNCLASSIFIED</span></td>`) {
		t.Fatalf("the unclassified device row did not render as UNCLASSIFIED:\n%s", page)
	}
	if !strings.Contains(page, `<td class="mono">fixture1-zone1-svc001</td><td class="mono">service-default-category</td><td>[ UP ]</td><td>yes</td><td><span class="badge">CATEGORY UNCLASSIFIED</span></td>`) {
		t.Fatalf("the unclassified-category device row did not render its reason:\n%s", page)
	}
	for _, code := range []string{"NODE_EXCLUDED_BY_OPERATOR", "DEVICE_HEALTH_WARNING", "NODE_UNCLASSIFIED", "CATEGORY_UNCLASSIFIED"} {
		if !strings.Contains(page, code) {
			t.Fatalf("discrepancy %s was not listed:\n%s", code, page)
		}
	}
	// A blocking preview is never approvable from this page.
	if strings.Contains(page, `<button type="submit">Approve and import this exact preview</button>`) {
		t.Fatalf("a blocking preview offered an enabled import button:\n%s", page)
	}
	if !preview.NodeExcluded("fixture1-zone1-loginnode") || preview.NodeUnclassified("fixture1-zone1-loginnode") ||
		!preview.NodeUnclassified("fixture1-zone1-comp012") || preview.NodeExcluded("fixture1-zone1-comp012") {
		t.Fatal("the device-row helpers did not follow the findings")
	}
	if !preview.CategoryUnclassified("service-default-category") || preview.CategoryUnclassified("login-default-category") ||
		preview.CategoryUnclassified("") {
		t.Fatal("the category helper did not follow the findings")
	}
}
