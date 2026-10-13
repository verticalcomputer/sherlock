package adminapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const testPreviewDigest = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"

type fakeExpectedInventory struct {
	subject            string
	sourceID           string
	exclusions         []string
	categoryExclusions []string
	previewID          string
	digest             string
	audit              adminmanage.MutationAudit
	err                error
	blocking           bool
	noPreview          bool
	alreadyDone        bool
}

func (fake *fakeExpectedInventory) preview(cluster string) adminmanage.ExpectedInventoryPreviewRecord {
	generated := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	return adminmanage.ExpectedInventoryPreviewRecord{
		PreviewID: "ipv_abc", ClusterID: cluster, SourceID: "head-prometheus", DigestHex: testPreviewDigest,
		Blocking: fake.blocking, GeneratedBy: "access-a", GeneratedAt: generated, ExpiresAt: generated.Add(24 * time.Hour),
		Preview: domain.ExpectedInventoryPreview{
			SchemaVersion: 1, ClusterID: domain.ClusterID(cluster), SourceID: "head-prometheus",
			GeneratedAt: generated, DiscoveryTestID: "ctest_inv", DiscoveryCompletedAt: generated.Add(-time.Hour),
			CredentialID: "cred_active", CredentialVersion: 2, BCMVersion: "10.0", Blocking: fake.blocking,
			NodeCount: 1, GPUCount: 1, Additions: 2,
			Entities: []domain.EntityIdentity{
				{ClusterID: domain.ClusterID(cluster), Kind: domain.EntityNode, NodeID: "node001"},
				{ClusterID: domain.ClusterID(cluster), Kind: domain.EntityGPU, NodeID: "node001", PhysicalGPUUUID: "GPU-1"},
			},
			Devices:            []domain.PreviewDevice{{Type: "PhysicalNode", Hostname: "node001", Category: "asus-h100-compute-category", Status: "UP", Managed: true, ObservedGPUs: 1, Included: true}},
			Discrepancies:      []domain.InventoryDiscrepancy{{Code: domain.DiscrepancyUnmanagedDevice, DeviceType: "HeadNode", Detail: "listed device is not a managed compute node type and is excluded"}},
			Removals:           []domain.EntityIdentity{},
			ExcludedNodes:      []domain.StableNodeID{"fixture1-zone1-loginnode"},
			ExcludedCategories: []string{"login-default-category"},
		},
	}
}

func (fake *fakeExpectedInventory) GenerateExpectedInventoryPreview(_ context.Context, cluster, subject, sourceID string, excludeNodes, excludeCategories []string, audit adminmanage.MutationAudit) (adminmanage.ExpectedInventoryPreviewRecord, error) {
	fake.subject, fake.sourceID, fake.exclusions, fake.categoryExclusions, fake.audit = subject, sourceID, excludeNodes, excludeCategories, audit
	if fake.err != nil {
		return adminmanage.ExpectedInventoryPreviewRecord{}, fake.err
	}
	return fake.preview(cluster), nil
}

func (fake *fakeExpectedInventory) GetExpectedInventory(_ context.Context, cluster, subject, sourceID string) (adminmanage.ExpectedInventoryState, error) {
	fake.subject, fake.sourceID = subject, sourceID
	if fake.err != nil {
		return adminmanage.ExpectedInventoryState{}, fake.err
	}
	state := adminmanage.ExpectedInventoryState{
		ClusterID: cluster, SourceID: "head-prometheus", DiscoveryAvailable: true,
		DiscoveryTestID: "ctest_inv", DiscoveryCompletedAt: time.Date(2026, 9, 21, 11, 0, 0, 0, time.UTC),
		Current: &adminmanage.ExpectedInventoryRevisionSummary{RevisionID: "exp_abc", NodeCount: 1, GPUCount: 1},
	}
	if !fake.noPreview {
		record := fake.preview(cluster)
		state.LatestPreview = &record
	}
	return state, nil
}

func (fake *fakeExpectedInventory) ImportExpectedInventoryPreview(_ context.Context, _, subject, previewID, digest string, audit adminmanage.MutationAudit) (adminmanage.ExpectedInventoryImport, error) {
	fake.subject, fake.previewID, fake.digest, fake.audit = subject, previewID, digest, audit
	if fake.err != nil {
		return adminmanage.ExpectedInventoryImport{}, fake.err
	}
	return adminmanage.ExpectedInventoryImport{PreviewID: previewID, RevisionID: "exp_abc", AlreadyImported: fake.alreadyDone}, nil
}

func newExpectedInventoryServer(t *testing.T, inventory ExpectedInventoryManagement) *Server {
	t.Helper()
	server, err := New(Options{
		Provider: &fakeProvider{}, Management: &fakeManagement{}, Credentials: &fakeCredentialManagement{},
		AccessTests: &fakeAccessTesting{}, ExpectedInventory: inventory, Auditor: &fakeAuditor{},
		ServiceToken: []byte(testServiceToken), Clock: fixedClock{now: time.Now().UTC()},
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func mutationBody(values map[string]any) []byte {
	values["session_fingerprint"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
	values["request_id"] = "request-1"
	body, _ := json.Marshal(values)
	return body
}

func TestExpectedInventoryPrivateAPIProposesWithoutImporting(t *testing.T) {
	inventory := &fakeExpectedInventory{}
	server := newExpectedInventoryServer(t, inventory)

	body := mutationBody(map[string]any{"actor_subject": "access-a", "source_id": "head-prometheus", "exclude_nodes": []string{"fixture1-zone1-loginnode"}, "exclude_categories": []string{"login-default-category"}})
	response := serve(server, http.MethodPost, "/internal/admin/v1/clusters/cluster-1/expected-inventory/previews", body, "application/json")
	if response.Code != http.StatusCreated {
		t.Fatalf("preview code=%d body=%s", response.Code, response.Body.String())
	}
	if len(inventory.exclusions) != 1 || inventory.exclusions[0] != "fixture1-zone1-loginnode" {
		t.Fatalf("the exclusion list was not forwarded: %+v", inventory.exclusions)
	}
	if len(inventory.categoryExclusions) != 1 || inventory.categoryExclusions[0] != "login-default-category" {
		t.Fatalf("the category exclusion list was not forwarded: %+v", inventory.categoryExclusions)
	}
	var decoded expectedInventoryPreviewDTO
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Devices) != 1 || decoded.Devices[0].Category != "asus-h100-compute-category" {
		t.Fatalf("the device category was not projected: %+v", decoded.Devices)
	}
	if len(decoded.ExcludedCategories) != 1 || decoded.ExcludedCategories[0] != "login-default-category" {
		t.Fatalf("excluded categories were not projected: %+v", decoded.ExcludedCategories)
	}
	if inventory.subject != "access-a" || inventory.sourceID != "head-prometheus" ||
		inventory.audit.EventKind != adminmanage.EventExpectedInventoryPreviewed || inventory.audit.ActorSubject != "access-a" {
		t.Fatalf("preview did not use the trusted actor: %+v", inventory)
	}
	if !strings.Contains(response.Body.String(), `"excluded_nodes":["fixture1-zone1-loginnode"]`) {
		t.Fatalf("the preview DTO did not expose the exclusions: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"digest":"`+testPreviewDigest+`"`) ||
		!strings.Contains(response.Body.String(), `"code":"UNMANAGED_DEVICE"`) ||
		strings.Contains(response.Body.String(), "password") {
		t.Fatalf("preview response: %s", response.Body.String())
	}

	state := serveWithHeaders(server, http.MethodGet, "/internal/admin/v1/clusters/cluster-1/expected-inventory", nil, "", map[string]string{"X-Sherlock-Access-Subject": "access-b"})
	if state.Code != http.StatusOK || inventory.subject != "access-b" {
		t.Fatalf("state code=%d subject=%q", state.Code, inventory.subject)
	}
	if !strings.Contains(state.Body.String(), `"revision_id":"exp_abc"`) || !strings.Contains(state.Body.String(), `"discovery_available":true`) {
		t.Fatalf("state response: %s", state.Body.String())
	}
	if noSubject := serveWithHeaders(server, http.MethodGet, "/internal/admin/v1/clusters/cluster-1/expected-inventory", nil, "", nil); noSubject.Code != http.StatusForbidden {
		t.Fatalf("missing subject accepted: %d", noSubject.Code)
	}
}

func TestExpectedInventoryPrivateAPIImportForwardsDigestUnchanged(t *testing.T) {
	inventory := &fakeExpectedInventory{}
	server := newExpectedInventoryServer(t, inventory)
	body := mutationBody(map[string]any{"actor_subject": "access-a", "digest": testPreviewDigest})
	response := serve(server, http.MethodPost, "/internal/admin/v1/clusters/cluster-1/expected-inventory/previews/ipv_abc/import", body, "application/json")
	if response.Code != http.StatusOK {
		t.Fatalf("import code=%d body=%s", response.Code, response.Body.String())
	}
	if inventory.previewID != "ipv_abc" || inventory.digest != testPreviewDigest ||
		inventory.audit.EventKind != adminmanage.EventExpectedInventoryImported {
		t.Fatalf("import did not forward the approval unchanged: %+v", inventory)
	}
	if !strings.Contains(response.Body.String(), `"revision_id":"exp_abc"`) || !strings.Contains(response.Body.String(), `"already_imported":false`) {
		t.Fatalf("import response: %s", response.Body.String())
	}

	inventory.alreadyDone = true
	repeat := serve(server, http.MethodPost, "/internal/admin/v1/clusters/cluster-1/expected-inventory/previews/ipv_abc/import", body, "application/json")
	if repeat.Code != http.StatusOK || !strings.Contains(repeat.Body.String(), `"already_imported":true`) {
		t.Fatalf("idempotent import code=%d body=%s", repeat.Code, repeat.Body.String())
	}
}

func TestExpectedInventoryPrivateAPIRejectsInvalidApprovals(t *testing.T) {
	inventory := &fakeExpectedInventory{}
	server := newExpectedInventoryServer(t, inventory)
	cases := []struct {
		name   string
		path   string
		body   map[string]any
		status int
	}{
		{"short digest", "/internal/admin/v1/clusters/cluster-1/expected-inventory/previews/ipv_abc/import", map[string]any{"actor_subject": "access-a", "digest": "abcd"}, http.StatusBadRequest},
		{"non hex digest", "/internal/admin/v1/clusters/cluster-1/expected-inventory/previews/ipv_abc/import", map[string]any{"actor_subject": "access-a", "digest": strings.Repeat("Z", 64)}, http.StatusBadRequest},
		{"bad preview id", "/internal/admin/v1/clusters/cluster-1/expected-inventory/previews/exp_abc/import", map[string]any{"actor_subject": "access-a", "digest": testPreviewDigest}, http.StatusBadRequest},
		{"no subject", "/internal/admin/v1/clusters/cluster-1/expected-inventory/previews/ipv_abc/import", map[string]any{"digest": testPreviewDigest}, http.StatusBadRequest},
		{"preview without subject", "/internal/admin/v1/clusters/cluster-1/expected-inventory/previews", map[string]any{}, http.StatusBadRequest},
		// A mistyped exclusion is refused at the boundary, naming the field,
		// rather than reaching the store as an unprocessable preview.
		{"empty exclusion", "/internal/admin/v1/clusters/cluster-1/expected-inventory/previews", map[string]any{"actor_subject": "access-a", "exclude_nodes": []string{""}}, http.StatusBadRequest},
		{"exclusion with whitespace", "/internal/admin/v1/clusters/cluster-1/expected-inventory/previews", map[string]any{"actor_subject": "access-a", "exclude_nodes": []string{"fixture1 bom"}}, http.StatusBadRequest},
		{"oversized exclusion", "/internal/admin/v1/clusters/cluster-1/expected-inventory/previews", map[string]any{"actor_subject": "access-a", "exclude_nodes": []string{strings.Repeat("n", 129)}}, http.StatusBadRequest},
		{"too many exclusions", "/internal/admin/v1/clusters/cluster-1/expected-inventory/previews", map[string]any{"actor_subject": "access-a", "exclude_nodes": tooManyExclusions()}, http.StatusBadRequest},
		{"empty category exclusion", "/internal/admin/v1/clusters/cluster-1/expected-inventory/previews", map[string]any{"actor_subject": "access-a", "exclude_categories": []string{""}}, http.StatusBadRequest},
		{"category exclusion with whitespace", "/internal/admin/v1/clusters/cluster-1/expected-inventory/previews", map[string]any{"actor_subject": "access-a", "exclude_categories": []string{"login default"}}, http.StatusBadRequest},
		{"too many category exclusions", "/internal/admin/v1/clusters/cluster-1/expected-inventory/previews", map[string]any{"actor_subject": "access-a", "exclude_categories": tooManyCategoryExclusions()}, http.StatusBadRequest},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			response := serve(server, http.MethodPost, testCase.path, mutationBody(testCase.body), "application/json")
			if response.Code != testCase.status {
				t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestExpectedInventoryPrivateAPIRedactsRefusals(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
	}{
		{"denied", adminmanage.ErrCredentialAccessDenied, http.StatusForbidden},
		{"blocking or expired", adminmanage.ErrInvalid, http.StatusUnprocessableEntity},
		{"conflict", adminmanage.ErrConflict, http.StatusConflict},
		{"missing", adminmanage.ErrNotFound, http.StatusNotFound},
		{"unconfigured", adminmanage.ErrExpectedInventoryUnavailable, http.StatusServiceUnavailable},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			server := newExpectedInventoryServer(t, &fakeExpectedInventory{err: testCase.err})
			body := mutationBody(map[string]any{"actor_subject": "access-a", "digest": testPreviewDigest})
			response := serve(server, http.MethodPost, "/internal/admin/v1/clusters/cluster-1/expected-inventory/previews/ipv_abc/import", body, "application/json")
			if response.Code != testCase.status {
				t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "sql") || strings.Contains(response.Body.String(), "revision identifier conflicts") {
				t.Fatalf("refusal leaked durable state: %s", response.Body.String())
			}
		})
	}
}

func TestExpectedInventoryPrivateAPIReportsUnconfiguredFeature(t *testing.T) {
	server, err := New(Options{
		Provider: &fakeProvider{}, Management: &fakeManagement{}, Auditor: &fakeAuditor{},
		ServiceToken: []byte(testServiceToken), Clock: fixedClock{now: time.Now().UTC()},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := serveWithHeaders(server, http.MethodGet, "/internal/admin/v1/clusters/cluster-1/expected-inventory", nil, "", map[string]string{"X-Sherlock-Access-Subject": "access-a"})
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
	}
}

// TestExpectedInventoryStateNamesTheAmbiguousSource: the endpoint rejects
// every query parameter, so a caller cannot disambiguate on the URL. The
// refusal must therefore name the field that does carry the answer instead of
// leaving the operator with the generic unprocessable-preview message.
func TestExpectedInventoryStateNamesTheAmbiguousSource(t *testing.T) {
	inventory := &fakeExpectedInventory{err: fmt.Errorf("%w: %w; name the exact source", adminmanage.ErrInvalid, adminmanage.ErrExpectedInventoryAmbiguousSource)}
	server := newExpectedInventoryServer(t, inventory)

	response := serveWithHeaders(server, http.MethodGet, "/internal/admin/v1/clusters/cluster-1/expected-inventory", nil, "", map[string]string{"X-Sherlock-Access-Subject": "access-a"})
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "cluster has more than one Prometheus source; specify source_id") {
		t.Fatalf("ambiguous-source message: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"AMBIGUOUS_SOURCE"`) {
		t.Fatalf("ambiguous-source code: %s", response.Body.String())
	}
	// The query convention is unchanged: source_id is not accepted on the URL.
	query := serveWithHeaders(server, http.MethodGet, "/internal/admin/v1/clusters/cluster-1/expected-inventory?source_id=head-prometheus", nil, "", map[string]string{"X-Sherlock-Access-Subject": "access-a"})
	if query.Code != http.StatusBadRequest || !strings.Contains(query.Body.String(), "query parameters are not accepted") {
		t.Fatalf("query rejection changed: code=%d body=%s", query.Code, query.Body.String())
	}
	// A plain invalid preview still gets the generic refusal.
	generic := &fakeExpectedInventory{err: fmt.Errorf("%w: something else", adminmanage.ErrInvalid)}
	other := serveWithHeaders(newExpectedInventoryServer(t, generic), http.MethodGet, "/internal/admin/v1/clusters/cluster-1/expected-inventory", nil, "", map[string]string{"X-Sherlock-Access-Subject": "access-a"})
	if other.Code != http.StatusUnprocessableEntity || !strings.Contains(other.Body.String(), "the preview cannot be imported as approved") {
		t.Fatalf("generic invalid refusal changed: %s", other.Body.String())
	}
}

// tooManyExclusions is one past the documented bound: an exclusion list is
// refused rather than truncated, for the same reason the preview's other
// bounds are.
func tooManyCategoryExclusions() []string {
	categories := make([]string, domain.ExpectedInventoryMaxExcludedCategories+1)
	for index := range categories {
		categories[index] = fmt.Sprintf("category%04d", index)
	}
	return categories
}

func tooManyExclusions() []string {
	nodes := make([]string, domain.ExpectedInventoryMaxExcludedNodes+1)
	for index := range nodes {
		nodes[index] = fmt.Sprintf("node%04d", index)
	}
	return nodes
}
