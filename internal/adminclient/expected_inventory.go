package adminclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminui"
)

type expectedInventoryEntityDTO struct {
	Kind    string `json:"kind"`
	NodeID  string `json:"node_id"`
	GPUUUID string `json:"physical_gpu_uuid,omitempty"`
}

type expectedInventoryDeviceDTO struct {
	Type         string `json:"type"`
	Hostname     string `json:"hostname"`
	Category     string `json:"category,omitempty"`
	Status       string `json:"status"`
	Managed      bool   `json:"managed"`
	ObservedGPUs int    `json:"observed_gpus"`
	Included     bool   `json:"included"`
}

type expectedInventoryDiscrepancyDTO struct {
	Code       string `json:"code"`
	Blocking   bool   `json:"blocking"`
	NodeID     string `json:"node_id,omitempty"`
	GPUUUID    string `json:"physical_gpu_uuid,omitempty"`
	DeviceType string `json:"device_type,omitempty"`
	Detail     string `json:"detail"`
}

type expectedInventoryPreviewDTO struct {
	PreviewID            string                            `json:"preview_id"`
	ClusterID            string                            `json:"cluster_id"`
	SourceID             string                            `json:"source_id"`
	Digest               string                            `json:"digest"`
	Blocking             bool                              `json:"blocking"`
	GeneratedBy          string                            `json:"generated_by"`
	GeneratedAt          time.Time                         `json:"generated_at"`
	ExpiresAt            time.Time                         `json:"expires_at"`
	DiscoveryTestID      string                            `json:"discovery_test_id"`
	DiscoveryCompletedAt time.Time                         `json:"discovery_completed_at"`
	CredentialID         string                            `json:"credential_id"`
	CredentialVersion    int64                             `json:"credential_version"`
	BCMVersion           string                            `json:"bcm_version,omitempty"`
	NodeCount            int                               `json:"node_count"`
	GPUCount             int                               `json:"gpu_count"`
	Additions            int                               `json:"additions"`
	Entities             []expectedInventoryEntityDTO      `json:"entities"`
	Devices              []expectedInventoryDeviceDTO      `json:"devices"`
	Discrepancies        []expectedInventoryDiscrepancyDTO `json:"discrepancies"`
	Removals             []expectedInventoryEntityDTO      `json:"removals"`
	ExcludedNodes        []string                          `json:"excluded_nodes"`
	ExcludedCategories   []string                          `json:"excluded_categories"`
	ImportedRevisionID   string                            `json:"imported_revision_id,omitempty"`
	ImportedBy           string                            `json:"imported_by,omitempty"`
	ImportedAt           *time.Time                        `json:"imported_at,omitempty"`
	Superseded           bool                              `json:"superseded,omitempty"`
	SupersededReason     string                            `json:"superseded_reason,omitempty"`
}

type expectedInventoryRevisionDTO struct {
	RevisionID  string    `json:"revision_id"`
	SourceAt    time.Time `json:"source_at"`
	EffectiveAt time.Time `json:"effective_at"`
	ObservedAt  time.Time `json:"observed_at"`
	NodeCount   int       `json:"node_count"`
	GPUCount    int       `json:"gpu_count"`
}

type expectedInventoryStateDTO struct {
	ClusterID            string                        `json:"cluster_id"`
	SourceID             string                        `json:"source_id"`
	Current              *expectedInventoryRevisionDTO `json:"current,omitempty"`
	LatestPreview        *expectedInventoryPreviewDTO  `json:"latest_preview,omitempty"`
	DiscoveryAvailable   bool                          `json:"discovery_available"`
	DiscoveryTestID      string                        `json:"discovery_test_id,omitempty"`
	DiscoveryCompletedAt *time.Time                    `json:"discovery_completed_at,omitempty"`
}

type generateExpectedInventoryPreviewRequest struct {
	SourceID           string   `json:"source_id"`
	ExcludeNodes       []string `json:"exclude_nodes"`
	ExcludeCategories  []string `json:"exclude_categories"`
	ActorSubject       string   `json:"actor_subject"`
	SessionFingerprint []byte   `json:"session_fingerprint"`
	RequestID          string   `json:"request_id"`
}

type importExpectedInventoryPreviewRequest struct {
	Digest             string `json:"digest"`
	ActorSubject       string `json:"actor_subject"`
	SessionFingerprint []byte `json:"session_fingerprint"`
	RequestID          string `json:"request_id"`
}

type expectedInventoryImportResponse struct {
	PreviewID       string `json:"preview_id"`
	RevisionID      string `json:"revision_id"`
	AlreadyImported bool   `json:"already_imported"`
}

func mapExpectedInventoryEntities(items []expectedInventoryEntityDTO) []adminui.ExpectedInventoryEntity {
	mapped := make([]adminui.ExpectedInventoryEntity, 0, len(items))
	for _, item := range items {
		mapped = append(mapped, adminui.ExpectedInventoryEntity{Kind: item.Kind, NodeID: item.NodeID, GPUUUID: item.GPUUUID})
	}
	return mapped
}

func mapExpectedInventoryPreview(item expectedInventoryPreviewDTO) adminui.ExpectedInventoryPreview {
	preview := adminui.ExpectedInventoryPreview{
		PreviewID: item.PreviewID, ClusterID: item.ClusterID, SourceID: item.SourceID, Digest: item.Digest,
		Blocking: item.Blocking, GeneratedBy: item.GeneratedBy, GeneratedAt: item.GeneratedAt, ExpiresAt: item.ExpiresAt,
		DiscoveryTestID: item.DiscoveryTestID, DiscoveryCompletedAt: item.DiscoveryCompletedAt,
		CredentialID: item.CredentialID, CredentialVersion: item.CredentialVersion, BCMVersion: item.BCMVersion,
		NodeCount: item.NodeCount, GPUCount: item.GPUCount, Additions: item.Additions,
		Entities: mapExpectedInventoryEntities(item.Entities), Removals: mapExpectedInventoryEntities(item.Removals),
		Devices:            make([]adminui.ExpectedInventoryDevice, 0, len(item.Devices)),
		Discrepancies:      make([]adminui.ExpectedInventoryDiscrepancy, 0, len(item.Discrepancies)),
		ExcludedNodes:      append([]string{}, item.ExcludedNodes...),
		ExcludedCategories: append([]string{}, item.ExcludedCategories...),
		ImportedRevisionID: item.ImportedRevisionID, ImportedBy: item.ImportedBy, ImportedAt: item.ImportedAt,
		Superseded: item.Superseded, SupersededReason: item.SupersededReason,
	}
	for _, device := range item.Devices {
		preview.Devices = append(preview.Devices, adminui.ExpectedInventoryDevice{
			Type: device.Type, Hostname: device.Hostname, Category: device.Category, Status: device.Status,
			Managed: device.Managed, ObservedGPUs: device.ObservedGPUs, Included: device.Included,
		})
	}
	for _, finding := range item.Discrepancies {
		preview.Discrepancies = append(preview.Discrepancies, adminui.ExpectedInventoryDiscrepancy{
			Code: finding.Code, Blocking: finding.Blocking, NodeID: finding.NodeID,
			GPUUUID: finding.GPUUUID, DeviceType: finding.DeviceType, Detail: finding.Detail,
		})
	}
	return preview
}

// GetExpectedInventory loads the revision in force and the newest proposal
// for a cluster, using the verified Access subject supplied by the dashboard.
func (client *Client) GetExpectedInventory(ctx context.Context, clusterID, actorSubject string) (adminui.ExpectedInventoryState, error) {
	if !validClusterID(clusterID) || !validActorSubject(actorSubject) {
		return adminui.ExpectedInventoryState{}, errors.New("admin API expected inventory scope is invalid")
	}
	request, err := client.request(ctx, http.MethodGet, "/internal/admin/v1/clusters/"+url.PathEscape(clusterID)+"/expected-inventory", nil)
	if err != nil {
		return adminui.ExpectedInventoryState{}, err
	}
	request.Header.Set("X-Sherlock-Access-Subject", actorSubject)
	responseBody, err := client.do(request)
	if err != nil {
		return adminui.ExpectedInventoryState{}, err
	}
	var item expectedInventoryStateDTO
	if err := decodeStrict(responseBody, &item); err != nil {
		return adminui.ExpectedInventoryState{}, errors.New("decode admin API expected inventory response")
	}
	state := adminui.ExpectedInventoryState{
		ClusterID: item.ClusterID, SourceID: item.SourceID,
		DiscoveryAvailable: item.DiscoveryAvailable, DiscoveryTestID: item.DiscoveryTestID,
	}
	if item.DiscoveryCompletedAt != nil {
		state.DiscoveryCompletedAt = *item.DiscoveryCompletedAt
	}
	if item.Current != nil {
		state.Current = &adminui.ExpectedInventoryRevision{
			RevisionID: item.Current.RevisionID, SourceAt: item.Current.SourceAt,
			EffectiveAt: item.Current.EffectiveAt, ObservedAt: item.Current.ObservedAt,
			NodeCount: item.Current.NodeCount, GPUCount: item.Current.GPUCount,
		}
	}
	if item.LatestPreview != nil {
		preview := mapExpectedInventoryPreview(*item.LatestPreview)
		state.LatestPreview = &preview
	}
	return state, nil
}

// GenerateExpectedInventoryPreview asks the private API to reconcile the
// newest successful BCM discovery with observed identities. It imports
// nothing; the returned proposal must be approved separately.
func (client *Client) GenerateExpectedInventoryPreview(ctx context.Context, clusterID, actorSubject, sourceID string, excludeNodes, excludeCategories []string, mutation adminui.MutationContext) (adminui.ExpectedInventoryPreview, error) {
	if !validClusterID(clusterID) || !validActorSubject(actorSubject) || (sourceID != "" && !validClusterID(sourceID)) ||
		!validExcludedNodes(excludeNodes) || !validExcludedCategories(excludeCategories) {
		return adminui.ExpectedInventoryPreview{}, errors.New("admin API expected inventory preview request is invalid")
	}
	payload, err := json.Marshal(generateExpectedInventoryPreviewRequest{
		SourceID: sourceID, ExcludeNodes: excludeNodes, ExcludeCategories: excludeCategories, ActorSubject: actorSubject,
		SessionFingerprint: mutation.SessionFingerprint, RequestID: mutation.RequestID,
	})
	if err != nil {
		return adminui.ExpectedInventoryPreview{}, errors.New("encode admin API expected inventory preview request")
	}
	request, err := client.request(ctx, http.MethodPost, "/internal/admin/v1/clusters/"+url.PathEscape(clusterID)+"/expected-inventory/previews", bytes.NewReader(payload))
	if err != nil {
		return adminui.ExpectedInventoryPreview{}, err
	}
	responseBody, err := client.do(request)
	if err != nil {
		return adminui.ExpectedInventoryPreview{}, err
	}
	var item expectedInventoryPreviewDTO
	if err := decodeStrict(responseBody, &item); err != nil {
		return adminui.ExpectedInventoryPreview{}, errors.New("decode admin API expected inventory preview response")
	}
	return mapExpectedInventoryPreview(item), nil
}

// ImportExpectedInventoryPreview approves exactly one stored proposal. The
// digest travels unchanged from the operator's form to the private API, so
// the approval names precisely the reconciliation that was displayed.
func (client *Client) ImportExpectedInventoryPreview(ctx context.Context, clusterID, actorSubject, previewID, digest string, mutation adminui.MutationContext) (adminui.ExpectedInventoryImport, error) {
	if !validClusterID(clusterID) || !validActorSubject(actorSubject) || !validPreviewIdentifier(previewID) || !validPreviewDigestHex(digest) {
		return adminui.ExpectedInventoryImport{}, errors.New("admin API expected inventory import request is invalid")
	}
	payload, err := json.Marshal(importExpectedInventoryPreviewRequest{
		Digest: digest, ActorSubject: actorSubject,
		SessionFingerprint: mutation.SessionFingerprint, RequestID: mutation.RequestID,
	})
	if err != nil {
		return adminui.ExpectedInventoryImport{}, errors.New("encode admin API expected inventory import request")
	}
	request, err := client.request(ctx, http.MethodPost, "/internal/admin/v1/clusters/"+url.PathEscape(clusterID)+"/expected-inventory/previews/"+url.PathEscape(previewID)+"/import", bytes.NewReader(payload))
	if err != nil {
		return adminui.ExpectedInventoryImport{}, err
	}
	responseBody, err := client.do(request)
	if err != nil {
		return adminui.ExpectedInventoryImport{}, err
	}
	var item expectedInventoryImportResponse
	if err := decodeStrict(responseBody, &item); err != nil {
		return adminui.ExpectedInventoryImport{}, errors.New("decode admin API expected inventory import response")
	}
	return adminui.ExpectedInventoryImport{
		PreviewID: item.PreviewID, RevisionID: item.RevisionID, AlreadyImported: item.AlreadyImported,
	}, nil
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

// validExcludedNodes keeps the client from forwarding a list the private API
// would refuse: an exclusion is matched against a hostname exactly.
func validExcludedNodes(nodes []string) bool {
	if len(nodes) > 256 {
		return false
	}
	for _, node := range nodes {
		if node == "" || len(node) > 128 || strings.ContainsAny(node, "\x00\r\n\t ") {
			return false
		}
	}
	return true
}

// validExcludedCategories keeps the same rule for the category list, with the
// private API's smaller count bound.
func validExcludedCategories(categories []string) bool {
	if len(categories) > 64 {
		return false
	}
	for _, category := range categories {
		if category == "" || len(category) > 128 || strings.ContainsAny(category, "\x00\r\n\t ") {
			return false
		}
	}
	return true
}

func validPreviewDigestHex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') {
			continue
		}
		return false
	}
	return true
}
