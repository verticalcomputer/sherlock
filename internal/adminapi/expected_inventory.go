package adminapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// ExpectedInventoryManagement is the optional durable boundary for the
// expected-inventory proposal and approval. It is separate from
// CredentialAccessTesting so a deployment without the GP-02 goodput store, or
// an existing fake, is unaffected.
type ExpectedInventoryManagement interface {
	GenerateExpectedInventoryPreview(context.Context, string, string, string, []string, []string, adminmanage.MutationAudit) (adminmanage.ExpectedInventoryPreviewRecord, error)
	GetExpectedInventory(context.Context, string, string, string) (adminmanage.ExpectedInventoryState, error)
	ImportExpectedInventoryPreview(context.Context, string, string, string, string, adminmanage.MutationAudit) (adminmanage.ExpectedInventoryImport, error)
}

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

type generateExpectedInventoryPreviewDTO struct {
	SourceID           string   `json:"source_id"`
	ExcludeNodes       []string `json:"exclude_nodes"`
	ExcludeCategories  []string `json:"exclude_categories"`
	ActorSubject       string   `json:"actor_subject"`
	SessionFingerprint []byte   `json:"session_fingerprint"`
	RequestID          string   `json:"request_id"`
}

type importExpectedInventoryPreviewDTO struct {
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

func mapExpectedInventoryEntities(entities []domain.EntityIdentity) []expectedInventoryEntityDTO {
	mapped := make([]expectedInventoryEntityDTO, 0, len(entities))
	for _, entity := range entities {
		mapped = append(mapped, expectedInventoryEntityDTO{
			Kind: string(entity.Kind), NodeID: string(entity.NodeID), GPUUUID: string(entity.PhysicalGPUUUID),
		})
	}
	return mapped
}

func mapExpectedInventoryPreview(record adminmanage.ExpectedInventoryPreviewRecord) expectedInventoryPreviewDTO {
	preview := record.Preview
	dto := expectedInventoryPreviewDTO{
		PreviewID: record.PreviewID, ClusterID: record.ClusterID, SourceID: record.SourceID,
		Digest: record.DigestHex, Blocking: record.Blocking, GeneratedBy: record.GeneratedBy,
		GeneratedAt: record.GeneratedAt, ExpiresAt: record.ExpiresAt,
		DiscoveryTestID: preview.DiscoveryTestID, DiscoveryCompletedAt: preview.DiscoveryCompletedAt,
		CredentialID: preview.CredentialID, CredentialVersion: preview.CredentialVersion, BCMVersion: preview.BCMVersion,
		NodeCount: preview.NodeCount, GPUCount: preview.GPUCount, Additions: preview.Additions,
		Entities: mapExpectedInventoryEntities(preview.Entities), Removals: mapExpectedInventoryEntities(preview.Removals),
		Devices:            make([]expectedInventoryDeviceDTO, 0, len(preview.Devices)),
		Discrepancies:      make([]expectedInventoryDiscrepancyDTO, 0, len(preview.Discrepancies)),
		ExcludedNodes:      make([]string, 0, len(preview.ExcludedNodes)),
		ExcludedCategories: append([]string{}, preview.ExcludedCategories...),
		ImportedRevisionID: record.ImportedRevisionID, ImportedBy: record.ImportedBy, ImportedAt: record.ImportedAt,
		Superseded: record.Superseded, SupersededReason: record.SupersededReason,
	}
	for _, node := range preview.ExcludedNodes {
		dto.ExcludedNodes = append(dto.ExcludedNodes, string(node))
	}
	for _, device := range preview.Devices {
		dto.Devices = append(dto.Devices, expectedInventoryDeviceDTO{
			Type: device.Type, Hostname: device.Hostname, Category: device.Category, Status: device.Status,
			Managed: device.Managed, ObservedGPUs: device.ObservedGPUs, Included: device.Included,
		})
	}
	for _, finding := range preview.Discrepancies {
		dto.Discrepancies = append(dto.Discrepancies, expectedInventoryDiscrepancyDTO{
			Code: string(finding.Code), Blocking: finding.Blocking, NodeID: string(finding.NodeID),
			GPUUUID: string(finding.GPUUUID), DeviceType: finding.DeviceType, Detail: finding.Detail,
		})
	}
	return dto
}

func (server *Server) expectedInventoryAvailable(writer http.ResponseWriter) bool {
	if server.expectedInventory == nil {
		writeProblem(writer, http.StatusServiceUnavailable, "CREDENTIALS_DISABLED", "expected inventory management is not configured")
		return false
	}
	return true
}

// generateExpectedInventoryPreview reconciles the newest successful BCM
// inventory discovery with observed identities and persists the proposal. It
// imports nothing: approval is a separate, explicit request.
func (server *Server) generateExpectedInventoryPreview(writer http.ResponseWriter, request *http.Request) {
	if rejectQuery(writer, request) || !server.expectedInventoryAvailable(writer) {
		return
	}
	clusterID := request.PathValue("cluster_id")
	if !validClusterIDPath(clusterID) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the cluster ID is invalid")
		return
	}
	var body generateExpectedInventoryPreviewDTO
	if !decodeMutationBody(writer, request, &body) {
		return
	}
	if !validAccessSubjectAPI(body.ActorSubject) || !validMutationContext(mutationContextDTO{SessionFingerprint: body.SessionFingerprint, RequestID: body.RequestID}) || !server.humanMutationMatches(request.Context(), body.SessionFingerprint, body.ActorSubject) || !validExpectedInventorySourceAPI(body.SourceID) || !validExpectedInventoryExclusionsAPI(body.ExcludeNodes) || !validExpectedInventoryCategoryExclusionsAPI(body.ExcludeCategories) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the expected inventory preview request is invalid")
		return
	}
	audit, err := server.mutationAudit(adminmanage.EventExpectedInventoryPreviewed, "expected_inventory_previewed", mutationContextDTO{SessionFingerprint: body.SessionFingerprint, RequestID: body.RequestID})
	if err != nil {
		writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "the expected inventory preview could not be recorded")
		return
	}
	audit.ActorSubject = body.ActorSubject
	record, err := server.expectedInventory.GenerateExpectedInventoryPreview(request.Context(), clusterID, body.ActorSubject, strings.TrimSpace(body.SourceID), body.ExcludeNodes, body.ExcludeCategories, audit)
	if err != nil {
		writeExpectedInventoryError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, mapExpectedInventoryPreview(record))
}

// expectedInventory serves the revision in force and the newest proposal.
func (server *Server) expectedInventoryState(writer http.ResponseWriter, request *http.Request) {
	if rejectQuery(writer, request) || !server.expectedInventoryAvailable(writer) {
		return
	}
	clusterID := request.PathValue("cluster_id")
	if !validClusterIDPath(clusterID) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the cluster ID is invalid")
		return
	}
	subject := strings.TrimSpace(request.Header.Get("X-Sherlock-Access-Subject"))
	if !validAccessSubjectAPI(subject) {
		writeProblem(writer, http.StatusForbidden, "FORBIDDEN", "the credential administrator grant was not accepted")
		return
	}
	state, err := server.expectedInventory.GetExpectedInventory(request.Context(), clusterID, subject, "")
	if err != nil {
		writeExpectedInventoryError(writer, err)
		return
	}
	response := expectedInventoryStateDTO{
		ClusterID: state.ClusterID, SourceID: state.SourceID,
		DiscoveryAvailable: state.DiscoveryAvailable, DiscoveryTestID: state.DiscoveryTestID,
	}
	if state.DiscoveryAvailable {
		completedAt := state.DiscoveryCompletedAt
		response.DiscoveryCompletedAt = &completedAt
	}
	if state.Current != nil {
		response.Current = &expectedInventoryRevisionDTO{
			RevisionID: state.Current.RevisionID, SourceAt: state.Current.SourceAt,
			EffectiveAt: state.Current.EffectiveAt, ObservedAt: state.Current.ObservedAt,
			NodeCount: state.Current.NodeCount, GPUCount: state.Current.GPUCount,
		}
	}
	if state.LatestPreview != nil {
		preview := mapExpectedInventoryPreview(*state.LatestPreview)
		response.LatestPreview = &preview
	}
	writeJSON(writer, http.StatusOK, response)
}

// importExpectedInventoryPreview approves exactly one stored proposal by its
// digest. The digest travels unchanged from the operator to the store, which
// compares it in constant time against the stored content's digest.
func (server *Server) importExpectedInventoryPreview(writer http.ResponseWriter, request *http.Request) {
	if rejectQuery(writer, request) || !server.expectedInventoryAvailable(writer) {
		return
	}
	clusterID, previewID := request.PathValue("cluster_id"), request.PathValue("preview_id")
	if !validClusterIDPath(clusterID) || !validExpectedInventoryPreviewIDAPI(previewID) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the expected inventory preview reference is invalid")
		return
	}
	var body importExpectedInventoryPreviewDTO
	if !decodeMutationBody(writer, request, &body) {
		return
	}
	if !validAccessSubjectAPI(body.ActorSubject) || !validMutationContext(mutationContextDTO{SessionFingerprint: body.SessionFingerprint, RequestID: body.RequestID}) || !server.humanMutationMatches(request.Context(), body.SessionFingerprint, body.ActorSubject) || !validPreviewDigestAPI(body.Digest) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the expected inventory import request is invalid")
		return
	}
	audit, err := server.mutationAudit(adminmanage.EventExpectedInventoryImported, "expected_inventory_imported", mutationContextDTO{SessionFingerprint: body.SessionFingerprint, RequestID: body.RequestID})
	if err != nil {
		writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "the expected inventory import could not be recorded")
		return
	}
	audit.ActorSubject = body.ActorSubject
	result, err := server.expectedInventory.ImportExpectedInventoryPreview(request.Context(), clusterID, body.ActorSubject, previewID, body.Digest, audit)
	if err != nil {
		writeExpectedInventoryError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, expectedInventoryImportResponse{
		PreviewID: result.PreviewID, RevisionID: result.RevisionID, AlreadyImported: result.AlreadyImported,
	})
}

// writeExpectedInventoryError keeps the credential family's redaction: a
// refusal names the class of problem, never durable state or host output.
func writeExpectedInventoryError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, adminmanage.ErrExpectedInventoryUnavailable):
		writeProblem(writer, http.StatusServiceUnavailable, "CREDENTIALS_DISABLED", "expected inventory management is not configured")
	case errors.Is(err, adminmanage.ErrExpectedInventoryAmbiguousSource):
		// This endpoint rejects every query parameter (see rejectQuery), so
		// the caller cannot name the source on the URL. The message names the
		// exact field the private API body carries instead of leaving the
		// operator with a generic unprocessable refusal.
		writeProblem(writer, http.StatusUnprocessableEntity, "AMBIGUOUS_SOURCE", "cluster has more than one Prometheus source; specify source_id")
	case errors.Is(err, adminmanage.ErrInvalid):
		writeProblem(writer, http.StatusUnprocessableEntity, "UNPROCESSABLE_PREVIEW", "the preview cannot be imported as approved")
	default:
		writeCredentialError(writer, err)
	}
}

func validExpectedInventorySourceAPI(value string) bool {
	trimmed := strings.TrimSpace(value)
	return len(trimmed) <= 128 && !strings.ContainsAny(trimmed, "\x00\r\n")
}

// validExpectedInventoryExclusionsAPI bounds the operator's exclusion list at
// the boundary. The store validates it again; a 400 here names the request
// field rather than leaving the caller with an unprocessable preview.
func validExpectedInventoryExclusionsAPI(nodes []string) bool {
	if len(nodes) > domain.ExpectedInventoryMaxExcludedNodes {
		return false
	}
	for _, node := range nodes {
		trimmed := strings.TrimSpace(node)
		if trimmed == "" || len(trimmed) > 128 || strings.ContainsAny(trimmed, "\x00\r\n\t ") {
			return false
		}
	}
	return true
}

// validExpectedInventoryCategoryExclusionsAPI applies the same bound to the
// category list, whose maximum is deliberately smaller: a head has a handful
// of device categories.
func validExpectedInventoryCategoryExclusionsAPI(categories []string) bool {
	if len(categories) > domain.ExpectedInventoryMaxExcludedCategories {
		return false
	}
	for _, category := range categories {
		trimmed := strings.TrimSpace(category)
		if trimmed == "" || len(trimmed) > 128 || strings.ContainsAny(trimmed, "\x00\r\n\t ") {
			return false
		}
	}
	return true
}

func validExpectedInventoryPreviewIDAPI(value string) bool {
	return len(value) >= 5 && len(value) <= 128 && strings.HasPrefix(value, "ipv_") && !strings.ContainsAny(value, "\x00\r\n/\\")
}

func validPreviewDigestAPI(value string) bool {
	if len(value) != 2*len(domain.SHA256{}) {
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
