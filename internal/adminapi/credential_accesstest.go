package adminapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// CredentialAccessTesting is the optional durable boundary for "Test BCM
// access". It is separate from CredentialManagement so deployments without
// the keyring, and existing fakes, remain unchanged.
type CredentialAccessTesting interface {
	RequestCredentialAccessTest(context.Context, string, string, string, int64, adminmanage.MutationAudit) (adminmanage.CredentialAccessTest, error)
	RequestCredentialInventoryDiscovery(context.Context, string, string, string, int64, adminmanage.MutationAudit) (adminmanage.CredentialAccessTest, error)
	ListCredentialAccessTests(context.Context, string, string, int) ([]adminmanage.CredentialAccessTest, error)
	CancelCredentialAccessTest(context.Context, string, string, string, adminmanage.MutationAudit) error
	LatestInventoryDiscovery(context.Context, string, string) (adminmanage.CredentialInventoryDiscovery, bool, error)
}

const credentialAccessTestListLimit = 50

type credentialAccessTestDTO struct {
	ID                string     `json:"test_id"`
	ClusterID         string     `json:"cluster_id"`
	CredentialID      string     `json:"credential_id"`
	CredentialVersion int64      `json:"credential_version"`
	Host              string     `json:"host"`
	Purpose           string     `json:"purpose"`
	Username          string     `json:"username"`
	Operation         string     `json:"operation"`
	Status            string     `json:"status"`
	RequestedBy       string     `json:"requested_by"`
	RequestedAt       time.Time  `json:"requested_at"`
	Deadline          time.Time  `json:"deadline"`
	Attempt           int        `json:"attempt"`
	CollectorID       string     `json:"collector_id,omitempty"`
	LeaseExpiresAt    *time.Time `json:"lease_expires_at,omitempty"`
	OutcomeCode       string     `json:"outcome_code,omitempty"`
	OutcomeSummary    string     `json:"outcome_summary,omitempty"`
	BCMVersion        string     `json:"bcm_version,omitempty"`
	DevicesListed     int        `json:"devices_listed"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
	CancelledBy       string     `json:"cancelled_by,omitempty"`
	CredentialCurrent bool       `json:"credential_current"`
	CredentialStatus  string     `json:"credential_status"`
	// Devices is present only for a succeeded inventory discovery.
	Devices []credentialAccessDeviceDTO `json:"devices,omitempty"`
}

type credentialAccessDeviceDTO struct {
	Type     string `json:"type"`
	Hostname string `json:"hostname"`
	Category string `json:"category,omitempty"`
	Status   string `json:"status"`
}

type credentialInventoryDiscoveryDTO struct {
	TestID            string                      `json:"test_id"`
	ClusterID         string                      `json:"cluster_id"`
	CredentialID      string                      `json:"credential_id"`
	CredentialVersion int64                       `json:"credential_version"`
	Host              string                      `json:"host"`
	BCMVersion        string                      `json:"bcm_version,omitempty"`
	CompletedAt       time.Time                   `json:"completed_at"`
	CredentialCurrent bool                        `json:"credential_current"`
	Devices           []credentialAccessDeviceDTO `json:"devices"`
}

type credentialAccessTestListResponse struct {
	Tests []credentialAccessTestDTO `json:"tests"`
}

func mapCredentialAccessDevices(devices []domain.CredentialAccessDevice) []credentialAccessDeviceDTO {
	mapped := make([]credentialAccessDeviceDTO, 0, len(devices))
	for _, device := range devices {
		mapped = append(mapped, credentialAccessDeviceDTO{Type: device.Type, Hostname: device.Hostname, Category: device.Category, Status: device.Status})
	}
	return mapped
}

type requestCredentialAccessTestDTO struct {
	ExpectedVersion    int64  `json:"expected_version"`
	ActorSubject       string `json:"actor_subject"`
	SessionFingerprint []byte `json:"session_fingerprint"`
	RequestID          string `json:"request_id"`
}

type cancelCredentialAccessTestDTO struct {
	ActorSubject       string `json:"actor_subject"`
	SessionFingerprint []byte `json:"session_fingerprint"`
	RequestID          string `json:"request_id"`
}

func mapCredentialAccessTest(test adminmanage.CredentialAccessTest) credentialAccessTestDTO {
	var devices []credentialAccessDeviceDTO
	if len(test.Devices) > 0 {
		devices = mapCredentialAccessDevices(test.Devices)
	}
	return credentialAccessTestDTO{
		Operation: test.Operation, Devices: devices,
		ID: test.ID, ClusterID: test.ClusterID, CredentialID: test.CredentialID, CredentialVersion: test.CredentialVersion,
		Host: test.Host, Purpose: test.Purpose, Username: test.Username, Status: string(test.Status), RequestedBy: test.RequestedBy,
		RequestedAt: test.RequestedAt, Deadline: test.Deadline, Attempt: test.Attempt, CollectorID: test.CollectorID, LeaseExpiresAt: test.LeaseExpiresAt,
		OutcomeCode: test.OutcomeCode, OutcomeSummary: test.OutcomeSummary, BCMVersion: test.BCMVersion, DevicesListed: test.DevicesListed,
		CompletedAt: test.CompletedAt, CancelledBy: test.CancelledBy, CredentialCurrent: test.CredentialCurrent, CredentialStatus: test.CredentialStatus,
	}
}

func (server *Server) accessTestsAvailable(writer http.ResponseWriter) bool {
	if server.accessTests == nil {
		writeProblem(writer, http.StatusServiceUnavailable, "CREDENTIALS_DISABLED", "credential access testing is not configured")
		return false
	}
	return true
}

func (server *Server) requestCredentialAccessTest(writer http.ResponseWriter, request *http.Request) {
	server.requestCredentialAccessOperation(writer, request, false)
}

// requestCredentialInventoryDiscovery schedules the second reviewed
// operation. Body, validation, authorization and redacted errors are exactly
// those of the access-test route; only the scheduled operation differs.
func (server *Server) requestCredentialInventoryDiscovery(writer http.ResponseWriter, request *http.Request) {
	server.requestCredentialAccessOperation(writer, request, true)
}

func (server *Server) requestCredentialAccessOperation(writer http.ResponseWriter, request *http.Request, inventory bool) {
	if rejectQuery(writer, request) || !server.accessTestsAvailable(writer) {
		return
	}
	clusterID, credentialID := request.PathValue("cluster_id"), request.PathValue("credential_id")
	if !validClusterIDPath(clusterID) || !validCredentialIDAPI(credentialID) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the credential reference is invalid")
		return
	}
	var body requestCredentialAccessTestDTO
	if !decodeMutationBody(writer, request, &body) {
		return
	}
	if !validAccessSubjectAPI(body.ActorSubject) || !validMutationContext(mutationContextDTO{SessionFingerprint: body.SessionFingerprint, RequestID: body.RequestID}) || !server.humanMutationMatches(request.Context(), body.SessionFingerprint, body.ActorSubject) || body.ExpectedVersion < 1 {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the credential access test request is invalid")
		return
	}
	audit, err := server.mutationAudit(adminmanage.EventAccessTestRequested, "credential_access_test_requested", mutationContextDTO{SessionFingerprint: body.SessionFingerprint, RequestID: body.RequestID})
	if err != nil {
		writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "the credential access test could not be recorded")
		return
	}
	audit.ActorSubject = body.ActorSubject
	requestOperation := server.accessTests.RequestCredentialAccessTest
	if inventory {
		requestOperation = server.accessTests.RequestCredentialInventoryDiscovery
	}
	test, err := requestOperation(request.Context(), clusterID, body.ActorSubject, credentialID, body.ExpectedVersion, audit)
	if err != nil {
		writeCredentialError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, mapCredentialAccessTest(test))
}

// latestCredentialInventoryDiscovery serves the newest retained listing for a
// cluster. It uses the same verified-subject header and redacted errors as
// the other credential routes; absence is a NOT_FOUND problem, not an empty
// document, so a caller can never mistake "none yet" for "no devices".
func (server *Server) latestCredentialInventoryDiscovery(writer http.ResponseWriter, request *http.Request) {
	if rejectQuery(writer, request) || !server.accessTestsAvailable(writer) {
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
	discovery, found, err := server.accessTests.LatestInventoryDiscovery(request.Context(), clusterID, subject)
	if err != nil {
		writeCredentialError(writer, err)
		return
	}
	if !found {
		writeProblem(writer, http.StatusNotFound, "NOT_FOUND", "no inventory discovery has succeeded for this cluster")
		return
	}
	writeJSON(writer, http.StatusOK, credentialInventoryDiscoveryDTO{
		TestID: discovery.TestID, ClusterID: discovery.ClusterID, CredentialID: discovery.CredentialID,
		CredentialVersion: discovery.CredentialVersion, Host: discovery.Host, BCMVersion: discovery.BCMVersion,
		CompletedAt: discovery.CompletedAt, CredentialCurrent: discovery.CredentialCurrent,
		Devices: mapCredentialAccessDevices(discovery.Devices),
	})
}

func (server *Server) listCredentialAccessTests(writer http.ResponseWriter, request *http.Request) {
	if rejectQuery(writer, request) || !server.accessTestsAvailable(writer) {
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
	tests, err := server.accessTests.ListCredentialAccessTests(request.Context(), clusterID, subject, credentialAccessTestListLimit)
	if err != nil {
		writeCredentialError(writer, err)
		return
	}
	response := credentialAccessTestListResponse{Tests: make([]credentialAccessTestDTO, 0, len(tests))}
	for _, test := range tests {
		response.Tests = append(response.Tests, mapCredentialAccessTest(test))
	}
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) cancelCredentialAccessTest(writer http.ResponseWriter, request *http.Request) {
	if rejectQuery(writer, request) || !server.accessTestsAvailable(writer) {
		return
	}
	clusterID, testID := request.PathValue("cluster_id"), request.PathValue("test_id")
	if !validClusterIDPath(clusterID) || !domain.ValidCredentialAccessTestID(testID) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the credential access test reference is invalid")
		return
	}
	var body cancelCredentialAccessTestDTO
	if !decodeMutationBody(writer, request, &body) {
		return
	}
	if !validAccessSubjectAPI(body.ActorSubject) || !validMutationContext(mutationContextDTO{SessionFingerprint: body.SessionFingerprint, RequestID: body.RequestID}) || !server.humanMutationMatches(request.Context(), body.SessionFingerprint, body.ActorSubject) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the credential access test cancellation is invalid")
		return
	}
	audit, err := server.mutationAudit(adminmanage.EventAccessTestCancelled, "credential_access_test_cancelled", mutationContextDTO{SessionFingerprint: body.SessionFingerprint, RequestID: body.RequestID})
	if err != nil {
		writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "the credential access test cancellation could not be recorded")
		return
	}
	audit.ActorSubject = body.ActorSubject
	if err := server.accessTests.CancelCredentialAccessTest(request.Context(), clusterID, body.ActorSubject, testID, audit); err != nil {
		writeCredentialError(writer, err)
		return
	}
	writeJSON(writer, http.StatusNoContent, nil)
}
