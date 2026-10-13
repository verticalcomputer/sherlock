// Package adminclient connects the server-rendered admin dashboard to the
// Sherlock API's private administrative endpoints.
package adminclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminui"
	"github.com/verticalcomputer/sherlock/internal/adminview"
	"github.com/verticalcomputer/sherlock/internal/auth"
)

const (
	maximumResponseBytes       int64 = 1 << 20
	maximumReportResponseBytes int64 = 64 << 20
	// The bounded GPU table can carry up to 1,024 rows of per-field evidence.
	maximumGPUMetricsResponseBytes int64 = 16 << 20
)

var errRedirectRejected = errors.New("admin API redirect rejected")

// Client implements both adminui.DataProvider and adminui.Auditor. Its bearer
// token is used only on server-to-server requests and is never returned in an
// error.
type Client struct {
	baseURL *url.URL
	token   string
	http    *http.Client
}

// New constructs a private admin API client. Plain HTTP is accepted only for
// literal loopback addresses and localhost development endpoints.
func New(baseURL string, serviceToken []byte, httpClient *http.Client) (*Client, error) {
	endpoint, err := validateBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if len(serviceToken) < 32 || len(serviceToken) > 512 {
		return nil, errors.New("admin API service token must contain between 32 and 512 bytes")
	}
	if strings.ContainsAny(string(serviceToken), " ,\t\r\n") {
		return nil, errors.New("admin API service token contains invalid characters")
	}
	if httpClient == nil {
		return nil, errors.New("admin API HTTP client is required")
	}
	if httpClient.Timeout <= 0 {
		return nil, errors.New("admin API HTTP client must have a timeout")
	}
	clientCopy := *httpClient
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errRedirectRejected
	}
	return &Client{baseURL: endpoint, token: string(serviceToken), http: &clientCopy}, nil
}

func validateBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("admin API base URL must be an absolute HTTP or HTTPS URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("admin API base URL must use HTTP or HTTPS")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("admin API base URL must not contain credentials, a path, query, or fragment")
	}
	if parsed.Scheme == "http" && !loopbackHost(parsed.Hostname()) {
		return nil, errors.New("admin API base URL must use HTTPS unless it is loopback")
	}
	parsed.Path = ""
	return parsed, nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

// LoadDashboard retrieves the redacted API projection and maps it into the
// dashboard's presentation model.
func (client *Client) LoadDashboard(ctx context.Context) (adminui.Dashboard, error) {
	request, err := client.request(ctx, http.MethodGet, "/internal/admin/v1/dashboard", nil)
	if err != nil {
		return adminui.Dashboard{}, err
	}
	responseBody, err := client.do(request)
	if err != nil {
		return adminui.Dashboard{}, err
	}
	var snapshot adminview.Dashboard
	if err := decodeStrict(responseBody, &snapshot); err != nil {
		return adminui.Dashboard{}, errors.New("decode admin API dashboard response")
	}
	return mapDashboard(snapshot), nil
}

// ListClusters retrieves every active cluster from the private management API.
func (client *Client) ListClusters(ctx context.Context) ([]adminui.ClusterRecord, error) {
	request, err := client.request(ctx, http.MethodGet, "/internal/admin/v1/clusters", nil)
	if err != nil {
		return nil, err
	}
	responseBody, err := client.do(request)
	if err != nil {
		return nil, err
	}
	var response clustersResponse
	if err := decodeStrict(responseBody, &response); err != nil {
		return nil, errors.New("decode admin API cluster response")
	}
	clusters := make([]adminui.ClusterRecord, 0, len(response.Clusters))
	for _, cluster := range response.Clusters {
		clusters = append(clusters, mapClusterRecord(cluster))
	}
	return clusters, nil
}

func (client *Client) CheckHumanSession(ctx context.Context) error {
	request, err := client.request(ctx, http.MethodGet, "/internal/admin/v1/human-session", nil)
	if err != nil {
		return err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return errors.New("check human session")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden {
		return adminui.ErrHumanAccessDenied
	}
	if response.StatusCode != http.StatusOK {
		return errors.New("human session check unavailable")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	if err != nil || len(payload) > 1024 {
		return errors.New("human session response invalid")
	}
	var result struct {
		ClusterCount int `json:"cluster_count"`
	}
	if err := decodeStrict(payload, &result); err != nil || result.ClusterCount < 1 || result.ClusterCount > 64 {
		return errors.New("human session response invalid")
	}
	return nil
}

// GetCluster returns one active cluster without exposing an additional public
// endpoint. The private list is bounded by the API and remains the canonical
// source for the clusters page.
func (client *Client) GetCluster(ctx context.Context, id string) (adminui.ClusterRecord, error) {
	if !validClusterID(id) {
		return adminui.ClusterRecord{}, errors.New("admin API cluster ID is invalid")
	}
	clusters, err := client.ListClusters(ctx)
	if err != nil {
		return adminui.ClusterRecord{}, err
	}
	for _, cluster := range clusters {
		if cluster.ID == id {
			return cluster, nil
		}
	}
	return adminui.ClusterRecord{}, errors.New("admin API cluster was not found")
}

// GetClusterSummary retrieves one bounded redacted operational projection.
func (client *Client) GetClusterSummary(ctx context.Context, id string) (adminui.Cluster, error) {
	if !validClusterID(id) {
		return adminui.Cluster{}, errors.New("admin API cluster ID is invalid")
	}
	request, err := client.request(ctx, http.MethodGet, "/internal/admin/v1/clusters/"+url.PathEscape(id)+"/summary", nil)
	if err != nil {
		return adminui.Cluster{}, err
	}
	responseBody, err := client.do(request)
	if err != nil {
		return adminui.Cluster{}, err
	}
	var summary adminview.ClusterSummary
	if err := decodeStrict(responseBody, &summary); err != nil {
		return adminui.Cluster{}, errors.New("decode admin API cluster summary response")
	}
	return mapCluster(summary), nil
}

// UpdateCluster changes an active cluster's display name. Audit occurrence
// time is intentionally assigned by the API server, not trusted from the UI.
func (client *Client) UpdateCluster(ctx context.Context, id string, update adminui.ClusterUpdate, mutation adminui.MutationContext) error {
	if !validClusterID(id) {
		return errors.New("admin API cluster ID is invalid")
	}
	payload, err := json.Marshal(updateClusterRequest{
		DisplayName: update.DisplayName, ExpectedCollectors: append([]string{}, update.ExpectedCollectors...), SessionFingerprint: mutation.SessionFingerprint,
		RequestID: mutation.RequestID,
	})
	if err != nil {
		return errors.New("encode admin API cluster update")
	}
	request, err := client.request(ctx, http.MethodPatch, "/internal/admin/v1/clusters/"+url.PathEscape(id), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	_, err = client.do(request)
	return err
}

// RemoveCluster performs the API's audited soft-removal operation. Repeating
// the cluster ID in the confirmation field prevents an accidental broad or
// mismatched delete request.
func (client *Client) RemoveCluster(ctx context.Context, id string, mutation adminui.MutationContext) error {
	if !validClusterID(id) {
		return errors.New("admin API cluster ID is invalid")
	}
	payload, err := json.Marshal(removeClusterRequest{
		Confirmation: id, SessionFingerprint: mutation.SessionFingerprint,
		RequestID: mutation.RequestID,
	})
	if err != nil {
		return errors.New("encode admin API cluster removal")
	}
	request, err := client.request(ctx, http.MethodDelete, "/internal/admin/v1/clusters/"+url.PathEscape(id), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	_, err = client.do(request)
	return err
}

func (client *Client) ListCredentialMetadata(ctx context.Context, clusterID, actorSubject string) ([]adminui.CredentialMetadata, error) {
	if !validClusterID(clusterID) || !validActorSubject(actorSubject) {
		return nil, errors.New("admin API credential scope is invalid")
	}
	request, err := client.request(ctx, http.MethodGet, "/internal/admin/v1/clusters/"+url.PathEscape(clusterID)+"/credentials", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("X-Sherlock-Access-Subject", actorSubject)
	body, err := client.do(request)
	if err != nil {
		return nil, err
	}
	var response credentialMetadataResponse
	if err := decodeStrict(body, &response); err != nil {
		return nil, errors.New("decode admin API credential response")
	}
	metadata := make([]adminui.CredentialMetadata, 0, len(response.Credentials))
	for _, item := range response.Credentials {
		metadata = append(metadata, adminui.CredentialMetadata{ID: item.ID, ClusterID: item.ClusterID, Host: item.Host, Purpose: item.Purpose, Username: item.Username, KeyVersion: item.KeyVersion, Version: item.Version, Status: item.Status, CreatedAt: item.CreatedAt, RevokedAt: item.RevokedAt, ReplacedBy: item.ReplacedBy})
	}
	return metadata, nil
}

func (client *Client) PutCredential(ctx context.Context, clusterID, actorSubject string, input adminui.CredentialInput, mutation adminui.MutationContext) (adminui.CredentialMetadata, error) {
	if !validClusterID(clusterID) || !validActorSubject(actorSubject) || input.ExpectedVersion < 0 {
		return adminui.CredentialMetadata{}, errors.New("admin API credential input is invalid")
	}
	payload, err := json.Marshal(putCredentialRequest{Host: input.Host, Purpose: input.Purpose, Username: input.Username, SSHPassword: input.SSHPassword, SudoPassword: input.SudoPassword, ExpectedVersion: input.ExpectedVersion, ExpectedCredentialID: input.ExpectedCredentialID, ActorSubject: actorSubject, SessionFingerprint: mutation.SessionFingerprint, RequestID: mutation.RequestID})
	if err != nil {
		return adminui.CredentialMetadata{}, errors.New("encode admin API credential request")
	}
	request, err := client.request(ctx, http.MethodPost, "/internal/admin/v1/clusters/"+url.PathEscape(clusterID)+"/credentials", bytes.NewReader(payload))
	if err != nil {
		return adminui.CredentialMetadata{}, err
	}
	body, err := client.do(request)
	if err != nil {
		return adminui.CredentialMetadata{}, err
	}
	var item credentialMetadataDTO
	if err := decodeStrict(body, &item); err != nil {
		return adminui.CredentialMetadata{}, errors.New("decode admin API credential response")
	}
	return adminui.CredentialMetadata{ID: item.ID, ClusterID: item.ClusterID, Host: item.Host, Purpose: item.Purpose, Username: item.Username, KeyVersion: item.KeyVersion, Version: item.Version, Status: item.Status, CreatedAt: item.CreatedAt, RevokedAt: item.RevokedAt, ReplacedBy: item.ReplacedBy}, nil
}

func (client *Client) RevokeCredential(ctx context.Context, clusterID, credentialID string, expectedVersion int64, mutation adminui.MutationContext) error {
	if !validClusterID(clusterID) || !validClusterID(credentialID) || expectedVersion < 1 || !validActorSubject(mutation.ActorSubject) {
		return errors.New("admin API credential reference is invalid")
	}
	payload, err := json.Marshal(revokeCredentialRequest{ExpectedVersion: expectedVersion, ActorSubject: mutation.ActorSubject, SessionFingerprint: mutation.SessionFingerprint, RequestID: mutation.RequestID})
	if err != nil {
		return errors.New("encode admin API credential revocation")
	}
	request, err := client.request(ctx, http.MethodDelete, "/internal/admin/v1/clusters/"+url.PathEscape(clusterID)+"/credentials/"+url.PathEscape(credentialID), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	_, err = client.do(request)
	return err
}

// LoadOperations retrieves the combined live-ticket and investigation view.
func (client *Client) LoadOperations(ctx context.Context) (adminui.Operations, error) {
	return client.loadOperations(ctx, "/internal/admin/v1/operations")
}

func (client *Client) LoadClusterOperations(ctx context.Context, id string) (adminui.Operations, error) {
	if !validClusterID(id) {
		return adminui.Operations{}, errors.New("admin API cluster ID is invalid")
	}
	return client.loadOperations(ctx, "/internal/admin/v1/clusters/"+url.PathEscape(id)+"/operations")
}

// StartInvestigation submits a bounded, non-privileged investigation through
// the private API. The Access-token digest is durable attribution only and is never
// returned to the browser or included in errors.
func (client *Client) StartInvestigation(ctx context.Context, clusterID string, input adminui.InvestigationStart, mutation adminui.MutationContext) (adminui.InvestigationStartResult, error) {
	if !validClusterID(clusterID) {
		return adminui.InvestigationStartResult{}, errors.New("admin API cluster ID is invalid")
	}
	payload, err := json.Marshal(investigationStartRequest{
		IncidentID: input.IncidentID, Question: input.Question, Purpose: input.Purpose,
		Scope:           investigationScopeRequest{EntityKind: input.EntityKind, EntityIDs: input.EntityIDs, Start: input.WindowStart, End: input.WindowEnd},
		SuccessCriteria: input.SuccessCriteria,
		Budget: investigationBudgetRequest{
			MaxDecisions: input.MaxDecisions, MaxToolCalls: input.MaxToolCalls,
			MaxDiagnosticCalls: input.MaxDiagnosticCalls, MaxPrivilegedCalls: 0,
			MaxFanOut: input.MaxFanOut, MaxModelTokens: input.MaxModelTokens,
			MaxCostMicros: input.MaxCostMicrounits,
		},
		Deadline: input.Deadline, IdempotencyKey: input.IdempotencyKey,
		SessionFingerprint: mutation.SessionFingerprint, RequestID: mutation.RequestID,
	})
	if err != nil {
		return adminui.InvestigationStartResult{}, errors.New("encode admin API investigation request")
	}
	request, err := client.request(ctx, http.MethodPost, "/internal/admin/v1/clusters/"+url.PathEscape(clusterID)+"/investigations", bytes.NewReader(payload))
	if err != nil {
		return adminui.InvestigationStartResult{}, err
	}
	responseBody, err := client.do(request)
	if err != nil {
		return adminui.InvestigationStartResult{}, err
	}
	var response investigationStartResponse
	if err := decodeStrict(responseBody, &response); err != nil {
		return adminui.InvestigationStartResult{}, errors.New("decode admin API investigation response")
	}
	return adminui.InvestigationStartResult{ID: response.ID, Status: response.Status, Replayed: response.Replayed}, nil
}

func (client *Client) loadOperations(ctx context.Context, path string) (adminui.Operations, error) {
	request, err := client.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return adminui.Operations{}, err
	}
	responseBody, err := client.do(request)
	if err != nil {
		return adminui.Operations{}, err
	}
	var response operationsResponse
	if err := decodeStrict(responseBody, &response); err != nil {
		return adminui.Operations{}, errors.New("decode admin API operations response")
	}
	operations := adminui.Operations{GeneratedAt: response.GeneratedAt}
	operations.Repairs = adminui.RepairOverview{Available: response.Repairs.Available, GlobalEnabled: response.Repairs.GlobalEnabled, ActiveRequests: response.Repairs.ActiveRequests, PendingVerification: response.Repairs.PendingVerification, Succeeded: response.Repairs.Succeeded, Contained: response.Repairs.Contained, Cancelled: response.Repairs.Cancelled, RolledBack: response.Repairs.RolledBack}
	for _, d := range response.Repairs.Decisions {
		operations.Repairs.Decisions = append(operations.Repairs.Decisions, adminui.RepairDecision{Code: d.Code, Count: d.Count})
	}

	operations.Tickets = make([]adminui.Ticket, 0, len(response.Tickets))
	for _, ticket := range response.Tickets {
		operations.Tickets = append(operations.Tickets, adminui.Ticket{
			ID: ticket.ID, ClusterID: ticket.ClusterID, RuleID: ticket.RuleID, Title: ticket.Title,
			Summary: ticket.Summary, Severity: ticket.Severity, Status: ticket.Status,
			UpdatedAt: ticket.UpdatedAt, LastSignalAt: ticket.LastSignalAt, AutoStartStatus: ticket.AutoStartStatus,
			AutoStartDecision: ticket.AutoStartDecision, AutoStartUpdatedAt: ticket.AutoStartUpdatedAt,
		})
	}
	operations.Investigations = make([]adminui.Investigation, 0, len(response.Investigations))
	for _, investigation := range response.Investigations {
		operations.Investigations = append(operations.Investigations, adminui.Investigation{
			ID: investigation.ID, ClusterID: investigation.ClusterID,
			IncidentID: investigation.IncidentID, Question: investigation.Question,
			Status: investigation.Status, EntityKind: investigation.EntityKind,
			EntityIDs: investigation.EntityIDs, AuditedTokens: investigation.AuditedTokens,
			AuditedCostMicrounits: investigation.AuditedCostMicrounits, UpdatedAt: investigation.UpdatedAt,
		})
	}
	return operations, nil
}

// LoadInvestigationReport retrieves the redacted durable report projection.
func (client *Client) LoadInvestigationReport(ctx context.Context, id string) (adminui.InvestigationReport, error) {
	if !validClusterID(id) {
		return adminui.InvestigationReport{}, errors.New("admin API investigation ID is invalid")
	}
	request, err := client.request(ctx, http.MethodGet, "/internal/admin/v1/investigations/"+url.PathEscape(id)+"/shared", nil)
	if err != nil {
		return adminui.InvestigationReport{}, err
	}
	responseBody, err := client.do(request)
	if err != nil {
		return adminui.InvestigationReport{}, err
	}
	var response investigationReportResponse
	if err := decodeStrict(responseBody, &response); err != nil {
		return adminui.InvestigationReport{}, errors.New("decode admin API investigation report response")
	}
	if !response.Shared || len(response.ModelCalls) != 0 || len(response.ContextManifests) != 0 {
		return adminui.InvestigationReport{}, errors.New("shared investigation report contract invalid")
	}
	for _, evidence := range response.Evidence {
		if evidence.ExactScope != "" {
			return adminui.InvestigationReport{}, errors.New("shared investigation report contract invalid")
		}
	}
	report := adminui.InvestigationReport{
		ID: response.ID, ClusterID: response.ClusterID, IncidentID: response.IncidentID, Shared: response.Shared, Version: response.Version,
		Question: response.Question, Status: response.Status, StopReason: response.StopReason,
		EntityKind: response.EntityKind, EntityIDs: response.EntityIDs,
		WindowStart: response.WindowStart, WindowEnd: response.WindowEnd,
		SuccessCriteria: response.SuccessCriteria, CreatedAt: response.CreatedAt,
		UpdatedAt: response.UpdatedAt, CompletedAt: response.CompletedAt,
		ModelUsage: adminui.ReportModelUsage{
			MaxTokens: response.ModelUsage.MaxTokens, AdmittedTokens: response.ModelUsage.AdmittedTokens,
			AuditedTokens: response.ModelUsage.AuditedTokens, MaxCostMicrounits: response.ModelUsage.MaxCostMicrounits,
			AdmittedCostMicrounits: response.ModelUsage.AdmittedCostMicrounits, AuditedCostMicrounits: response.ModelUsage.AuditedCostMicrounits,
		},
		Findings:         make([]adminui.ReportFinding, 0, len(response.Findings)),
		ReportSections:   make([]adminui.ReportSection, 0, len(response.ReportSections)),
		ReportOmissions:  make([]adminui.ReportOmission, 0, len(response.ReportOmissions)),
		Evidence:         make([]adminui.ReportEvidence, 0, len(response.Evidence)),
		ModelCalls:       make([]adminui.ModelCall, 0, len(response.ModelCalls)),
		ContextManifests: make([]adminui.ContextManifest, 0, len(response.ContextManifests)),
	}
	if response.PrimaryAction != nil {
		action := response.PrimaryAction
		report.PrimaryAction = &adminui.ReportActionCard{
			ID: action.ID, Owner: action.Owner, Action: action.Action, Urgency: action.Urgency,
			Targets: action.Targets, Rationale: action.Rationale, EvidenceIDs: action.EvidenceIDs,
			BlockingGaps: action.BlockingGaps, EscalationCondition: action.EscalationCondition,
		}
	}
	for _, finding := range response.Findings {
		report.Findings = append(report.Findings, adminui.ReportFinding{
			ID: finding.ID, Kind: finding.Kind, Statement: finding.Statement,
			EntityIDs: finding.EntityIDs, Severity: finding.Severity,
			Confidence: finding.Confidence, EvidenceIDs: finding.EvidenceIDs,
			CounterEvidenceIDs: finding.CounterEvidenceIDs,
		})
	}
	for _, section := range response.ReportSections {
		report.ReportSections = append(report.ReportSections, adminui.ReportSection{
			ID: section.ID, Kind: section.Kind, Ordinal: section.Ordinal,
			Statement: section.Statement, ObservedAt: section.ObservedAt,
			EvidenceIDs: section.EvidenceIDs,
		})
	}
	for _, omission := range response.ReportOmissions {
		report.ReportOmissions = append(report.ReportOmissions, adminui.ReportOmission{
			Kind: omission.Kind, Reason: omission.Reason, Count: omission.Count,
		})
	}
	for _, evidence := range response.Evidence {
		report.Evidence = append(report.Evidence, adminui.ReportEvidence{
			ID: evidence.ID, Kind: evidence.Kind, Status: evidence.Status,
			ExactScope: evidence.ExactScope, ObservedStart: evidence.ObservedStart,
			ObservedEnd: evidence.ObservedEnd, RecordedAt: evidence.RecordedAt,
		})
	}
	for _, call := range response.ModelCalls {
		report.ModelCalls = append(report.ModelCalls, adminui.ModelCall{
			ID: call.ID, Kind: call.Kind, Provider: call.Provider, Model: call.Model,
			ModelConfigVersion: call.ModelConfigVersion, PromptSchemaVersion: call.PromptSchemaVersion,
			ToolSchemaVersion: call.ToolSchemaVersion, InputTokens: call.InputTokens,
			OutputTokens: call.OutputTokens, CostMicrounits: call.CostMicrounits,
			LatencyMilliseconds: call.LatencyMilliseconds, Outcome: call.Outcome,
			ReasonCode: call.ReasonCode, OccurredAt: call.OccurredAt,
			Input: mapModelPayload(call.Input), Output: mapModelPayload(call.Output),
		})
	}
	for _, manifest := range response.ContextManifests {
		report.ContextManifests = append(report.ContextManifests, adminui.ContextManifest{CallKey: manifest.CallKey, CallKind: manifest.CallKind, EstimatorVersion: manifest.EstimatorVersion, AllowanceTokens: manifest.AllowanceTokens, EstimatedInputTokens: manifest.EstimatedInputTokens, RawEstimatedInputTokens: manifest.RawEstimatedInputTokens, CalibrationFactorMillionths: manifest.CalibrationFactorMillionths, CalibrationSampleCount: manifest.CalibrationSampleCount, FixedMarginTokens: manifest.FixedMarginTokens, MaximumOutputTokens: manifest.MaximumOutputTokens, ActualInputTokens: manifest.ActualInputTokens, EstimatorUnderrun: manifest.EstimatorUnderrun, MemoryAllowanceTokens: manifest.MemoryAllowanceTokens, MemoryCandidateCount: manifest.MemoryCandidateCount, SelectedMemoryIDs: manifest.SelectedMemoryIDs, SelectedEvidenceIDs: manifest.SelectedEvidenceIDs, ExclusionReasons: manifest.ExclusionReasons, SectionTokens: manifest.SectionTokens, RetrievalLatencyMilliseconds: manifest.RetrievalLatencyMilliseconds, IndexVersion: manifest.IndexVersion, FallbackState: manifest.FallbackState, ContextMode: manifest.ContextMode, CheckpointDigest: manifest.CheckpointDigest, DeltaFromVersion: manifest.DeltaFromVersion, ShadowOnly: manifest.ShadowOnly, CreatedAt: manifest.CreatedAt})
	}
	return report, nil
}

type clustersResponse struct {
	Clusters []clusterResponse `json:"clusters"`
}

type clusterResponse struct {
	ID                 string     `json:"cluster_id"`
	DisplayName        string     `json:"display_name"`
	ExpectedCollectors []string   `json:"expected_collectors"`
	CreatedAt          time.Time  `json:"created_at"`
	RemovedAt          *time.Time `json:"removed_at,omitempty"`
}

type operationsResponse struct {
	Repairs        repairOverviewDTO       `json:"repairs"`
	GeneratedAt    time.Time               `json:"generated_at"`
	Tickets        []ticketResponse        `json:"tickets"`
	Investigations []investigationResponse `json:"investigations"`
}

type ticketResponse struct {
	ID                 string     `json:"ticket_id"`
	ClusterID          string     `json:"cluster_id"`
	RuleID             string     `json:"rule_id"`
	Title              string     `json:"title"`
	Summary            string     `json:"summary,omitempty"`
	Severity           string     `json:"severity"`
	Status             string     `json:"status"`
	UpdatedAt          time.Time  `json:"updated_at"`
	LastSignalAt       time.Time  `json:"last_signal_at"`
	AutoStartStatus    string     `json:"auto_start_status,omitempty"`
	AutoStartDecision  string     `json:"auto_start_decision,omitempty"`
	AutoStartUpdatedAt *time.Time `json:"auto_start_updated_at,omitempty"`
}

type investigationResponse struct {
	ID                    string    `json:"investigation_id"`
	ClusterID             string    `json:"cluster_id"`
	IncidentID            string    `json:"incident_id"`
	Question              string    `json:"question"`
	Status                string    `json:"status"`
	EntityKind            string    `json:"entity_kind"`
	EntityIDs             []string  `json:"entity_ids"`
	AuditedTokens         int64     `json:"audited_tokens"`
	AuditedCostMicrounits int64     `json:"audited_cost_microunits"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type investigationReportResponse struct {
	Shared           bool                      `json:"shared"`
	Version          int                       `json:"version"`
	ID               string                    `json:"investigation_id"`
	ClusterID        string                    `json:"cluster_id"`
	IncidentID       string                    `json:"incident_id"`
	Question         string                    `json:"question"`
	Status           string                    `json:"status"`
	StopReason       string                    `json:"stop_reason"`
	EntityKind       string                    `json:"entity_kind"`
	EntityIDs        []string                  `json:"entity_ids"`
	WindowStart      time.Time                 `json:"window_start"`
	WindowEnd        time.Time                 `json:"window_end"`
	SuccessCriteria  []string                  `json:"success_criteria"`
	CreatedAt        time.Time                 `json:"created_at"`
	UpdatedAt        time.Time                 `json:"updated_at"`
	CompletedAt      *time.Time                `json:"completed_at"`
	ModelUsage       reportModelUsageResponse  `json:"model_usage"`
	Findings         []reportFindingResponse   `json:"findings"`
	ReportSections   []reportSectionResponse   `json:"report_sections"`
	ReportOmissions  []reportOmissionResponse  `json:"report_omissions"`
	PrimaryAction    *reportActionCardResponse `json:"primary_action"`
	Evidence         []reportEvidenceResponse  `json:"evidence"`
	ModelCalls       []modelCallResponse       `json:"model_calls"`
	ContextManifests []contextManifestResponse `json:"context_manifests"`
}

type reportActionCardResponse struct {
	ID                  string   `json:"id"`
	Owner               string   `json:"owner"`
	Action              string   `json:"action"`
	Urgency             string   `json:"urgency"`
	Targets             []string `json:"targets"`
	Rationale           string   `json:"rationale"`
	EvidenceIDs         []string `json:"evidence_ids"`
	BlockingGaps        []string `json:"blocking_gaps"`
	EscalationCondition string   `json:"escalation_condition"`
}

type reportOmissionResponse struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type reportSectionResponse struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	Ordinal     int        `json:"ordinal"`
	Statement   string     `json:"statement"`
	ObservedAt  *time.Time `json:"observed_at"`
	EvidenceIDs []string   `json:"evidence_ids"`
}

type contextManifestResponse struct {
	CallKey                      string    `json:"call_key"`
	CallKind                     string    `json:"call_kind"`
	EstimatorVersion             string    `json:"estimator_version"`
	AllowanceTokens              int64     `json:"allowance_tokens"`
	EstimatedInputTokens         int64     `json:"estimated_input_tokens"`
	RawEstimatedInputTokens      int64     `json:"raw_estimated_input_tokens"`
	CalibrationFactorMillionths  int64     `json:"calibration_factor_millionths"`
	CalibrationSampleCount       int       `json:"calibration_sample_count"`
	FixedMarginTokens            int64     `json:"fixed_margin_tokens"`
	MaximumOutputTokens          int64     `json:"maximum_output_tokens"`
	ActualInputTokens            *int64    `json:"actual_input_tokens"`
	EstimatorUnderrun            bool      `json:"estimator_underrun"`
	MemoryAllowanceTokens        int64     `json:"memory_allowance_tokens"`
	MemoryCandidateCount         int       `json:"memory_candidate_count"`
	SelectedMemoryIDs            []string  `json:"selected_memory_ids"`
	SelectedEvidenceIDs          []string  `json:"selected_evidence_ids"`
	ExclusionReasons             string    `json:"exclusion_reasons"`
	SectionTokens                string    `json:"section_tokens"`
	RetrievalLatencyMilliseconds int64     `json:"retrieval_latency_milliseconds"`
	IndexVersion                 string    `json:"index_version"`
	FallbackState                string    `json:"fallback_state"`
	ContextMode                  string    `json:"context_mode"`
	CheckpointDigest             string    `json:"checkpoint_digest"`
	DeltaFromVersion             *int      `json:"delta_from_version"`
	ShadowOnly                   bool      `json:"shadow_only"`
	CreatedAt                    time.Time `json:"created_at"`
}

type reportModelUsageResponse struct {
	MaxTokens              int64 `json:"max_tokens"`
	AdmittedTokens         int64 `json:"admitted_tokens"`
	AuditedTokens          int64 `json:"audited_tokens"`
	MaxCostMicrounits      int64 `json:"max_cost_microunits"`
	AdmittedCostMicrounits int64 `json:"admitted_cost_microunits"`
	AuditedCostMicrounits  int64 `json:"audited_cost_microunits"`
}

type reportEvidenceResponse struct {
	ID            string    `json:"evidence_id"`
	Kind          string    `json:"kind"`
	Status        string    `json:"status"`
	ExactScope    string    `json:"exact_scope"`
	ObservedStart time.Time `json:"observed_start"`
	ObservedEnd   time.Time `json:"observed_end"`
	RecordedAt    time.Time `json:"recorded_at"`
}

type modelCallResponse struct {
	ID                  string               `json:"call_id"`
	Kind                string               `json:"kind"`
	Provider            string               `json:"provider"`
	Model               string               `json:"model"`
	ModelConfigVersion  string               `json:"model_config_version"`
	PromptSchemaVersion string               `json:"prompt_schema_version"`
	ToolSchemaVersion   string               `json:"tool_schema_version"`
	InputTokens         int64                `json:"input_tokens"`
	OutputTokens        int64                `json:"output_tokens"`
	CostMicrounits      int64                `json:"cost_microunits"`
	LatencyMilliseconds int64                `json:"latency_milliseconds"`
	Outcome             string               `json:"outcome"`
	ReasonCode          string               `json:"reason_code"`
	OccurredAt          time.Time            `json:"occurred_at"`
	Input               modelPayloadResponse `json:"input"`
	Output              modelPayloadResponse `json:"output"`
}

type modelPayloadResponse struct {
	EvidenceID   string `json:"evidence_id"`
	Availability string `json:"availability"`
	MediaType    string `json:"media_type"`
	Content      string `json:"content"`
}

func mapModelPayload(payload modelPayloadResponse) adminui.ModelPayload {
	return adminui.ModelPayload{EvidenceID: payload.EvidenceID, Availability: payload.Availability, MediaType: payload.MediaType, Content: payload.Content}
}

type reportFindingResponse struct {
	ID                 string   `json:"finding_id"`
	Kind               string   `json:"kind"`
	Statement          string   `json:"statement"`
	EntityIDs          []string `json:"entity_ids"`
	Severity           string   `json:"severity"`
	Confidence         *float64 `json:"confidence"`
	EvidenceIDs        []string `json:"evidence_ids"`
	CounterEvidenceIDs []string `json:"counter_evidence_ids"`
}

type updateClusterRequest struct {
	DisplayName        string   `json:"display_name"`
	ExpectedCollectors []string `json:"expected_collectors"`
	SessionFingerprint []byte   `json:"session_fingerprint"`
	RequestID          string   `json:"request_id"`
}

type credentialMetadataResponse struct {
	Credentials []credentialMetadataDTO `json:"credentials"`
}
type credentialMetadataDTO struct {
	ID         string     `json:"credential_id"`
	ClusterID  string     `json:"cluster_id"`
	Host       string     `json:"host"`
	Purpose    string     `json:"purpose"`
	Username   string     `json:"username"`
	KeyVersion string     `json:"key_version"`
	Version    int64      `json:"version"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	ReplacedBy string     `json:"replaced_by,omitempty"`
}
type putCredentialRequest struct {
	Host                 string `json:"host"`
	Purpose              string `json:"purpose"`
	Username             string `json:"username"`
	SSHPassword          string `json:"ssh_password,omitempty"`
	SudoPassword         string `json:"sudo_password"`
	ExpectedVersion      int64  `json:"expected_version"`
	ExpectedCredentialID string `json:"expected_credential_id,omitempty"`
	ActorSubject         string `json:"actor_subject"`
	SessionFingerprint   []byte `json:"session_fingerprint"`
	RequestID            string `json:"request_id"`
}
type revokeCredentialRequest struct {
	ExpectedVersion    int64  `json:"expected_version"`
	ActorSubject       string `json:"actor_subject"`
	SessionFingerprint []byte `json:"session_fingerprint"`
	RequestID          string `json:"request_id"`
}

type removeClusterRequest struct {
	Confirmation       string `json:"confirmation"`
	SessionFingerprint []byte `json:"session_fingerprint"`
	RequestID          string `json:"request_id"`
}

type investigationStartRequest struct {
	Purpose            string                     `json:"purpose,omitempty"`
	IncidentID         string                     `json:"incident_id"`
	Question           string                     `json:"question"`
	Scope              investigationScopeRequest  `json:"scope"`
	SuccessCriteria    []string                   `json:"success_criteria"`
	Budget             investigationBudgetRequest `json:"budget"`
	Deadline           time.Time                  `json:"deadline"`
	IdempotencyKey     string                     `json:"idempotency_key"`
	SessionFingerprint []byte                     `json:"session_fingerprint"`
	RequestID          string                     `json:"request_id"`
}

type investigationScopeRequest struct {
	EntityKind string    `json:"entity_kind"`
	EntityIDs  []string  `json:"entity_ids"`
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
}

type investigationBudgetRequest struct {
	MaxDecisions       int   `json:"max_decisions"`
	MaxToolCalls       int   `json:"max_tool_calls"`
	MaxDiagnosticCalls int   `json:"max_diagnostic_calls"`
	MaxPrivilegedCalls int   `json:"max_privileged_calls"`
	MaxFanOut          int   `json:"max_fan_out"`
	MaxModelTokens     int64 `json:"max_model_tokens"`
	MaxCostMicros      int64 `json:"max_cost_micros"`
}

type investigationStartResponse struct {
	ID       string `json:"investigation_id"`
	Status   string `json:"status"`
	Replayed bool   `json:"replayed"`
}

func mapClusterRecord(cluster clusterResponse) adminui.ClusterRecord {
	state := adminui.StateNoData
	description := "Active cluster"
	if cluster.RemovedAt != nil {
		state = adminui.StateUnavailable
		description = "Removed cluster"
	}
	return adminui.ClusterRecord{
		ID: cluster.ID, DisplayName: cluster.DisplayName, State: state,
		ExpectedCollectors: append([]string(nil), cluster.ExpectedCollectors...),
		CreatedAt:          cluster.CreatedAt, RemovedAt: cluster.RemovedAt, Description: description,
	}
}

func validClusterID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, character := range id {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func validActorSubject(subject string) bool {
	return len(subject) > 0 && len(subject) <= 256 && !strings.ContainsAny(subject, "\x00\r\n")
}

// RecordAdminEvent sends a sanitized dashboard security event to the API.
func (client *Client) RecordAdminEvent(ctx context.Context, event adminui.AuditEvent) error {
	payload, err := json.Marshal(auditEvent{
		Kind: event.Kind, Outcome: event.Outcome, ReasonCode: event.ReasonCode,
		SessionFingerprint: event.SessionFingerprint, RequestID: event.RequestID,
		OccurredAt: event.OccurredAt,
	})
	if err != nil {
		return errors.New("encode admin API audit request")
	}
	request, err := client.request(ctx, http.MethodPost, "/internal/admin/v1/audit", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	_, err = client.do(request)
	return err
}

type auditEvent struct {
	Kind               adminui.EventKind    `json:"kind"`
	Outcome            adminui.EventOutcome `json:"outcome"`
	ReasonCode         string               `json:"reason_code"`
	SessionFingerprint []byte               `json:"session_fingerprint,omitempty"`
	RequestID          string               `json:"request_id"`
	OccurredAt         time.Time            `json:"occurred_at"`
}

func (client *Client) request(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	endpoint := *client.baseURL
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, errors.New("create admin API request")
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("Accept", "application/json")
	if session, ok := adminui.HumanSessionFromContext(ctx); ok {
		sealed, err := auth.SealHumanSession([]byte(client.token), session, method, request.URL.RequestURI(), time.Now().UTC())
		if err != nil {
			return nil, errors.New("bind admin request to human session")
		}
		request.Header.Set(auth.HumanSessionHeader, sealed)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request, nil
}

func (client *Client) do(request *http.Request) ([]byte, error) {
	response, err := client.http.Do(request)
	if err != nil {
		if errors.Is(err, errRedirectRejected) {
			return nil, errors.New("admin API request rejected a redirect")
		}
		return nil, errors.New("admin API request failed")
	}
	defer response.Body.Close()
	limit := maximumResponseBytes
	if strings.HasPrefix(request.URL.Path, "/internal/admin/v1/investigations/") {
		limit = maximumReportResponseBytes
	}
	if strings.HasSuffix(request.URL.Path, "/gpu-metrics") {
		limit = maximumGPUMetricsResponseBytes
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if readErr != nil {
		return nil, errors.New("read admin API response")
	}
	if int64(len(body)) > limit {
		return nil, errors.New("admin API response exceeded size limit")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if response.StatusCode == http.StatusNotFound && mediaType == "application/problem+json" {
			return nil, fmt.Errorf("%w: admin API record", adminui.ErrRecordNotFound)
		}
		return nil, fmt.Errorf("admin API request returned status %d", response.StatusCode)
	}
	if len(body) > 0 {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return nil, errors.New("admin API response content type is not JSON")
		}
	}
	return body, nil
}

func decodeStrict(body []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("admin API response contains trailing JSON")
	}
	return nil
}

func mapDashboard(snapshot adminview.Dashboard) adminui.Dashboard {
	dashboard := adminui.Dashboard{GeneratedAt: snapshot.GeneratedAt, State: adminui.StateNoData}
	dashboard.Summary = "No cluster operational records are available. Missing data is not interpreted as healthy."
	if len(snapshot.Clusters) == 0 {
		return dashboard
	}
	dashboard.Summary = "Cross-cluster operational state from bounded, redacted API projections. Review every degraded dimension before acting."
	dashboard.State = adminui.StateHealthy
	var collectors, freshCollectors, overdue, activeInvestigations, awaitingEvidence, modelCalls, modelCost, evidenceTotal, evidenceComplete int64
	for _, cluster := range snapshot.Clusters {
		collectors += cluster.Connectivity.Collectors
		freshCollectors += cluster.Connectivity.FreshCollectors
		overdue += cluster.Queue.Overdue
		activeInvestigations += cluster.Investigations.Active
		awaitingEvidence += cluster.Investigations.AwaitingEvidence
		modelCalls += cluster.ModelUsage.Calls
		modelCost += cluster.ModelUsage.CostMicrounits
		evidenceTotal += cluster.Evidence.CurrentTotal
		evidenceComplete += cluster.Evidence.CurrentComplete
		mapped := mapCluster(cluster)
		dashboard.Clusters = append(dashboard.Clusters, mapped)
		dashboard.State = worseState(dashboard.State, mapped.State)
		dashboard.Activity = append(dashboard.Activity, clusterActivity(cluster)...)
	}
	dashboard.Metrics = []adminui.Metric{
		{Label: "Collector connectivity", Value: fmt.Sprintf("%d / %d", freshCollectors, collectors), Detail: "fresh / expected", State: aggregateRatioState(freshCollectors, collectors)},
		{Label: "Overdue queue work", Value: strconv.FormatInt(overdue, 10), Detail: "collection, diagnostic, and investigation items", State: zeroHealthyState(overdue)},
		{Label: "Active investigations", Value: strconv.FormatInt(activeInvestigations, 10), Detail: investigationActivityDetail(awaitingEvidence), State: adminui.StateHealthy},
		{Label: "Model usage", Value: strconv.FormatInt(modelCalls, 10), Detail: fmt.Sprintf("calls · %d cost microunits", modelCost), State: usageState(snapshot.Clusters)},
		{Label: "Current evidence streams", Value: fmt.Sprintf("%d / %d", evidenceComplete, evidenceTotal), Detail: "latest complete / applicable streams", State: aggregateRatioState(evidenceComplete, evidenceTotal)},
	}
	return dashboard
}

func mapCluster(cluster adminview.ClusterSummary) adminui.Cluster {
	result := adminui.Cluster{
		ID: cluster.ClusterID, Name: cluster.DisplayName, State: mapState(cluster.Overall), Network: cluster.Network, Health: cluster.Health,
		EvidenceExpected: cluster.Evidence.CurrentExpectedTargets, EvidenceCovered: cluster.Evidence.CurrentCoveredTargets,
		LastSeenAt:              latestTime(cluster.Connectivity.LastCollectorContact, cluster.Freshness.LastSuccessAt, cluster.Evidence.LastCollectedAt),
		Description:             fmt.Sprintf("%d expected collectors · %d sources", cluster.Connectivity.Collectors, cluster.Connectivity.Sources),
		MissingCollectorNames:   append([]string(nil), cluster.Connectivity.MissingCollectorNames...),
		MissingCollectorLabels:  append([]string(nil), cluster.Connectivity.MissingCollectorLabels...),
		ExcludedCollectorLabels: append([]string(nil), cluster.Connectivity.ExcludedCollectorLabels...),
		ExpectedCollectorNames:  append([]string(nil), cluster.ExpectedCollectorNames...),
		SourceGapLabels:         append([]string(nil), cluster.Connectivity.SourceGapLabels...),
		OnDemandSourceLabels:    append([]string(nil), cluster.Connectivity.OnDemandSourceLabels...),
		EvidenceHistory: adminui.EvidenceHistory{
			Total: cluster.Evidence.Total, Complete: cluster.Evidence.Complete,
			Partial: cluster.Evidence.Partial, NoData: cluster.Evidence.NoData,
			Unavailable: cluster.Evidence.Unavailable, Superseded: cluster.Evidence.HistoricalSuperseded,
		},
		Resources: adminui.ResourceSummary{
			Truncated: cluster.Resources.Truncated,
			State:     mapState(cluster.Resources.State), ObservedNodes: cluster.Resources.ObservedNodes,
			ObservedGPUs:          cluster.Resources.ObservedGPUs,
			GPUUtilizationPercent: cluster.Resources.GPUUtilizationPercent,
			GPUUtilizationSamples: cluster.Resources.GPUUtilizationSamples,
			CPUUtilizationPercent: cluster.Resources.CPUUtilizationPercent,
			CPUUtilizationSamples: cluster.Resources.CPUUtilizationSamples,
			LastObservedAt:        cluster.Resources.LastObservedAt,
		},
		Dimensions: []adminui.Metric{
			{Label: "Connectivity", Value: fmt.Sprintf("%d / %d", cluster.Connectivity.FreshCollectors, cluster.Connectivity.Collectors), Detail: "fresh / expected collectors", State: mapState(cluster.Connectivity.State)},
			{Label: "Freshness", Value: fmt.Sprintf("%d fresh", cluster.Freshness.FreshSources), Detail: fmt.Sprintf("%d stale · %d no data", cluster.Freshness.StaleSources, cluster.Freshness.SourcesWithoutData), State: mapState(cluster.Freshness.State)},
			{Label: "Queue", Value: fmt.Sprintf("%d overdue", cluster.Queue.Overdue), Detail: fmt.Sprintf("%d diagnostic blocked", cluster.Queue.DiagnosticBlocked), State: mapState(cluster.Queue.State)},
			{Label: "Investigations", Value: fmt.Sprintf("%d active", cluster.Investigations.Active), Detail: fmt.Sprintf("%d partial · %d blocked", cluster.Investigations.Partial, cluster.Investigations.Blocked), State: mapState(cluster.Investigations.State)},
			{Label: "Model usage", Value: fmt.Sprintf("%d calls", cluster.ModelUsage.Calls), Detail: fmt.Sprintf("%d rejected · %d failed · trailing 24h", cluster.ModelUsage.Rejected, cluster.ModelUsage.Failed), Explanation: "Degraded when any model call was rejected or failed in the trailing 24 hours. This is cluster-wide call reliability, not the status of the current investigation.", State: mapState(cluster.ModelUsage.State)},
			{Label: "Evidence", Value: fmt.Sprintf("%d / %d current", cluster.Evidence.CurrentComplete, cluster.Evidence.CurrentTotal), Detail: fmt.Sprintf("%d partial · %d no data · %d unavailable", cluster.Evidence.CurrentPartial, cluster.Evidence.CurrentNoData, cluster.Evidence.CurrentUnavailable), Explanation: fmt.Sprintf("Current health uses only the newest applicable envelope in each source, operation, and scope stream. The trailing 24 hours contain %d envelopes and remain historical context only.", cluster.Evidence.Total), State: mapState(cluster.Evidence.State)},
			{Label: "Diagnostic audit", Value: fmt.Sprintf("%d events", cluster.Audit.Events), Detail: fmt.Sprintf("%d denied or failed", cluster.Audit.DeniedOrFailed), State: mapState(cluster.Audit.State)},
		},
	}
	for _, stream := range cluster.Evidence.CurrentStreams {
		result.EvidenceStreams = append(result.EvidenceStreams, adminui.EvidenceStreamHealth{
			SourceID: stream.SourceID, Operation: stream.Operation, Scope: stream.Scope,
			Status: stream.Status, RunID: stream.RunID, LatestAttempt: stream.LatestAttempt,
			State:           mapEvidenceStatus(stream.Status),
			ExpectedTargets: append([]string(nil), stream.ExpectedTargets...),
			CoveredTargets:  append([]string(nil), stream.CoveredTargets...),
			MissingTargets:  append([]string(nil), stream.MissingTargets...),
			SeriesExpected:  stream.SeriesExpected, SeriesReturned: stream.SeriesReturned,
			FailureCode: stream.FailureCode, SafeFailureReason: stream.SafeFailureReason,
			Condition: stream.Condition, RecommendedAction: stream.RecommendedAction,
		})
	}
	for _, operation := range cluster.SlurmOperations {
		result.SlurmOperations = append(result.SlurmOperations, adminui.SlurmOperationStatus{
			SourceID: operation.SourceID, Operation: operation.Operation, Status: operation.Status,
			Fresh: operation.Fresh, LastCompletedAt: operation.LastCompletedAt,
		})
	}
	return result
}

func clusterActivity(cluster adminview.ClusterSummary) []adminui.Activity {
	items := make([]adminui.Activity, 0, 3)
	if cluster.Investigations.LastUpdate != nil {
		items = append(items, adminui.Activity{OccurredAt: *cluster.Investigations.LastUpdate, Kind: "Investigation state · " + cluster.DisplayName, Summary: fmt.Sprintf("%d active, %d completed, %d partial, %d blocked", cluster.Investigations.Active, cluster.Investigations.Completed, cluster.Investigations.Partial, cluster.Investigations.Blocked), State: mapState(cluster.Investigations.State)})
	}
	if cluster.ModelUsage.LastCallAt != nil {
		items = append(items, adminui.Activity{OccurredAt: *cluster.ModelUsage.LastCallAt, Kind: "Model usage · " + cluster.DisplayName, Summary: fmt.Sprintf("%d calls, %d input tokens, %d output tokens", cluster.ModelUsage.Calls, cluster.ModelUsage.InputTokens, cluster.ModelUsage.OutputTokens), State: mapState(cluster.ModelUsage.State)})
	}
	if cluster.Evidence.LastCollectedAt != nil {
		items = append(items, adminui.Activity{OccurredAt: *cluster.Evidence.LastCollectedAt, Kind: "Evidence coverage · " + cluster.DisplayName, Summary: fmt.Sprintf("current: %d complete, %d partial, %d unavailable · trailing 24h: %d envelopes", cluster.Evidence.CurrentComplete, cluster.Evidence.CurrentPartial, cluster.Evidence.CurrentUnavailable, cluster.Evidence.Total), State: mapState(cluster.Evidence.State)})
	}
	return items
}

func mapState(state adminview.State) adminui.OperationalState {
	switch state {
	case adminview.StateHealthy:
		return adminui.StateHealthy
	case adminview.StateDegraded:
		return adminui.StateDegraded
	case adminview.StateUnavailable:
		return adminui.StateUnavailable
	default:
		return adminui.StateNoData
	}
}

func mapEvidenceStatus(status string) adminui.OperationalState {
	switch status {
	case "COMPLETE":
		return adminui.StateHealthy
	case "UNAVAILABLE":
		return adminui.StateUnavailable
	case "NO_DATA":
		return adminui.StateNoData
	default:
		return adminui.StatePartial
	}
}

func worseState(current, candidate adminui.OperationalState) adminui.OperationalState {
	rank := map[adminui.OperationalState]int{adminui.StateHealthy: 0, adminui.StateNoData: 1, adminui.StateDegraded: 2, adminui.StatePartial: 2, adminui.StateStale: 3, adminui.StateUnavailable: 4}
	if rank[candidate] > rank[current] {
		return candidate
	}
	return current
}

func aggregateRatioState(current, total int64) adminui.OperationalState {
	if total == 0 {
		return adminui.StateNoData
	}
	if current == 0 {
		return adminui.StateUnavailable
	}
	if current < total {
		return adminui.StateDegraded
	}
	return adminui.StateHealthy
}

func zeroHealthyState(value int64) adminui.OperationalState {
	if value == 0 {
		return adminui.StateHealthy
	}
	return adminui.StateDegraded
}

func usageState(clusters []adminview.ClusterSummary) adminui.OperationalState {
	state := adminui.StateNoData
	for _, cluster := range clusters {
		state = worseState(state, mapState(cluster.ModelUsage.State))
	}
	return state
}

func latestTime(values ...*time.Time) time.Time {
	var latest time.Time
	for _, value := range values {
		if value != nil && value.After(latest) {
			latest = value.UTC()
		}
	}
	return latest
}

// Compile-time assertions keep the dashboard boundaries explicit.
var _ adminui.DataProvider = (*Client)(nil)
var _ adminui.Auditor = (*Client)(nil)

// investigationActivityDetail names the reason a non-terminal count is not
// moving. An investigation parked on an outstanding remote execution is
// working, not stuck, and an operator must be able to tell the two apart
// without opening each run.
func investigationActivityDetail(awaitingEvidence int64) string {
	if awaitingEvidence == 0 {
		return "non-terminal workflows"
	}
	return fmt.Sprintf("non-terminal workflows · %d awaiting outstanding diagnostic evidence", awaitingEvidence)
}

type repairOverviewDTO struct {
	Available           bool                `json:"available"`
	GlobalEnabled       bool                `json:"global_enabled"`
	ActiveRequests      int64               `json:"active_requests"`
	PendingVerification int64               `json:"pending_verification"`
	Succeeded           int64               `json:"succeeded"`
	Contained           int64               `json:"contained"`
	Cancelled           int64               `json:"cancelled"`
	RolledBack          int64               `json:"rolled_back"`
	Decisions           []repairDecisionDTO `json:"decisions"`
}
type repairDecisionDTO struct {
	Code  string `json:"code"`
	Count int64  `json:"count"`
}

type credentialAccessTestListResponse struct {
	Tests []credentialAccessTestDTO `json:"tests"`
}
type credentialAccessTestDTO struct {
	ID                string                      `json:"test_id"`
	ClusterID         string                      `json:"cluster_id"`
	CredentialID      string                      `json:"credential_id"`
	CredentialVersion int64                       `json:"credential_version"`
	Host              string                      `json:"host"`
	Purpose           string                      `json:"purpose"`
	Username          string                      `json:"username"`
	Operation         string                      `json:"operation"`
	Status            string                      `json:"status"`
	RequestedBy       string                      `json:"requested_by"`
	RequestedAt       time.Time                   `json:"requested_at"`
	Deadline          time.Time                   `json:"deadline"`
	Attempt           int                         `json:"attempt"`
	CollectorID       string                      `json:"collector_id,omitempty"`
	LeaseExpiresAt    *time.Time                  `json:"lease_expires_at,omitempty"`
	OutcomeCode       string                      `json:"outcome_code,omitempty"`
	OutcomeSummary    string                      `json:"outcome_summary,omitempty"`
	BCMVersion        string                      `json:"bcm_version,omitempty"`
	DevicesListed     int                         `json:"devices_listed"`
	CompletedAt       *time.Time                  `json:"completed_at,omitempty"`
	CancelledBy       string                      `json:"cancelled_by,omitempty"`
	CredentialCurrent bool                        `json:"credential_current"`
	CredentialStatus  string                      `json:"credential_status"`
	Devices           []credentialAccessDeviceDTO `json:"devices,omitempty"`
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
type requestCredentialAccessTestRequest struct {
	ExpectedVersion    int64  `json:"expected_version"`
	ActorSubject       string `json:"actor_subject"`
	SessionFingerprint []byte `json:"session_fingerprint"`
	RequestID          string `json:"request_id"`
}
type cancelCredentialAccessTestRequest struct {
	ActorSubject       string `json:"actor_subject"`
	SessionFingerprint []byte `json:"session_fingerprint"`
	RequestID          string `json:"request_id"`
}

func mapCredentialAccessDevices(items []credentialAccessDeviceDTO) []adminui.CredentialAccessDevice {
	devices := make([]adminui.CredentialAccessDevice, 0, len(items))
	for _, item := range items {
		devices = append(devices, adminui.CredentialAccessDevice{Type: item.Type, Hostname: item.Hostname, Category: item.Category, Status: item.Status})
	}
	return devices
}

func mapCredentialAccessTest(item credentialAccessTestDTO) adminui.CredentialAccessTest {
	var devices []adminui.CredentialAccessDevice
	if len(item.Devices) > 0 {
		devices = mapCredentialAccessDevices(item.Devices)
	}
	return adminui.CredentialAccessTest{
		Operation: item.Operation, Devices: devices,
		ID: item.ID, ClusterID: item.ClusterID, CredentialID: item.CredentialID, CredentialVersion: item.CredentialVersion,
		Host: item.Host, Purpose: item.Purpose, Username: item.Username, Status: item.Status, RequestedBy: item.RequestedBy,
		RequestedAt: item.RequestedAt, Deadline: item.Deadline, Attempt: item.Attempt, CollectorID: item.CollectorID, LeaseExpiresAt: item.LeaseExpiresAt,
		OutcomeCode: item.OutcomeCode, OutcomeSummary: item.OutcomeSummary, BCMVersion: item.BCMVersion, DevicesListed: item.DevicesListed,
		CompletedAt: item.CompletedAt, CancelledBy: item.CancelledBy, CredentialCurrent: item.CredentialCurrent, CredentialStatus: item.CredentialStatus,
	}
}

// ListCredentialAccessTests loads the redacted test history for a cluster
// using the verified Access subject supplied by the dashboard.
func (client *Client) ListCredentialAccessTests(ctx context.Context, clusterID, actorSubject string) ([]adminui.CredentialAccessTest, error) {
	if !validClusterID(clusterID) || !validActorSubject(actorSubject) {
		return nil, errors.New("admin API credential scope is invalid")
	}
	request, err := client.request(ctx, http.MethodGet, "/internal/admin/v1/clusters/"+url.PathEscape(clusterID)+"/credential-access-tests", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("X-Sherlock-Access-Subject", actorSubject)
	responseBody, err := client.do(request)
	if err != nil {
		return nil, err
	}
	var response credentialAccessTestListResponse
	if err := decodeStrict(responseBody, &response); err != nil {
		return nil, errors.New("decode admin API credential access test response")
	}
	tests := make([]adminui.CredentialAccessTest, 0, len(response.Tests))
	for _, item := range response.Tests {
		tests = append(tests, mapCredentialAccessTest(item))
	}
	return tests, nil
}

// RequestCredentialAccessTest asks the private API to schedule a head-side
// test for one exact active credential version.
func (client *Client) RequestCredentialAccessTest(ctx context.Context, clusterID, actorSubject, credentialID string, expectedVersion int64, mutation adminui.MutationContext) (adminui.CredentialAccessTest, error) {
	if !validClusterID(clusterID) || !validClusterID(credentialID) || expectedVersion < 1 || !validActorSubject(actorSubject) {
		return adminui.CredentialAccessTest{}, errors.New("admin API credential access test request is invalid")
	}
	payload, err := json.Marshal(requestCredentialAccessTestRequest{ExpectedVersion: expectedVersion, ActorSubject: actorSubject, SessionFingerprint: mutation.SessionFingerprint, RequestID: mutation.RequestID})
	if err != nil {
		return adminui.CredentialAccessTest{}, errors.New("encode admin API credential access test request")
	}
	request, err := client.request(ctx, http.MethodPost, "/internal/admin/v1/clusters/"+url.PathEscape(clusterID)+"/credentials/"+url.PathEscape(credentialID)+"/access-tests", bytes.NewReader(payload))
	if err != nil {
		return adminui.CredentialAccessTest{}, err
	}
	responseBody, err := client.do(request)
	if err != nil {
		return adminui.CredentialAccessTest{}, err
	}
	var item credentialAccessTestDTO
	if err := decodeStrict(responseBody, &item); err != nil {
		return adminui.CredentialAccessTest{}, errors.New("decode admin API credential access test response")
	}
	return mapCredentialAccessTest(item), nil
}

// RequestCredentialInventoryDiscovery asks the private API to schedule the
// second reviewed operation for one exact active credential version. It is
// the same request shape as the access test; only the route differs.
func (client *Client) RequestCredentialInventoryDiscovery(ctx context.Context, clusterID, actorSubject, credentialID string, expectedVersion int64, mutation adminui.MutationContext) (adminui.CredentialAccessTest, error) {
	if !validClusterID(clusterID) || !validClusterID(credentialID) || expectedVersion < 1 || !validActorSubject(actorSubject) {
		return adminui.CredentialAccessTest{}, errors.New("admin API credential inventory discovery request is invalid")
	}
	payload, err := json.Marshal(requestCredentialAccessTestRequest{ExpectedVersion: expectedVersion, ActorSubject: actorSubject, SessionFingerprint: mutation.SessionFingerprint, RequestID: mutation.RequestID})
	if err != nil {
		return adminui.CredentialAccessTest{}, errors.New("encode admin API credential inventory discovery request")
	}
	request, err := client.request(ctx, http.MethodPost, "/internal/admin/v1/clusters/"+url.PathEscape(clusterID)+"/credentials/"+url.PathEscape(credentialID)+"/inventory-discoveries", bytes.NewReader(payload))
	if err != nil {
		return adminui.CredentialAccessTest{}, err
	}
	responseBody, err := client.do(request)
	if err != nil {
		return adminui.CredentialAccessTest{}, err
	}
	var item credentialAccessTestDTO
	if err := decodeStrict(responseBody, &item); err != nil {
		return adminui.CredentialAccessTest{}, errors.New("decode admin API credential inventory discovery response")
	}
	return mapCredentialAccessTest(item), nil
}

// LatestInventoryDiscovery loads the newest retained listing for a cluster.
// found is false when none has succeeded yet, which the private API reports
// as a NOT_FOUND problem rather than an empty document.
func (client *Client) LatestInventoryDiscovery(ctx context.Context, clusterID, actorSubject string) (adminui.CredentialInventoryDiscovery, bool, error) {
	if !validClusterID(clusterID) || !validActorSubject(actorSubject) {
		return adminui.CredentialInventoryDiscovery{}, false, errors.New("admin API credential scope is invalid")
	}
	request, err := client.request(ctx, http.MethodGet, "/internal/admin/v1/clusters/"+url.PathEscape(clusterID)+"/inventory-discovery/latest", nil)
	if err != nil {
		return adminui.CredentialInventoryDiscovery{}, false, err
	}
	request.Header.Set("X-Sherlock-Access-Subject", actorSubject)
	responseBody, err := client.do(request)
	if err != nil {
		if errors.Is(err, adminui.ErrRecordNotFound) {
			return adminui.CredentialInventoryDiscovery{}, false, nil
		}
		return adminui.CredentialInventoryDiscovery{}, false, err
	}
	var item credentialInventoryDiscoveryDTO
	if err := decodeStrict(responseBody, &item); err != nil {
		return adminui.CredentialInventoryDiscovery{}, false, errors.New("decode admin API credential inventory discovery response")
	}
	return adminui.CredentialInventoryDiscovery{
		TestID: item.TestID, ClusterID: item.ClusterID, CredentialID: item.CredentialID, CredentialVersion: item.CredentialVersion,
		Host: item.Host, BCMVersion: item.BCMVersion, CompletedAt: item.CompletedAt, CredentialCurrent: item.CredentialCurrent,
		Devices: mapCredentialAccessDevices(item.Devices),
	}, true, nil
}

// CancelCredentialAccessTest cancels a pending test.
func (client *Client) CancelCredentialAccessTest(ctx context.Context, clusterID, actorSubject, testID string, mutation adminui.MutationContext) error {
	if !validClusterID(clusterID) || !validClusterID(testID) || !validActorSubject(actorSubject) {
		return errors.New("admin API credential access test reference is invalid")
	}
	payload, err := json.Marshal(cancelCredentialAccessTestRequest{ActorSubject: actorSubject, SessionFingerprint: mutation.SessionFingerprint, RequestID: mutation.RequestID})
	if err != nil {
		return errors.New("encode admin API credential access test cancellation")
	}
	request, err := client.request(ctx, http.MethodPost, "/internal/admin/v1/clusters/"+url.PathEscape(clusterID)+"/credential-access-tests/"+url.PathEscape(testID)+"/cancel", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	_, err = client.do(request)
	return err
}
