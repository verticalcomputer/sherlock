package adminui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/auth"
)

const (
	maxFormBodySize              = 16 << 10
	maxDisplayName               = 200
	operationsInvestigationLimit = 10
)

//go:embed templates/*.html static/*.css static/*.js static/*.woff2
var assets embed.FS

type Clock interface {
	Now() time.Time
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now().UTC() }

type Options struct {
	Provider                  DataProvider
	AccessVerifier            AccessVerifier
	RequireHumanAuthorization bool
	Auditor                   Auditor
	ErrorReporter             ErrorReporter
	Clock                     Clock
}

type Server struct {
	provider                  DataProvider
	credentialProvider        CredentialProvider
	accessTestProvider        CredentialAccessTestProvider
	expectedInventoryProvider ExpectedInventoryProvider
	accessVerifier            AccessVerifier
	humanAccessProvider       HumanAccessProvider
	auditor                   Auditor
	errorReporter             ErrorReporter
	clock                     Clock
	clustersTemplate          *template.Template
	detailTemplate            *template.Template
	editTemplate              *template.Template
	operationsTemplate        *template.Template
	reportTemplate            *template.Template
	handler                   http.Handler
	gpuMetricsProvider        GPUMetricsProvider
	gpuMetricsTemplate        *template.Template
}

func New(options Options) (*Server, error) {
	if options.Provider == nil {
		return nil, errors.New("admin dashboard data provider is required")
	}
	if options.AccessVerifier == nil {
		return nil, errors.New("cloudflare Access verifier is required")
	}
	if options.RequireHumanAuthorization {
		if _, ok := options.Provider.(HumanAccessProvider); !ok {
			return nil, errors.New("human authorization requires a private API access projection")
		}
	}
	if options.Auditor == nil {
		return nil, errors.New("admin auditor is required")
	}
	if options.ErrorReporter == nil {
		return nil, errors.New("admin audit error reporter is required")
	}
	if options.Clock == nil {
		options.Clock = wallClock{}
	}
	funcs := template.FuncMap{
		"repairDecisionLabel":   repairDecisionLabel,
		"healthCount":           healthCount,
		"sharedHealthAvailable": sharedHealthAvailable,
		"stateClass":            stateClass,
		"formatTime": func(value time.Time) string {
			if value.IsZero() {
				return "Not observed"
			}
			return value.UTC().Format("02 Jan 2006, 15:04 UTC")
		},
		// localTime emits only server-owned time data. The UTC text remains a
		// complete no-script fallback; the same-origin static script replaces it
		// with an Intl-formatted value in the browser's local time zone.
		"localTime": func(value time.Time) template.HTML {
			if value.IsZero() {
				return template.HTML("<time>Not observed</time>")
			}
			utc := value.UTC()
			return template.HTML(fmt.Sprintf(`<time data-local-time datetime="%s">%s</time>`,
				utc.Format(time.RFC3339Nano), utc.Format("02 Jan 2006, 15:04 UTC")))
		},
		"formatPayload": func(value string) string {
			var formatted bytes.Buffer
			if json.Indent(&formatted, []byte(value), "", "  ") == nil {
				return formatted.String()
			}
			return value
		},
		// Refusals were already durable in the model-call audit; they had simply
		// never been stated as a fact about the report. A proposal the controller
		// refused before execution is exactly what an operator needs to see when
		// a run stops early.
		"refusedCalls": func(calls []ModelCall) []ModelCall {
			refused := []ModelCall{}
			for _, call := range calls {
				if call.Outcome == "REJECTED" {
					refused = append(refused, call)
				}
			}
			return refused
		},
		"totalOmitted": func(omissions []ReportOmission) int {
			total := 0
			for _, omission := range omissions {
				total += omission.Count
			}
			return total
		},
		"describeOmission": func(reason string) string {
			switch reason {
			case "NO_SUPPORTED_ENTITY":
				return "citations covered no entity in the evidence ledger"
			case "CITATION_NOT_IN_LEDGER":
				return "cited evidence the ledger does not hold"
			case "VALIDATION_REFUSED":
				return "refused by durable record validation"
			case "CONTEXT_ITEM_LIMIT":
				return "not shown to the model: the context already held its limit of items"
			case "CONTEXT_SIZE_LIMIT":
				return "not shown to the model: the context reached its size ceiling"
			case "PROVIDER_INPUT_ALLOWANCE":
				return "not shown to the model: the context exceeded the provider input allowance"
			default:
				return reason
			}
		},
		"sectionsOfKind": func(kind string, sections []ReportSection) []ReportSection {
			selected := []ReportSection{}
			for _, section := range sections {
				if section.Kind == kind {
					selected = append(selected, section)
				}
			}
			return selected
		},
		"formatInstant": func(value *time.Time) string {
			if value == nil || value.IsZero() {
				return "Time not recorded"
			}
			return value.UTC().Format("02 Jan 2006, 15:04:05 UTC")
		},
		"formatConfidence": func(value *float64) string {
			if value == nil {
				return ""
			}
			return fmt.Sprintf("%.2f", *value)
		},
		"formatPercent": func(value *float64) string {
			if value == nil {
				return "No data"
			}
			return fmt.Sprintf("%.1f%%", *value)
		},
		"formatUSD": func(microunits int64) string {
			return fmt.Sprintf("$%.6f", float64(microunits)/1_000_000)
		},
		"formatCost":    formatCost,
		"formatCount":   formatCount,
		"countLabel":    countLabel,
		"entitySummary": entitySummary,
		"shortQuestion": shortQuestion,
		"statusClass":   statusClass,
		"severityClass": severityClass,
	}
	const partials = "templates/partials.html"
	clustersTemplate, err := template.New("clusters.html").Funcs(funcs).ParseFS(assets, "templates/clusters.html", partials)
	if err != nil {
		return nil, fmt.Errorf("parse admin clusters template: %w", err)
	}
	detailTemplate, err := template.New("cluster-detail.html").Funcs(funcs).ParseFS(assets, "templates/cluster-detail.html", partials)
	if err != nil {
		return nil, fmt.Errorf("parse admin cluster detail template: %w", err)
	}
	editTemplate, err := template.New("cluster-edit.html").Funcs(funcs).ParseFS(assets, "templates/cluster-edit.html", "templates/expected-inventory.html", partials)
	if err != nil {
		return nil, fmt.Errorf("parse admin cluster edit template: %w", err)
	}
	operationsTemplate, err := template.New("operations.html").Funcs(funcs).ParseFS(assets, "templates/operations.html", "templates/repairs.html", partials)
	if err != nil {
		return nil, fmt.Errorf("parse admin operations template: %w", err)
	}
	reportTemplate, err := template.New("investigation-report.html").Funcs(funcs).ParseFS(assets, "templates/investigation-report.html", partials)
	if err != nil {
		return nil, fmt.Errorf("parse admin investigation report template: %w", err)
	}
	gpuMetricsTemplate, err := template.New("cluster-gpu-metrics.html").Funcs(funcs).ParseFS(assets, "templates/cluster-gpu-metrics.html", partials)
	if err != nil {
		return nil, fmt.Errorf("parse admin GPU metrics template: %w", err)
	}
	server := &Server{
		provider:           options.Provider,
		accessVerifier:     options.AccessVerifier,
		auditor:            options.Auditor,
		errorReporter:      options.ErrorReporter,
		clock:              options.Clock,
		clustersTemplate:   clustersTemplate,
		detailTemplate:     detailTemplate,
		editTemplate:       editTemplate,
		operationsTemplate: operationsTemplate,
		reportTemplate:     reportTemplate,
		gpuMetricsTemplate: gpuMetricsTemplate,
	}
	if options.RequireHumanAuthorization {
		server.humanAccessProvider = options.Provider.(HumanAccessProvider)
	}
	if provider, ok := options.Provider.(GPUMetricsProvider); ok {
		server.gpuMetricsProvider = provider
	}
	if provider, ok := options.Provider.(CredentialProvider); ok {
		server.credentialProvider = provider
	}
	if provider, ok := options.Provider.(CredentialAccessTestProvider); ok && server.credentialProvider != nil {
		server.accessTestProvider = provider
	}
	if provider, ok := options.Provider.(ExpectedInventoryProvider); ok {
		server.expectedInventoryProvider = provider
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", server.adminRoot)
	mux.HandleFunc("GET /admin/assets/dashboard.css", server.stylesheet)
	mux.HandleFunc("GET /admin/assets/dashboard.js", server.script)
	mux.HandleFunc("GET /admin/assets/GeistMono-Variable.woff2", server.font)
	mux.HandleFunc("GET /admin", server.adminRoot)
	mux.HandleFunc("GET /admin/clusters", server.clustersPage)
	mux.HandleFunc("GET /admin/clusters/{id}", server.clusterDetailTab("summary"))
	mux.HandleFunc("GET /admin/clusters/{id}/gates", server.clusterDetailTab("gates"))
	mux.HandleFunc("GET /admin/clusters/{id}/investigations", server.clusterDetailTab("investigations"))
	mux.HandleFunc("GET /admin/clusters/{id}/health", server.clusterDetailTab("health"))
	mux.HandleFunc("GET /admin/clusters/{id}/gpu-metrics", server.clusterGPUMetricsPage)
	mux.HandleFunc("POST /admin/clusters/{id}/investigations", server.startInvestigation)
	mux.HandleFunc("POST /admin/clusters/{id}/evidence-repair-proposals", server.startEvidenceRepairProposal)
	mux.HandleFunc("GET /admin/clusters/{id}/edit", server.clusterEditPage)
	mux.HandleFunc("POST /admin/clusters/{id}/edit", server.updateCluster)
	mux.HandleFunc("POST /admin/clusters/{id}/delete", server.removeCluster)
	mux.HandleFunc("POST /admin/clusters/{id}/credentials", server.putCredential)
	mux.HandleFunc("POST /admin/clusters/{id}/credentials/{credential_id}/revoke", server.revokeCredential)
	mux.HandleFunc("POST /admin/clusters/{id}/credentials/{credential_id}/test", server.requestCredentialAccessTest)
	mux.HandleFunc("POST /admin/clusters/{id}/credentials/{credential_id}/inventory-discovery", server.requestCredentialInventoryDiscovery)
	mux.HandleFunc("POST /admin/clusters/{id}/credential-tests/{test_id}/cancel", server.cancelCredentialAccessTest)
	mux.HandleFunc("POST /admin/clusters/{id}/expected-inventory/previews", server.generateExpectedInventoryPreview)
	mux.HandleFunc("POST /admin/clusters/{id}/expected-inventory/import", server.importExpectedInventoryPreview)
	mux.HandleFunc("GET /admin/operations", server.operationsPage)
	mux.HandleFunc("GET /admin/incidents", server.operationsPage)
	mux.HandleFunc("GET /admin/investigations", server.operationsPage)
	mux.HandleFunc("GET /admin/repairs", server.operationsPage)
	mux.HandleFunc("GET /admin/investigations/{id}", server.investigationReportPage)
	mux.HandleFunc("POST /admin/investigations/{id}/cancel", server.cancelInvestigation)
	server.handler = server.securityHeaders(server.requireCloudflareAccess(mux))
	return server, nil
}

func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	server.handler.ServeHTTP(writer, request)
}

type requestKey struct{}
type accessRequestKey struct{}

type accessRequest struct {
	Identity    AccessIdentity
	Fingerprint [sha256.Size]byte
	CSRFToken   string
}

func (server *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestID := newRequestID()
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self' data:; script-src 'self'; connect-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		writer.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		writer.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("X-Request-ID", requestID)
		request = request.WithContext(context.WithValue(request.Context(), requestKey{}, requestID))
		if hasAPIAuthentication(request) {
			server.auditRejected(request.Context(), AuditEvent{Kind: eventKindForPath(request.URL.Path), Outcome: OutcomeRejected, ReasonCode: "api_credentials_not_accepted", RequestID: requestID})
			http.Error(writer, "API credentials are not accepted by the admin dashboard", http.StatusUnauthorized)
			return
		}
		if request.Method == http.MethodPost && !sameOrigin(request) {
			server.auditRejected(request.Context(), AuditEvent{Kind: eventKindForPath(request.URL.Path), Outcome: OutcomeRejected, ReasonCode: "cross_origin_request", RequestID: requestID})
			http.Error(writer, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (server *Server) requireCloudflareAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestID, _ := request.Context().Value(requestKey{}).(string)
		values := request.Header.Values(accessAssertionHeader)
		if len(values) != 1 || len(values[0]) < 1 || len(values[0]) > maxAccessAssertion || strings.ContainsAny(values[0], "\r\n,") {
			server.auditRejected(request.Context(), AuditEvent{Kind: EventAuthentication, Outcome: OutcomeRejected, ReasonCode: "access_assertion_missing", RequestID: requestID})
			http.Error(writer, "Cloudflare Access authentication is required", http.StatusUnauthorized)
			return
		}
		assertion := values[0]
		identity, err := server.accessVerifier.Verify(request.Context(), assertion)
		if err != nil {
			server.auditRejected(request.Context(), AuditEvent{Kind: EventAuthentication, Outcome: OutcomeRejected, ReasonCode: "access_assertion_invalid", RequestID: requestID})
			http.Error(writer, "Cloudflare Access authentication was not accepted", http.StatusUnauthorized)
			return
		}
		fingerprint := sha256.Sum256([]byte("sherlock-admin-access\x00" + assertion))
		access := accessRequest{Identity: identity, Fingerprint: fingerprint, CSRFToken: server.csrfToken(assertion)}
		request = request.WithContext(context.WithValue(request.Context(), accessRequestKey{}, access))
		if server.humanAccessProvider != nil {
			rows, err := server.humanAccessProvider.LoadHumanAccess(request.Context())
			if err == nil && len(rows) == 0 {
				err = ErrHumanAccessDenied
			}
			if err != nil {
				if errors.Is(err, ErrHumanAccessDenied) {
					server.auditRejected(request.Context(), AuditEvent{Kind: EventAuthentication, Outcome: OutcomeRejected, ReasonCode: "human_membership_missing", RequestID: requestID})
					http.Error(writer, "an active cluster membership is required", http.StatusForbidden)
					return
				}
				server.auditRejected(request.Context(), AuditEvent{Kind: EventAuthentication, Outcome: OutcomeRejected, ReasonCode: "human_authorization_unavailable", RequestID: requestID})
				http.Error(writer, "dashboard authorization is temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			access := make(map[string]ClusterAccess, len(rows))
			for _, row := range rows {
				access[row.ClusterID] = row
			}
			request = request.WithContext(context.WithValue(request.Context(), humanAccessKey{}, access))
			if !authorizeHumanUIRoute(writer, request) {
				return
			}
		}
		next.ServeHTTP(writer, request)
	})
}

func (server *Server) stylesheet(writer http.ResponseWriter, _ *http.Request) {
	content, err := assets.ReadFile("static/dashboard.css")
	if err != nil {
		http.Error(writer, "asset unavailable", http.StatusInternalServerError)
		return
	}
	workspace, err := assets.ReadFile("static/workspace.css")
	if err != nil {
		http.Error(writer, "asset unavailable", http.StatusInternalServerError)
		return
	}
	content = append(append(content, '\n'), workspace...)
	writer.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = writer.Write(content)
}

func (server *Server) script(writer http.ResponseWriter, _ *http.Request) {
	content, err := assets.ReadFile("static/dashboard.js")
	if err != nil {
		http.Error(writer, "asset unavailable", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = writer.Write(content)
}

// font serves the self-hosted Geist Mono face; the CSP allows fonts only from
// this origin.
func (server *Server) font(writer http.ResponseWriter, _ *http.Request) {
	content, err := assets.ReadFile("static/GeistMono-Variable.woff2")
	if err != nil {
		http.Error(writer, "asset unavailable", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "font/woff2")
	_, _ = writer.Write(content)
}

func (server *Server) adminRoot(writer http.ResponseWriter, request *http.Request) {
	if _, _, ok := server.requireAccess(writer, request); !ok {
		return
	}
	http.Redirect(writer, request, "/admin/operations", http.StatusSeeOther)
}

func (server *Server) clustersPage(writer http.ResponseWriter, request *http.Request) {
	key, csrfToken, ok := server.requireAccess(writer, request)
	if !ok {
		return
	}
	page := clustersPageData{pageBase: pageBase{Page: "clusters", CSRFToken: csrfToken}}
	records, err := server.provider.ListClusters(request.Context())
	if err != nil {
		page.Error = "Cluster inventory is temporarily unavailable."
	} else {
		page.Rows, page.SummariesOmitted = server.loadClusterHealthRows(request.Context(), records)
		if operations, operationsErr := server.provider.LoadOperations(request.Context()); operationsErr == nil {
			operations.Tickets, _ = splitHistoricalXIDTickets(operations.Tickets, server.clock.Now())
			operations.Tickets = consolidateTickets(operations.Tickets)
			windowStart, _ := activityWindowBounds(server.clock.Now())
			applyClusterOperations(page.Rows, operations, windowStart)
		}
		for index := range page.Rows {
			page.Rows[index].CanConfigure = clusterAccess(request.Context(), page.Rows[index].ID).CanConfigure
		}
		page.FleetBar = fleetStateBar(page.Rows)
		for _, row := range page.Rows {
			if row.RemovedAt == nil {
				page.ActiveClusters++
			}
		}
	}
	if updated := strings.TrimSpace(request.URL.Query().Get("updated")); validAdminToken(updated) {
		page.Updated = updated
	}
	if deleted := strings.TrimSpace(request.URL.Query().Get("deleted")); validAdminToken(deleted) {
		page.Deleted = deleted
	}
	if !server.auditView(writer, request, key, "clusters") {
		return
	}
	server.renderTemplate(writer, server.clustersTemplate, "clusters.html", page)
}

func (server *Server) clusterEditPage(writer http.ResponseWriter, request *http.Request) {
	key, csrfToken, ok := server.requireAccess(writer, request)
	if !ok {
		return
	}
	id := strings.TrimSpace(request.PathValue("id"))
	cluster, err := server.provider.GetCluster(request.Context(), id)
	if err != nil || id == "" {
		http.Error(writer, "cluster not found", http.StatusNotFound)
		return
	}
	if !server.auditView(writer, request, key, "cluster_edit") {
		return
	}
	var credentials []CredentialMetadata
	credentialStatus := ""
	credentialEnabled := false
	if server.credentialProvider != nil && clusterAccess(request.Context(), id).CanManageCredentials {
		identity := requestIdentity(request)
		credentials, err = server.credentialProvider.ListCredentialMetadata(request.Context(), id, identity.Subject)
		if err != nil {
			credentialStatus = "Credential metadata is unavailable or this Access identity has no cluster grant."
		} else {
			credentialEnabled = true
		}
	}
	message := ""
	switch request.URL.Query().Get("credential") {
	case "saved":
		message = "Credential saved. Connection has not been tested."
	case "revoked":
		message = "Credential revoked."
	case "error":
		message = "Credential change was not applied. Refresh and retry with the current record version."
	case "test_requested":
		message = "BCM access test requested. A compatible head collector must claim and run it; this page refreshes while it is pending."
	case "test_cancelled":
		message = "BCM access test cancelled."
	case "test_error":
		message = "BCM access test was not requested. The credential may have changed, a test may already be pending, or this identity has no grant."
	case "discovery_requested":
		message = "BCM inventory discovery requested. A compatible head collector must claim and run it; this page refreshes while it is pending."
	case "discovery_error":
		message = "BCM inventory discovery was not requested. The credential may have changed, another test or discovery may already be pending, or this identity has no grant."
	}
	// Tests are keyed by (credential, operation): an access test and an
	// inventory discovery for the same credential are separate results with
	// separate status lines, and neither may mask the other.
	accessTests := map[string]CredentialAccessTest{}
	discoveries := map[string]CredentialAccessTest{}
	accessTestEnabled, accessTestPending := false, false
	if server.accessTestProvider != nil && credentialEnabled {
		identity := requestIdentity(request)
		tests, err := server.accessTestProvider.ListCredentialAccessTests(request.Context(), id, identity.Subject)
		if err == nil {
			accessTestEnabled = true
			for _, test := range tests {
				bucket := accessTests
				if test.Operation == CredentialInventoryDiscoveryOperation {
					bucket = discoveries
				}
				if _, seen := bucket[test.CredentialID]; !seen {
					bucket[test.CredentialID] = test
					accessTestPending = accessTestPending || test.Pending()
				}
			}
		}
	}
	server.renderTemplate(writer, server.editTemplate, "cluster-edit.html", clusterEditPageData{
		pageBase: pageBase{Page: "clusters", CSRFToken: csrfToken}, Cluster: cluster, Access: clusterAccess(request.Context(), id),
		ExpectedCollectorsText: strings.Join(cluster.ExpectedCollectors, "\n"),
		Credentials:            credentials, CredentialStatus: credentialStatus, CredentialEnabled: credentialEnabled, CredentialMessage: message,
		AccessTests: accessTests, InventoryDiscoveries: discoveries, AccessTestEnabled: accessTestEnabled, AccessTestPending: accessTestPending,
		ExpectedInventory: server.loadExpectedInventorySection(request, id),
	})
}

func (server *Server) requestCredentialAccessTest(writer http.ResponseWriter, request *http.Request) {
	server.requestCredentialAccessOperation(writer, request, false)
}

// requestCredentialInventoryDiscovery posts the second reviewed operation. It
// shares the CSRF, same-origin, expected-version and grant handling of the
// access-test button; only the scheduled operation and the redirect differ.
func (server *Server) requestCredentialInventoryDiscovery(writer http.ResponseWriter, request *http.Request) {
	server.requestCredentialAccessOperation(writer, request, true)
}

func (server *Server) requestCredentialAccessOperation(writer http.ResponseWriter, request *http.Request, inventory bool) {
	key, csrfToken, ok := server.requireAccess(writer, request)
	if !ok {
		return
	}
	if server.accessTestProvider == nil {
		http.Error(writer, "credential access testing is not configured", http.StatusServiceUnavailable)
		return
	}
	if !server.parseAndVerifyCSRF(writer, request, csrfToken) {
		return
	}
	clusterID, credentialID := strings.TrimSpace(request.PathValue("id")), strings.TrimSpace(request.PathValue("credential_id"))
	version, err := strconv.ParseInt(strings.TrimSpace(request.PostForm.Get("expected_version")), 10, 64)
	if !validAdminToken(clusterID) || !validAdminToken(credentialID) || err != nil || version < 1 {
		http.Error(writer, "invalid credential reference", http.StatusBadRequest)
		return
	}
	identity := requestIdentity(request)
	scheduleOperation, failure, success := server.accessTestProvider.RequestCredentialAccessTest, "test_error", "test_requested"
	if inventory {
		scheduleOperation, failure, success = server.accessTestProvider.RequestCredentialInventoryDiscovery, "discovery_error", "discovery_requested"
	}
	if _, err := scheduleOperation(request.Context(), clusterID, identity.Subject, credentialID, version, server.mutationContext(request, key)); err != nil {
		http.Redirect(writer, request, "/admin/clusters/"+url.PathEscape(clusterID)+"/edit?credential="+failure, http.StatusSeeOther)
		return
	}
	http.Redirect(writer, request, "/admin/clusters/"+url.PathEscape(clusterID)+"/edit?credential="+success, http.StatusSeeOther)
}

func (server *Server) cancelCredentialAccessTest(writer http.ResponseWriter, request *http.Request) {
	key, csrfToken, ok := server.requireAccess(writer, request)
	if !ok {
		return
	}
	if server.accessTestProvider == nil {
		http.Error(writer, "credential access testing is not configured", http.StatusServiceUnavailable)
		return
	}
	if !server.parseAndVerifyCSRF(writer, request, csrfToken) {
		return
	}
	clusterID, testID := strings.TrimSpace(request.PathValue("id")), strings.TrimSpace(request.PathValue("test_id"))
	if !validAdminToken(clusterID) || !validAdminToken(testID) {
		http.Error(writer, "invalid credential access test reference", http.StatusBadRequest)
		return
	}
	identity := requestIdentity(request)
	if err := server.accessTestProvider.CancelCredentialAccessTest(request.Context(), clusterID, identity.Subject, testID, server.mutationContext(request, key)); err != nil {
		http.Redirect(writer, request, "/admin/clusters/"+url.PathEscape(clusterID)+"/edit?credential=test_error", http.StatusSeeOther)
		return
	}
	http.Redirect(writer, request, "/admin/clusters/"+url.PathEscape(clusterID)+"/edit?credential=test_cancelled", http.StatusSeeOther)
}

func (server *Server) updateCluster(writer http.ResponseWriter, request *http.Request) {
	key, csrfToken, ok := server.requireAccess(writer, request)
	if !ok {
		return
	}
	if !server.parseAndVerifyCSRF(writer, request, csrfToken) {
		return
	}
	id := strings.TrimSpace(request.PathValue("id"))
	name := strings.TrimSpace(request.PostForm.Get("display_name"))
	expectedCollectors, err := parseExpectedCollectors(request.PostForm.Get("expected_collectors"))
	if err != nil || id == "" || name == "" || len(name) > maxDisplayName {
		http.Error(writer, "display name is required and must not exceed 200 bytes", http.StatusBadRequest)
		return
	}
	if err := server.provider.UpdateCluster(request.Context(), id, ClusterUpdate{DisplayName: name, ExpectedCollectors: expectedCollectors}, server.mutationContext(request, key)); err != nil {
		http.Error(writer, "unable to update cluster", http.StatusBadGateway)
		return
	}
	http.Redirect(writer, request, "/admin/clusters?updated="+url.QueryEscape(id), http.StatusSeeOther)
}

func (server *Server) putCredential(writer http.ResponseWriter, request *http.Request) {
	key, csrfToken, ok := server.requireAccess(writer, request)
	if !ok {
		return
	}
	if server.credentialProvider == nil {
		http.Error(writer, "credential onboarding is not configured", http.StatusServiceUnavailable)
		return
	}
	if !server.parseAndVerifyCSRF(writer, request, csrfToken) {
		return
	}
	clusterID := strings.TrimSpace(request.PathValue("id"))
	if !validAdminToken(clusterID) {
		http.Error(writer, "invalid cluster ID", http.StatusBadRequest)
		return
	}
	parseVersion := func(name string) (int64, error) {
		value := strings.TrimSpace(request.PostForm.Get(name))
		if value == "" {
			return 0, nil
		}
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil || parsed < 0 {
			return 0, errors.New("invalid credential version")
		}
		return parsed, nil
	}
	expectedVersion, err := parseVersion("expected_version")
	if err != nil {
		http.Error(writer, "invalid credential version", http.StatusBadRequest)
		return
	}
	expectedID := strings.TrimSpace(request.PostForm.Get("expected_credential_id"))
	host, purpose, username := strings.TrimSpace(request.PostForm.Get("host")), strings.TrimSpace(request.PostForm.Get("purpose")), strings.TrimSpace(request.PostForm.Get("username"))
	sshPassword, sudoPassword := request.PostForm.Get("ssh_password"), request.PostForm.Get("sudo_password")
	passwordMode := purpose == "BCM_READ_ONLY" && sudoPassword != ""
	passwordlessMode := purpose == "BCM_READ_ONLY_PASSWORDLESS" && sudoPassword == "" && sshPassword == ""
	if host == "" || len(host) > 256 || (!passwordMode && !passwordlessMode) || username == "" || len(username) > 256 || expectedVersion < 0 || (expectedVersion > 0 && !validAdminToken(expectedID)) {
		http.Error(writer, "credential fields are invalid", http.StatusBadRequest)
		return
	}
	identity := requestIdentity(request)
	if _, err := server.credentialProvider.PutCredential(request.Context(), clusterID, identity.Subject, CredentialInput{Host: host, Purpose: purpose, Username: username, SSHPassword: sshPassword, SudoPassword: sudoPassword, ExpectedVersion: expectedVersion, ExpectedCredentialID: expectedID}, server.mutationContext(request, key)); err != nil {
		http.Redirect(writer, request, "/admin/clusters/"+url.PathEscape(clusterID)+"/edit?credential=error", http.StatusSeeOther)
		return
	}
	http.Redirect(writer, request, "/admin/clusters/"+url.PathEscape(clusterID)+"/edit?credential=saved", http.StatusSeeOther)
}

func (server *Server) revokeCredential(writer http.ResponseWriter, request *http.Request) {
	key, csrfToken, ok := server.requireAccess(writer, request)
	if !ok {
		return
	}
	if server.credentialProvider == nil {
		http.Error(writer, "credential onboarding is not configured", http.StatusServiceUnavailable)
		return
	}
	if !server.parseAndVerifyCSRF(writer, request, csrfToken) {
		return
	}
	clusterID, credentialID := strings.TrimSpace(request.PathValue("id")), strings.TrimSpace(request.PathValue("credential_id"))
	version, err := strconv.ParseInt(strings.TrimSpace(request.PostForm.Get("expected_version")), 10, 64)
	if !validAdminToken(clusterID) || !validAdminToken(credentialID) || err != nil || version < 1 {
		http.Error(writer, "invalid credential reference", http.StatusBadRequest)
		return
	}
	if err := server.credentialProvider.RevokeCredential(request.Context(), clusterID, credentialID, version, server.mutationContext(request, key)); err != nil {
		http.Redirect(writer, request, "/admin/clusters/"+url.PathEscape(clusterID)+"/edit?credential=error", http.StatusSeeOther)
		return
	}
	http.Redirect(writer, request, "/admin/clusters/"+url.PathEscape(clusterID)+"/edit?credential=revoked", http.StatusSeeOther)
}

func parseExpectedCollectors(raw string) ([]string, error) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	collectors := make([]string, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		if len(name) > 256 || strings.ContainsAny(name, "\x00\r\n") {
			return nil, errors.New("expected collector name is invalid")
		}
		key := strings.ToLower(name)
		if _, duplicate := seen[key]; duplicate {
			return nil, errors.New("expected collector names must be unique")
		}
		seen[key] = struct{}{}
		collectors = append(collectors, name)
	}
	if len(collectors) > 100 {
		return nil, errors.New("expected collector inventory is too large")
	}
	return collectors, nil
}

func (server *Server) removeCluster(writer http.ResponseWriter, request *http.Request) {
	key, csrfToken, ok := server.requireAccess(writer, request)
	if !ok {
		return
	}
	if !server.parseAndVerifyCSRF(writer, request, csrfToken) {
		return
	}
	id := strings.TrimSpace(request.PathValue("id"))
	if id == "" || request.PostForm.Get("confirmation") != id {
		http.Error(writer, "enter the exact cluster ID to confirm deletion", http.StatusBadRequest)
		return
	}
	if err := server.provider.RemoveCluster(request.Context(), id, server.mutationContext(request, key)); err != nil {
		http.Error(writer, "unable to delete cluster", http.StatusBadGateway)
		return
	}
	http.Redirect(writer, request, "/admin/clusters?deleted="+url.QueryEscape(id), http.StatusSeeOther)
}

func splitHistoricalXIDTickets(tickets []Ticket, now time.Time) (current, historical []Ticket) {
	current = make([]Ticket, 0, len(tickets))
	for _, ticket := range tickets {
		if ticket.RuleID == "dcgm.xid.nonzero.v1" && ticket.Status == "OPEN" &&
			!ticket.LastSignalAt.IsZero() && now.Sub(ticket.LastSignalAt) > 24*time.Hour {
			historical = append(historical, ticket)
			continue
		}
		current = append(current, ticket)
	}
	return current, historical
}

// consolidateTickets keeps durable incidents independently addressable in the
// private API while presenting one current issue for each automatic rule. A
// changing affected-entity set can create several incident fingerprints for
// the same continuing condition; listing each fingerprint as a separate issue
// makes the operational dashboard look noisier than the underlying state.
func consolidateTickets(tickets []Ticket) []Ticket {
	result := make([]Ticket, 0, len(tickets))
	indexByRule := make(map[string]int)
	for _, ticket := range tickets {
		ticket.RelatedIncidentCount = 1
		if ticket.RuleID == "" {
			result = append(result, ticket)
			continue
		}
		key := ticket.ClusterID + "\x00" + ticket.RuleID
		if index, found := indexByRule[key]; found {
			result[index].RelatedIncidentCount++
			continue
		}
		indexByRule[key] = len(result)
		result = append(result, ticket)
	}
	return result
}

// buildClusterGlance turns the existing redacted cluster and operations
// projections into a presentation-only summary. It deliberately does not infer
// health, ownership, or remediation beyond the states already supplied by the
// private API.
func buildClusterGlance(cluster Cluster, issues []Ticket, investigations []Investigation) clusterGlance {
	glance := clusterGlance{
		State:              cluster.State,
		IssueCount:         len(issues),
		InvestigationCount: len(investigations),
		Connectivity:       dimensionByLabel(cluster.Dimensions, "Connectivity"),
		Freshness:          dimensionByLabel(cluster.Dimensions, "Freshness"),
		Queue:              dimensionByLabel(cluster.Dimensions, "Queue"),
		InvestigationState: dimensionByLabel(cluster.Dimensions, "Investigations"),
		ModelUsage:         dimensionByLabel(cluster.Dimensions, "Model usage"),
		Evidence:           dimensionByLabel(cluster.Dimensions, "Evidence"),
		Audit:              dimensionByLabel(cluster.Dimensions, "Diagnostic audit"),
	}
	switch cluster.State {
	case StateHealthy:
		glance.Label = "Stable"
		glance.Headline = "No current issues are recorded."
		glance.Summary = "Sherlock's current projections do not contain an open cluster issue."
	case StateUnavailable:
		glance.Label = "Visibility unavailable"
		glance.Headline = "The current cluster picture is unavailable."
		glance.Summary = "Review the telemetry and evidence states before drawing an operational conclusion."
	case StateNoData:
		glance.Label = "No data"
		glance.Headline = "Sherlock does not have enough current data to describe this cluster."
		glance.Summary = "Missing data remains explicit and is not interpreted as healthy."
	default:
		glance.Label = "Action needed"
		glance.Headline = "The cluster has degraded operational signals."
		glance.Summary = "Review the primary issue and the trust signals below."
	}
	if cluster.State == StateDegraded && len(issues) == 0 &&
		glance.Connectivity.State == StateHealthy && glance.Freshness.State == StateHealthy &&
		glance.Evidence.State == StateDegraded && glance.Queue.State == StateHealthy &&
		stateRank(glance.InvestigationState.State) <= stateRank(StateNoData) &&
		stateRank(glance.ModelUsage.State) <= stateRank(StateNoData) &&
		stateRank(glance.Audit.State) <= stateRank(StateNoData) &&
		stateRank(cluster.Resources.State) <= stateRank(StateNoData) {
		glance.Label = "Coverage incomplete"
		glance.Headline = "Monitoring is current, but evidence coverage is incomplete."
		glance.Summary = "Review the partial evidence streams and their missing fields below."
	}
	if cluster.Network.Enrolled && cluster.Network.State != "HEALTHY" {
		glance.State = StateDegraded
		glance.Label = "Network attention"
		glance.Headline = "InfiniBand monitoring needs attention."
		glance.Summary = fmt.Sprintf("%d confirmed down IB ports · %d unknown IB ports · %d down management links · %d unknown management links · %d open network episodes. Review the kernel readings and Slack delivery status below.", cluster.Network.DownPorts, cluster.Network.UnknownPorts, cluster.Network.Management.DownLinks, cluster.Network.Management.UnknownLinks, cluster.Network.OpenEpisodes)
	}
	if len(issues) > 0 {
		glance.PrimaryIssue = &issues[0]
		if strings.TrimSpace(issues[0].Title) != "" {
			glance.Headline = issues[0].Title
		}
		if strings.TrimSpace(issues[0].Summary) != "" {
			glance.Summary = issues[0].Summary
		}
	}
	if len(investigations) > 0 {
		for index := range investigations {
			if glance.PrimaryIssue != nil && investigations[index].IncidentID == glance.PrimaryIssue.ID {
				glance.PrimaryInvestigation = &investigations[index]
				break
			}
		}
		if glance.PrimaryInvestigation == nil {
			glance.LatestInvestigation = &investigations[0]
		} else {
			glance.LatestInvestigation = glance.PrimaryInvestigation
		}
	}
	return glance
}

func dimensionByLabel(dimensions []Metric, label string) Metric {
	for _, dimension := range dimensions {
		if dimension.Label == label {
			return dimension
		}
	}
	return Metric{Label: label, Value: "No data", Detail: "No current projection", State: StateNoData}
}

func buildRecoveryPlan(glance clusterGlance, expectedCollectors, missingCollectors, excludedCollectors, sourceGaps, onDemandSources []string, evidenceStreams []EvidenceStreamHealth, evidenceHistory EvidenceHistory) []recoveryStep {
	telemetryState := recoveryWorseState(glance.Connectivity.State, glance.Freshness.State)
	collectorGapSummary := fmt.Sprintf("None. All expected collectors are fresh (%d configured).", len(expectedCollectors))
	telemetryAction := "Every expected collector is fresh. Restore periodic collection for the sources listed below."
	if len(expectedCollectors) == 0 {
		collectorGapSummary = "Expected collector inventory is not configured. Add collector hostnames in Edit cluster."
		telemetryAction = "Configure the expected collector inventory before treating collector coverage as known."
	} else if len(missingCollectors) > 0 {
		telemetryAction = "Restore heartbeat and collection on the collectors listed below."
	} else if len(sourceGaps) == 0 {
		telemetryAction = "Every expected collector and periodically collected telemetry source is fresh."
	}
	evidenceIssues := blockingEvidenceStreams(evidenceStreams)
	evidenceAction := "Every current evidence stream is complete. Older failures no longer degrade this gate."
	if len(evidenceIssues) > 0 {
		evidenceAction = fmt.Sprintf("%s block completeness, grouped below by shared cause. Apply each group's fix or generate one combined repair plan; waiting alone is not a repair.", countLabel(len(evidenceIssues), "evidence stream", "evidence streams"))
	} else if len(evidenceStreams) == 0 {
		evidenceAction = "No current evidence stream exists. Run the required collection after its target inventory and source connectivity are configured."
	}
	steps := []recoveryStep{
		{Number: 1, Kind: "telemetry", Title: "Restore current telemetry", Current: glance.Connectivity.Value + " · " + glance.Freshness.Value, Target: "Every expected collector and periodic source is fresh", Action: telemetryAction, CollectorGapSummary: collectorGapSummary, Collectors: append([]string(nil), missingCollectors...), ExcludedCollectors: append([]string(nil), excludedCollectors...), Sources: append([]string(nil), sourceGaps...), OnDemandSources: append([]string(nil), onDemandSources...), State: telemetryState},
		{Number: 2, Kind: "evidence", Title: "Establish complete evidence", Current: glance.Evidence.Value + " · " + glance.Evidence.Detail, Target: "The latest applicable envelope for every affected source, operation, and scope is complete", Action: evidenceAction, EvidenceHistory: evidenceHistory, State: glance.Evidence.State},
		{Number: 3, Kind: "investigation", Title: "Run a bounded investigation", Current: investigationCurrent(glance), Target: "A current report reaches a supported conclusion or names its remaining gap", Action: "Run once fresh evidence is available. Use a custom investigation to change the question, scope, or hard limits.", State: investigationRecoveryState(glance)},
		{Number: 4, Kind: "disposition", Title: "Disposition the incident and backlog", Current: fmt.Sprintf("%d live issue · %s", glance.IssueCount, glance.Queue.Value), Target: "No unresolved live issue and no overdue work", Action: "Review the latest report, assign the recommended safe action, then resolve or monitor the incident and drain overdue work.", State: recoveryWorseState(glance.Queue.State, StateDegraded)},
	}
	if glance.IssueCount == 0 {
		steps[2].NotApplicable = true
		steps[2].Current = "No current incident"
		steps[2].Action = "No investigation is needed for an incident that is not current. Older runs remain in investigation history."
		steps[3].State = glance.Queue.State
		if glance.Queue.State == StateHealthy {
			steps[3].NotApplicable = true
			steps[3].Current = "No current incident · " + glance.Queue.Value
			steps[3].Action = "No current incident needs disposition. Older open records remain available for review."
		} else {
			steps[3].Title = "Drain overdue or blocked work"
			steps[3].Current = glance.Queue.Value
			steps[3].Action = "Review the current queue and resolve overdue or blocked work."
		}
	}
	return steps
}

func stateRank(state OperationalState) int {
	switch state {
	case StateNoData:
		return 1
	case StateDegraded, StatePartial:
		return 2
	case StateStale:
		return 3
	case StateUnavailable:
		return 4
	default:
		return 0
	}
}

func recoveryWorseState(current, candidate OperationalState) OperationalState {
	if stateRank(candidate) > stateRank(current) {
		return candidate
	}
	return current
}

func investigationCurrent(glance clusterGlance) string {
	if glance.IssueCount == 0 {
		return "No current incident"
	}
	if glance.PrimaryIssue != nil && glance.PrimaryIssue.AutoStartDecision != "" {
		return glance.PrimaryIssue.AutoStartStatus + " · " + glance.PrimaryIssue.AutoStartDecision
	}
	if glance.PrimaryInvestigation != nil {
		return glance.PrimaryInvestigation.Status
	}
	return "No investigation for the current incident"
}

func investigationRecoveryState(glance clusterGlance) OperationalState {
	if glance.IssueCount == 0 {
		return StateHealthy
	}
	if glance.PrimaryInvestigation != nil && glance.PrimaryInvestigation.Status == "COMPLETED" {
		return StateHealthy
	}
	return StateDegraded
}

func buildInvestigationForm(glance clusterGlance, idempotencyKey string) investigationForm {
	form := investigationForm{
		Question:   "What caused the current incident, what is the current impact, and what safe action should the operator take next?",
		EntityKind: "node", SuccessCriteria: strings.Join([]string{
			"Determine whether the active fault is ongoing or contained.",
			"Identify affected entities and cite current evidence.",
			"Recommend the next safe operator action and state remaining uncertainty.",
		}, "\n"),
		LookbackMinutes: 60, MaxDecisions: 12, MaxToolCalls: 12,
		MaxDiagnosticCalls: 2, MaxFanOut: 8, MaxModelTokens: 120000,
		MaxCostUSD: "2.00", DeadlineMinutes: 30, IdempotencyKey: idempotencyKey,
	}
	if glance.PrimaryIssue != nil {
		form.IncidentID = glance.PrimaryIssue.ID
	}
	if glance.LatestInvestigation != nil {
		latest := glance.LatestInvestigation
		if latest.IncidentID != "" {
			form.IncidentID = latest.IncidentID
		}
		// A combined repair run's generated question is not a useful rerun
		// question; keep its scope but fall back to the default question.
		if strings.TrimSpace(latest.Question) != "" && !strings.HasPrefix(latest.Question, evidenceRepairQuestionPrefix) {
			form.Question = latest.Question
		}
		if latest.EntityKind != "" {
			form.EntityKind = latest.EntityKind
		}
		form.EntityIDs = strings.Join(latest.EntityIDs, "\n")
		if len(latest.EntityIDs) > 0 {
			form.MaxFanOut = len(latest.EntityIDs)
			if form.MaxFanOut > 256 {
				form.MaxFanOut = 256
			}
		}
	}
	// Offer a run only when the submitted scope would pass the same parser;
	// otherwise the page advertises an action the server always rejects.
	entityIDs, entityErr := parseTokenLines(form.EntityIDs, 256)
	form.Available = validAdminToken(form.IncidentID) && entityErr == nil && len(entityIDs) > 0
	return form
}

func parseInvestigationForm(values url.Values, now time.Time) (InvestigationStart, error) {
	parseInt := func(name string, minimum, maximum int) (int, error) {
		value, err := strconv.Atoi(strings.TrimSpace(values.Get(name)))
		if err != nil || value < minimum || value > maximum {
			return 0, fmt.Errorf("%s is outside its allowed range", name)
		}
		return value, nil
	}
	lookback, err := parseInt("lookback_minutes", 1, 10080)
	if err != nil {
		return InvestigationStart{}, err
	}
	decisions, err := parseInt("max_decisions", 1, 100)
	if err != nil {
		return InvestigationStart{}, err
	}
	toolCalls, err := parseInt("max_tool_calls", 1, 1000)
	if err != nil {
		return InvestigationStart{}, err
	}
	diagnosticCalls, err := parseInt("max_diagnostic_calls", 0, 1000)
	if err != nil {
		return InvestigationStart{}, err
	}
	fanOut, err := parseInt("max_fan_out", 1, 256)
	if err != nil {
		return InvestigationStart{}, err
	}
	deadlineMinutes, err := parseInt("deadline_minutes", 1, 1440)
	if err != nil {
		return InvestigationStart{}, err
	}
	modelTokens, err := strconv.ParseInt(strings.TrimSpace(values.Get("max_model_tokens")), 10, 64)
	if err != nil || modelTokens < 0 || modelTokens > 10_000_000 {
		return InvestigationStart{}, errors.New("max_model_tokens is outside its allowed range")
	}
	costUSD, err := strconv.ParseFloat(strings.TrimSpace(values.Get("max_cost_usd")), 64)
	if err != nil || costUSD < 0 || costUSD > 1000 {
		return InvestigationStart{}, errors.New("max_cost_usd is outside its allowed range")
	}
	entityIDs, err := parseTokenLines(values.Get("entity_ids"), 256)
	if err != nil || len(entityIDs) == 0 {
		return InvestigationStart{}, errors.New("at least one valid entity is required")
	}
	criteria, err := parseTextLines(values.Get("success_criteria"), 32, 512)
	if err != nil || len(criteria) == 0 {
		return InvestigationStart{}, errors.New("at least one success criterion is required")
	}
	incidentID := strings.TrimSpace(values.Get("incident_id"))
	entityKind := strings.TrimSpace(values.Get("entity_kind"))
	idempotencyKey := strings.TrimSpace(values.Get("idempotency_key"))
	question := strings.TrimSpace(values.Get("question"))
	if !validAdminToken(incidentID) || !validAdminToken(entityKind) || !validAdminToken(idempotencyKey) || question == "" || len(question) > 4096 || strings.IndexByte(question, 0) >= 0 {
		return InvestigationStart{}, errors.New("investigation identity or question is invalid")
	}
	return InvestigationStart{
		IncidentID: incidentID, Question: question, EntityKind: entityKind, EntityIDs: entityIDs,
		WindowStart: now.Add(-time.Duration(lookback) * time.Minute), WindowEnd: now,
		SuccessCriteria: criteria, MaxDecisions: decisions, MaxToolCalls: toolCalls,
		MaxDiagnosticCalls: diagnosticCalls, MaxFanOut: fanOut, MaxModelTokens: modelTokens,
		MaxCostMicrounits: int64(math.Round(costUSD * 1_000_000)),
		Deadline:          now.Add(time.Duration(deadlineMinutes) * time.Minute), IdempotencyKey: idempotencyKey,
	}, nil
}

func parseTokenLines(raw string, maximum int) ([]string, error) {
	seen := make(map[string]struct{})
	result := make([]string, 0)
	for _, value := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' ' }) {
		value = strings.TrimSpace(value)
		if !validAdminToken(value) {
			return nil, errors.New("invalid token")
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
		if len(result) > maximum {
			return nil, errors.New("too many values")
		}
	}
	return result, nil
}

func parseTextLines(raw string, maximumLines, maximumLength int) ([]string, error) {
	result := make([]string, 0)
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > maximumLength || strings.IndexByte(line, 0) >= 0 {
			return nil, errors.New("invalid text")
		}
		result = append(result, line)
		if len(result) > maximumLines {
			return nil, errors.New("too many lines")
		}
	}
	return result, nil
}

func validAdminToken(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

type pageBase struct{ Page, CSRFToken, Error string }
type clustersPageData struct {
	pageBase
	Rows                             []clusterHealthRow
	FleetBar                         stackedBar
	ActiveClusters, SummariesOmitted int
	Updated, Deleted                 string
}
type clusterEditPageData struct {
	Access ClusterAccess
	pageBase
	Cluster                ClusterRecord
	ExpectedCollectorsText string
	Credentials            []CredentialMetadata
	CredentialStatus       string
	CredentialEnabled      bool
	CredentialMessage      string
	AccessTests            map[string]CredentialAccessTest
	InventoryDiscoveries   map[string]CredentialAccessTest
	AccessTestEnabled      bool
	AccessTestPending      bool
	ExpectedInventory      expectedInventorySection
}
type clusterDetailPageData struct {
	Access ClusterAccess
	pageBase
	Record                   ClusterRecord
	Cluster                  Cluster
	SummaryAvailable         bool
	OperationsAvailable      bool
	Issues                   []Ticket
	HistoricalXID            []Ticket
	Investigations           []Investigation
	RecentInvestigations     []Investigation
	EarlierInvestigations    []Investigation
	GeneratedAt              time.Time
	Glance                   clusterGlance
	Recovery                 []recoveryStep
	GatesMet                 int
	ApplicableGates          int
	Blockers                 []evidenceBlockerGroup
	BlockerStreamCount       int
	NextAction               clusterAction
	Rerun                    investigationForm
	StartedInvestigationID   string
	StartedRepairProposalID  string
	ExistingRepairProposalID string
	StartFailed              bool
	RepairProposalFailed     bool
	RepairProposalCleared    bool
	RepairProposalNoIncident bool
	Tab, TabTitle            string
	Signals                  []Metric
	SignalAttention          int
	WorkflowSignals          []Metric
	EvidenceBar, HistoryBar  stackedBar
	GPUWidth, CPUWidth       string
	Activity                 activityWindow
}

type clusterGlance struct {
	State                                                                           OperationalState
	Label, Headline, Summary                                                        string
	IssueCount, InvestigationCount                                                  int
	PrimaryIssue                                                                    *Ticket
	PrimaryInvestigation                                                            *Investigation
	LatestInvestigation                                                             *Investigation
	Connectivity, Freshness, Queue, InvestigationState, ModelUsage, Evidence, Audit Metric
}

type recoveryStep struct {
	Number                                                    int
	Kind, Title, Current, Target, Action, CollectorGapSummary string
	Collectors, ExcludedCollectors, Sources, OnDemandSources  []string
	EvidenceHistory                                           EvidenceHistory
	State                                                     OperationalState
	Open                                                      bool
	NotApplicable                                             bool
}

type investigationForm struct {
	Available                                                                    bool
	IncidentID, Question, EntityKind, EntityIDs, SuccessCriteria, IdempotencyKey string
	LookbackMinutes, MaxDecisions, MaxToolCalls, MaxDiagnosticCalls, MaxFanOut   int
	MaxModelTokens                                                               int64
	MaxCostUSD                                                                   string
	DeadlineMinutes                                                              int
}
type operationsPageData struct {
	pageBase
	Operations
	Title                 string
	HistoricalXID         []Ticket
	RecentInvestigations  []Investigation
	EarlierInvestigations []Investigation
	Overview              overviewData
}
type investigationReportPageData struct {
	CanCancel bool
	pageBase
	Report InvestigationReport
}

func (server *Server) requireAccess(writer http.ResponseWriter, request *http.Request) ([sha256.Size]byte, string, bool) {
	access, ok := request.Context().Value(accessRequestKey{}).(accessRequest)
	if !ok {
		http.Error(writer, "Cloudflare Access authentication is required", http.StatusUnauthorized)
		return [sha256.Size]byte{}, "", false
	}
	return access.Fingerprint, access.CSRFToken, true
}

func (server *Server) validCSRF(expected, provided string) bool {
	return len(provided) == len(expected) && subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func (server *Server) csrfToken(assertion string) string {
	digest := sha256.Sum256([]byte("sherlock-admin-csrf\x00" + assertion))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (server *Server) parseAndVerifyCSRF(writer http.ResponseWriter, request *http.Request, expectedCSRF string) bool {
	request.Body = http.MaxBytesReader(writer, request.Body, maxFormBodySize)
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" || request.ParseForm() != nil {
		http.Error(writer, "invalid form request", http.StatusBadRequest)
		return false
	}
	if !server.validCSRF(expectedCSRF, request.PostForm.Get("csrf_token")) {
		http.Error(writer, "invalid request token", http.StatusForbidden)
		return false
	}
	return true
}

func (server *Server) mutationContext(request *http.Request, key [sha256.Size]byte) MutationContext {
	requestID, _ := request.Context().Value(requestKey{}).(string)
	identity := requestIdentity(request)
	return MutationContext{SessionFingerprint: append([]byte(nil), key[:]...), RequestID: requestID, OccurredAt: server.clock.Now().UTC(), ActorSubject: identity.Subject}
}

func requestIdentity(request *http.Request) AccessIdentity {
	access, _ := request.Context().Value(accessRequestKey{}).(accessRequest)
	return access.Identity
}

// HumanSessionFromContext returns identity proved by this server's Access
// verifier. The private API client uses it to bind its next request to the
// human, without forwarding a browser-supplied identity header or service key.
func HumanSessionFromContext(ctx context.Context) (auth.HumanSession, bool) {
	access, ok := ctx.Value(accessRequestKey{}).(accessRequest)
	if !ok {
		return auth.HumanSession{}, false
	}
	principal := auth.HumanPrincipal{Issuer: access.Identity.Issuer, Subject: access.Identity.Subject, Email: access.Identity.Email}
	if principal.Validate() != nil {
		return auth.HumanSession{}, false
	}
	return auth.HumanSession{Principal: principal, Fingerprint: access.Fingerprint}, true
}

func (server *Server) auditView(writer http.ResponseWriter, request *http.Request, key [sha256.Size]byte, page string) bool {
	requestID, _ := request.Context().Value(requestKey{}).(string)
	if err := server.recordAudit(request.Context(), AuditEvent{Kind: EventDashboardViewed, Outcome: OutcomeSucceeded, ReasonCode: page, SessionFingerprint: key[:], RequestID: requestID}); err != nil {
		server.reportAuditFailure(request.Context(), EventDashboardViewed, OutcomeSucceeded)
		http.Error(writer, "unable to record this administrator view", http.StatusServiceUnavailable)
		return false
	}
	return true
}

func (server *Server) renderTemplate(writer http.ResponseWriter, tmpl *template.Template, name string, data any) {
	var output strings.Builder
	if err := tmpl.ExecuteTemplate(&output, name, data); err != nil {
		http.Error(writer, "unable to render administrator page", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(writer, output.String())
}

func (server *Server) recordAudit(ctx context.Context, event AuditEvent) error {
	event.OccurredAt = server.clock.Now().UTC()
	if event.SessionFingerprint != nil {
		event.SessionFingerprint = append([]byte(nil), event.SessionFingerprint...)
	}
	return server.auditor.RecordAdminEvent(ctx, event)
}

func (server *Server) auditRejected(ctx context.Context, event AuditEvent) {
	if err := server.recordAudit(ctx, event); err != nil {
		server.reportAuditFailure(ctx, event.Kind, event.Outcome)
	}
}

func (server *Server) reportAuditFailure(ctx context.Context, kind EventKind, outcome EventOutcome) {
	if server.errorReporter != nil {
		server.errorReporter.ReportAdminError(ctx, AuditDeliveryError{Kind: kind, Outcome: outcome})
	}
}

func hasAPIAuthentication(request *http.Request) bool {
	return request.Header.Get("Authorization") != "" || request.Header.Get("X-API-Key") != "" || request.Header.Get("X-Cluster-Key") != "" || request.Header.Get("X-Cluster-API-Key") != ""
}

func sameOrigin(request *http.Request) bool {
	// Fetch Metadata is set by modern browsers after redirects and remains
	// authoritative when a local development browser is reached through an
	// internal proxy whose Host differs from the visible origin.
	if request.Header.Get("Sec-Fetch-Site") == "same-origin" {
		return true
	}
	origin := request.Header.Get("Origin")
	if origin == "" {
		return request.Header.Get("Sec-Fetch-Site") != "cross-site"
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host != request.Host {
		return false
	}
	expectedScheme := "http"
	if request.TLS != nil {
		expectedScheme = "https"
	}
	return parsed.Scheme == expectedScheme
}

func newRequestID() string {
	value := make([]byte, 12)
	if _, err := rand.Read(value); err == nil {
		return hex.EncodeToString(value)
	}
	return fmt.Sprintf("admin-%d", time.Now().UnixNano())
}

func eventKindForPath(_ string) EventKind {
	return EventDashboardViewed
}

func normalizeState(state OperationalState) OperationalState {
	switch state {
	case StateHealthy, StateDegraded, StatePartial, StateStale, StateUnavailable, StateNoData:
		return state
	default:
		return StateNoData
	}
}

func stateClass(state OperationalState) string {
	switch normalizeState(state) {
	case StateHealthy:
		return "healthy"
	case StateDegraded:
		return "degraded"
	case StatePartial:
		return "partial"
	case StateStale:
		return "stale"
	case StateUnavailable:
		return "unavailable"
	default:
		return "no-data"
	}
}
