package adminapi

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type humanScopeKey struct{}

type humanRouteGrant struct {
	capability auth.Capability
	privilege  auth.HumanPrivilege
	platform   bool
}

// authorizeHumanRequest is the private admin API's explicit route inventory.
// Unknown routes fail closed when the GP-10 gate is on. It runs after the
// server-token and signed human-session checks, before any handler mutation.
func (server *Server) authorizeHumanRequest(writer http.ResponseWriter, request *http.Request, session auth.HumanSession) bool {
	if actor := request.Header.Get("X-Sherlock-Access-Subject"); actor != "" && actor != session.Principal.Subject {
		writeProblem(writer, http.StatusForbidden, "FORBIDDEN", "the actor does not match the verified human session")
		return false
	}
	path := strings.TrimPrefix(request.URL.Path, "/internal/admin/v1/")
	if path == request.URL.Path || path == "" {
		writeProblem(writer, http.StatusNotFound, "NOT_FOUND", "the route does not exist")
		return false
	}
	parts := strings.Split(path, "/")
	if request.Method == http.MethodGet && (path == "human-session" || path == "human-access" || path == "dashboard" || path == "clusters" || path == "operations") ||
		(len(parts) >= 2 && parts[0] == "investigations" &&
			(request.Method == http.MethodGet && (len(parts) == 2 || len(parts) == 3 && parts[2] == "shared") ||
				request.Method == http.MethodPost && len(parts) == 3 && parts[2] == "cancel")) {
		scope, err := server.liveHumanScope(request.Context(), session.Principal)
		if err != nil {
			writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "human authorization is temporarily unavailable")
			return false
		}
		if len(scope) == 0 {
			writeProblem(writer, http.StatusForbidden, "FORBIDDEN", "no active cluster membership")
			return false
		}
		*request = *request.WithContext(context.WithValue(request.Context(), humanScopeKey{}, scope))
		return true
	}
	if len(parts) < 2 || parts[0] != "clusters" || !validClusterIDPath(parts[1]) {
		writeProblem(writer, http.StatusNotFound, "NOT_FOUND", "the route does not exist")
		return false
	}
	grant, ok := reviewedHumanRoute(request.Method, parts[2:])
	if !ok {
		writeProblem(writer, http.StatusNotFound, "NOT_FOUND", "the route does not exist")
		return false
	}
	return server.authorizeHumanCluster(writer, request, session.Principal, parts[1], grant)
}

func reviewedHumanRoute(method string, rest []string) (humanRouteGrant, bool) {
	if len(rest) == 0 {
		switch method {
		case http.MethodPatch:
			return humanRouteGrant{capability: auth.CapabilityConfigurationWrite}, true
		case http.MethodDelete:
			return humanRouteGrant{capability: auth.CapabilityConfigurationWrite, platform: true}, true
		}
		return humanRouteGrant{}, false
	}
	if len(rest) == 1 {
		switch method + " " + rest[0] {
		case "GET summary", "GET expected-inventory":
			return humanRouteGrant{capability: auth.CapabilityClusterRead}, true
		case "GET operations":
			return humanRouteGrant{capability: auth.CapabilityIncidentsRead}, true
		case "GET gpu-metrics", "GET progress":
			return humanRouteGrant{capability: auth.CapabilityTelemetryRead}, true
		case "POST investigations":
			return humanRouteGrant{capability: auth.CapabilityInvestigationsRun}, true
		case "GET credentials", "POST credentials", "GET credential-access-tests":
			return humanRouteGrant{capability: auth.CapabilityConfigurationRead, privilege: auth.PrivilegeCredentialManage}, true
		}
	}
	if len(rest) == 2 {
		switch {
		case method == http.MethodGet && rest[0] == "inventory-discovery" && rest[1] == "latest":
			return humanRouteGrant{capability: auth.CapabilityConfigurationRead, privilege: auth.PrivilegeCredentialManage}, true
		case method == http.MethodPost && rest[0] == "expected-inventory" && rest[1] == "previews":
			return humanRouteGrant{capability: auth.CapabilityConfigurationWrite, privilege: auth.PrivilegePolicyManage}, true
		case method == http.MethodDelete && rest[0] == "credentials" && validClusterIDPath(rest[1]):
			return humanRouteGrant{capability: auth.CapabilityConfigurationWrite, privilege: auth.PrivilegeCredentialManage}, true
		}
	}
	if len(rest) == 3 {
		switch {
		case method == http.MethodPost && rest[0] == "credential-access-tests" && validClusterIDPath(rest[1]) && rest[2] == "cancel":
			return humanRouteGrant{capability: auth.CapabilityConfigurationWrite, privilege: auth.PrivilegeCredentialManage}, true
		case method == http.MethodPost && rest[0] == "credentials" && validClusterIDPath(rest[1]) &&
			(rest[2] == "access-tests" || rest[2] == "inventory-discoveries"):
			return humanRouteGrant{capability: auth.CapabilityConfigurationWrite, privilege: auth.PrivilegeCredentialManage}, true
		}
	}
	if len(rest) == 4 && method == http.MethodPost && rest[0] == "expected-inventory" && rest[1] == "previews" && validClusterIDPath(rest[2]) && rest[3] == "import" {
		return humanRouteGrant{capability: auth.CapabilityConfigurationWrite, privilege: auth.PrivilegePolicyManage}, true
	}
	return humanRouteGrant{}, false
}

func (server *Server) authorizeHumanCluster(writer http.ResponseWriter, request *http.Request, principal auth.HumanPrincipal, clusterID string, grant humanRouteGrant) bool {
	membership, err := server.humanAuthorization.HumanMembership(request.Context(), principal, domain.ClusterID(clusterID))
	if errors.Is(err, adminmanage.ErrNotFound) || membership.RevokedAt != nil {
		writeProblem(writer, http.StatusNotFound, "NOT_FOUND", "the cluster does not exist")
		return false
	}
	if err != nil {
		writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "human authorization is temporarily unavailable")
		return false
	}
	if err := membership.Authorize(principal, domain.ClusterID(clusterID), grant.capability); err != nil {
		writeProblem(writer, http.StatusForbidden, "FORBIDDEN", "the cluster role does not allow this action")
		return false
	}
	if grant.privilege.Valid() {
		privilege, err := server.humanAuthorization.HumanPrivilege(request.Context(), principal, domain.ClusterID(clusterID), grant.privilege)
		if errors.Is(err, adminmanage.ErrNotFound) {
			writeProblem(writer, http.StatusForbidden, "FORBIDDEN", "a separate privilege is required")
			return false
		}
		if err != nil {
			writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "human authorization is temporarily unavailable")
			return false
		}
		if membership.AuthorizePrivilege(principal, domain.ClusterID(clusterID), grant.privilege, privilege) != nil {
			writeProblem(writer, http.StatusForbidden, "FORBIDDEN", "a separate privilege is required")
			return false
		}
	}
	if grant.platform {
		platform, err := server.humanAuthorization.HumanPlatformAdmin(request.Context(), principal)
		if errors.Is(err, adminmanage.ErrNotFound) || err == nil && platform.Authorize(principal) != nil {
			writeProblem(writer, http.StatusForbidden, "FORBIDDEN", "platform administration is required")
			return false
		}
		if err != nil {
			writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "human authorization is temporarily unavailable")
			return false
		}
	}
	return true
}

func (server *Server) liveHumanScope(ctx context.Context, principal auth.HumanPrincipal) (map[string]auth.HumanMembership, error) {
	memberships, err := server.humanAuthorization.ListHumanMemberships(ctx, principal)
	if err != nil || len(memberships) > 64 {
		return nil, errors.New("human membership list unavailable or too large")
	}
	scope := make(map[string]auth.HumanMembership, len(memberships))
	for _, membership := range memberships {
		if membership.Authorize(principal, membership.ClusterID, auth.CapabilityClusterRead) != nil {
			return nil, errors.New("invalid active human membership")
		}
		scope[string(membership.ClusterID)] = membership
	}
	return scope, nil
}

func humanScope(ctx context.Context) map[string]auth.HumanMembership {
	scope, _ := ctx.Value(humanScopeKey{}).(map[string]auth.HumanMembership)
	return scope
}

func (server *Server) humanMutationMatches(ctx context.Context, fingerprint []byte, actor string) bool {
	if !server.requireHumanAuthorization {
		return true
	}
	session, ok := verifiedHumanSession(ctx)
	return ok && len(fingerprint) == len(session.Fingerprint) &&
		subtle.ConstantTimeCompare(fingerprint, session.Fingerprint[:]) == 1 &&
		(actor == "" || actor == session.Principal.Subject)
}
