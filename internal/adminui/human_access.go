package adminui

import (
	"context"
	"net/http"
	"strings"
)

// ClusterAccess is a per-request UI hint from the private API. API mutation
// handlers still recheck live membership and grants independently.
type ClusterAccess struct {
	ClusterID            string `json:"cluster_id"`
	Role                 string `json:"role"`
	CanConfigure         bool   `json:"can_configure"`
	CanInvestigate       bool   `json:"can_investigate"`
	CanManageCredentials bool   `json:"can_manage_credentials"`
	CanManagePolicy      bool   `json:"can_manage_policy"`
	CanRemove            bool   `json:"can_remove"`
}

type HumanAccessProvider interface {
	LoadHumanAccess(context.Context) ([]ClusterAccess, error)
}

type humanAccessKey struct{}

func clusterAccess(ctx context.Context, id string) ClusterAccess {
	if access, enforced := ctx.Value(humanAccessKey{}).(map[string]ClusterAccess); enforced {
		return access[id]
	}
	// Compatibility for the existing Access-only operator deployment. This is
	// never used when membership enforcement is enabled, including failures.
	return ClusterAccess{ClusterID: id, Role: "OPERATOR", CanConfigure: true, CanInvestigate: true, CanManageCredentials: true, CanManagePolicy: true, CanRemove: true}
}

// authorizeHumanUIRoute rejects direct viewer mutation URLs before rendering
// or forwarding forms. The private API remains the authorization authority.
func authorizeHumanUIRoute(w http.ResponseWriter, r *http.Request) bool {
	access, enforced := r.Context().Value(humanAccessKey{}).(map[string]ClusterAccess)
	if !enforced {
		return true
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "admin" || parts[1] != "clusters" {
		return true
	}
	grant, found := access[parts[2]]
	if !found {
		http.Error(w, "cluster not found", http.StatusNotFound)
		return false
	}
	if len(parts) < 4 {
		return true
	}
	allowed := true
	switch parts[3] {
	case "edit":
		allowed = grant.CanConfigure
	case "delete":
		allowed = grant.CanRemove
	case "credentials", "credential-tests":
		allowed = grant.CanManageCredentials
	case "expected-inventory":
		allowed = grant.CanManagePolicy
	case "investigations", "evidence-repair-proposals":
		if r.Method != http.MethodGet {
			allowed = grant.CanInvestigate
		}
	}
	if !allowed {
		http.Error(w, "this action requires an active cluster grant", http.StatusForbidden)
	}
	return allowed
}
