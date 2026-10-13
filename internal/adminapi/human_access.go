package adminapi

import (
	"errors"
	"net/http"
	"sort"

	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/adminui"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// humanAccess projects live grants for UI controls; it is not a reusable grant
// or a substitute for mutation authorization. No identity or secret is sent.
func (server *Server) humanAccess(w http.ResponseWriter, r *http.Request) {
	if !server.requireHumanAuthorization {
		writeProblem(w, 503, "HUMAN_AUTH_DISABLED", "human authorization is not configured")
		return
	}
	if rejectQuery(w, r) {
		return
	}
	session, _ := verifiedHumanSession(r.Context())
	rows := make([]adminui.ClusterAccess, 0, len(humanScope(r.Context())))
	for id := range humanScope(r.Context()) {
		membership, err := server.humanAuthorization.HumanMembership(r.Context(), session.Principal, domain.ClusterID(id))
		if errors.Is(err, adminmanage.ErrNotFound) {
			continue
		}
		if err != nil {
			writeProblem(w, 503, "SERVICE_UNAVAILABLE", "human authorization is temporarily unavailable")
			return
		}
		if membership.Authorize(session.Principal, domain.ClusterID(id), auth.CapabilityClusterRead) != nil {
			continue
		}
		row := adminui.ClusterAccess{ClusterID: id, Role: string(membership.Role),
			CanConfigure:   membership.Authorize(session.Principal, domain.ClusterID(id), auth.CapabilityConfigurationWrite) == nil,
			CanInvestigate: membership.Authorize(session.Principal, domain.ClusterID(id), auth.CapabilityInvestigationsRun) == nil}
		for _, privilege := range []auth.HumanPrivilege{auth.PrivilegeCredentialManage, auth.PrivilegePolicyManage} {
			grant, err := server.humanAuthorization.HumanPrivilege(r.Context(), session.Principal, domain.ClusterID(id), privilege)
			if errors.Is(err, adminmanage.ErrNotFound) {
				continue
			}
			if err != nil {
				writeProblem(w, 503, "SERVICE_UNAVAILABLE", "human authorization is temporarily unavailable")
				return
			}
			allowed := membership.AuthorizePrivilege(session.Principal, domain.ClusterID(id), privilege, grant) == nil
			if privilege == auth.PrivilegeCredentialManage {
				row.CanManageCredentials = allowed
			} else {
				row.CanManagePolicy = allowed
			}
		}
		platform, err := server.humanAuthorization.HumanPlatformAdmin(r.Context(), session.Principal)
		if err != nil && !errors.Is(err, adminmanage.ErrNotFound) {
			writeProblem(w, 503, "SERVICE_UNAVAILABLE", "human authorization is temporarily unavailable")
			return
		}
		row.CanRemove = err == nil && row.CanConfigure && platform.Authorize(session.Principal) == nil
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		writeProblem(w, 403, "FORBIDDEN", "no active cluster membership")
		return
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ClusterID < rows[j].ClusterID })
	writeJSON(w, 200, struct {
		Clusters []adminui.ClusterAccess `json:"clusters"`
	}{rows})
}
