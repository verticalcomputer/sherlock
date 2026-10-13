package auth

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// HumanPrincipal is the identity proved by a verified end-user assertion.
// Email is display metadata only and is never an authorization key.
type HumanPrincipal struct {
	Issuer  string
	Subject string
	Email   string
}

func (p HumanPrincipal) Validate() error {
	u, err := url.Parse(p.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" || u.Path != "" || len(p.Issuer) > 512 ||
		len(p.Subject) < 1 || len(p.Subject) > 256 || strings.ContainsAny(p.Subject, "\x00\r\n") ||
		len(p.Email) > 320 || strings.ContainsAny(p.Email, "\x00\r\n") {
		return fmt.Errorf("invalid verified human principal")
	}
	return nil
}

type HumanRole string

const (
	RoleClusterViewer HumanRole = "CLUSTER_VIEWER"
	RoleClusterAdmin  HumanRole = "CLUSTER_ADMIN"
)

func (r HumanRole) Valid() bool { return r == RoleClusterViewer || r == RoleClusterAdmin }

type HumanPrivilege string

const (
	PrivilegeCredentialManage HumanPrivilege = "CREDENTIAL_MANAGE"
	PrivilegePolicyManage     HumanPrivilege = "POLICY_MANAGE"
	PrivilegeRawEvidence      HumanPrivilege = "RAW_EVIDENCE"
)

func (p HumanPrivilege) Valid() bool {
	return p == PrivilegeCredentialManage || p == PrivilegePolicyManage || p == PrivilegeRawEvidence
}

type HumanMembership struct {
	Issuer    string
	Subject   string
	ClusterID domain.ClusterID
	Role      HumanRole
	Revision  int64
	RevokedAt *time.Time
}

// Authorize binds a verified issuer+subject to one live cluster membership.
// A platform administrator grant alone never supplies cluster membership.
func (m HumanMembership) Authorize(p HumanPrincipal, clusterID domain.ClusterID, capability Capability) error {
	if p.Validate() != nil || m.Issuer != p.Issuer || m.Subject != p.Subject ||
		m.ClusterID == "" || m.ClusterID != clusterID || m.Revision < 1 || m.RevokedAt != nil || !m.Role.Valid() {
		return ErrForbidden
	}
	for _, allowed := range humanRoleCapabilities(m.Role) {
		if allowed == capability {
			return nil
		}
	}
	return ErrForbidden
}

func (m HumanMembership) AuthorizePrivilege(p HumanPrincipal, clusterID domain.ClusterID, privilege HumanPrivilege, grant HumanPrivilegeGrant) error {
	if !privilege.Valid() || m.Authorize(p, clusterID, CapabilityClusterRead) != nil ||
		(privilege != PrivilegeRawEvidence && m.Role != RoleClusterAdmin) ||
		grant.Issuer != p.Issuer || grant.Subject != p.Subject || grant.ClusterID != clusterID ||
		grant.Privilege != privilege || grant.Revision < 1 || grant.RevokedAt != nil {
		return ErrForbidden
	}
	return nil
}

type HumanPrivilegeGrant struct {
	Issuer    string
	Subject   string
	ClusterID domain.ClusterID
	Privilege HumanPrivilege
	Revision  int64
	RevokedAt *time.Time
}

type HumanPlatformGrant struct {
	Issuer    string
	Subject   string
	Revision  int64
	RevokedAt *time.Time
}

func (g HumanPlatformGrant) Authorize(p HumanPrincipal) error {
	if p.Validate() != nil || g.Issuer != p.Issuer || g.Subject != p.Subject || g.Revision < 1 || g.RevokedAt != nil {
		return ErrForbidden
	}
	return nil
}

func humanRoleCapabilities(role HumanRole) []Capability {
	reads := []Capability{
		CapabilityClusterRead, CapabilityTelemetryRead, CapabilityIncidentsRead,
		CapabilityInvestigationsRead,
	}
	if role == RoleClusterViewer {
		return reads
	}
	if role == RoleClusterAdmin {
		return append(reads, CapabilityIncidentsWrite, CapabilityInvestigationsRun,
			CapabilityDiagnosticsPrivileged, CapabilityConfigurationRead,
			CapabilityConfigurationWrite)
	}
	return nil
}
