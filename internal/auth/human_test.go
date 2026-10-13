package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestHumanMembershipRoleAndIdentityMatrix(t *testing.T) {
	p := HumanPrincipal{Issuer: "https://vertical.cloudflareaccess.com", Subject: "subject-1", Email: "person@example.com"}
	m := HumanMembership{Issuer: p.Issuer, Subject: p.Subject, ClusterID: "cluster-1", Role: RoleClusterViewer, Revision: 1}
	if err := m.Authorize(p, "cluster-1", CapabilityTelemetryRead); err != nil {
		t.Fatal(err)
	}
	for _, capability := range []Capability{CapabilityIncidentsWrite, CapabilityInvestigationsRun, CapabilityConfigurationWrite, CapabilityEvidenceRaw} {
		if !errors.Is(m.Authorize(p, "cluster-1", capability), ErrForbidden) {
			t.Fatalf("viewer was allowed %s", capability)
		}
	}
	m.Role = RoleClusterAdmin
	for _, capability := range []Capability{CapabilityIncidentsWrite, CapabilityInvestigationsRun, CapabilityConfigurationWrite} {
		if err := m.Authorize(p, "cluster-1", capability); err != nil {
			t.Fatalf("admin denied %s: %v", capability, err)
		}
	}
	if !errors.Is(m.Authorize(p, "cluster-1", CapabilityEvidenceRaw), ErrForbidden) {
		t.Fatal("raw evidence became a role capability")
	}
	for _, changed := range []struct {
		name string
		p    HumanPrincipal
		m    HumanMembership
		c    string
	}{
		{"foreign issuer", HumanPrincipal{Issuer: "https://foreign.cloudflareaccess.com", Subject: p.Subject}, m, "cluster-1"},
		{"foreign subject", HumanPrincipal{Issuer: p.Issuer, Subject: "other"}, m, "cluster-1"},
		{"foreign cluster", p, m, "cluster-2"},
		{"unknown membership", p, HumanMembership{}, "cluster-1"},
	} {
		t.Run(changed.name, func(t *testing.T) {
			if !errors.Is(changed.m.Authorize(changed.p, domain.ClusterID(changed.c), CapabilityClusterRead), ErrForbidden) {
				t.Fatal("unreviewed identity authorized")
			}
		})
	}
	revoked := time.Now().UTC()
	m.RevokedAt = &revoked
	if !errors.Is(m.Authorize(p, "cluster-1", CapabilityClusterRead), ErrForbidden) {
		t.Fatal("revoked membership authorized")
	}
}

func TestHumanPrivilegeAndPlatformGrantsAreIndependent(t *testing.T) {
	p := HumanPrincipal{Issuer: "https://vertical.cloudflareaccess.com", Subject: "subject-1"}
	m := HumanMembership{Issuer: p.Issuer, Subject: p.Subject, ClusterID: "cluster-1", Role: RoleClusterViewer, Revision: 1}
	g := HumanPrivilegeGrant{Issuer: p.Issuer, Subject: p.Subject, ClusterID: "cluster-1", Privilege: PrivilegeRawEvidence, Revision: 1}
	if err := m.AuthorizePrivilege(p, "cluster-1", PrivilegeRawEvidence, g); err != nil {
		t.Fatal(err)
	}
	g.Privilege = PrivilegeCredentialManage
	if !errors.Is(m.AuthorizePrivilege(p, "cluster-1", PrivilegeCredentialManage, g), ErrForbidden) {
		t.Fatal("viewer managed credentials")
	}
	m.Role = RoleClusterAdmin
	if err := m.AuthorizePrivilege(p, "cluster-1", PrivilegeCredentialManage, g); err != nil {
		t.Fatal(err)
	}
	platform := HumanPlatformGrant{Issuer: p.Issuer, Subject: p.Subject, Revision: 1}
	if err := platform.Authorize(p); err != nil {
		t.Fatal(err)
	}
	if err := (HumanMembership{}).Authorize(p, "cluster-1", CapabilityClusterRead); !errors.Is(err, ErrForbidden) {
		t.Fatal("platform grant created cluster membership")
	}
}
