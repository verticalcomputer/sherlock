//go:build integration

package adminmanage_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestHumanMembershipBootstrapRevisionsAndRevocation(t *testing.T) {
	f := newCredentialFixture(t, 8)
	ctx := context.Background()
	p := auth.HumanPrincipal{Issuer: "https://vertical.cloudflareaccess.com", Subject: "human-1", Email: "operator@example.com"}
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := f.store.HumanMembership(ctx, p, domain.ClusterID(f.clusterID)); !errors.Is(err, adminmanage.ErrNotFound) {
		t.Fatalf("unknown member=%v", err)
	}
	input := adminmanage.HumanMembershipGrant{Principal: p, ClusterID: domain.ClusterID(f.clusterID), Role: auth.RoleClusterViewer, Actor: f.actor, At: at}
	member, err := f.store.GrantHumanMembership(ctx, input)
	if err != nil || member.Revision != 1 || member.Authorize(p, input.ClusterID, auth.CapabilityTelemetryRead) != nil ||
		!errors.Is(member.Authorize(p, input.ClusterID, auth.CapabilityIncidentsWrite), auth.ErrForbidden) {
		t.Fatalf("viewer=%+v err=%v", member, err)
	}
	replay, err := f.store.GrantHumanMembership(ctx, input)
	if err != nil || replay.Revision != 1 {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	if _, err := f.store.GrantHumanPrivilege(ctx, p, input.ClusterID, auth.PrivilegeCredentialManage, f.actor, at.Add(time.Second)); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("viewer credential grant=%v", err)
	}
	raw, err := f.store.GrantHumanPrivilege(ctx, p, input.ClusterID, auth.PrivilegeRawEvidence, f.actor, at.Add(time.Second))
	if err != nil || raw.Revision != 1 || member.AuthorizePrivilege(p, input.ClusterID, auth.PrivilegeRawEvidence, raw) != nil {
		t.Fatalf("raw=%+v err=%v", raw, err)
	}
	input.Role, input.At = auth.RoleClusterAdmin, at.Add(2*time.Second)
	member, err = f.store.GrantHumanMembership(ctx, input)
	if err != nil || member.Revision != 2 || member.Authorize(p, input.ClusterID, auth.CapabilityIncidentsWrite) != nil {
		t.Fatalf("admin=%+v err=%v", member, err)
	}
	credential, err := f.store.GrantHumanPrivilege(ctx, p, input.ClusterID, auth.PrivilegeCredentialManage, f.actor, at.Add(3*time.Second))
	if err != nil || credential.Revision != 1 || member.AuthorizePrivilege(p, input.ClusterID, auth.PrivilegeCredentialManage, credential) != nil {
		t.Fatalf("credential=%+v err=%v", credential, err)
	}
	platform, err := f.store.GrantHumanPlatformAdmin(ctx, p, f.actor, at.Add(4*time.Second))
	if err != nil || platform.Revision != 1 || platform.Authorize(p) != nil {
		t.Fatalf("platform=%+v err=%v", platform, err)
	}
	if err := f.store.RevokeHumanMembership(ctx, p, input.ClusterID, f.actor, at.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	member, err = f.store.HumanMembership(ctx, p, input.ClusterID)
	if err != nil || member.Revision != 3 || !errors.Is(member.Authorize(p, input.ClusterID, auth.CapabilityClusterRead), auth.ErrForbidden) ||
		!errors.Is(member.AuthorizePrivilege(p, input.ClusterID, auth.PrivilegeCredentialManage, credential), auth.ErrForbidden) {
		t.Fatalf("revoked=%+v err=%v", member, err)
	}
	credential, err = f.store.HumanPrivilege(ctx, p, input.ClusterID, auth.PrivilegeCredentialManage)
	if err != nil || credential.Revision != 2 || credential.RevokedAt == nil {
		t.Fatalf("credential was not revoked with membership: %+v %v", credential, err)
	}
	input.At = at.Add(6 * time.Second)
	member, err = f.store.GrantHumanMembership(ctx, input)
	if err != nil || member.Revision != 4 || !errors.Is(member.AuthorizePrivilege(p, input.ClusterID, auth.PrivilegeCredentialManage, credential), auth.ErrForbidden) {
		t.Fatalf("revoked privilege resurrected: member=%+v grant=%+v err=%v", member, credential, err)
	}
	if err := f.store.RevokeHumanPlatformAdmin(ctx, p, f.actor, at.Add(7*time.Second)); err != nil {
		t.Fatal(err)
	}
	platform, err = f.store.HumanPlatformAdmin(ctx, p)
	if err != nil || platform.Revision != 2 || !errors.Is(platform.Authorize(p), auth.ErrForbidden) {
		t.Fatalf("platform revoked=%+v err=%v", platform, err)
	}
	var audits int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM human_authorization_audit_events WHERE issuer=$1 AND subject=$2`, p.Issuer, p.Subject).Scan(&audits); err != nil || audits != 10 {
		t.Fatalf("audit count=%d err=%v", audits, err)
	}
	foreign := p
	foreign.Issuer = "https://other.cloudflareaccess.com"
	if !errors.Is(member.Authorize(foreign, input.ClusterID, auth.CapabilityClusterRead), auth.ErrForbidden) {
		t.Fatal("foreign issuer authorized")
	}
}

func TestHumanMembershipConcurrentBootstrapCreatesOneGrant(t *testing.T) {
	f := newCredentialFixture(t, 8)
	p := auth.HumanPrincipal{Issuer: "https://vertical.cloudflareaccess.com", Subject: "concurrent-human"}
	input := adminmanage.HumanMembershipGrant{Principal: p, ClusterID: domain.ClusterID(f.clusterID), Role: auth.RoleClusterViewer, Actor: f.actor, At: time.Now().UTC().Truncate(time.Microsecond)}
	var group sync.WaitGroup
	errorsCh := make(chan error, 8)
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			member, err := f.store.GrantHumanMembership(context.Background(), input)
			if err == nil && member.Revision != 1 {
				err = errors.New("unexpected revision")
			}
			errorsCh <- err
		}()
	}
	group.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	var grants, audits int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM human_cluster_memberships WHERE issuer=$1 AND subject=$2`, p.Issuer, p.Subject).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM human_authorization_audit_events WHERE issuer=$1 AND subject=$2`, p.Issuer, p.Subject).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if grants != 1 || audits != 1 {
		t.Fatalf("grants=%d audits=%d", grants, audits)
	}
}

func TestHumanMembershipDowngradeRevokesAdminPrivilege(t *testing.T) {
	f := newCredentialFixture(t, 4)
	ctx := context.Background()
	p := auth.HumanPrincipal{Issuer: "https://vertical.cloudflareaccess.com", Subject: "downgraded-human"}
	at := time.Now().UTC().Truncate(time.Microsecond)
	input := adminmanage.HumanMembershipGrant{Principal: p, ClusterID: domain.ClusterID(f.clusterID), Role: auth.RoleClusterAdmin, Actor: f.actor, At: at}
	if _, err := f.store.GrantHumanMembership(ctx, input); err != nil {
		t.Fatal(err)
	}
	grant, err := f.store.GrantHumanPrivilege(ctx, p, input.ClusterID, auth.PrivilegePolicyManage, f.actor, at.Add(time.Second))
	if err != nil || grant.Revision != 1 {
		t.Fatalf("grant=%+v err=%v", grant, err)
	}
	input.Role, input.At = auth.RoleClusterViewer, at.Add(2*time.Second)
	member, err := f.store.GrantHumanMembership(ctx, input)
	if err != nil || member.Revision != 2 {
		t.Fatalf("downgrade=%+v err=%v", member, err)
	}
	grant, err = f.store.HumanPrivilege(ctx, p, input.ClusterID, auth.PrivilegePolicyManage)
	if err != nil || grant.RevokedAt == nil || grant.Revision != 2 {
		t.Fatalf("privilege remains active: %+v err=%v", grant, err)
	}
	input.Role, input.At = auth.RoleClusterAdmin, at.Add(3*time.Second)
	member, err = f.store.GrantHumanMembership(ctx, input)
	if err != nil || member.Revision != 3 || !errors.Is(member.AuthorizePrivilege(p, input.ClusterID, auth.PrivilegePolicyManage, grant), auth.ErrForbidden) {
		t.Fatalf("privilege resurrected: member=%+v grant=%+v err=%v", member, grant, err)
	}
}

func TestHumanMembershipListExcludesForeignPrincipalsAndRemovedClusters(t *testing.T) {
	f := newCredentialFixture(t, 4)
	ctx := context.Background()
	p := auth.HumanPrincipal{Issuer: "https://vertical.cloudflareaccess.com", Subject: "scoped-human"}
	foreign := auth.HumanPrincipal{Issuer: p.Issuer, Subject: "other-human"}
	at := time.Now().UTC().Truncate(time.Microsecond)
	for _, item := range []struct {
		principal auth.HumanPrincipal
		clusterID domain.ClusterID
	}{
		{p, domain.ClusterID(f.clusterID)},
		{p, domain.ClusterID(f.foreignID)},
		{foreign, domain.ClusterID(f.clusterID)},
	} {
		if _, err := f.store.GrantHumanMembership(ctx, adminmanage.HumanMembershipGrant{Principal: item.principal, ClusterID: item.clusterID, Role: auth.RoleClusterViewer, Actor: f.actor, At: at}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := f.store.ListHumanMemberships(ctx, p)
	if err != nil || len(list) != 2 || string(list[0].ClusterID) != f.clusterID || string(list[1].ClusterID) != f.foreignID {
		t.Fatalf("active memberships=%+v err=%v", list, err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE clusters SET removed_at=clock_timestamp() WHERE cluster_id=$1`, f.foreignID); err != nil {
		t.Fatal(err)
	}
	list, err = f.store.ListHumanMemberships(ctx, p)
	if err != nil || len(list) != 1 || string(list[0].ClusterID) != f.clusterID {
		t.Fatalf("removed cluster leaked: %+v err=%v", list, err)
	}
	if _, err := f.store.HumanMembership(ctx, p, domain.ClusterID(f.foreignID)); !errors.Is(err, adminmanage.ErrNotFound) {
		t.Fatalf("removed cluster still authorized: %v", err)
	}
	list, err = f.store.ListHumanMemberships(ctx, foreign)
	if err != nil || len(list) != 1 || string(list[0].ClusterID) != f.clusterID {
		t.Fatalf("foreign principal scope=%+v err=%v", list, err)
	}
}
