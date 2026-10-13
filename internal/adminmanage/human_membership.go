package adminmanage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type HumanMembershipGrant struct {
	Principal auth.HumanPrincipal
	ClusterID domain.ClusterID
	Role      auth.HumanRole
	Actor     string
	At        time.Time
}

// GrantHumanMembership is an operator-only bootstrap operation. Nothing in
// the browser or private API calls it. A repeated identical active grant is a
// no-op; each actual transition increments the revision and appends an audit.
func (store *PostgresStore) GrantHumanMembership(ctx context.Context, input HumanMembershipGrant) (auth.HumanMembership, error) {
	if input.Principal.Validate() != nil || validateClusterID(string(input.ClusterID)) != nil || !input.Role.Valid() ||
		!validAccessSubject(input.Actor) || input.At.IsZero() {
		return auth.HumanMembership{}, ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return auth.HumanMembership{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockActiveHumanCluster(ctx, tx, input.ClusterID); err != nil {
		return auth.HumanMembership{}, err
	}
	if err := ensureHumanPrincipal(ctx, tx, input.Principal); err != nil {
		return auth.HumanMembership{}, err
	}
	result := auth.HumanMembership{Issuer: input.Principal.Issuer, Subject: input.Principal.Subject, ClusterID: input.ClusterID, Role: input.Role}
	at := input.At.UTC()
	err = tx.QueryRow(ctx, `INSERT INTO human_cluster_memberships(issuer,subject,cluster_id,role,revision,granted_at,updated_at)
		VALUES($1,$2,$3,$4,1,$5,$5) ON CONFLICT DO NOTHING RETURNING revision`, result.Issuer, result.Subject, result.ClusterID, result.Role, at).Scan(&result.Revision)
	changed := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return auth.HumanMembership{}, err
	}
	if !changed {
		var oldRole auth.HumanRole
		var revoked *time.Time
		if err := tx.QueryRow(ctx, `SELECT role,revision,revoked_at FROM human_cluster_memberships
			WHERE issuer=$1 AND subject=$2 AND cluster_id=$3 FOR UPDATE`, result.Issuer, result.Subject, result.ClusterID).Scan(&oldRole, &result.Revision, &revoked); err != nil {
			return auth.HumanMembership{}, err
		}
		if oldRole != input.Role || revoked != nil {
			if revoked != nil || oldRole == auth.RoleClusterAdmin && input.Role == auth.RoleClusterViewer {
				if err := revokeHumanPrivilegesTx(ctx, tx, result.Issuer, result.Subject, result.ClusterID, input.Actor, at, revoked != nil); err != nil {
					return auth.HumanMembership{}, err
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE human_cluster_memberships SET role=$4,revision=revision+1,
				granted_at=$5,updated_at=$5,revoked_at=NULL WHERE issuer=$1 AND subject=$2 AND cluster_id=$3`, result.Issuer, result.Subject, result.ClusterID, result.Role, at); err != nil {
				return auth.HumanMembership{}, err
			}
			result.Revision++
			changed = true
		}
	}
	if changed {
		if err := appendHumanAudit(ctx, tx, result.Issuer, result.Subject, string(result.ClusterID), "MEMBERSHIP_GRANTED", string(result.Role), "", result.Revision, input.Actor, at); err != nil {
			return auth.HumanMembership{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return auth.HumanMembership{}, err
	}
	return result, nil
}

func (store *PostgresStore) RevokeHumanMembership(ctx context.Context, principal auth.HumanPrincipal, clusterID domain.ClusterID, actor string, at time.Time) error {
	if principal.Validate() != nil || validateClusterID(string(clusterID)) != nil || !validAccessSubject(actor) || at.IsZero() {
		return ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var role auth.HumanRole
	var revision int64
	err = tx.QueryRow(ctx, `SELECT role,revision FROM human_cluster_memberships WHERE issuer=$1 AND subject=$2 AND cluster_id=$3 AND revoked_at IS NULL FOR UPDATE`, principal.Issuer, principal.Subject, clusterID).Scan(&role, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	at = at.UTC()
	if err := revokeHumanPrivilegesTx(ctx, tx, principal.Issuer, principal.Subject, clusterID, actor, at, true); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE human_cluster_memberships SET revision=revision+1,updated_at=$4,revoked_at=$4 WHERE issuer=$1 AND subject=$2 AND cluster_id=$3`, principal.Issuer, principal.Subject, clusterID, at); err != nil {
		return err
	}
	if err := appendHumanAudit(ctx, tx, principal.Issuer, principal.Subject, string(clusterID), "MEMBERSHIP_REVOKED", string(role), "", revision+1, actor, at); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func revokeHumanPrivilegesTx(ctx context.Context, tx pgx.Tx, issuer, subject string, clusterID domain.ClusterID, actor string, at time.Time, all bool) error {
	rows, err := tx.Query(ctx, `SELECT privilege,revision FROM human_cluster_privileges
		WHERE issuer=$1 AND subject=$2 AND cluster_id=$3 AND revoked_at IS NULL
		ORDER BY privilege FOR UPDATE`, issuer, subject, clusterID)
	if err != nil {
		return err
	}
	type activePrivilege struct {
		name     auth.HumanPrivilege
		revision int64
	}
	var active []activePrivilege
	for rows.Next() {
		var item activePrivilege
		if err := rows.Scan(&item.name, &item.revision); err != nil {
			rows.Close()
			return err
		}
		if all || item.name != auth.PrivilegeRawEvidence {
			active = append(active, item)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, item := range active {
		if _, err := tx.Exec(ctx, `UPDATE human_cluster_privileges SET revision=revision+1,updated_at=$5,revoked_at=$5
			WHERE issuer=$1 AND subject=$2 AND cluster_id=$3 AND privilege=$4 AND revoked_at IS NULL`, issuer, subject, clusterID, item.name, at); err != nil {
			return err
		}
		if err := appendHumanAudit(ctx, tx, issuer, subject, string(clusterID), "PRIVILEGE_REVOKED", "", string(item.name), item.revision+1, actor, at); err != nil {
			return err
		}
	}
	return nil
}

func (store *PostgresStore) HumanMembership(ctx context.Context, principal auth.HumanPrincipal, clusterID domain.ClusterID) (auth.HumanMembership, error) {
	if principal.Validate() != nil || validateClusterID(string(clusterID)) != nil {
		return auth.HumanMembership{}, ErrInvalid
	}
	result := auth.HumanMembership{Issuer: principal.Issuer, Subject: principal.Subject, ClusterID: clusterID}
	err := store.pool.QueryRow(ctx, `SELECT m.role,m.revision,m.revoked_at FROM human_cluster_memberships m
		JOIN clusters c ON c.cluster_id=m.cluster_id AND c.removed_at IS NULL
		WHERE m.issuer=$1 AND m.subject=$2 AND m.cluster_id=$3`, principal.Issuer, principal.Subject, clusterID).Scan(&result.Role, &result.Revision, &result.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.HumanMembership{}, ErrNotFound
	}
	return result, err
}

// ListHumanMemberships returns only live memberships on active clusters. It
// is the scope source for cross-cluster dashboard and operations projections.
func (store *PostgresStore) ListHumanMemberships(ctx context.Context, principal auth.HumanPrincipal) ([]auth.HumanMembership, error) {
	if principal.Validate() != nil {
		return nil, ErrInvalid
	}
	rows, err := store.pool.Query(ctx, `SELECT m.cluster_id,m.role,m.revision FROM human_cluster_memberships m
		JOIN clusters c ON c.cluster_id=m.cluster_id AND c.removed_at IS NULL
		WHERE m.issuer=$1 AND m.subject=$2 AND m.revoked_at IS NULL ORDER BY m.cluster_id LIMIT 2001`, principal.Issuer, principal.Subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]auth.HumanMembership, 0)
	for rows.Next() {
		if len(result) >= 2000 {
			return nil, ErrInvalid
		}
		item := auth.HumanMembership{Issuer: principal.Issuer, Subject: principal.Subject}
		if err := rows.Scan(&item.ClusterID, &item.Role, &item.Revision); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (store *PostgresStore) GrantHumanPrivilege(ctx context.Context, principal auth.HumanPrincipal, clusterID domain.ClusterID, privilege auth.HumanPrivilege, actor string, at time.Time) (auth.HumanPrivilegeGrant, error) {
	if principal.Validate() != nil || validateClusterID(string(clusterID)) != nil || !privilege.Valid() || !validAccessSubject(actor) || at.IsZero() {
		return auth.HumanPrivilegeGrant{}, ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return auth.HumanPrivilegeGrant{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var role auth.HumanRole
	err = tx.QueryRow(ctx, `SELECT role FROM human_cluster_memberships WHERE issuer=$1 AND subject=$2 AND cluster_id=$3 AND revoked_at IS NULL FOR SHARE`, principal.Issuer, principal.Subject, clusterID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.HumanPrivilegeGrant{}, ErrNotFound
	}
	if err != nil {
		return auth.HumanPrivilegeGrant{}, err
	}
	if privilege != auth.PrivilegeRawEvidence && role != auth.RoleClusterAdmin {
		return auth.HumanPrivilegeGrant{}, auth.ErrForbidden
	}
	result := auth.HumanPrivilegeGrant{Issuer: principal.Issuer, Subject: principal.Subject, ClusterID: clusterID, Privilege: privilege}
	at = at.UTC()
	err = tx.QueryRow(ctx, `INSERT INTO human_cluster_privileges(issuer,subject,cluster_id,privilege,revision,granted_at,updated_at)
		VALUES($1,$2,$3,$4,1,$5,$5) ON CONFLICT (issuer,subject,cluster_id,privilege) DO UPDATE
		SET revision=human_cluster_privileges.revision+1,granted_at=EXCLUDED.granted_at,updated_at=EXCLUDED.updated_at,revoked_at=NULL
		WHERE human_cluster_privileges.revoked_at IS NOT NULL RETURNING revision`, principal.Issuer, principal.Subject, clusterID, privilege, at).Scan(&result.Revision)
	changed := err == nil
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `SELECT revision FROM human_cluster_privileges WHERE issuer=$1 AND subject=$2 AND cluster_id=$3 AND privilege=$4`, principal.Issuer, principal.Subject, clusterID, privilege).Scan(&result.Revision)
	}
	if err != nil {
		return auth.HumanPrivilegeGrant{}, err
	}
	if changed {
		if err := appendHumanAudit(ctx, tx, principal.Issuer, principal.Subject, string(clusterID), "PRIVILEGE_GRANTED", "", string(privilege), result.Revision, actor, at); err != nil {
			return auth.HumanPrivilegeGrant{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return auth.HumanPrivilegeGrant{}, err
	}
	return result, nil
}

func (store *PostgresStore) RevokeHumanPrivilege(ctx context.Context, principal auth.HumanPrincipal, clusterID domain.ClusterID, privilege auth.HumanPrivilege, actor string, at time.Time) error {
	if principal.Validate() != nil || validateClusterID(string(clusterID)) != nil || !privilege.Valid() || !validAccessSubject(actor) || at.IsZero() {
		return ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var revision int64
	at = at.UTC()
	err = tx.QueryRow(ctx, `UPDATE human_cluster_privileges SET revision=revision+1,updated_at=$5,revoked_at=$5
		WHERE issuer=$1 AND subject=$2 AND cluster_id=$3 AND privilege=$4 AND revoked_at IS NULL RETURNING revision`, principal.Issuer, principal.Subject, clusterID, privilege, at).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := appendHumanAudit(ctx, tx, principal.Issuer, principal.Subject, string(clusterID), "PRIVILEGE_REVOKED", "", string(privilege), revision, actor, at); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (store *PostgresStore) HumanPrivilege(ctx context.Context, principal auth.HumanPrincipal, clusterID domain.ClusterID, privilege auth.HumanPrivilege) (auth.HumanPrivilegeGrant, error) {
	if principal.Validate() != nil || validateClusterID(string(clusterID)) != nil || !privilege.Valid() {
		return auth.HumanPrivilegeGrant{}, ErrInvalid
	}
	result := auth.HumanPrivilegeGrant{Issuer: principal.Issuer, Subject: principal.Subject, ClusterID: clusterID, Privilege: privilege}
	err := store.pool.QueryRow(ctx, `SELECT revision,revoked_at FROM human_cluster_privileges WHERE issuer=$1 AND subject=$2 AND cluster_id=$3 AND privilege=$4`, principal.Issuer, principal.Subject, clusterID, privilege).Scan(&result.Revision, &result.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.HumanPrivilegeGrant{}, ErrNotFound
	}
	return result, err
}

func (store *PostgresStore) GrantHumanPlatformAdmin(ctx context.Context, principal auth.HumanPrincipal, actor string, at time.Time) (auth.HumanPlatformGrant, error) {
	if principal.Validate() != nil || !validAccessSubject(actor) || at.IsZero() {
		return auth.HumanPlatformGrant{}, ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return auth.HumanPlatformGrant{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := ensureHumanPrincipal(ctx, tx, principal); err != nil {
		return auth.HumanPlatformGrant{}, err
	}
	result := auth.HumanPlatformGrant{Issuer: principal.Issuer, Subject: principal.Subject}
	at = at.UTC()
	err = tx.QueryRow(ctx, `INSERT INTO human_platform_admins(issuer,subject,revision,granted_at,updated_at)
		VALUES($1,$2,1,$3,$3) ON CONFLICT (issuer,subject) DO UPDATE
		SET revision=human_platform_admins.revision+1,granted_at=EXCLUDED.granted_at,updated_at=EXCLUDED.updated_at,revoked_at=NULL
		WHERE human_platform_admins.revoked_at IS NOT NULL RETURNING revision`, principal.Issuer, principal.Subject, at).Scan(&result.Revision)
	changed := err == nil
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `SELECT revision FROM human_platform_admins WHERE issuer=$1 AND subject=$2`, principal.Issuer, principal.Subject).Scan(&result.Revision)
	}
	if err != nil {
		return auth.HumanPlatformGrant{}, err
	}
	if changed {
		if err := appendHumanAudit(ctx, tx, principal.Issuer, principal.Subject, "", "PLATFORM_GRANTED", "", "", result.Revision, actor, at); err != nil {
			return auth.HumanPlatformGrant{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return auth.HumanPlatformGrant{}, err
	}
	return result, nil
}

func (store *PostgresStore) RevokeHumanPlatformAdmin(ctx context.Context, principal auth.HumanPrincipal, actor string, at time.Time) error {
	if principal.Validate() != nil || !validAccessSubject(actor) || at.IsZero() {
		return ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var revision int64
	at = at.UTC()
	err = tx.QueryRow(ctx, `UPDATE human_platform_admins SET revision=revision+1,updated_at=$3,revoked_at=$3
		WHERE issuer=$1 AND subject=$2 AND revoked_at IS NULL RETURNING revision`, principal.Issuer, principal.Subject, at).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := appendHumanAudit(ctx, tx, principal.Issuer, principal.Subject, "", "PLATFORM_REVOKED", "", "", revision, actor, at); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (store *PostgresStore) HumanPlatformAdmin(ctx context.Context, principal auth.HumanPrincipal) (auth.HumanPlatformGrant, error) {
	if principal.Validate() != nil {
		return auth.HumanPlatformGrant{}, ErrInvalid
	}
	result := auth.HumanPlatformGrant{Issuer: principal.Issuer, Subject: principal.Subject}
	err := store.pool.QueryRow(ctx, `SELECT revision,revoked_at FROM human_platform_admins WHERE issuer=$1 AND subject=$2`, principal.Issuer, principal.Subject).Scan(&result.Revision, &result.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.HumanPlatformGrant{}, ErrNotFound
	}
	return result, err
}

func lockActiveHumanCluster(ctx context.Context, tx pgx.Tx, clusterID domain.ClusterID) error {
	var id string
	err := tx.QueryRow(ctx, `SELECT cluster_id FROM clusters WHERE cluster_id=$1 AND removed_at IS NULL FOR SHARE`, clusterID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func ensureHumanPrincipal(ctx context.Context, tx pgx.Tx, principal auth.HumanPrincipal) error {
	_, err := tx.Exec(ctx, `INSERT INTO human_principals(issuer,subject,display_email) VALUES($1,$2,$3)
		ON CONFLICT (issuer,subject) DO NOTHING`, principal.Issuer, principal.Subject, principal.Email)
	return err
}

func appendHumanAudit(ctx context.Context, tx pgx.Tx, issuer, subject, clusterID, action, role, privilege string, revision int64, actor string, at time.Time) error {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	id := "human-audit-" + hex.EncodeToString(random[:])
	var cluster any
	if clusterID != "" {
		cluster = clusterID
	}
	_, err := tx.Exec(ctx, `INSERT INTO human_authorization_audit_events(event_id,issuer,subject,cluster_id,action,role,privilege,revision,actor_subject,occurred_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, issuer, subject, cluster, action, role, privilege, revision, actor, at)
	if err != nil {
		return fmt.Errorf("record human authorization audit: %w", err)
	}
	return nil
}
