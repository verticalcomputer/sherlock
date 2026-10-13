package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type humanCommand struct {
	Action    string
	Principal auth.HumanPrincipal
	ClusterID domain.ClusterID
	Role      auth.HumanRole
	Privilege auth.HumanPrivilege
	Actor     string
}

func parseHumanCommand(arguments []string) (humanCommand, error) {
	if len(arguments) == 0 {
		return humanCommand{}, fmt.Errorf("human authorization action is required")
	}
	command := humanCommand{Action: arguments[0]}
	switch command.Action {
	case "grant-membership", "revoke-membership", "show-membership", "grant-privilege", "revoke-privilege", "show-privilege", "grant-platform", "revoke-platform", "show-platform":
	default:
		return humanCommand{}, fmt.Errorf("unknown human authorization action")
	}
	flags := flag.NewFlagSet("human-auth "+command.Action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	issuer := flags.String("issuer", "", "verified Access issuer")
	subject := flags.String("subject", "", "verified Access subject")
	cluster := flags.String("cluster", "", "cluster identifier")
	role := flags.String("role", "", "cluster role")
	privilege := flags.String("privilege", "", "separate privilege")
	actor := flags.String("actor", "", "operator subject")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 {
		return humanCommand{}, fmt.Errorf("invalid human authorization flags")
	}
	command.Principal = auth.HumanPrincipal{Issuer: strings.TrimSpace(*issuer), Subject: strings.TrimSpace(*subject)}
	if command.Principal.Validate() != nil {
		return humanCommand{}, fmt.Errorf("invalid human principal")
	}
	command.ClusterID, command.Role, command.Privilege, command.Actor = domain.ClusterID(*cluster), auth.HumanRole(*role), auth.HumanPrivilege(*privilege), *actor
	mutation := strings.HasPrefix(command.Action, "grant-") || strings.HasPrefix(command.Action, "revoke-")
	if mutation && !validAccessSubjectCLI(command.Actor) || !mutation && command.Actor != "" {
		return humanCommand{}, fmt.Errorf("operator subject is invalid")
	}
	clusterAction := strings.Contains(command.Action, "membership") || strings.Contains(command.Action, "privilege")
	if clusterAction && !validIdentifier(*cluster) || !clusterAction && *cluster != "" {
		return humanCommand{}, fmt.Errorf("cluster scope is invalid")
	}
	if command.Action == "grant-membership" {
		if !command.Role.Valid() || command.Privilege != "" {
			return humanCommand{}, fmt.Errorf("membership role is invalid")
		}
	} else if command.Role != "" {
		return humanCommand{}, fmt.Errorf("role is only valid for membership grant")
	}
	if strings.Contains(command.Action, "privilege") {
		if !command.Privilege.Valid() {
			return humanCommand{}, fmt.Errorf("privilege is invalid")
		}
	} else if command.Privilege != "" {
		return humanCommand{}, fmt.Errorf("privilege is not valid for action")
	}
	return command, nil
}

func administerHuman(ctx context.Context, databaseURL string, command humanCommand, stdout io.Writer) error {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	store, err := adminmanage.NewPostgresStore(pool)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	switch command.Action {
	case "grant-membership":
		member, err := store.GrantHumanMembership(ctx, adminmanage.HumanMembershipGrant{Principal: command.Principal, ClusterID: command.ClusterID, Role: command.Role, Actor: command.Actor, At: now})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "%s\t%s\t%s\t%d\tACTIVE\n", member.Subject, member.ClusterID, member.Role, member.Revision)
		return err
	case "revoke-membership":
		return store.RevokeHumanMembership(ctx, command.Principal, command.ClusterID, command.Actor, now)
	case "show-membership":
		member, err := store.HumanMembership(ctx, command.Principal, command.ClusterID)
		if err != nil {
			return err
		}
		status := "ACTIVE"
		if member.RevokedAt != nil {
			status = "REVOKED"
		}
		_, err = fmt.Fprintf(stdout, "%s\t%s\t%s\t%d\t%s\n", member.Subject, member.ClusterID, member.Role, member.Revision, status)
		return err
	case "grant-privilege":
		grant, err := store.GrantHumanPrivilege(ctx, command.Principal, command.ClusterID, command.Privilege, command.Actor, now)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "%s\t%s\t%s\t%d\tACTIVE\n", grant.Subject, grant.ClusterID, grant.Privilege, grant.Revision)
		return err
	case "revoke-privilege":
		return store.RevokeHumanPrivilege(ctx, command.Principal, command.ClusterID, command.Privilege, command.Actor, now)
	case "show-privilege":
		grant, err := store.HumanPrivilege(ctx, command.Principal, command.ClusterID, command.Privilege)
		if err != nil {
			return err
		}
		status := "ACTIVE"
		if grant.RevokedAt != nil {
			status = "REVOKED"
		}
		_, err = fmt.Fprintf(stdout, "%s\t%s\t%s\t%d\t%s\n", grant.Subject, grant.ClusterID, grant.Privilege, grant.Revision, status)
		return err
	case "grant-platform":
		grant, err := store.GrantHumanPlatformAdmin(ctx, command.Principal, command.Actor, now)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "%s\tPLATFORM_ADMIN\t%d\tACTIVE\n", grant.Subject, grant.Revision)
		return err
	case "revoke-platform":
		return store.RevokeHumanPlatformAdmin(ctx, command.Principal, command.Actor, now)
	case "show-platform":
		grant, err := store.HumanPlatformAdmin(ctx, command.Principal)
		if err != nil {
			return err
		}
		status := "ACTIVE"
		if grant.RevokedAt != nil {
			status = "REVOKED"
		}
		_, err = fmt.Fprintf(stdout, "%s\tPLATFORM_ADMIN\t%d\t%s\n", grant.Subject, grant.Revision, status)
		return err
	default:
		return fmt.Errorf("unknown human authorization action")
	}
}
