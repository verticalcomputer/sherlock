package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/slurmfailures"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

type slurmFailureCommand struct {
	action, actor string
	policy        slurmfailures.Policy
	revision      int64
}

func parseSlurmFailureCommand(args []string) (slurmFailureCommand, error) {
	c := slurmFailureCommand{}
	if len(args) == 0 {
		return c, errors.New("slurm failure action required")
	}
	c.action = args[0]
	f := flag.NewFlagSet("slurm-failures", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	cluster := f.String("cluster", "", "exact cluster")
	id := f.String("policy-id", "", "immutable policy ID")
	f.StringVar(&c.actor, "actor", "", "local operator audit attribution, not authentication")
	f.Int64Var(&c.revision, "expected-revision", -1, "zero creates; existing revision enables or disables")
	source := f.String("source", "", "enrolled Slurm source")
	namespace := f.String("namespace", "", "exact scheduler namespace")
	node := f.String("node", "", "optional stable node ID")
	threshold := f.Int("threshold", 3, "distinct failed attempts")
	window := f.Duration("window", 30*time.Minute, "rolling failure window")
	fresh := f.Duration("fresh-for", 5*time.Minute, "accounting freshness")
	if err := uniqueMonitoringFlags(args[1:], f); err != nil {
		return c, err
	}
	if err := f.Parse(args[1:]); err != nil || f.NArg() != 0 {
		return c, errors.New("invalid Slurm failure flags")
	}
	allowed := map[string]bool{"cluster": true, "policy-id": true}
	switch c.action {
	case "enroll":
		for _, name := range []string{"actor", "expected-revision", "source", "namespace", "node", "threshold", "window", "fresh-for"} {
			allowed[name] = true
		}
	case "disable":
		allowed["actor"], allowed["expected-revision"] = true, true
	case "status":
	default:
		return c, errors.New("unknown Slurm failure action")
	}
	bad := false
	f.Visit(func(v *flag.Flag) {
		if !allowed[v.Name] {
			bad = true
		}
	})
	if bad || !slurmfailures.Token(*cluster) || !slurmfailures.Token(*id) {
		return c, errors.New("invalid Slurm failure scope")
	}
	c.policy = slurmfailures.Policy{ID: *id, ClusterID: domain.ClusterID(*cluster), SourceID: domain.SourceID(*source), SchedulerNamespace: domain.SchedulerNamespace(*namespace), NodeID: domain.StableNodeID(*node), Threshold: *threshold, WindowSeconds: int(*window / time.Second), FreshForSeconds: int(*fresh / time.Second)}
	if c.action != "status" && (!slurmfailures.Token(c.actor) || c.revision < 0) {
		return c, errors.New("explicit actor and expected revision required")
	}
	if c.action == "disable" && c.revision < 1 {
		return c, errors.New("existing revision required")
	}
	if c.action == "enroll" {
		if *window%time.Second != 0 || *fresh%time.Second != 0 {
			return c, errors.New("whole-second intervals required")
		}
		if err := c.policy.Validate(); err != nil {
			return c, err
		}
	}
	return c, nil
}
func runSlurmFailureAdmin(args []string, out, stderr io.Writer) int {
	c, err := parseSlurmFailureCommand(args)
	if err != nil {
		fmt.Fprintln(stderr, "usage: sherlock-admin slurm-failures enroll|status|disable --cluster <id> --policy-id <id> [--source <id> --namespace <id> --node <id> --threshold 3 --window 30m --fresh-for 5m] [--expected-revision <n> --actor <local-operator>]")
		return 2
	}
	cfg, err := config.LoadControlAdmin()
	if err != nil {
		fmt.Fprintln(stderr, "invalid admin configuration")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintln(stderr, "Slurm monitoring database unavailable")
		return 1
	}
	defer pool.Close()
	store := storepg.NewSlurmFailureStore(pool)
	var status storepg.SlurmFailureStatus
	switch c.action {
	case "enroll":
		status, err = store.Enroll(ctx, c.policy, c.revision, c.actor)
	case "disable":
		err = store.Disable(ctx, c.policy.ClusterID, c.policy.ID, c.revision, c.actor)
		if err == nil {
			status, err = store.Status(ctx, c.policy.ClusterID, c.policy.ID)
		}
	case "status":
		status, err = store.Status(ctx, c.policy.ClusterID, c.policy.ID)
	}
	if err != nil {
		code := "Slurm monitoring command failed"
		if errors.Is(err, storepg.ErrMonitoringRevision) {
			code = "Slurm monitoring revision conflict"
		}
		if errors.Is(err, storepg.ErrMonitoringPolicyConflict) {
			code = "Slurm policy content is immutable; use a new policy ID"
		}
		fmt.Fprintln(stderr, code)
		return 1
	}
	if err = json.NewEncoder(out).Encode(status); err != nil {
		return 1
	}
	return 0
}
