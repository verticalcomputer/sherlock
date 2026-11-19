package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"io"
	"os"
	"time"
)

type assessmentCommand struct {
	Action, Cluster, Enrollment, Occurrence, Actor, Reason string
	Version, Seconds, After, Audit                         int64
}

func parseAssessmentCommand(args []string) (assessmentCommand, error) {
	var c assessmentCommand
	if len(args) == 0 {
		return c, errors.New("assessment action required")
	}
	c.Action = args[0]
	f := flag.NewFlagSet("assessment", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&c.Cluster, "cluster", "", "")
	f.StringVar(&c.Enrollment, "enrollment", "", "")
	f.StringVar(&c.Occurrence, "occurrence", "", "")
	f.StringVar(&c.Actor, "actor", "", "")
	f.StringVar(&c.Reason, "reason", "", "")
	f.Int64Var(&c.Version, "expected-version", 0, "")
	f.Int64Var(&c.Seconds, "seconds", -1, "")
	f.Int64Var(&c.After, "after", 0, "")
	f.Int64Var(&c.Audit, "after-audit", 0, "")
	if err := uniqueMonitoringFlags(args[1:], f); err != nil {
		return c, errors.New("duplicate or invalid assessment flags")
	}
	if err := f.Parse(args[1:]); err != nil || f.NArg() != 0 {
		return c, errors.New("invalid assessment arguments")
	}
	allowed := map[string]bool{"cluster": true, "enrollment": true}
	switch c.Action {
	case "status":
	case "history":
		allowed["occurrence"] = true
		allowed["after"] = true
		allowed["after-audit"] = true
	case "acknowledge", "maintenance":
		allowed["occurrence"] = true
		allowed["actor"] = true
		allowed["expected-version"] = true
		if c.Action == "maintenance" {
			allowed["seconds"] = true
			allowed["reason"] = true
		}
	case "disable-notifications":
		allowed["actor"] = true
		allowed["expected-version"] = true
	default:
		return c, errors.New("unsupported assessment action")
	}
	invalid := false
	f.Visit(func(f *flag.Flag) {
		if !allowed[f.Name] {
			invalid = true
		}
	})
	if invalid || !a.ValidID(c.Cluster, 128) || !a.ValidID(c.Enrollment, 128) || c.After < 0 || c.Audit < 0 {
		return c, errors.New("invalid assessment scope")
	}
	if c.Action != "disable-notifications" && c.Action != "status" && !a.ValidID(c.Occurrence, 128) {
		return c, errors.New("exact occurrence required")
	}
	if c.Action != "history" && c.Action != "status" && (!a.ValidID(c.Actor, 128) || c.Version < 1) {
		return c, errors.New("actor and expected version required")
	}
	if c.Action == "maintenance" && (c.Seconds < 0 || c.Seconds > 86400 || len(c.Reason) == 0 || len(c.Reason) > 512) {
		return c, errors.New("maintenance requires reason and seconds in 0..86400")
	}
	return c, nil
}
func runAssessmentAdmin(args []string, out, errout io.Writer) int {
	c, err := parseAssessmentCommand(args)
	if err != nil {
		fmt.Fprintln(errout, err)
		return 2
	}
	dsn := os.Getenv("SHERLOCK_PRODUCTION_ASSESSMENT_DATABASE_URL")
	if dsn == "" {
		fmt.Fprintln(errout, "dedicated production assessment database is required")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		fmt.Fprintln(errout, "invalid database configuration")
		return 1
	}
	pc.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		fmt.Fprintln(errout, "assessment store unavailable")
		return 1
	}
	defer pool.Close()
	s := storepg.NewProductionNotificationStore(pool)
	var result any
	switch c.Action {
	case "status":
		result, err = storepg.ReadProductionAssessmentStatus(ctx, pool, c.Cluster, c.Enrollment)
	case "history":
		result, err = s.HistoryPageWithAudit(ctx, c.Cluster, c.Enrollment, c.Occurrence, c.After, c.Audit)
	case "acknowledge":
		result, err = s.Acknowledge(ctx, c.Cluster, c.Enrollment, c.Occurrence, c.Version, c.Actor)
	case "maintenance":
		result, err = s.SetMaintenance(ctx, c.Cluster, c.Enrollment, c.Occurrence, c.Version, c.Actor, c.Reason, c.Seconds)
	case "disable-notifications":
		var version int64
		version, err = storepg.SetProductionAssessmentNotifications(ctx, pool, c.Cluster, c.Enrollment, c.Version, false, c.Actor)
		result = map[string]any{"revision": version, "notifications_enabled": false}
	}
	if err != nil {
		fmt.Fprintln(errout, "assessment operation rejected; reconcile scope/version and inspect local audit")
		return 1
	}
	if err = json.NewEncoder(out).Encode(result); err != nil {
		return 1
	}
	return 0
}
