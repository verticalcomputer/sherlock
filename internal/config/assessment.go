package config

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

// Assessment is optional. Invalid settings disable only this component; its
// dedicated URL is never populated from the control server's database setting.
type Assessment struct {
	Mode        string
	DatabaseURL string
	ConfigFile  string
	Invalid     bool
}

func (c Assessment) String() string {
	return fmt.Sprintf("assessment{mode=%s,invalid=%t}", c.Mode, c.Invalid)
}
func LoadAssessment() Assessment {
	mode := strings.TrimSpace(os.Getenv("SHERLOCK_ASSESSMENT_MODE"))
	if mode == "" {
		mode = "disabled"
	}
	c := Assessment{Mode: mode}
	if mode == "disabled" {
		return c
	}
	if mode != "shadow" {
		c.Invalid = true
		return c
	}
	c.DatabaseURL = os.Getenv("SHERLOCK_ASSESSMENT_DATABASE_URL")
	c.ConfigFile = os.Getenv("SHERLOCK_ASSESSMENT_CONFIG_FILE")
	c.Invalid = c.DatabaseURL == "" || c.ConfigFile == ""
	return c
}
func (c Assessment) Read(ctx context.Context, registry *a.Registry) (a.Config, error) {
	if c.Mode != "shadow" || c.Invalid {
		return a.Config{}, fmt.Errorf("assessment configuration invalid")
	}
	info, err := os.Lstat(c.ConfigFile)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return a.Config{}, fmt.Errorf("assessment configuration file invalid")
	}
	f, err := os.Open(c.ConfigFile)
	if err != nil {
		return a.Config{}, fmt.Errorf("assessment configuration unreadable")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return a.Config{}, fmt.Errorf("assessment configuration changed")
	}
	body, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return a.Config{}, fmt.Errorf("assessment configuration unreadable")
	}
	cfg, err := a.ParseConfig(ctx, body, registry)
	if err != nil {
		// An existing pinned run may need host-only expiry after a rollback to
		// a binary without its codec. The store permits this shape-only path
		// solely for an exact match to the persisted configuration/descriptor.
		cfg, err = a.ParseRecoveryConfig(body)
		if err != nil {
			return a.Config{}, fmt.Errorf("assessment configuration contract invalid")
		}
	}
	return cfg, nil
}
