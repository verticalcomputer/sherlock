package config

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

// AssessmentProduction has dedicated credentials and is read only by the
// explicitly selected production assessment command. It never falls back to
// the general control or restricted shadow database role.
type AssessmentProduction struct{ DatabaseURL, ConfigFile string }

func (AssessmentProduction) String() string { return "assessment-production{dedicated configuration}" }
func LoadAssessmentProduction() (AssessmentProduction, error) {
	c := AssessmentProduction{os.Getenv("SHERLOCK_PRODUCTION_ASSESSMENT_DATABASE_URL"), os.Getenv("SHERLOCK_PRODUCTION_ASSESSMENT_CONFIG_FILE")}
	if strings.TrimSpace(c.DatabaseURL) == "" || strings.TrimSpace(c.ConfigFile) == "" {
		return c, errors.New("dedicated production assessment configuration is required")
	}
	if mode := strings.TrimSpace(os.Getenv("SHERLOCK_ASSESSMENT_MODE")); mode != "" && mode != "disabled" {
		return c, errors.New("production command cannot also enroll a shadow run")
	}
	return c, nil
}
func (c AssessmentProduction) Read(ctx context.Context, r *a.Registry) (a.ProductionConfig, error) {
	info, err := os.Lstat(c.ConfigFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 64<<10 {
		return a.ProductionConfig{}, errors.New("production configuration must be a private regular file")
	}
	f, err := os.Open(c.ConfigFile)
	if err != nil {
		return a.ProductionConfig{}, errors.New("production configuration unavailable")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return a.ProductionConfig{}, errors.New("production configuration changed")
	}
	b, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return a.ProductionConfig{}, errors.New("production configuration unreadable")
	}
	cfg, err := a.ParseProductionConfig(ctx, b, r)
	if err != nil {
		return a.ProductionConfig{}, errors.New("production configuration contract invalid")
	}
	return cfg, nil
}
