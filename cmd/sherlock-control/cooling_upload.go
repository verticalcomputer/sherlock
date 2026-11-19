package main

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type coolingUploadStore interface {
	collectorcontrol.CoolingUploadStore
	RegisterCoolingUploadProfile(context.Context, domain.CoolingUploadProfile, string) error
}

// An optional cooling profile cannot widen the intake's existing collector
// allow-list. Failures disable only this endpoint, preserving V1 collection.
func configureCoolingUpload(ctx context.Context, base http.Handler, identity collectorcontrol.IdentityAuthenticator,
	auth collectorcontrol.RequestAuthenticator, store coolingUploadStore, clock collectorcontrol.Clock,
	scope config.PrometheusUploadScope, logger *slog.Logger) http.Handler {
	profiles, err := config.LoadCoolingUploadProfiles()
	if err != nil {
		logger.Warn("control.cooling_upload_disabled", "reason", "invalid optional profile")
		return base
	}
	if len(profiles) == 0 {
		return base
	}
	enrollments := make([]collectorcontrol.CoolingUploadEnrollment, 0, len(profiles))
	for _, p := range profiles {
		if !coolingUploadScopeAllowed(p.Profile, scope) {
			logger.Warn("control.cooling_upload_disabled", "reason", "profile outside intake scope")
			return base
		}
		enrollments = append(enrollments, collectorcontrol.CoolingUploadEnrollment{Profile: p.Profile, Hash: p.Hash})
	}
	// Validate the complete set before any registration; authentication and source
	// ownership are checked again by durable registration and each receipt.
	admitted := enrollments[:0]
	for _, e := range enrollments {
		// A stalled cluster cannot consume the other cluster's admission budget.
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := store.RegisterCoolingUploadProfile(bounded, e.Profile, e.Hash)
		cancel()
		if err != nil {
			logger.Warn("control.cooling_upload_disabled", "profile", e.Profile.ProfileID, "reason", "profile admission rejected")
			continue
		}
		admitted = append(admitted, e)
	}
	if len(admitted) == 0 {
		return base
	}
	cooling, err := collectorcontrol.NewSharedCoolingUploadHandler(identity, auth, store, clock, admitted)
	if err != nil {
		logger.Warn("control.cooling_upload_disabled", "reason", "profile handler rejected")
		return base
	}

	mux := http.NewServeMux()
	mux.Handle(domain.CoolingUploadPath, cooling)
	mux.Handle("/", base)
	for _, p := range admitted {
		logger.Info("control.cooling_upload_configured", "profile", p.Profile.ProfileID, "revision", p.Profile.Revision)
	}
	return mux
}

func coolingUploadScopeAllowed(p domain.CoolingUploadProfile, scope config.PrometheusUploadScope) bool {
	if len(scope.Bindings) == 0 {
		return string(p.CollectorID) == scope.CollectorID && string(p.ClusterID) == scope.ClusterID && string(p.SourceID) == scope.SourceID
	}
	for _, binding := range scope.Bindings {
		if binding.CollectorID == string(p.CollectorID) && binding.SourceID == string(p.SourceID) {
			return true
		}
	}
	return false
}
