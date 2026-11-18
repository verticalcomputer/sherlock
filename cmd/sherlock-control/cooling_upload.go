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
	profile, hash, err := config.LoadCoolingUploadProfile()
	if err != nil {
		logger.Warn("control.cooling_upload_disabled", "reason", "invalid optional profile")
		return base
	}
	if hash == "" {
		return base
	}
	if !coolingUploadScopeAllowed(profile, scope) {
		logger.Warn("control.cooling_upload_disabled", "reason", "profile outside intake scope")
		return base
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := store.RegisterCoolingUploadProfile(bounded, profile, hash); err != nil {
		logger.Warn("control.cooling_upload_disabled", "reason", "profile admission rejected")
		return base
	}
	cooling, err := collectorcontrol.NewCoolingUploadHandler(identity, auth, store, clock, profile, hash)
	if err != nil {
		logger.Warn("control.cooling_upload_disabled", "reason", "profile handler rejected")
		return base
	}
	mux := http.NewServeMux()
	mux.Handle(domain.CoolingUploadPath, cooling)
	mux.Handle("/", base)
	logger.Info("control.cooling_upload_configured", "profile", profile.ProfileID, "revision", profile.Revision)
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
