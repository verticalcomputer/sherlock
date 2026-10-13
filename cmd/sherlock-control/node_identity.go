package main

import (
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/nodeidentity"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetrylocal"
)

func configureNodeIdentity(cfg config.Control, transport *collectorcontrol.Transport, store *storepg.TelemetryStore) error {
	var issuer *nodeidentity.Issuer
	if cfg.NodeCA != "" || cfg.NodeCAPrivateKey != "" {
		ca, e := telemetrylocal.ReadProtected(cfg.NodeCA, nodeidentity.MaxPEMBytes)
		if e != nil {
			return e
		}
		key, e := telemetrylocal.ReadProtected(cfg.NodeCAPrivateKey, nodeidentity.MaxPEMBytes)
		if e != nil {
			return e
		}
		defer clear(key)
		issuer, e = nodeidentity.NewIssuer(string(ca), string(key))
		if e != nil {
			return telemetry.ErrInvalid
		}
		// Compare actual CA public material, rather than path strings. The node CA
		// must not issue collector certificates or the control server identity.
		collector, e := telemetrylocal.ReadProtected(cfg.CollectorCA, 64<<10)
		if e != nil {
			return e
		}
		nodeChain, e := nodeidentity.ParseCertificateChain(ca)
		if e != nil || len(nodeChain) != 1 {
			return telemetry.ErrInvalid
		}
		collectorChain, e := nodeidentity.ParseCertificateChain(collector)
		if e != nil || nodeidentity.ValidateCASeparation(nodeChain[0], collectorChain) != nil {
			return telemetry.ErrInvalid
		}
		server, e := telemetrylocal.ReadProtected(cfg.ServerCertificate, 64<<10)
		if e != nil {
			return e
		}
		serverChain, e := nodeidentity.ParseCertificateChain(server)
		if e != nil || nodeidentity.ValidateCASeparation(nodeChain[0], serverChain) != nil {
			return telemetry.ErrInvalid
		}
	}
	return transport.ConfigureNodeIdentity(store, issuer)
}
