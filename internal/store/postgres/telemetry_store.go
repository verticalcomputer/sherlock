package postgres

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

type TelemetryStore struct{ pool *pgxpool.Pool }

func NewTelemetryStore(pool *pgxpool.Pool) *TelemetryStore { return &TelemetryStore{pool: pool} }

// EnrollmentRequest is protected local operator input. All semantic scope is
// immutable; control revisions fence rotation/revocation, not owned signatures.
// Public key is canonical unpadded base64. No private key or cloud secret enters.
type EnrollmentRequest struct {
	EnrollmentID        string              `json:"enrollment_id"`
	ClusterID           domain.ClusterID    `json:"cluster_id"`
	NodeID              domain.StableNodeID `json:"node_id"`
	InventoryRevisionID string              `json:"inventory_revision_id"`
	SourceIDs           []domain.SourceID   `json:"source_ids"`
	GatewayCollectorID  domain.CollectorID  `json:"gateway_collector_id"`
	PublicKeyBase64     string              `json:"public_key_base64"`
	KeyID               string              `json:"key_id"`
	GatewaySPKISHA256   string              `json:"gateway_spki_sha256"`
	AgentVersion        string              `json:"agent_version"`
	BuildSHA256         string              `json:"build_sha256"`
}

func telemetrySafeError(err error) error {
	if err == nil {
		return nil
	}
	for _, safe := range []error{context.Canceled, context.DeadlineExceeded, telemetry.ErrInvalid, telemetry.ErrUnauthorized, telemetry.ErrConflict, telemetry.ErrBackpressure, telemetry.ErrReplayExpired} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	if errors.Is(err, telemetry.ErrSignature) {
		return telemetry.ErrUnauthorized
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return telemetry.ErrUnauthorized
	}
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) && pgerr.Code == "23505" {
		return telemetry.ErrConflict
	}
	return telemetry.ErrUnavailable
}
func beginTelemetryTx(ctx context.Context, pool *pgxpool.Pool) (pgx.Tx, error) {
	// Enrollment row locks serialize every intake/control mutation and keep
	// bounded Status/Grant reads stable. READ COMMITTED is essential after an
	// inventory advisory-lock wait: the next query must see the writer's commit.
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout='1s'; SET LOCAL lock_timeout='250ms'`); err != nil {
		rollbackMonitoringTx(tx)
		return nil, err
	}
	return tx, nil
}

func (s *TelemetryStore) CreateEnrollment(ctx context.Context, request EnrollmentRequest, expectedRevision int64, actor string) (grant telemetry.Grant, err error) {
	defer func() { err = telemetrySafeError(err) }()
	if expectedRevision != 0 || !monitoringID(actor, 128) || len(request.SourceIDs) < 1 || len(request.SourceIDs) > telemetry.MaxSources {
		return grant, telemetry.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := beginTelemetryTx(ctx, s.pool)
	if err != nil {
		return grant, err
	}
	defer rollbackMonitoringTx(tx)
	var at time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return grant, err
	}
	grant = telemetry.Grant{ProtocolVersion: 1, EnrollmentID: request.EnrollmentID, EnrollmentRevision: 1, ControlRevision: 1, Status: "ACTIVE", ClusterID: string(request.ClusterID), NodeID: string(request.NodeID), InventoryRevisionID: request.InventoryRevisionID, GatewayCollectorID: string(request.GatewayCollectorID), AgentVersion: request.AgentVersion, BuildSHA256: request.BuildSHA256, GatewaySPKISHA256: request.GatewaySPKISHA256, NotBefore: at, NotAfter: at.Add(telemetry.GrantLease), Keys: []telemetry.NodeKey{{ID: request.KeyID, Epoch: "1", PublicKeyBase64: request.PublicKeyBase64, State: "ACTIVE"}}}
	for _, source := range request.SourceIDs {
		grant.Sources = append(grant.Sources, telemetry.SourceGrant{SourceID: string(source), SchemaVersion: 1, ProfileID: telemetry.FixtureProfile})
	}
	sort.Slice(grant.Sources, func(i, j int) bool { return grant.Sources[i].SourceID < grant.Sources[j].SourceID })
	if telemetry.ValidateGrant(grant, at) != nil {
		return grant, telemetry.ErrInvalid
	}
	// Idempotent retry compares immutable scope/key; a revoked ID cannot regain
	// authority through an expected-zero create. Never adopt old journals.
	var existing string
	scanerr := tx.QueryRow(ctx, `SELECT enrollment_id FROM gp06f_telemetry_enrollments WHERE enrollment_id=$1 FOR UPDATE`, grant.EnrollmentID).Scan(&existing)
	if scanerr == nil {
		old, e := loadTelemetryGrant(ctx, tx, request.ClusterID, request.GatewayCollectorID, grant.EnrollmentID, at, false)
		if e != nil {
			return grant, e
		}
		a, b := old, grant
		a.NotBefore = time.Time{}
		a.NotAfter = time.Time{}
		b.NotBefore = time.Time{}
		b.NotAfter = time.Time{}
		aj, _ := json.Marshal(a)
		bj, _ := json.Marshal(b)
		if string(aj) != string(bj) {
			return grant, telemetry.ErrConflict
		}
		return old, tx.Commit(ctx)
	}
	if !errors.Is(scanerr, pgx.ErrNoRows) {
		return grant, scanerr
	}
	if err = validateTelemetryAuthority(ctx, tx, grant, at); err != nil {
		return grant, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO gp06f_telemetry_enrollments(enrollment_id,cluster_id,node_id,inventory_revision_id,gateway_collector_id,agent_version,build_sha256,gateway_spki_sha256,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, grant.EnrollmentID, grant.ClusterID, grant.NodeID, grant.InventoryRevisionID, grant.GatewayCollectorID, grant.AgentVersion, grant.BuildSHA256, grant.GatewaySPKISHA256, at)
	if err != nil {
		return grant, err
	}
	for _, source := range grant.Sources {
		if _, err = tx.Exec(ctx, `INSERT INTO gp06f_telemetry_sources(cluster_id,enrollment_id,source_id,schema_version,profile_id) VALUES($1,$2,$3,$4,$5)`, grant.ClusterID, grant.EnrollmentID, source.SourceID, source.SchemaVersion, source.ProfileID); err != nil {
			return grant, err
		}
	}
	public, _ := base64.RawStdEncoding.DecodeString(request.PublicKeyBase64)
	if _, err = tx.Exec(ctx, `INSERT INTO gp06f_telemetry_keys(enrollment_id,key_id,key_epoch,public_key,state,created_at) VALUES($1,$2,1,$3,'ACTIVE',$4)`, grant.EnrollmentID, request.KeyID, public, at); err != nil {
		return grant, err
	}
	if err = telemetryAudit(ctx, tx, grant.EnrollmentID, 1, "ENROLLED", actor, map[string]any{"source_count": len(grant.Sources), "profile": telemetry.FixtureProfile}, at); err != nil {
		return grant, err
	}
	return grant, tx.Commit(ctx)
}
func telemetryAudit(ctx context.Context, tx pgx.Tx, id string, revision int64, action, actor string, details any, at time.Time) error {
	body, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO gp06f_telemetry_audit(enrollment_id,control_revision,action,actor,details,occurred_at) VALUES($1,$2,$3,$4,$5,$6)`, id, revision, action, actor, body, at)
	return err
}

func (s *TelemetryStore) Grant(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, id string) (out telemetry.Grant, err error) {
	defer func() { err = telemetrySafeError(err) }()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := beginTelemetryTx(ctx, s.pool)
	if err != nil {
		return out, err
	}
	defer rollbackMonitoringTx(tx)
	var at time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return out, err
	}
	out, err = loadTelemetryGrant(ctx, tx, cluster, collector, id, at, false)
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

func loadTelemetryGrant(ctx context.Context, tx pgx.Tx, cluster domain.ClusterID, collector domain.CollectorID, id string, at time.Time, write bool) (out telemetry.Grant, err error) {
	lock := " FOR SHARE"
	if write {
		lock = " FOR UPDATE"
	}
	err = tx.QueryRow(ctx, `SELECT enrollment_id,cluster_id,node_id,inventory_revision_id,gateway_collector_id,enrollment_revision,control_revision,status,agent_version,build_sha256,gateway_spki_sha256 FROM gp06f_telemetry_enrollments WHERE cluster_id=$1 AND gateway_collector_id=$2 AND enrollment_id=$3`+lock, cluster, collector, id).Scan(&out.EnrollmentID, &out.ClusterID, &out.NodeID, &out.InventoryRevisionID, &out.GatewayCollectorID, &out.EnrollmentRevision, &out.ControlRevision, &out.Status, &out.AgentVersion, &out.BuildSHA256, &out.GatewaySPKISHA256)
	if err != nil {
		return out, err
	}
	out.ProtocolVersion = 1
	out.NotBefore = at
	out.NotAfter = at.Add(telemetry.GrantLease)
	rows, err := tx.Query(ctx, `SELECT source_id,schema_version,profile_id FROM gp06f_telemetry_sources WHERE enrollment_id=$1 ORDER BY source_id LIMIT 17`, id)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var source telemetry.SourceGrant
		if err = rows.Scan(&source.SourceID, &source.SchemaVersion, &source.ProfileID); err != nil {
			rows.Close()
			return out, err
		}
		out.Sources = append(out.Sources, source)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	rows, err = tx.Query(ctx, `SELECT key_id,key_epoch::text,public_key,state FROM gp06f_telemetry_keys WHERE enrollment_id=$1 AND archived_at IS NULL ORDER BY key_epoch LIMIT 3`, id)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var key telemetry.NodeKey
		var public []byte
		if err = rows.Scan(&key.ID, &key.Epoch, &public, &key.State); err != nil {
			rows.Close()
			return out, err
		}
		key.PublicKeyBase64 = base64.RawStdEncoding.EncodeToString(public)
		out.Keys = append(out.Keys, key)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if out.Status != "ACTIVE" {
		return out, telemetry.ErrUnauthorized
	}
	if telemetry.ValidateGrant(out, at) != nil {
		return out, telemetry.ErrUnauthorized
	}
	err = validateTelemetryAuthority(ctx, tx, out, at)
	return out, err
}

func telemetrySigningKey(g telemetry.Grant, id string) (telemetry.NodeKey, ed25519.PublicKey, error) {
	for _, key := range g.Keys {
		if key.ID == id && key.State != "REVOKED" {
			public, err := telemetry.ParseNodePublicKey(key)
			return key, public, err
		}
	}
	return telemetry.NodeKey{}, nil, telemetry.ErrUnauthorized
}

func retryTelemetryTransaction(ctx context.Context, operation func() error) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err = operation()
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || (pgerr.Code != "40001" && pgerr.Code != "23505") {
			return err
		}
	}
	return err
}
