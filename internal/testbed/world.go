package testbed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationcontext"
	"github.com/verticalcomputer/sherlock/internal/investigationtools"

	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// These tables belong only to the disposable lab, never to production migrations.
func Setup(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS testbed_worlds (investigation_id text PRIMARY KEY, world jsonb NOT NULL);
 CREATE TABLE IF NOT EXISTS testbed_evidence (evidence_id text PRIMARY KEY, investigation_id text NOT NULL, role text NOT NULL, available_after integer NOT NULL, projection jsonb NOT NULL);
 CREATE TABLE IF NOT EXISTS testbed_requests (investigation_id text NOT NULL, kind text NOT NULL, turn integer NOT NULL, payload jsonb NOT NULL, PRIMARY KEY(investigation_id,kind,turn));
 CREATE TABLE IF NOT EXISTS testbed_workers (investigation_id text NOT NULL, process_id bigint NOT NULL, PRIMARY KEY(investigation_id,process_id));
 CREATE TABLE IF NOT EXISTS testbed_effects (idempotency_key text PRIMARY KEY, investigation_id text NOT NULL, action_digest bytea NOT NULL, replay_count integer NOT NULL DEFAULT 0, result jsonb NOT NULL);
 CREATE TABLE IF NOT EXISTS testbed_pipeline_inputs (prefix text PRIMARY KEY, observed_at timestamptz NOT NULL);
 CREATE TABLE IF NOT EXISTS testbed_pipeline_workers (prefix text NOT NULL, boundary text NOT NULL, process_id bigint NOT NULL, PRIMARY KEY(prefix,boundary));
 CREATE TABLE IF NOT EXISTS testbed_crashes (prefix text NOT NULL, boundary text NOT NULL, process_id bigint NOT NULL, PRIMARY KEY(prefix,boundary));`)
	return err
}

type worldAdapter struct {
	pool *pgxpool.Pool
	id   domain.InvestigationID
}

func (w worldAdapter) LoadInvestigationEvidenceContext(ctx context.Context, snapshot application.InvestigationSnapshot) ([]investigationcontext.EvidenceInput, error) {
	var out []investigationcontext.EvidenceInput
	for _, entry := range snapshot.Evidence.Entries() {
		var raw []byte
		if err := w.pool.QueryRow(ctx, `SELECT projection FROM testbed_evidence WHERE evidence_id=$1 AND investigation_id=$2`, entry.EvidenceID, snapshot.Investigation.Request().ID).Scan(&raw); err != nil {
			return nil, err
		}
		var value investigationcontext.EvidenceInput
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, err
		}
		// Scope/cluster/time facts are independently enforced by SelectEvidence.
		out = append(out, value)
	}
	return out, nil
}
func (w worldAdapter) ExecuteInvestigationAction(ctx context.Context, key string, action domain.InvestigationAction) (application.InvestigationExecutionResult, error) {
	rawAction, err := json.Marshal(action)
	if err != nil {
		return application.InvestigationExecutionResult{}, err
	}
	digest := domain.ChecksumSHA256(rawAction)
	var prior, priorDigest []byte
	err = w.pool.QueryRow(ctx, `SELECT result,action_digest FROM testbed_effects WHERE idempotency_key=$1 AND investigation_id=$2`, key, w.id).Scan(&prior, &priorDigest)
	if err == nil {
		if !bytes.Equal(priorDigest, digest[:]) {
			return application.InvestigationExecutionResult{}, fmt.Errorf("simulator replay identity changed")
		}
		var out application.InvestigationExecutionResult
		err = json.Unmarshal(prior, &out)
		if err == nil {
			_, err = w.pool.Exec(ctx, `UPDATE testbed_effects SET replay_count=replay_count+1 WHERE idempotency_key=$1 AND investigation_id=$2`, key, w.id)
		}
		return out, err
	}
	// Missing rows are the only admissible replay miss.
	if !isNoRows(err) {
		return application.InvestigationExecutionResult{}, err
	}
	store, err := storepg.NewInvestigationStore(w.pool)
	if err != nil {
		return application.InvestigationExecutionResult{}, err
	}
	snapshot, found, err := store.LoadInvestigation(ctx, w.id)
	if err != nil || !found {
		return application.InvestigationExecutionResult{}, fmt.Errorf("world investigation unavailable: %w", err)
	}
	role := "PRIMARY"
	if action.ToolID == "node.detail.v1" {
		role = "DETAIL"
	} else if slices.Contains(investigationtools.XIDRequiredEvidenceTools(), investigationtools.ToolID(action.ToolID)) {
		role = action.ToolID
	} else if action.ToolID != "evidence.lookup.v1" {
		return application.InvestigationExecutionResult{}, fmt.Errorf("unsupported simulator tool")
	}
	if !slices.Equal(action.Targets, snapshot.Investigation.Request().Scope.EntityIDs) || action.Start.Before(snapshot.Investigation.Request().Scope.Start) || action.End.After(snapshot.Investigation.Request().Scope.End) {
		return application.InvestigationExecutionResult{}, fmt.Errorf("simulator scope mismatch")
	}
	rows, err := w.pool.Query(ctx, `SELECT projection FROM testbed_evidence WHERE investigation_id=$1 AND role=$2 AND available_after <= $3 ORDER BY evidence_id`, w.id, role, len(snapshot.PriorActions))
	if err != nil {
		return application.InvestigationExecutionResult{}, err
	}
	defer rows.Close()
	result := application.InvestigationExecutionResult{Receipt: "simulated:" + key}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return result, err
		}
		var input investigationcontext.EvidenceInput
		if err = json.Unmarshal(raw, &input); err != nil {
			return result, err
		}
		if input.ObservedFrom.Before(action.Start) || input.ObservedTo.After(action.End) || input.CommittedAt.After(snapshot.Investigation.Request().RequestedAt) {
			continue
		}
		result.Evidence = append(result.Evidence, domain.InvestigationEvidence{EvidenceID: input.EvidenceID, InvestigationID: w.id, ClusterID: input.ClusterID, EntityIDs: slices.Clone(input.EntityIDs), Status: input.Status, ObservedStart: input.ObservedFrom, ObservedEnd: input.ObservedTo, RecordedAt: input.CollectedAt})
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	if action.Diagnostic {
		binding, ok := investigationtools.DiagnosticBindingForTool(investigationtools.ToolID(action.ToolID))
		if !ok {
			return result, fmt.Errorf("unknown simulated diagnostic")
		}
		if err := w.pool.QueryRow(ctx, `SELECT run_id FROM diagnostic_runs WHERE cluster_id=$1 AND definition_id=$2 AND pack_id='testbed-unavailable' AND status='FAILED'`, snapshot.Investigation.Request().ClusterID, binding.DefinitionID).Scan(&result.DiagnosticRunID); err != nil {
			return result, err
		}
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return result, err
	}
	_, err = w.pool.Exec(ctx, `INSERT INTO testbed_effects(idempotency_key,investigation_id,action_digest,result) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, key, w.id, digest[:], raw)
	return result, err
}
func logicalID(id, prefix string) string {
	if prefix == "" {
		return id
	}
	return strings.TrimPrefix(id, prefix+"-")
}
func physicalID(id, prefix string) domain.EvidenceID {
	if prefix == "" {
		return domain.EvidenceID(id)
	}
	return domain.EvidenceID(prefix + "-" + id)
}
