package testbed

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationcontext"
	"github.com/verticalcomputer/sherlock/internal/investigationtools"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// Summaries and citations are derived from committed normalized observations and
// immutable production collection envelopes, never from expected outcomes.
func pipelineWorld(ctx context.Context, pool *pgxpool.Pool, prefix string, id domain.InvestigationID) (Scenario, error) {
	store, _ := storepg.NewInvestigationStore(pool)
	snapshot, found, err := store.LoadInvestigation(ctx, id)
	if err != nil || !found {
		return Scenario{}, fmt.Errorf("pipeline investigation unavailable: %w", err)
	}
	request := snapshot.Investigation.Request()
	s := Scenario{ID: "telemetry-incident-investigation-recovery", World: World{Question: request.Question, Start: request.Scope.Start, End: request.Scope.End}, Detection: DetectionInput{Kind: "not_exercised"}, Oracle: Oracle{ExpectedOutcome: "PARTIAL"}}
	evidenceStore, _ := storepg.NewEvidenceStore(pool)
	for i, q := range []domain.QueryKind{domain.QueryGPUXID, domain.QueryGPUTemperature} {
		var eid domain.EvidenceID
		var committed time.Time
		var metric, unit, entityKey string
		var labelsRaw []byte
		var value float64
		if err := pool.QueryRow(ctx, `SELECT e.evidence_id,e.created_at,o.metric,o.value,o.unit,o.entity_key,o.labels FROM evidence_envelopes e JOIN observations o ON o.run_id=e.run_id WHERE e.cluster_id=$1 AND e.run_id=$2`, prefix, prefix+"-"+string(q)).Scan(&eid, &committed, &metric, &value, &unit, &entityKey, &labelsRaw); err != nil {
			return s, err
		}
		envelope, _, ok, err := evidenceStore.LoadEvidence(ctx, eid)
		if err != nil || !ok {
			return s, fmt.Errorf("committed pipeline envelope unavailable: %w", err)
		}
		var labels []domain.Label
		if err := json.Unmarshal(labelsRaw, &labels); err != nil {
			return s, err
		}
		node, gpu, valid := domain.DCGMIdentity(labels, domain.CollectionTask{Node: "node-1"})
		if !valid {
			return s, fmt.Errorf("committed pipeline identity is ambiguous or outside scope")
		}
		expectedKey := "node/" + node + "/gpu/" + gpu
		if q == domain.QueryGPUTemperature {
			expectedKey = (domain.EntityIdentity{ClusterID: request.ClusterID, Kind: domain.EntityGPU, NodeID: domain.StableNodeID(node), PhysicalGPUUUID: domain.PhysicalGPUUUID(gpu)}).Key()
		}
		if entityKey != expectedKey {
			return s, fmt.Errorf("committed pipeline entity key disagrees with identity labels")
		}
		role := string(investigationtools.XIDRequiredEvidenceTools()[i])
		summary := fmt.Sprintf("%s on %s reported %s = %g %s; this observation does not establish a physical cause.", gpu, node, metric, value, unit)
		input := investigationcontext.EvidenceInput{EvidenceID: eid, ClusterID: request.ClusterID, Operation: envelope.Source().Operation, EvidenceClass: string(q), Status: envelope.Status(), EntityIDs: slices.Clone(request.Scope.EntityIDs), ObservedFrom: envelope.TimeRange().Start, ObservedTo: envelope.TimeRange().End, CollectedAt: envelope.CollectedAt(), Source: string(envelope.Source().SourceID), Summary: summary, SummaryQuality: "MEANINGFUL", SummaryVersion: "testbed-collection-v1", Coverage: envelope.Coverage(), ExpectedFrom: request.Scope.Start, ExpectedTo: request.Scope.End, CommittedAt: committed, Retained: true, ArtifactAvailable: true, CitationEligible: true, KeepDistinct: true}
		raw, err := json.Marshal(input)
		if err != nil {
			return s, err
		}
		if _, err = pool.Exec(ctx, `INSERT INTO testbed_evidence(evidence_id,investigation_id,role,available_after,projection) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, eid, id, role, i, raw); err != nil {
			return s, err
		}
		s.World.Evidence = append(s.World.Evidence, Evidence{ID: string(eid), Role: role, Summary: summary, Status: envelope.Status(), AvailableAfterAction: i})
		s.Oracle.RequiredEvidence = append(s.Oracle.RequiredEvidence, string(eid))
	}
	for i, tool := range investigationtools.XIDRequiredEvidenceTools() {
		eid := domain.EvidenceID(prefix + "-missing-" + string(tool))
		envelope, _, ok, err := evidenceStore.LoadEvidence(ctx, eid)
		if err != nil || !ok {
			return s, fmt.Errorf("missing diagnostic envelope unavailable: %w", err)
		}
		var committed time.Time
		if err := pool.QueryRow(ctx, `SELECT created_at FROM evidence_envelopes WHERE evidence_id=$1`, eid).Scan(&committed); err != nil {
			return s, err
		}
		summary := "The simulated lab has no native diagnostic result for " + string(tool) + "; this evidence class remains unavailable."
		input := investigationcontext.EvidenceInput{EvidenceID: eid, ClusterID: request.ClusterID, Operation: envelope.Source().Operation, EvidenceClass: string(tool), Status: domain.EvidenceUnavailable, EntityIDs: slices.Clone(request.Scope.EntityIDs), ObservedFrom: envelope.TimeRange().Start, ObservedTo: envelope.TimeRange().End, CollectedAt: envelope.CollectedAt(), Source: string(envelope.Source().SourceID), Summary: summary, SummaryQuality: "MEANINGFUL", SummaryVersion: "testbed-missing-v1", Coverage: envelope.Coverage(), ExpectedFrom: request.Scope.Start, ExpectedTo: request.Scope.End, CommittedAt: committed, Retained: true, ArtifactAvailable: true, CitationEligible: true, KeepDistinct: true}
		raw, err := json.Marshal(input)
		if err != nil {
			return s, err
		}
		if _, err := pool.Exec(ctx, `INSERT INTO testbed_evidence(evidence_id,investigation_id,role,available_after,projection) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, eid, id, string(tool), i, raw); err != nil {
			return s, err
		}
		s.World.Evidence = append(s.World.Evidence, Evidence{ID: string(eid), Role: string(tool), Summary: summary, Status: domain.EvidenceUnavailable, AvailableAfterAction: i})
	}
	raw, err := json.Marshal(s.World)
	if err != nil {
		return s, err
	}
	_, err = pool.Exec(ctx, `INSERT INTO testbed_worlds(investigation_id,world) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, raw)
	return s, err
}

func pipelineMissingDiagnostics(ctx context.Context, pool *pgxpool.Pool, prefix string, at time.Time) error {
	store, _ := storepg.NewEvidenceStore(pool)
	for _, tool := range investigationtools.XIDRequiredEvidenceTools() {
		binding, _ := investigationtools.DiagnosticBindingForTool(tool)
		runID := domain.DiagnosticRunID(prefix + "-missing-run-" + string(tool))
		digest := domain.ChecksumSHA256([]byte("synthetic-unavailable:" + string(tool)))
		// Explicit terminal fixture attribution satisfies the controller/store FK.
		// It queues no work and makes no claim of native execution or signed packs.
		if _, err := pool.Exec(ctx, `INSERT INTO diagnostic_runs(run_id,cluster_id,pack_id,pack_version,definition_id,definition_version,definition_digest,privilege,status,requested_by,idempotency_key,requested_at,deadline,max_attempts,completed_at) VALUES($1,$2,'testbed-unavailable','1',$3,$4,$5,'UNPRIVILEGED','FAILED','testbed',$1,$6,$7,1,$6) ON CONFLICT DO NOTHING`, runID, prefix, binding.DefinitionID, binding.DefinitionVersion, digest[:], at, at.Add(time.Minute)); err != nil {
			return err
		}
		if _, err := pool.Exec(ctx, `INSERT INTO diagnostic_run_targets(run_id,target,ordinal) VALUES($1,'node-1',0) ON CONFLICT DO NOTHING`, runID); err != nil {
			return err
		}
		envelope, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{ID: domain.EvidenceID(prefix + "-missing-" + string(tool)), SchemaVersion: 1, ClusterID: domain.ClusterID(prefix), Status: domain.EvidenceUnavailable, Source: domain.EvidenceSourceReference{SourceID: domain.SourceID(prefix + "-source"), Operation: domain.EvidenceOperationID("testbed." + string(tool)), DefinitionVersion: "1", Reference: "synthetic:diagnostic-unavailable", DiagnosticRunID: runID}, TimeRange: domain.EvidenceTimeRange{Start: at, End: at}, CollectedAt: at.Add(time.Second), Coverage: domain.EvidenceCoverage{Expected: []domain.EvidenceTarget{{Kind: domain.EvidenceTargetNode, ID: "node-1"}}}})
		if err != nil {
			return err
		}
		if _, err := store.CreateEvidence(ctx, envelope); err != nil {
			return err
		}
	}
	return nil
}
