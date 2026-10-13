package clustermemory

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type Postgres struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func NewPostgres(pool *pgxpool.Pool) (*Postgres, error) {
	if pool == nil {
		return nil, fmt.Errorf("cluster memory PostgreSQL pool is required")
	}
	return &Postgres{pool: pool, now: time.Now}, nil
}

// ProjectInvestigation deterministically replaces only the derived rows for a
// terminal investigation. It never updates investigation or evidence rows.
func (store *Postgres) ProjectInvestigation(ctx context.Context, id domain.InvestigationID) error {
	if id == "" {
		return fmt.Errorf("source investigation is required")
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin memory projection: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var cluster domain.ClusterID
	var status, entityKind string
	var entityJSON []byte
	var completedAt *time.Time
	if err := tx.QueryRow(ctx, `SELECT cluster_id,status,scope->>'entity_kind',scope->'entity_ids',completed_at FROM investigations WHERE investigation_id=$1`, id).Scan(&cluster, &status, &entityKind, &entityJSON, &completedAt); err != nil {
		return fmt.Errorf("load memory source investigation: %w", err)
	}
	if status != "COMPLETED" && status != "PARTIAL" && status != "BLOCKED" {
		return nil
	}
	if completedAt == nil {
		return fmt.Errorf("terminal memory source investigation has no completion time")
	}
	var defaultEntities []string
	if err := json.Unmarshal(entityJSON, &defaultEntities); err != nil {
		return fmt.Errorf("decode memory source scope: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM cluster_memory_entries WHERE source_investigation_id=$1`, id); err != nil {
		return fmt.Errorf("replace memory projection: %w", err)
	}

	rows, err := tx.Query(ctx, `
		SELECT f.finding_id,f.kind,f.statement,f.scope,f.created_at,
		       coalesce(array_agg(ie.evidence_id ORDER BY ie.evidence_id) FILTER (WHERE ie.evidence_id IS NOT NULL AND c.relationship='EVIDENCE'),'{}')
		FROM investigation_findings f
		LEFT JOIN investigation_finding_citations c ON c.finding_id=f.finding_id
		LEFT JOIN investigation_evidence ie ON ie.ledger_entry_id=c.ledger_entry_id
		WHERE f.investigation_id=$1 AND f.status='CURRENT' AND f.validation_status='VALID'
		GROUP BY f.finding_id ORDER BY f.finding_id`, id)
	if err != nil {
		return fmt.Errorf("load projected findings: %w", err)
	}
	var projected []Entry
	for rows.Next() {
		var findingID domain.FindingID
		var findingKind, statement string
		var scopeJSON []byte
		var created time.Time
		var evidenceIDs []string
		if err := rows.Scan(&findingID, &findingKind, &statement, &scopeJSON, &created, &evidenceIDs); err != nil {
			rows.Close()
			return err
		}
		if len(evidenceIDs) == 0 {
			continue
		}
		entities := scopeEntities(scopeJSON, defaultEntities)
		entry := projectedEntry(cluster, id, KindValidatedFinding, TrustValidatedFinding, entityKind, entities, statement, *completedAt, created, "finding/"+string(findingID))
		entry.SourceFindingID = findingID
		for _, evidenceID := range evidenceIDs {
			entry.Citations = append(entry.Citations, Citation{EvidenceID: domain.EvidenceID(evidenceID), Relationship: "EVIDENCE"})
		}
		projected = append(projected, entry)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, entry := range projected {
		if err := insertEntry(ctx, tx, entry); err != nil {
			return err
		}
	}

	actionRows, err := tx.Query(ctx, `
		SELECT a.action_id,a.tool_id,a.status,a.created_at,coalesce(a.completed_at,a.created_at),
		       coalesce(array_agg(ie.evidence_id ORDER BY ie.evidence_id) FILTER (WHERE ie.evidence_id IS NOT NULL),'{}')
		FROM investigation_actions a LEFT JOIN investigation_evidence ie ON ie.action_id=a.action_id
		WHERE a.investigation_id=$1 AND a.status IN ('SUCCEEDED','FAILED','REJECTED')
		GROUP BY a.action_id ORDER BY a.action_id`, id)
	if err != nil {
		return fmt.Errorf("load projected actions: %w", err)
	}
	projected = projected[:0]
	for actionRows.Next() {
		var actionID, toolID, outcome string
		var started, ended time.Time
		var evidenceIDs []string
		if err := actionRows.Scan(&actionID, &toolID, &outcome, &started, &ended, &evidenceIDs); err != nil {
			actionRows.Close()
			return err
		}
		if len(evidenceIDs) == 0 {
			continue
		}
		statement := fmt.Sprintf("Read-only action %s finished with outcome %s.", toolID, outcome)
		entry := projectedEntry(cluster, id, KindActionOutcome, TrustActionOutcome, entityKind, defaultEntities, statement, ended, started, "action/"+actionID)
		entry.SourceActionID = actionID
		entry.ObservedFrom, entry.ObservedTo = started.UTC(), ended.UTC()
		for _, evidenceID := range evidenceIDs {
			entry.Citations = append(entry.Citations, Citation{EvidenceID: domain.EvidenceID(evidenceID), Relationship: "EVIDENCE"})
		}
		projected = append(projected, entry)
	}
	if err := actionRows.Err(); err != nil {
		actionRows.Close()
		return err
	}
	actionRows.Close()
	for _, entry := range projected {
		if err := insertEntry(ctx, tx, entry); err != nil {
			return err
		}
	}

	hypothesisRows, err := tx.Query(ctx, `
		SELECT h.hypothesis_id,h.statement,h.status,h.created_at,
		       coalesce(array_agg(ie.evidence_id ORDER BY ie.evidence_id) FILTER (WHERE ie.evidence_id IS NOT NULL),'{}')
		FROM investigation_hypotheses h
		LEFT JOIN investigation_hypothesis_evidence he ON he.hypothesis_id=h.hypothesis_id
		LEFT JOIN investigation_evidence ie ON ie.ledger_entry_id=he.ledger_entry_id
		WHERE h.investigation_id=$1 AND h.status IN ('SUPPORTED','UNRESOLVED','WEAKENED')
		GROUP BY h.hypothesis_id ORDER BY h.hypothesis_id`, id)
	if err != nil {
		return fmt.Errorf("load projected hypotheses: %w", err)
	}
	projected = projected[:0]
	for hypothesisRows.Next() {
		var hypothesisID, statement, status string
		var created time.Time
		var evidenceIDs []string
		if err := hypothesisRows.Scan(&hypothesisID, &statement, &status, &created, &evidenceIDs); err != nil {
			hypothesisRows.Close()
			return err
		}
		entry := projectedEntry(cluster, id, KindHypothesis, TrustHypothesis, entityKind, defaultEntities, statement, *completedAt, created, "hypothesis/"+hypothesisID)
		entry.Completeness = "UNKNOWN"
		for _, evidenceID := range evidenceIDs {
			entry.Citations = append(entry.Citations, Citation{EvidenceID: domain.EvidenceID(evidenceID), Relationship: "EVIDENCE"})
		}
		projected = append(projected, entry)
	}
	if err := hypothesisRows.Err(); err != nil {
		hypothesisRows.Close()
		return err
	}
	hypothesisRows.Close()
	for _, entry := range projected {
		if err := insertEntry(ctx, tx, entry); err != nil {
			return err
		}
	}

	gapRows, err := tx.Query(ctx, `SELECT ledger_entry_id,entry_kind,status,observed_start,observed_end,recorded_at FROM investigation_evidence WHERE investigation_id=$1 AND entry_kind<>'OBSERVATION' ORDER BY sequence`, id)
	if err != nil {
		return fmt.Errorf("load projected coverage gaps: %w", err)
	}
	projected = projected[:0]
	for gapRows.Next() {
		var ledgerID, entryKind, status string
		var observedStart, observedEnd, recorded time.Time
		if err := gapRows.Scan(&ledgerID, &entryKind, &status, &observedStart, &observedEnd, &recorded); err != nil {
			gapRows.Close()
			return err
		}
		statement := fmt.Sprintf("Investigation coverage recorded %s with status %s.", entryKind, status)
		entry := projectedEntry(cluster, id, KindCoverageGap, TrustCoverageGap, entityKind, defaultEntities, statement, *completedAt, recorded, "gap/"+ledgerID)
		entry.ObservedFrom, entry.ObservedTo, entry.Completeness = observedStart.UTC(), observedEnd.UTC(), "PARTIAL"
		projected = append(projected, entry)
	}
	if err := gapRows.Err(); err != nil {
		gapRows.Close()
		return err
	}
	gapRows.Close()
	for _, entry := range projected {
		if err := insertEntry(ctx, tx, entry); err != nil {
			return err
		}
	}

	sourceDigest, err := projectionDigest(ctx, tx, cluster)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO cluster_memory_projection_checkpoints(cluster_id,index_version,last_investigation_id,projected_at,source_digest) VALUES($1,$2,$3,$4,$5) ON CONFLICT(cluster_id) DO UPDATE SET index_version=excluded.index_version,last_investigation_id=excluded.last_investigation_id,projected_at=excluded.projected_at,source_digest=excluded.source_digest`, cluster, IndexVersion, id, store.now().UTC(), sourceDigest[:])
	if err != nil {
		return fmt.Errorf("write memory checkpoint: %w", err)
	}
	return tx.Commit(ctx)
}

func projectedEntry(cluster domain.ClusterID, investigation domain.InvestigationID, kind Kind, trust TrustClass, entityKind string, entities []string, statement string, validAt, created time.Time, key string) Entry {
	statement = strings.TrimSpace(statement)
	digest := domain.ChecksumSHA256([]byte(string(cluster) + "\x00" + key + "\x00" + statement))
	id := "memory-" + hex.EncodeToString(digest[:12])
	return Entry{ID: id, ClusterID: cluster, Kind: kind, Trust: trust, SourceInvestigationID: investigation, EntityKind: entityKind, EntityIDs: slices.Clone(entities), Statement: statement, Summary: statement, ValidFrom: validAt.UTC(), CreatedAt: created.UTC(), ExpiresAt: created.UTC().Add(180 * 24 * time.Hour), Completeness: "COMPLETE", Freshness: "CURRENT", RetentionClass: "investigation-180d", ContentDigest: digest, IdempotencyKey: key}
}

func scopeEntities(scopeJSON []byte, fallback []string) []string {
	var scope struct {
		EntityIDs []string `json:"entity_ids"`
	}
	if json.Unmarshal(scopeJSON, &scope) == nil && len(scope.EntityIDs) > 0 {
		return scope.EntityIDs
	}
	return slices.Clone(fallback)
}

func insertEntry(ctx context.Context, tx pgx.Tx, entry Entry) error {
	if err := entry.Validate(); err != nil {
		return err
	}
	entities, _ := json.Marshal(entry.EntityIDs)
	_, err := tx.Exec(ctx, `INSERT INTO cluster_memory_entries(memory_id,cluster_id,memory_kind,trust_class,source_investigation_id,source_action_id,source_finding_id,entity_kind,entity_ids,evidence_class,source_version,statement,compact_summary,observed_from,observed_to,valid_from,valid_to,created_at,expires_at,superseded_at,completeness,freshness,retention_class,content_digest,idempotency_key) VALUES($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),$8,$9,$10,$11,$12,$13,NULLIF($14,'0001-01-01T00:00:00Z')::timestamptz,NULLIF($15,'0001-01-01T00:00:00Z')::timestamptz,$16,NULLIF($17,'0001-01-01T00:00:00Z')::timestamptz,$18,NULLIF($19,'0001-01-01T00:00:00Z')::timestamptz,NULLIF($20,'0001-01-01T00:00:00Z')::timestamptz,$21,$22,$23,$24,$25)`, entry.ID, entry.ClusterID, entry.Kind, entry.Trust, entry.SourceInvestigationID, entry.SourceActionID, entry.SourceFindingID, entry.EntityKind, entities, entry.EvidenceClass, entry.SourceVersion, entry.Statement, entry.Summary, nullableTimeText(entry.ObservedFrom), nullableTimeText(entry.ObservedTo), entry.ValidFrom, nullableTimeText(entry.ValidTo), entry.CreatedAt, nullableTimeText(entry.ExpiresAt), nullableTimeText(entry.SupersededAt), entry.Completeness, entry.Freshness, entry.RetentionClass, entry.ContentDigest[:], entry.IdempotencyKey)
	if err != nil {
		return fmt.Errorf("insert cluster memory entry: %w", err)
	}
	for _, citation := range entry.Citations {
		if _, err := tx.Exec(ctx, `INSERT INTO cluster_memory_citations(cluster_id,memory_id,evidence_id,relationship) VALUES($1,$2,$3,$4)`, entry.ClusterID, entry.ID, citation.EvidenceID, citation.Relationship); err != nil {
			return fmt.Errorf("insert cluster memory citation: %w", err)
		}
	}
	outboxID := "outbox-" + strings.TrimPrefix(entry.ID, "memory-")
	_, err = tx.Exec(ctx, `INSERT INTO cluster_memory_outbox(outbox_id,cluster_id,memory_id,operation,status,available_at,created_at) VALUES($1,$2,$3,'UPSERT','PENDING',$4,$4)`, outboxID, entry.ClusterID, entry.ID, entry.CreatedAt)
	return err
}

func nullableTimeText(value time.Time) string {
	if value.IsZero() {
		return "0001-01-01T00:00:00Z"
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func projectionDigest(ctx context.Context, tx pgx.Tx, cluster domain.ClusterID) (domain.SHA256, error) {
	rows, err := tx.Query(ctx, `SELECT encode(content_digest,'hex') FROM cluster_memory_entries WHERE cluster_id=$1 ORDER BY memory_id`, cluster)
	if err != nil {
		return domain.SHA256{}, err
	}
	defer rows.Close()
	var document strings.Builder
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return domain.SHA256{}, err
		}
		document.WriteString(value)
		document.WriteByte('\n')
	}
	return domain.ChecksumSHA256([]byte(document.String())), rows.Err()
}

func (store *Postgres) RebuildCluster(ctx context.Context, cluster domain.ClusterID) error {
	if cluster == "" {
		return fmt.Errorf("cluster is required")
	}
	rows, err := store.pool.Query(ctx, `SELECT investigation_id FROM investigations WHERE cluster_id=$1 AND status IN ('COMPLETED','PARTIAL','BLOCKED') ORDER BY completed_at,investigation_id`, cluster)
	if err != nil {
		return err
	}
	var ids []domain.InvestigationID
	for rows.Next() {
		var id domain.InvestigationID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if _, err := store.pool.Exec(ctx, `DELETE FROM cluster_memory_entries WHERE cluster_id=$1`, cluster); err != nil {
		return err
	}
	for _, id := range ids {
		if err := store.ProjectInvestigation(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

func (store *Postgres) Supersede(ctx context.Context, cluster domain.ClusterID, memoryIDs []string, at time.Time) error {
	if cluster == "" || len(memoryIDs) == 0 || at.IsZero() {
		return fmt.Errorf("memory supersession is invalid")
	}
	command, err := store.pool.Exec(ctx, `UPDATE cluster_memory_entries SET superseded_at=$3,valid_to=least(coalesce(valid_to,$3),$3) WHERE cluster_id=$1 AND memory_id=ANY($2::text[]) AND superseded_at IS NULL`, cluster, memoryIDs, at.UTC())
	if err != nil {
		return fmt.Errorf("supersede cluster memory: %w", err)
	}
	if command.RowsAffected() != int64(len(memoryIDs)) {
		return fmt.Errorf("supersede cluster memory: one or more entries were absent or already superseded")
	}
	return nil
}

func (store *Postgres) PruneExpired(ctx context.Context, cluster domain.ClusterID, at time.Time) (int64, error) {
	if cluster == "" || at.IsZero() {
		return 0, fmt.Errorf("memory retention request is invalid")
	}
	command, err := store.pool.Exec(ctx, `DELETE FROM cluster_memory_entries WHERE cluster_id=$1 AND expires_at IS NOT NULL AND expires_at<=$2`, cluster, at.UTC())
	if err != nil {
		return 0, fmt.Errorf("prune expired cluster memory: %w", err)
	}
	return command.RowsAffected(), nil
}

func (store *Postgres) RecordProjectionFailure(ctx context.Context, investigationID domain.InvestigationID, reasonCode string, occurredAt time.Time) error {
	if investigationID == "" || reasonCode == "" || occurredAt.IsZero() {
		return fmt.Errorf("memory projection failure attribution is invalid")
	}
	for _, character := range reasonCode {
		if character != '_' && (character < 'A' || character > 'Z') {
			return fmt.Errorf("memory projection failure reason is invalid")
		}
	}
	var cluster domain.ClusterID
	if err := store.pool.QueryRow(ctx, `SELECT cluster_id FROM investigations WHERE investigation_id=$1`, investigationID).Scan(&cluster); err != nil {
		return fmt.Errorf("load failed memory projection cluster: %w", err)
	}
	digest := domain.ChecksumSHA256([]byte(string(investigationID) + "\x00" + occurredAt.UTC().Format(time.RFC3339Nano)))
	failureID := "memory-failure-" + hex.EncodeToString(digest[:12])
	_, err := store.pool.Exec(ctx, `INSERT INTO cluster_memory_projection_failures(failure_id,cluster_id,source_investigation_id,reason_code,occurred_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(failure_id) DO NOTHING`, failureID, cluster, investigationID, reasonCode, occurredAt.UTC())
	if err != nil {
		return fmt.Errorf("record memory projection failure: %w", err)
	}
	return nil
}

func (store *Postgres) Retrieve(ctx context.Context, query Query) (Result, error) {
	started := store.now()
	if query.ClusterID == "" || query.ValidAt.IsZero() || query.Limit < 1 || query.Limit > 100 {
		return Result{}, fmt.Errorf("cluster memory query is invalid")
	}
	if query.MaximumAge <= 0 {
		query.MaximumAge = 90 * 24 * time.Hour
	}
	lexicalQuery := tsQuery(query.Text, query.EntityIDs)
	rows, err := store.pool.Query(ctx, `
		WITH candidates AS (
		 SELECT m.*,
		   CASE WHEN btrim($2)='' THEN 0 ELSE ts_rank_cd(m.search_document,to_tsquery('simple',$2)) END AS rank
		 FROM cluster_memory_entries m
		 WHERE m.cluster_id=$1 AND m.superseded_at IS NULL
		   AND (m.expires_at IS NULL OR m.expires_at>$3)
		   AND m.valid_from<=$3 AND (m.valid_to IS NULL OR m.valid_to>=$3)
		   AND m.created_at >= $3-$4::interval
		   AND (cardinality($5::text[])=0 OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(m.entity_ids) e WHERE e.value=ANY($5)))
		)
		SELECT c.memory_id,c.memory_kind,c.trust_class,c.source_investigation_id,coalesce(c.source_action_id,''),coalesce(c.source_finding_id,''),c.entity_kind,c.entity_ids,c.statement,c.compact_summary,c.valid_from,c.created_at,c.completeness,c.freshness,c.retention_class,c.content_digest,c.idempotency_key,c.rank,
		       coalesce(array_agg(mc.evidence_id ORDER BY mc.evidence_id) FILTER (WHERE mc.evidence_id IS NOT NULL),'{}')
		FROM candidates c LEFT JOIN cluster_memory_citations mc ON mc.memory_id=c.memory_id
		LEFT JOIN evidence_envelopes e ON e.cluster_id=c.cluster_id AND e.evidence_id=mc.evidence_id
		GROUP BY c.memory_id,c.memory_kind,c.trust_class,c.source_investigation_id,c.source_action_id,c.source_finding_id,c.entity_kind,c.entity_ids,c.statement,c.compact_summary,c.valid_from,c.created_at,c.completeness,c.freshness,c.retention_class,c.content_digest,c.idempotency_key,c.rank
		HAVING c.memory_kind IN ('COVERAGE_GAP','HYPOTHESIS') OR count(mc.evidence_id)>0 AND count(mc.evidence_id)=count(e.evidence_id)
		ORDER BY c.rank DESC, CASE c.trust_class WHEN 'VALIDATED_FINDING' THEN 0 WHEN 'OBSERVED' THEN 1 WHEN 'ACTION_OUTCOME' THEN 2 ELSE 3 END,c.valid_from DESC,c.memory_id
		LIMIT $6`, query.ClusterID, lexicalQuery, query.ValidAt.UTC(), fmt.Sprintf("%f seconds", query.MaximumAge.Seconds()), query.EntityIDs, query.Limit*4)
	if err != nil {
		return Result{}, fmt.Errorf("retrieve cluster memory: %w", err)
	}
	defer rows.Close()
	result := Result{IndexVersion: IndexVersion, Fallback: "LEXICAL"}
	kindCounts, entityCounts := map[Kind]int{}, map[string]int{}
	seenDigests := map[domain.SHA256]struct{}{}
	var selectedTokens int64
	for rows.Next() {
		var entry Entry
		var entitiesJSON []byte
		var digest []byte
		var evidenceIDs []string
		entry.ClusterID = query.ClusterID
		if err := rows.Scan(&entry.ID, &entry.Kind, &entry.Trust, &entry.SourceInvestigationID, &entry.SourceActionID, &entry.SourceFindingID, &entry.EntityKind, &entitiesJSON, &entry.Statement, &entry.Summary, &entry.ValidFrom, &entry.CreatedAt, &entry.Completeness, &entry.Freshness, &entry.RetentionClass, &digest, &entry.IdempotencyKey, &entry.Rank, &evidenceIDs); err != nil {
			return Result{}, err
		}
		if len(digest) != 32 {
			return Result{}, fmt.Errorf("memory digest has invalid size")
		}
		copy(entry.ContentDigest[:], digest)
		if err := json.Unmarshal(entitiesJSON, &entry.EntityIDs); err != nil {
			return Result{}, err
		}
		for _, evidenceID := range evidenceIDs {
			entry.Citations = append(entry.Citations, Citation{EvidenceID: domain.EvidenceID(evidenceID), Relationship: "EVIDENCE"})
		}
		result.Candidates++
		entityKey := strings.Join(entry.EntityIDs, "\x00")
		entryTokens := int64((len(entry.Summary) + 3) / 4)
		if _, duplicate := seenDigests[entry.ContentDigest]; duplicate || kindCounts[entry.Kind] >= 4 || entityCounts[entityKey] >= 3 || query.TokenAllowance > 0 && selectedTokens+entryTokens > query.TokenAllowance || len(result.Entries) >= query.Limit {
			continue
		}
		seenDigests[entry.ContentDigest] = struct{}{}
		kindCounts[entry.Kind]++
		entityCounts[entityKey]++
		selectedTokens += entryTokens
		result.Entries = append(result.Entries, entry)
	}
	if err := rows.Err(); err != nil {
		return Result{}, err
	}
	result.Latency = store.now().Sub(started)
	return result, nil
}

func tsQuery(text string, entityIDs []string) string {
	excluded := map[string]struct{}{"why": {}, "what": {}, "is": {}, "are": {}, "the": {}, "a": {}, "an": {}, "on": {}, "in": {}, "for": {}, "of": {}, "to": {}, "and": {}, "or": {}, "was": {}, "were": {}, "did": {}, "does": {}, "how": {}, "cluster": {}}
	for _, id := range entityIDs {
		excluded[strings.ToLower(id)] = struct{}{}
	}
	seen := map[string]struct{}{}
	var terms []string
	for _, term := range strings.FieldsFunc(strings.ToLower(text), func(value rune) bool { return !unicode.IsLetter(value) && !unicode.IsDigit(value) && value != '_' }) {
		if len(term) < 2 {
			continue
		}
		if _, skip := excluded[term]; skip {
			continue
		}
		if _, duplicate := seen[term]; duplicate {
			continue
		}
		seen[term] = struct{}{}
		terms = append(terms, term)
		if len(terms) == 16 {
			break
		}
	}
	return strings.Join(terms, " | ")
}
