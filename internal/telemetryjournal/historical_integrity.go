package telemetryjournal

import (
	"context"
	"database/sql"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

// Historical keys establish integrity of local immutable facts only. This path
// deliberately does not consult, extend, or synthesize current admission grants.
func (q *Queue) historicalPublicKey(ctx context.Context, id string) (telemetry.NodeKey, bool, error) {
	var count int
	if q.db.QueryRowContext(ctx, `SELECT count(*)FROM public_keys`).Scan(&count) != nil {
		return telemetry.NodeKey{}, false, ErrCorrupt
	}
	if count == 0 {
		return telemetry.NodeKey{}, false, nil
	} // Legacy fixture verifier seam.
	var k telemetry.NodeKey
	k.ID = id
	k.State = "ARCHIVED"
	e := q.db.QueryRowContext(ctx, `SELECT epoch,public FROM public_keys WHERE id=?`, id).Scan(&k.Epoch, &k.PublicKeyBase64)
	if e == sql.ErrNoRows {
		return k, false, ErrCorrupt
	}
	if e != nil {
		return k, false, ErrCorrupt
	}
	return k, true, nil
}
func (q *Queue) verifyHistoricalRelease(ctx context.Context, r ReleaseRecord) error {
	k, ok, e := q.historicalPublicKey(ctx, r.Request.SigningKeyID)
	if e != nil {
		return e
	}
	if ok {
		pub, e := telemetry.ParseNodePublicKey(k)
		if e != nil || telemetry.VerifyReleaseSignature(r.Request, pub) != nil {
			return ErrCorrupt
		}
	}
	if r.Completion != nil {
		k, ok, e = q.historicalPublicKey(ctx, r.Completion.SigningKeyID)
		if e != nil {
			return e
		}
		if ok {
			pub, e := telemetry.ParseNodePublicKey(k)
			if e != nil || telemetry.VerifyNodeCompletionSignature(*r.Completion, pub) != nil {
				return ErrCorrupt
			}
		}
	}
	return nil
}

func (q *Queue) verifyKnownSessionSigner(ctx context.Context, m telemetry.SessionMessage) error {
	k, ok, e := q.historicalPublicKey(ctx, m.SigningKeyID)
	if e != nil {
		return ErrInvalid
	}
	if !ok {
		return nil
	}
	pub, e := telemetry.ParseNodePublicKey(k)
	if e != nil || telemetry.VerifySessionSignature(m, pub) != nil {
		return ErrInvalid
	}
	return nil
}

func (q *Queue) verifyHistoricalCompletion(ctx context.Context, c telemetry.NodeReleaseCompletion) error {
	k, ok, e := q.historicalPublicKey(ctx, c.SigningKeyID)
	if e != nil {
		return e
	}
	if !ok {
		return nil
	}
	pub, e := telemetry.ParseNodePublicKey(k)
	if e != nil || telemetry.VerifyNodeCompletionSignature(c, pub) != nil {
		return ErrCorrupt
	}
	return nil
}
func (q *Queue) recoverPublicKeys(ctx context.Context) error {
	rows, e := q.db.QueryContext(ctx, `SELECT id,epoch,public FROM public_keys`)
	if e != nil {
		return ErrCorrupt
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var k telemetry.NodeKey
		if rows.Scan(&k.ID, &k.Epoch, &k.PublicKeyBase64) != nil || !validID(k.ID) || !canonicalNumber(k.Epoch, true) {
			return ErrCorrupt
		}
		if _, e = telemetry.ParseNodePublicKey(k); e != nil {
			return ErrCorrupt
		}
		count++
		if count > 4096 {
			return ErrCapacity
		}
	}
	if rows.Err() != nil {
		return ErrCorrupt
	}
	return nil
}
