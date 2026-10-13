package telemetry

import "time"

const (
	ReleaseVersion        = 1
	MaxReleaseBytes       = 200 << 10
	MaxReleaseSpan        = 4096
	MaxReleaseFacts       = 256
	ReleaseReceiptHorizon = 7 * 24 * time.Hour
)

// A release is ownership disposition, never sensor coverage or health.
type ReleaseRequest struct {
	ProtocolVersion    int       `json:"protocol_version"`
	ReleaseVersion     int       `json:"release_version"`
	ReleaseID          string    `json:"release_id"`
	ClusterID          string    `json:"cluster_id"`
	NodeID             string    `json:"node_id"`
	EnrollmentID       string    `json:"enrollment_id"`
	EnrollmentRevision int64     `json:"enrollment_revision"`
	SessionEpoch       string    `json:"session_epoch"`
	SessionID          string    `json:"session_id"`
	SigningKeyID       string    `json:"signing_key_id"`
	CreatedAt          time.Time `json:"created_at"`
	FromSequence       string    `json:"from_sequence"`
	ThroughSequence    string    `json:"through_sequence"`
	ManifestDigest     string    `json:"manifest_digest"`
	Digest             string    `json:"digest"`
	Signature          string    `json:"signature"`
}

type ReleaseBatchFact struct {
	Sequence         string `json:"sequence"`
	Digest           string `json:"digest"`
	GatewayReceiptID string `json:"gateway_receipt_id"`
}
type ReleaseLossRef struct {
	SourceID string `json:"source_id"`
	LossID   string `json:"loss_id"`
	Digest   string `json:"digest"`
}
type ReleaseManifest struct {
	Batches []ReleaseBatchFact `json:"batches"`
	Loss    []ReleaseLossRef   `json:"loss"`
}
type ReleaseEnvelope struct {
	Request  ReleaseRequest  `json:"request"`
	Manifest ReleaseManifest `json:"manifest"`
}

type ReleaseBinding struct {
	ReleaseID          string `json:"release_id"`
	ClusterID          string `json:"cluster_id"`
	NodeID             string `json:"node_id"`
	EnrollmentID       string `json:"enrollment_id"`
	EnrollmentRevision int64  `json:"enrollment_revision"`
	SessionEpoch       string `json:"session_epoch"`
	SessionID          string `json:"session_id"`
	FromSequence       string `json:"from_sequence"`
	ThroughSequence    string `json:"through_sequence"`
	ReleaseDigest      string `json:"release_digest"`
	ManifestDigest     string `json:"manifest_digest"`
}

func (r ReleaseRequest) Binding() ReleaseBinding {
	return ReleaseBinding{ReleaseID: r.ReleaseID, ClusterID: r.ClusterID, NodeID: r.NodeID, EnrollmentID: r.EnrollmentID, EnrollmentRevision: r.EnrollmentRevision, SessionEpoch: r.SessionEpoch, SessionID: r.SessionID, FromSequence: r.FromSequence, ThroughSequence: r.ThroughSequence, ReleaseDigest: r.Digest, ManifestDigest: r.ManifestDigest}
}

type ReleaseAdmissionReceipt struct {
	ProtocolVersion int            `json:"protocol_version"`
	ReleaseVersion  int            `json:"release_version"`
	ID              string         `json:"id"`
	Binding         ReleaseBinding `json:"binding"`
	StoredAt        time.Time      `json:"stored_at"`
	Durability      string         `json:"durability"`
}
type CloudRetirementReceipt struct {
	ProtocolVersion    int            `json:"protocol_version"`
	ReleaseVersion     int            `json:"release_version"`
	ID                 string         `json:"id"`
	Phase              string         `json:"phase"`
	Binding            ReleaseBinding `json:"binding"`
	GatewayAdmissionID string         `json:"gateway_admission_id"`
	PreparedReceiptID  string         `json:"prepared_receipt_id"`
	GatewayCommitID    string         `json:"gateway_commit_id"`
	StoredAt           time.Time      `json:"stored_at"`
	Durability         string         `json:"durability"`
}
type GatewayReleaseCommit struct {
	ProtocolVersion    int            `json:"protocol_version"`
	ReleaseVersion     int            `json:"release_version"`
	ID                 string         `json:"id"`
	Binding            ReleaseBinding `json:"binding"`
	GatewayAdmissionID string         `json:"gateway_admission_id"`
	PreparedReceiptID  string         `json:"prepared_receipt_id"`
	CreatedAt          time.Time      `json:"created_at"`
}
type GatewayRetirementReceipt struct {
	ProtocolVersion    int                    `json:"protocol_version"`
	ReleaseVersion     int                    `json:"release_version"`
	ID                 string                 `json:"id"`
	Binding            ReleaseBinding         `json:"binding"`
	GatewayAdmissionID string                 `json:"gateway_admission_id"`
	PreparedReceiptID  string                 `json:"prepared_receipt_id"`
	GatewayCommitID    string                 `json:"gateway_commit_id"`
	CloudFinalReceipt  CloudRetirementReceipt `json:"cloud_final_receipt"`
	StoredAt           time.Time              `json:"stored_at"`
	Durability         string                 `json:"durability"`
}
type NodeReleaseCompletion struct {
	ProtocolVersion            int            `json:"protocol_version"`
	ReleaseVersion             int            `json:"release_version"`
	ID                         string         `json:"id"`
	Binding                    ReleaseBinding `json:"binding"`
	CloudFinalReceiptID        string         `json:"cloud_final_receipt_id"`
	GatewayRetirementReceiptID string         `json:"gateway_retirement_receipt_id"`
	SigningKeyID               string         `json:"signing_key_id"`
	CreatedAt                  time.Time      `json:"created_at"`
	Digest                     string         `json:"digest"`
	Signature                  string         `json:"signature"`
}
type NodeCompletionReceipt struct {
	ProtocolVersion            int            `json:"protocol_version"`
	ReleaseVersion             int            `json:"release_version"`
	ID                         string         `json:"id"`
	Binding                    ReleaseBinding `json:"binding"`
	CompletionDigest           string         `json:"completion_digest"`
	CloudFinalReceiptID        string         `json:"cloud_final_receipt_id"`
	GatewayRetirementReceiptID string         `json:"gateway_retirement_receipt_id"`
	StoredAt                   time.Time      `json:"stored_at"`
	Durability                 string         `json:"durability"`
}

// ReleasePrepareEnvelope and ReleaseCommitEnvelope travel only over the
// existing authenticated outbound collector boundary.
type ReleasePrepareEnvelope struct {
	Release   ReleaseEnvelope         `json:"release"`
	Admission ReleaseAdmissionReceipt `json:"admission"`
}
type ReleaseCommitEnvelope struct {
	Request ReleaseRequest       `json:"request"`
	Commit  GatewayReleaseCommit `json:"commit"`
}

// Capability negotiation is required before sealing, release or pruning.
// Absence does not authorize optimistic pruning.
type RetirementCapabilities struct {
	ProtocolVersion       int   `json:"protocol_version"`
	ReleaseVersion        int   `json:"release_version"`
	MaxBytes              int   `json:"max_bytes"`
	MaxSpan               int   `json:"max_span"`
	MaxFacts              int   `json:"max_facts"`
	ReceiptHorizonSeconds int64 `json:"receipt_horizon_seconds"`
}

func SupportedRetirementCapabilities() RetirementCapabilities {
	return RetirementCapabilities{ProtocolVersion: ProtocolVersion, ReleaseVersion: ReleaseVersion, MaxBytes: MaxReleaseBytes, MaxSpan: MaxReleaseSpan, MaxFacts: MaxReleaseFacts, ReceiptHorizonSeconds: int64(ReleaseReceiptHorizon / time.Second)}
}
func ValidateRetirementCapabilities(c RetirementCapabilities) error {
	if c != SupportedRetirementCapabilities() {
		return ErrInvalid
	}
	return nil
}
