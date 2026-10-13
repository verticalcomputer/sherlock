package telemetry

import "time"

const (
	MaxStatusSessions = 32
	MaxStatusReceipts = 64
	MaxStatusHistory  = 16
	MaxStatusRecords  = 16
	MaxStatusRanges   = 16
	MaxStatusBytes    = 200 << 10
)

// EnrollmentStatus is a bounded read-only snapshot, never a reconstruction of
// immutable batches or fresh physical evidence. Omitted facts are explicit.
type EnrollmentStatus struct {
	Grant                     Grant           `json:"grant"`
	Sessions                  []SessionStatus `json:"sessions"`
	Receipts                  []CloudReceipt  `json:"receipts"`
	History                   []BatchHistory  `json:"history"`
	SessionsTruncated         bool            `json:"sessions_truncated"`
	ReceiptsTruncated         bool            `json:"receipts_truncated"`
	HistoryTruncated          bool            `json:"history_truncated"`
	SessionsOmittedLowerBound int64           `json:"sessions_omitted_lower_bound"`
	ReceiptsOmittedLowerBound int64           `json:"receipts_omitted_lower_bound"`
	HistoryOmittedLowerBound  int64           `json:"history_omitted_lower_bound"`
}

type SequenceRange struct {
	From    string `json:"from"`
	Through string `json:"through"`
}

type SessionStatus struct {
	SessionEpoch            string          `json:"session_epoch"`
	SessionID               string          `json:"session_id"`
	BootID                  string          `json:"boot_id"`
	SigningKeyID            string          `json:"signing_key_id"`
	Finalized               bool            `json:"finalized"`
	Covered                 bool            `json:"covered"`
	LastAllocatedSequence   string          `json:"last_allocated_sequence,omitempty"`
	Retired                 bool            `json:"retired"`
	HighestReceivedSequence string          `json:"highest_received_sequence"`
	ReceivedRanges          []SequenceRange `json:"received_ranges"`
	RangesTruncated         bool            `json:"ranges_truncated"`
	OmittedRangesLowerBound int64           `json:"omitted_ranges_lower_bound"`
	Loss                    []SessionLoss   `json:"loss"`
	LossTruncated           bool            `json:"loss_truncated"`
	OmittedLossLowerBound   int64           `json:"omitted_loss_lower_bound"`
}

type BatchHistory struct {
	Key                      BatchKey      `json:"key"`
	Digest                   string        `json:"digest"`
	StoredAt                 time.Time     `json:"stored_at"`
	HistoryOnly              bool          `json:"history_only"`
	Sources                  []SourceFrame `json:"sources"`
	RecordCount              int64         `json:"record_count"`
	RecordsTruncated         bool          `json:"records_truncated"`
	OmittedRecordsLowerBound int64         `json:"omitted_records_lower_bound"`
	LossCount                int64         `json:"loss_count"`
	LossTruncated            bool          `json:"loss_truncated"`
	OmittedLossLowerBound    int64         `json:"omitted_loss_lower_bound"`
}
