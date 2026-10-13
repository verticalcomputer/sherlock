package collectorcontrol

import (
	"encoding/hex"
	"fmt"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	MaxResultChunkBytes = 256 << 10
	MaxResultChunks     = 64
)

type LeaseRef struct {
	WorkID     domain.WorkID
	Attempt    int
	LeaseToken string
}

type ResultChunk struct {
	LeaseRef
	Index   int
	Payload []byte
	SHA256  string
}

type ResultFinalization struct {
	LeaseRef
	RunID      domain.RunID
	Status     domain.ResultStatus
	ChunkCount int
	SHA256     string
	Bytes      int64
}

type ChunkOutcome struct {
	PreviouslyUploaded bool
}

type FinalizeOutcome struct {
	RunID               domain.RunID
	Status              domain.ResultStatus
	SHA256              string
	PreviouslyFinalized bool
}

func ValidateResultChunk(chunk ResultChunk) error {
	if err := validateLeaseRef(chunk.LeaseRef); err != nil {
		return err
	}
	if chunk.Index < 0 || chunk.Index >= MaxResultChunks {
		return fmt.Errorf("result chunk index must be between zero and %d", MaxResultChunks-1)
	}
	if len(chunk.Payload) == 0 || len(chunk.Payload) > MaxResultChunkBytes {
		return fmt.Errorf("result chunk must be between one and %d bytes", MaxResultChunkBytes)
	}
	return validateSHA256(chunk.SHA256)
}

func ValidateResultFinalization(finalization ResultFinalization) error {
	if err := validateLeaseRef(finalization.LeaseRef); err != nil {
		return err
	}
	if finalization.RunID == "" {
		return fmt.Errorf("result run identifier is required")
	}
	if finalization.Status != domain.ResultSucceeded && finalization.Status != domain.ResultNoData && finalization.Status != domain.ResultPartial && finalization.Status != domain.ResultFailed {
		return fmt.Errorf("unknown result status %q", finalization.Status)
	}
	if finalization.ChunkCount < 1 || finalization.ChunkCount > MaxResultChunks || finalization.Bytes < 1 {
		return fmt.Errorf("result chunk count or byte total is invalid")
	}
	return validateSHA256(finalization.SHA256)
}

func validateLeaseRef(reference LeaseRef) error {
	if reference.WorkID == "" || reference.Attempt < 1 || reference.LeaseToken == "" {
		return fmt.Errorf("work, attempt, and lease token are required")
	}
	return nil
}

func validateSHA256(value string) error {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != value {
		return fmt.Errorf("SHA-256 must be 64 lowercase hexadecimal characters")
	}
	return nil
}
