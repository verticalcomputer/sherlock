package diagnosticrunner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const RemoteResultSchemaV1 = "sherlock.runner-result.v1"
const RemoteResultSchemaV2 = "sherlock.runner-result.v2"

type remoteResultDocument struct {
	SchemaVersion string           `json:"schema_version"`
	Result        remoteWireResult `json:"result"`
}

type remoteWireResult struct {
	DefinitionID      string                   `json:"definition_id"`
	DefinitionVersion string                   `json:"definition_version"`
	DefinitionDigest  string                   `json:"definition_digest"`
	AttemptID         string                   `json:"attempt_id"`
	Targets           []remoteWireTargetResult `json:"targets"`
}

type remoteWireTargetResult struct {
	TargetID                  string `json:"target_id"`
	Started                   bool   `json:"started"`
	ExitCode                  int    `json:"exit_code"`
	Signal                    string `json:"signal"`
	TimedOut                  bool   `json:"timed_out"`
	Cancelled                 bool   `json:"cancelled"`
	ErrorCode                 string `json:"error_code"`
	Stdout                    []byte `json:"stdout"`
	Stderr                    []byte `json:"stderr"`
	StdoutBytes               int64  `json:"stdout_bytes"`
	StderrBytes               int64  `json:"stderr_bytes"`
	StdoutTruncated           bool   `json:"stdout_truncated"`
	StderrTruncated           bool   `json:"stderr_truncated"`
	StdoutSHA256              string `json:"stdout_sha256"`
	StdoutTransformationState string `json:"stdout_transformation_state,omitempty"`
	StderrSHA256              string `json:"stderr_sha256"`
	DurationNS                int64  `json:"duration_ns"`
}

// EncodeRemoteResult writes the fixed result contract consumed by the head
// transport. A forced-command runner serves exactly one fixed target.
func EncodeRemoteResult(output io.Writer, result Result) error {
	if output == nil || len(result.Targets) != 1 {
		return errors.New("encode remote result: invalid cardinality")
	}
	if err := validateRemoteResult(result, result.AttemptID, result.DefinitionID, result.DefinitionVersion, result.DefinitionDigest, result.Targets[0].TargetID, 0); err != nil {
		return errors.New("encode remote result: invalid result")
	}
	document := remoteResultDocument{SchemaVersion: RemoteResultSchemaV2, Result: toRemoteWireResult(result)}
	if err := json.NewEncoder(output).Encode(document); err != nil {
		return errors.New("encode remote result: write failed")
	}
	return nil
}

func decodeRemoteResult(payload []byte, request executionRequest, targetID string) (Result, error) {
	if request.MaxOutputBytes <= 0 || request.RemoteResultMaxOutputBytes <= 0 || len(payload) == 0 || int64(len(payload)) > request.MaxOutputBytes {
		return Result{}, errors.New("restricted ssh: remote result exceeds policy")
	}
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return Result{}, errors.New("restricted ssh: remote result is not strict JSON")
	}
	var document remoteResultDocument
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return Result{}, errors.New("restricted ssh: remote result is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Result{}, errors.New("restricted ssh: remote result has trailing data")
	}
	if document.SchemaVersion != RemoteResultSchemaV1 && document.SchemaVersion != RemoteResultSchemaV2 {
		return Result{}, errors.New("restricted ssh: remote result schema is unsupported")
	}
	result := fromRemoteWireResult(document.Result)
	if document.SchemaVersion == RemoteResultSchemaV1 && len(result.Targets) == 1 {
		// A v1 envelope has no producer proof, even if it carries an added field.
		result.Targets[0].StdoutTransformationState = domain.StdoutTransformationUnknown
	}
	if err := validateRemoteResult(result, request.AttemptID, request.DefinitionID, request.DefinitionVersion, request.DefinitionDigest, targetID, request.RemoteResultMaxOutputBytes); err != nil {
		return Result{}, err
	}
	return result, nil
}

func validateRemoteResult(result Result, attemptID, definitionID, definitionVersion, definitionDigest, targetID string, maximumDiagnosticOutput int64) error {
	if result.AttemptID != attemptID || result.DefinitionID != definitionID || result.DefinitionVersion != definitionVersion || result.DefinitionDigest != definitionDigest {
		return errors.New("restricted ssh: remote result attribution mismatch")
	}
	if !safeIdentifier(result.AttemptID) || !safeIdentifier(result.DefinitionID) || !safeIdentifier(result.DefinitionVersion) || !validSHA256(result.DefinitionDigest) || len(result.Targets) != 1 {
		return errors.New("restricted ssh: remote result attribution is invalid")
	}
	target := result.Targets[0]
	if target.TargetID != targetID || !validRemoteTargetResult(target, maximumDiagnosticOutput) {
		return errors.New("restricted ssh: remote target result is invalid")
	}
	return nil
}

func validRemoteTargetResult(result TargetResult, maximumDiagnosticOutput int64) bool {
	if !safeIdentifier(result.TargetID) || result.StdoutBytes < 0 || result.StderrBytes < 0 || result.Duration < 0 || !validSHA256(result.StdoutSHA256) || !validSHA256(result.StderrSHA256) {
		return false
	}
	if maximumDiagnosticOutput > 0 && (result.StdoutBytes > maximumDiagnosticOutput || result.StderrBytes > maximumDiagnosticOutput-result.StdoutBytes) {
		return false
	}
	if result.TimedOut && result.Cancelled {
		return false
	}
	if !result.Started && (result.ExitCode != -1 || result.Signal != "") {
		return false
	}
	if result.Signal != "" && !validRemoteSignal(result.Signal) {
		return false
	}
	switch result.ErrorCode {
	case "":
		return result.Started && result.ExitCode == 0 && result.Signal == "" && !result.TimedOut && !result.Cancelled
	case CodeStartFailed, CodeDefinitionInactive:
		return !result.Started && !result.TimedOut && !result.Cancelled
	case CodeExitNonZero:
		return result.Started && result.ExitCode != 0 && !result.TimedOut && !result.Cancelled
	case CodeTimedOut:
		return result.Started && result.TimedOut && !result.Cancelled
	case CodeCancelled:
		return result.Cancelled && !result.TimedOut
	case CodeExecutableReplaced:
		return !result.TimedOut && !result.Cancelled
	default:
		return false
	}
}

func validRemoteSignal(signal string) bool {
	if len(signal) == 0 || len(signal) > 64 {
		return false
	}
	for _, character := range signal {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == ' ' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func toRemoteWireResult(result Result) remoteWireResult {
	targets := make([]remoteWireTargetResult, len(result.Targets))
	for index, target := range result.Targets {
		targets[index] = remoteWireTargetResult{
			TargetID: target.TargetID, Started: target.Started, ExitCode: target.ExitCode, Signal: target.Signal,
			TimedOut: target.TimedOut, Cancelled: target.Cancelled, ErrorCode: target.ErrorCode,
			Stdout: target.Stdout, Stderr: target.Stderr, StdoutBytes: target.StdoutBytes, StderrBytes: target.StderrBytes,
			StdoutTruncated: target.StdoutTruncated, StderrTruncated: target.StderrTruncated,
			StdoutSHA256: target.StdoutSHA256, StderrSHA256: target.StderrSHA256, DurationNS: int64(target.Duration),
			StdoutTransformationState: string(domain.NormalizeStdoutTransformationState(string(target.StdoutTransformationState))),
		}
	}
	return remoteWireResult{
		DefinitionID: result.DefinitionID, DefinitionVersion: result.DefinitionVersion, DefinitionDigest: result.DefinitionDigest,
		AttemptID: result.AttemptID, Targets: targets,
	}
}

func fromRemoteWireResult(result remoteWireResult) Result {
	targets := make([]TargetResult, len(result.Targets))
	for index, target := range result.Targets {
		targets[index] = TargetResult{
			TargetID: target.TargetID, Started: target.Started, ExitCode: target.ExitCode, Signal: target.Signal,
			TimedOut: target.TimedOut, Cancelled: target.Cancelled, ErrorCode: target.ErrorCode,
			Stdout: append([]byte(nil), target.Stdout...), Stderr: append([]byte(nil), target.Stderr...),
			StdoutBytes: target.StdoutBytes, StderrBytes: target.StderrBytes,
			StdoutTruncated: target.StdoutTruncated, StderrTruncated: target.StderrTruncated,
			StdoutSHA256: target.StdoutSHA256, StderrSHA256: target.StderrSHA256, Duration: time.Duration(target.DurationNS),
			StdoutTransformationState: domain.NormalizeStdoutTransformationState(target.StdoutTransformationState),
		}
	}
	return Result{
		DefinitionID: result.DefinitionID, DefinitionVersion: result.DefinitionVersion, DefinitionDigest: result.DefinitionDigest,
		AttemptID: result.AttemptID, Targets: targets,
	}
}

func rejectDuplicateJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := scanStrictJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func scanStrictJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid JSON object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanStrictJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanStrictJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}
