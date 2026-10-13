// Package source contains the small, vendor-neutral metadata shared by source
// adapters. It intentionally does not define a broad adapter interface: each
// consumer owns the narrow interface for the information it needs.
package source

import (
	"fmt"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type Capability struct {
	ID      string
	Version string
}

type Health struct {
	Reachable    bool
	Capabilities []Capability
}

type Failure struct {
	Code      domain.FailureCode
	Retryable bool
	Target    string
	Message   string
}

type Error struct {
	Code      domain.FailureCode
	Retryable bool
	Message   string
	Cause     error
}

func (e *Error) Error() string { return e.Message }
func (e *Error) Unwrap() error { return e.Cause }

func NewError(code domain.FailureCode, retryable bool, message string, cause error) error {
	return &Error{Code: code, Retryable: retryable, Message: message, Cause: cause}
}

func InvalidArgument(message string) error {
	return &Error{Code: domain.FailureInvalidArgument, Message: message, Cause: fmt.Errorf("invalid bounded source query")}
}
