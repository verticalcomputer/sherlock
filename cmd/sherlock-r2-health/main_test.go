package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

type probeFake struct{ err error }

func (fake probeFake) Probe(context.Context) error { return fake.err }

func TestRunProbeEmitsOnlySafeAvailability(t *testing.T) {
	var output bytes.Buffer
	if err := runProbe(context.Background(), probeFake{}, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "{\"backend\":\"r2\",\"status\":\"available\"}\n" {
		t.Fatalf("output=%q", output.String())
	}
}

func TestRunProbeDoesNotRenderProviderFailure(t *testing.T) {
	var output bytes.Buffer
	err := runProbe(context.Background(), probeFake{err: errors.New("secret endpoint detail")}, &output)
	if err == nil || strings.Contains(output.String(), "secret") || output.Len() != 0 {
		t.Fatalf("err=%v output=%q", err, output.String())
	}
}
