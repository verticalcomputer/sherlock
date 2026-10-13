package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestGatewayRequiresExplicitModeAndKeepsFailuresClosed(t *testing.T) {
	for _, args := range [][]string{nil, {"--config", "/private-customer-config"}, {"relay-identity", "--config", "/private-customer-config"}, {"relay-identity", "--config", "/private-customer-config", "--token-file", "private-token", "--request", "request", "--bundle-output", "bundle"}} {
		var out, errs bytes.Buffer
		if code := run(context.Background(), args, &out, &errs); code != 2 || out.Len() != 0 || strings.Contains(errs.String(), "private-customer-config") || strings.Contains(errs.String(), "private-token") {
			t.Fatal("unsafe failure", code, errs.String())
		}
	}
	var out, errs bytes.Buffer
	if code := run(context.Background(), []string{"--help"}, &out, &errs); code != 0 || !strings.Contains(out.String(), "relay-identity") {
		t.Fatal(code)
	}
}
