package servicefailure

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"testing"
)

func TestPeerCertificateAlertsArePermanentButTransportFailuresAreNot(t *testing.T) {
	for _, text := range []string{"tls: bad certificate", "tls: unsupported certificate", "tls: revoked certificate", "tls: expired certificate", "tls: unknown certificate", "tls: unknown certificate authority", "tls: access denied", "tls: certificate required"} {
		err := fmt.Errorf("client: %w", &url.Error{Op: "Post", URL: "https://fixture.invalid/", Err: &net.OpError{Op: "remote error", Err: errors.New(text)}})
		if !IsAuthentication(err) || !Permanent(err) {
			t.Fatalf("peer authentication alert not permanent: %s", text)
		}
	}
	for _, alert := range []tls.AlertError{42, 43, 44, 45, 46, 48, 49, 116} {
		if !IsAuthentication(fmt.Errorf("TLS: %w", alert)) {
			t.Fatalf("exported authalert ignored: %d", alert)
		}
	}
	for _, err := range []error{io.EOF, io.ErrUnexpectedEOF, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, &net.OpError{Op: "remote error", Err: io.EOF}, &net.OpError{Op: "remote error", Err: errors.New("tls: internal error")}, &net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}, tls.AlertError(80), errors.New("remote error: tls: bad certificate")} {
		if IsAuthentication(err) || Permanent(err) {
			t.Fatalf("transient/unstructured transport error promoted: %v", err)
		}
	}
}
