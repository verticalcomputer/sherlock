// Package servicefailure separates failures requiring operator intervention from
// transient transport outages. Error wrapping preserves errors.Is semantics.
package servicefailure

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
)

var (
	ErrConfiguration  = errors.New("permanent configuration failure")
	ErrAuthentication = errors.New("authentication requires operator intervention")
	ErrPackExpired    = errors.New("signed command pack expired")
)

func Permanent(err error) bool {
	if errors.Is(err, ErrConfiguration) || IsAuthentication(err) || errors.Is(err, ErrPackExpired) {
		return true
	}
	var invalid x509.CertificateInvalidError
	var unknown x509.UnknownAuthorityError
	var verified *tls.CertificateVerificationError
	return errors.As(err, &invalid) || errors.As(err, &unknown) || errors.As(err, &verified)
}

// IsAuthentication recognizes explicit HTTP/application denial and certificate
// authentication alerts from a TLS peer. Go exposes peer alerts either as an
// AlertError or (including post-handshake TLS1.3 reads) a remote net.OpError
// containing its private alert type. Match only the documented certificate/auth
// alerts in that structured remote error, never arbitrary error substrings.
// EOF, resets, dial errors and nonspecific TLS handshake failures stay retryable.
func IsAuthentication(err error) bool {
	if errors.Is(err, ErrAuthentication) {
		return true
	}
	var exported tls.AlertError
	if errors.As(err, &exported) {
		switch uint8(exported) {
		case 42, 43, 44, 45, 46, 48, 49, 116:
			return true
		}
	}
	var remote *net.OpError
	if !errors.As(err, &remote) || remote.Op != "remote error" || remote.Err == nil {
		return false
	}
	switch remote.Err.Error() {
	case "tls: bad certificate", "tls: unsupported certificate", "tls: revoked certificate", "tls: expired certificate", "tls: unknown certificate", "tls: unknown certificate authority", "tls: access denied", "tls: certificate required":
		return true
	default:
		return false
	}
}
