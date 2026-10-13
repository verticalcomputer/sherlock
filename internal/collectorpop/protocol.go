package collectorpop

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

const (
	CertificateHeader = "X-Sherlock-Client-Certificate"
	TimestampHeader   = "X-Sherlock-Request-Timestamp"
	ContentHashHeader = "X-Sherlock-Content-SHA256"
	SignatureHeader   = "X-Sherlock-Request-Signature"
	ProtocolHeader    = "X-Sherlock-Protocol-Version"
	CorrelationHeader = "X-Correlation-ID"
	SignatureContext  = "sherlock-collector-pop-v1"
)

func CanonicalRequest(method, escapedPath, rawQuery, hostname, protocol, correlationID, timestamp string, bodyDigest [32]byte) ([]byte, error) {
	hostname = NormalizeHostname(hostname)
	if method == "" || escapedPath == "" || hostname == "" || protocol == "" || correlationID == "" || timestamp == "" {
		return nil, fmt.Errorf("proof-of-possession request fields are incomplete")
	}
	for _, value := range []string{method, escapedPath, rawQuery, hostname, protocol, correlationID, timestamp} {
		if strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("proof-of-possession request fields contain line breaks")
		}
	}
	return []byte(strings.Join([]string{
		SignatureContext,
		method,
		escapedPath,
		rawQuery,
		hostname,
		protocol,
		correlationID,
		timestamp,
		hex.EncodeToString(bodyDigest[:]),
	}, "\n")), nil
}

func NormalizeHostname(raw string) string {
	host := strings.TrimSpace(raw)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}
