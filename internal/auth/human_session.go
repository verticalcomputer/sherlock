package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const humanSessionLifetime = 30 * time.Second
const maxHumanSession = 4096

const HumanSessionHeader = "X-Sherlock-Human-Session"

var ErrHumanSession = errors.New("human session is invalid")

// HumanSession is a short-lived server-to-server proof that the dashboard has
// just verified an end-user Access assertion. The private service token is
// domain-separated before use as the MAC key and is never sent to a browser.
// Every API request still needs its ordinary service-token authentication.
type HumanSession struct {
	Principal   HumanPrincipal
	Fingerprint [sha256.Size]byte
}

type humanSessionEnvelope struct {
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	Fingerprint string `json:"fingerprint"`
	Method      string `json:"method"`
	RequestURI  string `json:"request_uri"`
	IssuedAt    int64  `json:"issued_at"`
}

func SealHumanSession(serviceToken []byte, session HumanSession, method, requestURI string, at time.Time) (string, error) {
	if !validHumanSessionInput(serviceToken, session.Principal, method, requestURI) || at.IsZero() {
		return "", ErrHumanSession
	}
	envelope := humanSessionEnvelope{
		Issuer: session.Principal.Issuer, Subject: session.Principal.Subject,
		Fingerprint: hex.EncodeToString(session.Fingerprint[:]),
		Method:      method, RequestURI: requestURI, IssuedAt: at.UTC().Unix(),
	}
	payload, err := json.Marshal(envelope)
	if err != nil || len(payload) > maxHumanSession/2 {
		return "", ErrHumanSession
	}
	key := humanSessionKey(serviceToken)
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(payload)
	sealed := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if len(sealed) > maxHumanSession {
		return "", ErrHumanSession
	}
	return sealed, nil
}

func VerifyHumanSession(serviceToken []byte, sealed, method, requestURI string, now time.Time) (HumanSession, error) {
	if len(sealed) < 1 || len(sealed) > maxHumanSession || len(serviceToken) < 32 || len(serviceToken) > 512 ||
		!validSessionRoute(method, requestURI) || now.IsZero() {
		return HumanSession{}, ErrHumanSession
	}
	parts := strings.Split(sealed, ".")
	if len(parts) != 2 {
		return HumanSession{}, ErrHumanSession
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || len(payload) == 0 || len(payload) > maxHumanSession/2 {
		return HumanSession{}, ErrHumanSession
	}
	provided, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(provided) != sha256.Size {
		return HumanSession{}, ErrHumanSession
	}
	key := humanSessionKey(serviceToken)
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(payload)
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return HumanSession{}, ErrHumanSession
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var envelope humanSessionEnvelope
	if decoder.Decode(&envelope) != nil {
		return HumanSession{}, ErrHumanSession
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || envelope.Method != method || envelope.RequestURI != requestURI {
		return HumanSession{}, ErrHumanSession
	}
	principal := HumanPrincipal{Issuer: envelope.Issuer, Subject: envelope.Subject}
	if !validHumanSessionInput(serviceToken, principal, method, requestURI) ||
		envelope.IssuedAt > now.UTC().Add(5*time.Second).Unix() ||
		now.UTC().After(time.Unix(envelope.IssuedAt, 0).Add(humanSessionLifetime)) {
		return HumanSession{}, ErrHumanSession
	}
	fingerprint, err := hex.DecodeString(envelope.Fingerprint)
	if err != nil || len(fingerprint) != sha256.Size || hex.EncodeToString(fingerprint) != envelope.Fingerprint {
		return HumanSession{}, ErrHumanSession
	}
	var result HumanSession
	result.Principal = principal
	copy(result.Fingerprint[:], fingerprint)
	return result, nil
}

func humanSessionKey(serviceToken []byte) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("sherlock-human-session-v1\x00"))
	_, _ = hash.Write(serviceToken)
	var key [sha256.Size]byte
	copy(key[:], hash.Sum(nil))
	return key
}

func validHumanSessionInput(token []byte, principal HumanPrincipal, method, requestURI string) bool {
	return len(token) >= 32 && len(token) <= 512 && principal.Validate() == nil && validSessionRoute(method, requestURI)
}

func validSessionRoute(method, requestURI string) bool {
	if len(requestURI) < len("/internal/admin/v1/") || len(requestURI) > 2048 ||
		!strings.HasPrefix(requestURI, "/internal/admin/v1/") || strings.ContainsAny(requestURI, "\x00\r\n") {
		return false
	}
	switch method {
	case "GET", "POST", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}
