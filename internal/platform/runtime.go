package platform

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }

type RandomIDGenerator struct{}

func (RandomIDGenerator) NewID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate random ID: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return hex.EncodeToString(value[:]), nil
}
