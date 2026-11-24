package modelprovider

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DecodeWarmingDecision accepts a routing decision only after checking the
// complete output document. An invalid response cannot authorize a notification.
func DecodeWarmingDecision(data []byte) (action, reason string, err error) {
	var fields map[string]string
	if err := decodeStrict(data, &fields); err != nil {
		return "", "", &ResponseValidationError{Stage: ResponseStructuredDecode, err: err}
	}
	action, reason = fields["action"], fields["reason"]
	if len(fields) != 2 || (action != "WATCH" && action != "NOTIFY") || !validText(reason, 1024) || !utf8.Valid(data) || strings.IndexFunc(reason, unicode.IsControl) >= 0 {
		return "", "", &ResponseValidationError{Stage: ResponseSemanticValidation, err: fmt.Errorf("invalid warming decision")}
	}
	return action, reason, nil
}
