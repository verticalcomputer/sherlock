package modelprovider

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// DecodeWarmingChoice checks the complete document for ambiguous JSON and reads
// the exact action field. Usage, probability and confidence are informational.
func DecodeWarmingChoice(data []byte, model string) (string, error) {
	invalid := errors.New("invalid warming decision response")
	var envelope map[string]json.RawMessage
	if decodeStrict(data, &envelope) != nil || envelope["error"] != nil {
		return "", invalid
	}
	var name string
	if json.Unmarshal(envelope["model"], &name) != nil {
		return "", invalid
	}
	if name != model {
		suffix, ok := strings.CutPrefix(name, model+"-")
		if !ok {
			return "", invalid
		}
		if _, err := time.Parse("20060102", suffix); err != nil {
			return "", invalid
		}
	}
	var answers map[string]map[string]json.RawMessage
	if json.Unmarshal(envelope["answers"], &answers) != nil || len(answers) != 1 {
		return "", invalid
	}
	var kind, choice string
	action := answers["action"]
	if json.Unmarshal(action["type"], &kind) != nil || kind != "choice" || json.Unmarshal(action["choice"], &choice) != nil || (choice != "NOTIFY" && choice != "WATCH") {
		return "", invalid
	}
	return choice, nil
}
