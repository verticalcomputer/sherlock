package main

import (
	"strings"
	"testing"
)

func TestAssessmentOperatorScopeAndBounds(t *testing.T) {
	good := []string{
		"status --cluster c --enrollment e",
		"history --cluster c --enrollment e --occurrence o --after 2 --after-audit 1",
		"acknowledge --cluster c --enrollment e --occurrence o --expected-version 2 --actor local",
		"maintenance --cluster c --enrollment e --occurrence o --expected-version 2 --actor local --seconds 0 --reason clear",
		"maintenance --cluster c --enrollment e --occurrence o --expected-version 2 --actor local --seconds 86400 --reason scheduled",
		"disable-notifications --cluster c --enrollment e --expected-version 2 --actor local",
	}
	for _, s := range good {
		if _, e := parseAssessmentCommand(strings.Fields(s)); e != nil {
			t.Fatalf("%s: %v", s, e)
		}
	}
	bad := []string{
		"history --cluster c --cluster other --enrollment e --occurrence o",
		"history --cluster c --enrollment e --occurrence o --actor local",
		"acknowledge --cluster c --enrollment e --occurrence o --actor local",
		"maintenance --cluster c --enrollment e --occurrence o --expected-version 2 --actor local --seconds 86401 --reason scheduled",
		"maintenance --cluster c --enrollment e --occurrence o --expected-version 2 --actor local --seconds 1",
		"disable-notifications --cluster c --enrollment e --expected-version 2 --actor local --occurrence o",
	}
	for _, s := range bad {
		if _, e := parseAssessmentCommand(strings.Fields(s)); e == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}
