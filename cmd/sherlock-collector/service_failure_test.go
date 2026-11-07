package main

import (
	"errors"
	"github.com/verticalcomputer/sherlock/internal/gpussh"
	"github.com/verticalcomputer/sherlock/internal/servicefailure"
	"testing"
)

func TestServiceExitStatusSeparatesOperatorIntervention(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want int
	}{{servicefailure.ErrAuthentication, 77}, {servicefailure.ErrConfiguration, 78}, {servicefailure.ErrPackExpired, 79}, {gpussh.ErrBlocked, 78}, {errors.New("temporary transport failure"), 1}} {
		if got := serviceExitCode(tt.err); got != tt.want {
			t.Errorf("status=%d want=%d", got, tt.want)
		}
	}
}
