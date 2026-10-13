package collectorcontrol

import (
	"context"
	"errors"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/networkmonitor"
)

type networkRecorder struct {
	calls int
	err   error
}

func (f *networkRecorder) RecordNetworkCycle(_ context.Context, cluster, collector string, _ networkmonitor.Cycle) error {
	f.calls++
	if cluster != "cluster-1" || collector != "collector-1" {
		return errors.New("identity not bound")
	}
	return f.err
}
func TestNetworkRouteRequiresAuthenticationProtocolAndBoundEnrollment(t *testing.T) {
	transport, _, _, _, _ := newTestTransport(t)
	f := &networkRecorder{}
	transport.ConfigureNetworkMonitoring(f)
	for _, tc := range []struct {
		version string
		auth    bool
		body    string
		code    int
	}{{"2", false, `{}`, 401}, {"1", true, `{}`, 426}, {"2", true, `{"unknown":1}`, 400}, {"2", true, `{}`, 200}} {
		r := serveTyped(transport, "POST", "/collector/v2/network/polls", tc.body, tc.version, tc.auth)
		if r.Code != tc.code {
			t.Fatalf("%+v got %d", tc, r.Code)
		}
	}
	if f.calls != 1 {
		t.Fatal(f.calls)
	}
	f.err = errors.New("not enrolled")
	if r := serveTyped(transport, "POST", "/collector/v2/network/polls", `{}`, "2", true); r.Code != 409 {
		t.Fatal(r.Code)
	}
}
