package redfish

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adapters/source"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func fixtureClient(t *testing.T, handler http.HandlerFunc, maxRecords int) (*Client, func()) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := NewClient(Config{BaseURL: server.URL, Username: "readonly", Password: "secret", Timeout: time.Second, MaxRecords: maxRecords, TLSConfig: &tls.Config{RootCAs: roots}})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return client, server.Close
}

func TestInventoryNormalizesAndReportsPerTargetFailure(t *testing.T) {
	client, closeServer := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "readonly" || password != "secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/redfish/v1/Systems/sys-1":
			_, _ = w.Write([]byte(`{"Id":"sys-1","Name":"GPU node","Manufacturer":"Example","Model":"HGX","SerialNumber":"S1","PowerState":"On","Status":{"Health":"OK"}}`))
		case "/redfish/v1/Systems/sys-2":
			http.Error(w, "fixture failure", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}, 8)
	defer closeServer()
	result, err := client.Inventory(context.Background(), []string{"sys-1", "sys-2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 1 || result.Records[0].Model != "HGX" || len(result.Failures) != 1 || result.Failures[0].Target != "sys-2" || !result.Failures[0].Retryable {
		t.Fatalf("result = %#v", result)
	}
}

func TestSensorsAndEventLogFollowOnlyFixedCollectionMembers(t *testing.T) {
	client, closeServer := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redfish/v1/Chassis/chassis-1/Sensors":
			_, _ = w.Write([]byte(`{"Members":[{"@odata.id":"/redfish/v1/Chassis/chassis-1/Sensors/temp-1"}]}`))
		case "/redfish/v1/Chassis/chassis-1/Sensors/temp-1":
			_, _ = w.Write([]byte(`{"Id":"temp-1","Name":"GPU inlet","Reading":27.5,"ReadingUnits":"Cel","Status":{"Health":"OK"}}`))
		case "/redfish/v1/Systems/sys-1/LogServices/SEL/Entries":
			if r.URL.Query().Get("$top") != "2" {
				t.Errorf("top = %q", r.URL.Query().Get("$top"))
			}
			_, _ = w.Write([]byte(`{"Members":[{"@odata.id":"/redfish/v1/Systems/sys-1/LogServices/SEL/Entries/42"}]}`))
		case "/redfish/v1/Systems/sys-1/LogServices/SEL/Entries/42":
			_, _ = w.Write([]byte(`{"Id":"42","Severity":"Critical","Message":"Power supply lost","Created":"2026-08-20T10:00:00Z"}`))
		default:
			http.NotFound(w, r)
		}
	}, 8)
	defer closeServer()
	sensors, err := client.Sensors(context.Background(), []string{"chassis-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sensors.Records) != 1 || sensors.Records[0].Reading != "27.5" {
		t.Fatalf("sensors = %#v", sensors)
	}
	events, err := client.EventLog(context.Background(), "sys-1", "SEL", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(events.Records) != 1 || events.Records[0].ID != "42" || !events.Records[0].CreatedAt.Equal(time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("events = %#v", events)
	}
}

func TestEventLogRejectsUnsafeAndOversizedScope(t *testing.T) {
	requests := 0
	client, closeServer := fixtureClient(t, func(http.ResponseWriter, *http.Request) { requests++ }, 2)
	defer closeServer()
	for _, input := range []struct {
		system, service string
		limit           int
	}{{"sys/1", "SEL", 1}, {"sys-1", "../Managers", 1}, {"sys-1", "SEL", 3}} {
		_, err := client.EventLog(context.Background(), input.system, input.service, input.limit)
		var typed *source.Error
		if !errors.As(err, &typed) || typed.Code != domain.FailureInvalidArgument {
			t.Fatalf("error = %#v", err)
		}
	}
	if requests != 0 {
		t.Fatalf("made %d rejected requests", requests)
	}
}

func TestNewClientRequiresHTTPS(t *testing.T) {
	if _, err := NewClient(Config{BaseURL: "http://bmc.example", Username: "u", Password: "p", Timeout: time.Second}); err == nil {
		t.Fatal("HTTP Redfish origin accepted")
	}
}

func TestRedfishDoesNotForwardCredentialsAcrossRedirect(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		destinationCalls.Add(1)
		if _, _, ok := request.BasicAuth(); ok {
			t.Error("Redfish credential reached redirect destination")
		}
	}))
	defer destination.Close()
	client, closeServer := fixtureClient(t, func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL, http.StatusTemporaryRedirect)
	}, 8)
	defer closeServer()
	_, err := client.DiscoverCapabilities(context.Background())
	var typed *source.Error
	if !errors.As(err, &typed) || destinationCalls.Load() != 0 {
		t.Fatalf("error=%v destination calls=%d", err, destinationCalls.Load())
	}
}

func TestInventoryRejectsIncompleteCollectionMetadata(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		code domain.FailureCode
	}{
		{"members next link", `{"Members":[{"@odata.id":"/redfish/v1/Systems/sys-1"}],"Members@odata.nextLink":"/redfish/v1/Systems?$skip=1"}`, domain.FailureResultLimit},
		{"odata next link", `{"Members":[{"@odata.id":"/redfish/v1/Systems/sys-1"}],"@odata.nextLink":"/redfish/v1/Systems?$skip=1"}`, domain.FailureResultLimit},
		{"larger count", `{"Members":[{"@odata.id":"/redfish/v1/Systems/sys-1"}],"Members@odata.count":2}`, domain.FailureResultLimit},
		{"smaller count", `{"Members":[{"@odata.id":"/redfish/v1/Systems/sys-1"}],"Members@odata.count":0}`, domain.FailureMalformedResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			client, closeServer := fixtureClient(t, func(writer http.ResponseWriter, _ *http.Request) {
				requests++
				_, _ = writer.Write([]byte(test.body))
			}, 8)
			defer closeServer()
			_, err := client.Inventory(context.Background(), nil)
			var typed *source.Error
			if !errors.As(err, &typed) || typed.Code != test.code || requests != 1 {
				t.Fatalf("error=%v requests=%d", err, requests)
			}
		})
	}
}
