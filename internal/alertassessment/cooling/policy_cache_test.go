package cooling

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

func TestPolicyDecodeCacheRetainsStrictIdentityAndValueIsolation(t *testing.T) {
	original := DefaultPolicy()
	payload, err := a.NewPayload(CategoryID, "policy", 1, original)
	if err != nil {
		t.Fatal(err)
	}
	first, err := decodePolicy(t.Context(), payload)
	if err != nil || first != original {
		t.Fatalf("initialdecode %+v %v", first, err)
	}
	first.RapidDeltaC++
	again, err := decodePolicy(t.Context(), payload)
	if err != nil || again != original {
		t.Fatal("returned policy aliases cached value")
	}
	canonical := bytes.Clone(payload.Body)
	// A caller may reuse its input buffer after the call. The cached witness
	// must own bytes so later mutation cannot turn an old digest into authority.
	payload.Body[0] = '['
	if _, err = decodePolicy(t.Context(), payload); err == nil {
		t.Fatal("mutated body reused old cached hash")
	}
	payload.Body = canonical
	tests := map[string]func(*a.Payload){
		"category": func(p *a.Payload) { p.Category = "other" },
		"kind":     func(p *a.Payload) { p.Kind = "tracker" },
		"schema":   func(p *a.Payload) { p.Schema++ },
		"hash":     func(p *a.Payload) { p.Hash = a.Hash("different", CategoryID, 1, p.Body) },
		"noncanonical": func(p *a.Payload) {
			p.Body = append([]byte(" "), p.Body...)
			p.Hash = a.Hash("policy", CategoryID, 1, p.Body)
		},
		"duplicate_field": func(p *a.Payload) {
			p.Body = append(bytes.Clone(p.Body[:len(p.Body)-1]), []byte(`,"profile":"cooling-experiment-v1"}`)...)
			p.Hash = a.Hash("policy", CategoryID, 1, p.Body)
		},
		"invalid_policy_with_valid_hash": func(p *a.Payload) {
			invalid := original
			invalid.CadenceSeconds = 0
			*p, _ = a.NewPayload(CategoryID, "policy", 1, invalid)
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			mutated := payload
			mutated.Body = bytes.Clone(payload.Body)
			change(&mutated)
			for i := 0; i < 2; i++ {
				if _, err := decodePolicy(t.Context(), mutated); err == nil {
					t.Fatal("invalid policy accepted")
				}
			}
		})
	}
	if got, err := decodePolicy(t.Context(), payload); err != nil || got != original {
		t.Fatal("invalid cache misses poisoned valid policy")
	}
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if _, err := decodePolicy(canceled, payload); !errors.Is(err, context.Canceled) {
		t.Fatalf("cached hit ignored cancellation: %v", err)
	}
}

func TestPolicyDecodeCacheConcurrentDistinctPolicies(t *testing.T) {
	policies := []Policy{DefaultPolicy(), DefaultPolicy()}
	policies[1].RapidDeltaC++
	payloads := make([]a.Payload, len(policies))
	for i, p := range policies {
		var err error
		payloads[i], err = a.NewPayload(CategoryID, "policy", 1, p)
		if err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	failures := make(chan error, 16)
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			for i := 0; i < 32; i++ {
				want := (index + i) % len(policies)
				got, err := decodePolicy(t.Context(), payloads[want])
				if err != nil || got != policies[want] {
					failures <- fmt.Errorf("policy%d result %+v: %v", want, got, err)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}
