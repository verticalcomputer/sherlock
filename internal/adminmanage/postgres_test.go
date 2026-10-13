package adminmanage

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewPostgresStoreRejectsNilPool(t *testing.T) {
	store, err := NewPostgresStore(nil)
	if store != nil || !errors.Is(err, ErrInvalid) {
		t.Fatalf("store=%v err=%v", store, err)
	}
}

func TestValidateLimit(t *testing.T) {
	for _, test := range []struct {
		limit int
		valid bool
	}{{0, false}, {1, true}, {2000, true}, {2001, false}, {-1, false}} {
		err := validateLimit(test.limit)
		if (err == nil) != test.valid {
			t.Errorf("limit %d: err=%v", test.limit, err)
		}
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Errorf("limit %d: unexpected error %v", test.limit, err)
		}
	}
}

func TestValidateInvestigationID(t *testing.T) {
	for _, test := range []struct {
		id    string
		valid bool
	}{{"investigation-1", true}, {"inv:one.two_three", true}, {"", false}, {"bad/id", false}, {"bad id", false}, {strings.Repeat("x", 129), false}} {
		err := validateInvestigationID(test.id)
		if (err == nil) != test.valid || (err != nil && !errors.Is(err, ErrInvalid)) {
			t.Errorf("ID %q: err=%v valid=%t", test.id, err, test.valid)
		}
	}
}

func TestValidateMutationAudit(t *testing.T) {
	valid := MutationAudit{
		EventID:            "event-1",
		EventKind:          EventClusterUpdated,
		ReasonCode:         "DISPLAY_NAME_CHANGED",
		SessionFingerprint: make([]byte, 32),
		RequestID:          "request-1",
		OccurredAt:         time.Now(),
	}
	if err := validateMutationAudit(valid, EventClusterUpdated); err != nil {
		t.Fatalf("valid audit rejected: %v", err)
	}

	tests := map[string]func(*MutationAudit){
		"missing event ID":      func(audit *MutationAudit) { audit.EventID = "" },
		"long event ID":         func(audit *MutationAudit) { audit.EventID = strings.Repeat("x", 129) },
		"wrong event kind":      func(audit *MutationAudit) { audit.EventKind = EventClusterRemoved },
		"missing reason":        func(audit *MutationAudit) { audit.ReasonCode = "" },
		"long reason":           func(audit *MutationAudit) { audit.ReasonCode = strings.Repeat("x", 129) },
		"long request ID":       func(audit *MutationAudit) { audit.RequestID = strings.Repeat("x", 129) },
		"short fingerprint":     func(audit *MutationAudit) { audit.SessionFingerprint = make([]byte, 31) },
		"missing occurred time": func(audit *MutationAudit) { audit.OccurredAt = time.Time{} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			audit := valid
			mutate(&audit)
			if err := validateMutationAudit(audit, EventClusterUpdated); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestMutationMethodsRejectInvalidInputsBeforeDatabaseAccess(t *testing.T) {
	store := &PostgresStore{}
	audit := MutationAudit{
		EventID:            "event-1",
		EventKind:          EventClusterUpdated,
		ReasonCode:         "DISPLAY_NAME_CHANGED",
		SessionFingerprint: make([]byte, 32),
		OccurredAt:         time.Now(),
	}
	if err := store.UpdateCluster(t.Context(), "", "name", nil, audit); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty ID: %v", err)
	}
	if err := store.UpdateCluster(t.Context(), "cluster", " ", nil, audit); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty name: %v", err)
	}
	audit.EventKind = EventClusterRemoved
	if err := store.RemoveCluster(t.Context(), "cluster", time.Time{}, audit); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty removal time: %v", err)
	}
}
