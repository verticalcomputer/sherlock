package main

import (
	"testing"

	"github.com/verticalcomputer/sherlock/internal/config"
)

func TestPrivateAdminAPIRemainsDisabledWithoutDatabaseComposition(t *testing.T) {
	server, err := configureAdminAPIServer(config.API{}, nil, nil)
	if err != nil || server != nil {
		t.Fatalf("disabled private admin API = %#v, %v", server, err)
	}
}

func TestClearBytesDestroysTemporaryServiceCredential(t *testing.T) {
	value := []byte("temporary-admin-service-credential")
	clearBytes(value)
	for index, item := range value {
		if item != 0 {
			t.Fatalf("byte %d was not cleared", index)
		}
	}
}
