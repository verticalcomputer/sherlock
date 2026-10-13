package main

import "testing"

func TestClearDestroysTemporarySecretBytes(t *testing.T) {
	value := []byte("temporary-service-secret")
	clear(value)
	for index, item := range value {
		if item != 0 {
			t.Fatalf("byte %d was not cleared", index)
		}
	}
}
