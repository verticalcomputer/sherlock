package domain

import (
	"encoding/json"
	"fmt"
	"regexp"
)

var processBootPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var processNamespacePattern = regexp.MustCompile(`^pid:\[[1-9][0-9]{0,19}\]$`)

// GPUProcessIdentity identifies a Linux process incarnation, not a PID alone.
// StartTicks is /proc/PID/stat field 22, in ticks since BootID. PIDNamespace
// identifies the namespace in which both the GPU source and proc PID are read.
// Node reuses GP-02 identity; no display name or timestamp substitutes for it.
type GPUProcessIdentity struct {
	Node         EntityIdentity
	BootID       string
	PIDNamespace string
	PID          uint32
	StartTicks   uint64
}

func CreateGPUProcessIdentity(value GPUProcessIdentity) (GPUProcessIdentity, error) {
	node, err := CreateEntityIdentity(value.Node)
	if err != nil || node.Kind != EntityNode || !processBootPattern.MatchString(value.BootID) ||
		!processNamespacePattern.MatchString(value.PIDNamespace) || value.PID == 0 || value.PID > 2147483647 || value.StartTicks == 0 {
		return GPUProcessIdentity{}, fmt.Errorf("invalid GPU process identity")
	}
	value.Node = node
	return value, nil
}

// Key refuses incomplete identities; callers must not deduplicate unknown
// incarnations by PID. JSON avoids delimiter ambiguity in scoped identifiers.
func (value GPUProcessIdentity) Key() (string, error) {
	validated, err := CreateGPUProcessIdentity(value)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(validated)
	return string(encoded), err
}
