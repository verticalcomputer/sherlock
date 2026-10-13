package domain

import "strings"

// GPUObservationIdentity describes a scoped read projection, not inventory
// enrollment authority. Canonical identifies an exact physical UUID; unresolved
// legacy index/device keys remain separate evidence and never imply a UUID.
type GPUObservationIdentity struct {
	EntityKey       string
	NodeID          StableNodeID
	PhysicalGPUUUID PhysicalGPUUUID
	Canonical       bool
}

// ResolveGPUObservationIdentity reconciles the existing EntityIdentity.Key()
// representation with the legacy node/<node>/gpu/<token> representation. Only
// an exact UUID in the key or consistent UUID label proves physical identity.
// Source and cluster always come from explicit persisted scope, never exporter
// metadata. No index, instance, device, or hostname alias supplies a mapping.
func ResolveGPUObservationIdentity(cluster ClusterID, source SourceID, observation Observation) (GPUObservationIdentity, bool) {
	if cluster == "" || source == "" || observation.ClusterID != cluster || observation.SourceID != source {
		return GPUObservationIdentity{}, false
	}
	parts := strings.Split(observation.EntityKey, "/")
	var node, gpu, token string
	canonical := false
	switch {
	case len(parts) == 5 && parts[0] == string(cluster) && parts[1] == string(EntityGPU) && parts[4] == "":
		node, gpu = parts[2], parts[3]
		if gpu == "" {
			return GPUObservationIdentity{}, false
		}
		canonical = true
	case len(parts) == 4 && parts[0] == "node" && parts[2] == "gpu":
		node, token = parts[1], parts[3]
		if !validDCGMIdentityToken(token) || strings.HasPrefix(token, "MIG-") {
			return GPUObservationIdentity{}, false
		}
		if strings.HasPrefix(token, "GPU-") {
			gpu = token
			canonical = true
		}
	default:
		return GPUObservationIdentity{}, false
	}
	if !validDCGMIdentityToken(node) {
		return GPUObservationIdentity{}, false
	}
	var labelNode, labelGPU string
	for _, label := range observation.Labels {
		switch label.Name {
		case "Hostname", "hostname":
			if label.Value == "" {
				continue
			}
			if labelNode != "" && labelNode != label.Value {
				return GPUObservationIdentity{}, false
			}
			labelNode = label.Value
		case "UUID", "uuid":
			if label.Value == "" {
				continue
			}
			if labelGPU != "" && labelGPU != label.Value {
				return GPUObservationIdentity{}, false
			}
			labelGPU = label.Value
		case "GPU_I_ID", "GPU_I_PROFILE", "GPU_CI_ID", "gpu_instance_id", "compute_instance_id", "MIG_UUID":
			return GPUObservationIdentity{}, false
		}
	}
	if labelNode != "" && labelNode != node || labelGPU != "" && gpu != "" && labelGPU != gpu {
		return GPUObservationIdentity{}, false
	}
	if labelGPU != "" {
		gpu = labelGPU
		canonical = true
	}
	identity := GPUObservationIdentity{EntityKey: observation.EntityKey, NodeID: StableNodeID(node), Canonical: canonical}
	if !canonical {
		return identity, true
	}
	if !validDCGMIdentityToken(gpu) || !strings.HasPrefix(gpu, "GPU-") {
		return GPUObservationIdentity{}, false
	}
	entity, err := CreateEntityIdentity(EntityIdentity{ClusterID: cluster, Kind: EntityGPU, NodeID: StableNodeID(node), PhysicalGPUUUID: PhysicalGPUUUID(gpu)})
	if err != nil {
		return GPUObservationIdentity{}, false
	}
	identity.EntityKey, identity.PhysicalGPUUUID = entity.Key(), entity.PhysicalGPUUUID
	return identity, true
}
