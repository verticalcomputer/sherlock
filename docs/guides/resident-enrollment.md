# Enroll a resident telemetry identity

This procedure describes the implemented operator-mediated identity flow. Use it
only for an approved exact binary and qualification target. It does not install a
service, approve workload impact or qualify a client fleet. See [current status](../../next.md),
[release review](release-review.md) and [identity reference](../reference/telemetry/node-identity.md).

## Prerequisites

- Review exact cluster, expected node and inventory revision, gateway collector,
  source IDs/profiles, node key ID and enrollment ID. Linux profiles are history-only.
- Independently approve separate node-CA fingerprint, gateway CA/SPKI and control
  CA/SPKI. Keep the node CA private key at the configured central issuer. The node
  holds its own signing key; the gateway holds its existing collector credential.
- Prepare owner-only local configuration and identity directories. Files containing
  keys, tokens, CSR requests and bundles are protected; preserve ownership journals
  across retry, renewal and explicit updates. No token belongs in command arguments,
  logs, Git or public artifacts.
- Configure the optional central node issuer and required expected inventory before
  enrollment. Administrative access is a separate protected local operator action.
  Supplied `--actor` is attribution, not a verified human login.

Commands below use placeholder paths and IDs that must be replaced by the reviewed
values. They are individual role-specific steps, not a script to run on one machine.

## 1. Create the node key and public request

On the approved node, use the exact intended enrollment/key identity:

```sh
umask 077
sherlock-node-agent identity-request \
  --directory /absolute/private/node-identity \
  --cluster REVIEWED_CLUSTER --node REVIEWED_NODE \
  --enrollment REVIEWED_ENROLLMENT --key REVIEWED_KEY \
  > /absolute/private/node-request.json
```

The private key remains local. Repeating this command resumes the same protected
key/request; it does not silently replace a corrupt or differently scoped identity.
Deliver only the public request through the approved protected operator channel.

## 2. Approve enrollment and mint a CSR-bound token

At central administration, prepare the reviewed enrollment JSON from
[EnrollmentRequest](../../internal/store/postgres/telemetry_store.go). Bind its
`public_key_base64` to the request, and map every declared Linux source ID to the
exact `linux.host.v1` or `linux.rootfs.v1` profile in `source_profiles`.
Omission retains `fixture.v1`; a Linux node cannot mix fixture sources. Source
profiles and version/build/pin scope are immutable; changes require explicit new
enrollment, preserving old ownership evidence.

```sh
sherlock-admin telemetry enroll \
  --enrollment /absolute/private/enrollment.json \
  --expected-revision 0 --actor REVIEWED_OPERATOR
sherlock-admin telemetry mint-node-token \
  --cluster REVIEWED_CLUSTER --collector REVIEWED_GATEWAY \
  --request /absolute/private/node-request.json \
  --expected-revision REVIEWED_CONTROL_REVISION --actor REVIEWED_OPERATOR \
  --token-output /absolute/private/new-bootstrap-token
```

Use the actual current control revision. The token is bound to the exact CSR and
scope, expires for first consumption within ten minutes, and is written to a new
protected file. Transfer it and the public request to the approved gateway through
the protected operator channel. Do not copy the node private key.

## 3. Relay through the gateway's authenticated control connection

For a Linux enrollment, the reviewed gateway configuration selects
`resident_sources: true` and `fixture_only: false`. It must explicitly list the
enrollment. Fixture-only mode rejects Linux grants; neither/both modes are invalid.
Resident mode permits the closed known profiles and does not create enrollment.

```sh
sherlock-gateway relay-identity \
  --config /absolute/private/gateway.json \
  --request /absolute/private/node-request.json \
  --token-file /absolute/private/new-bootstrap-token \
  --bundle-output /absolute/private/new-node-bundle.json
```

Do not add `--fixture` or `--telemetry` to this subcommand: mode comes from the
configuration. Relay does not open a telemetry listener or journal. It fetches a
current grant, checks source mode and CSR/key scope, then requests atomic issuance
through collector authentication and the independently pinned control connection.
The returned node CA must match the configured node CA.

If the response is lost after issuance commits, retry the same token and exact CSR
using a new output path as needed. The store returns the original unexpired bundle
only after current authority checks; it does not issue another certificate. A
revoked enrollment/key cannot use replay to recover authority.

## 4. Import and validate on the node

Deliver the public bundle back through the protected channel. Use the independently
approved node-CA fingerprint, never a fingerprint copied from an untrusted response:

```sh
sherlock-node-agent identity-import \
  --directory /absolute/private/node-identity \
  --bundle /absolute/private/new-node-bundle.json \
  --node-ca-sha256 REVIEWED_NODE_CA_SHA256
```

Import verifies certificate scope, original CSR/key, chain, lifetime, usages and
CA pin before publishing the local bundle. It preserves the previous identity on
failure. Node runtime configuration uses `identity_dir` plus `node_ca_sha256` and
the exact enrolled scope/profiles; raw certificate/key paths are an alternative,
not an additional identity source. The node's gateway CA/SPKI pin is independent.

An authorized canary uses node `--linux` and gateway `--telemetry` with their reviewed
configurations. Validate scoped history, missing states and replay before any SSH
retirement. This guide does not supply a service installer or fleet rollout approval.

## Renewal and failures

Renewal is manual: mint a new token for the same approved CSR/key, relay and import
before expiry, then use a separately qualified restart/reload procedure. Runtime
TLS configuration is loaded at startup; importing a file is not proof a running
process adopted it. There is no automated renewal loop. Signing-key rotation is a
separate authority and ownership operation, not an inferred result of renewal.

Never reset journals, regenerate keys or change enrollment scope to make a retry
pass. Preserve evidence on expired/revoked authority, changed pins, unavailable
issuer, schema incompatibility or ambiguous local state. Follow the reviewed
[removal and rollback requirements](release-review.md) if the canary cannot continue.
