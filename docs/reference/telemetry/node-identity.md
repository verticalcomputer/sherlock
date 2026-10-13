# GP-06f node identity bootstrap and certificate lifecycle

This extends [telemetry v1](protocol.md). Code owners are
[identity primitives](../../../internal/nodeidentity),
[transactional issuance](../../../internal/store/postgres/telemetry_identity.go),
[local relay](../../../internal/gatewaytelemetry/identity.go), and
[node commands](../../../cmd/sherlock-node-agent/identity.go).
See [current status](../../../next.md) for qualification limits.

## Authority and bootstrap

The node generates an Ed25519 private key locally and emits a public signed CSR.
The private key never leaves the node. The protected local operator approves the
exact cluster/node/enrollment/key, immutable enrollment revision, CSR DER digest
and SPKI digest. The current enrolled ACTIVE key must match the CSR public key.
A cryptographically random 256-bit token is delivered as a protected 0600 file;
only its domain-separated hash is persisted by the cloud. First consumption must
occur within ten minutes. No token, certificate or CSR can create an enrollment.

The head gateway relays the token and CSR through its existing authenticated
collector TLS route. There is no unauthenticated node listener or bootstrap
exception to required node mTLS. A separately configured dedicated cloud-side
node CA issues client certificates. Its private key is never sent to the gateway
or node. The node CA must differ from the collector CA and the gateway server CA.
Issuance is optional and fails closed if the protected issuer is unavailable.

Inside the cloud transaction, lock the token and current enrollment authority,
check authenticated gateway membership, inventory/source authority, token expiry,
CSR signature, exact binding and ACTIVE key. Generate a candidate certificate and
persist the actual certificate, public bundle, immutable issuance receipt and
consumed marker atomically. Signing before commit has no external publication.
Only the committed certificate may be returned. A rollback publishes nothing.
Concurrent candidates cannot produce two committed certificates for one token.

After a lost response, the same token, exact CSR DER and exact scope may retrieve
the original committed bundle until its original certificate expiry, after current
authority and non-revoked key checks. This is idempotent retrieval, never another
issuance or extension. Different bindings fail. A consumed token cannot mint a
replacement certificate. Retrieval under VERIFY_ONLY may return the historical
public certificate; that does not grant fresh session or TLS authority. Expired or
revoked identities fail before receipt lookup. Receipt retention/pruning remains
a separate qualification gate; never forget a consumed token while it can replay.

The foundation permits at most eight unconsumed unexpired tokens and 256 retained
bootstrap records per enrollment. Reaching either bound returns backpressure
without a secret or candidate certificate. There is no automatic history pruning;
production renewal capacity and safe consumed-token retention remain explicit gates.

## Certificate and import contract

`internal/nodeidentity` supplies pure CSR, issuer and import verification helpers.
The v1 issuer is one explicit Ed25519 self-signed dedicated node CA. Requests are
bounded PEM PKCS#10 with an empty subject and no SANs, attributes or requested
extensions; the issuer constructs identity from approved authority. The client
certificate has exactly one URI SAN:
`spiffe://sherlock/node/<cluster>/<node>/<enrollment>/<key>`, no DNS/IP/email SAN,
digitalSignature key usage and only clientAuth extended usage. Identifiers use
the existing closed node URI grammar. Certificate lifetime is at most 24 hours;
NotBefore may be backdated one minute. Issuance refuses an insufficient CA lifetime.

Node import verifies the original locally persisted CSR and private key, exact
scope/public key/CSR and SPKI digests, exact SAN/usages, signed CA chain, certificate
times and an independently approved SHA-256 node CA certificate fingerprint.
The returned CA is not its own trust anchor. Existing protected gateway server CA
and SPKI pin configuration remains independent and cannot be replaced by import.
Only after verification is the public bundle atomically published. The transport
loads matching key/certificate without exposing private material in output.

## Files, renewal and failure behavior

Local helpers use an owned 0700 directory, owned regular 0600 files, persistent
exclusive lock, no-follow relative opens, bounded reads, atomic same-directory
rename and file/directory fsync. Existing insecure, symlinked, hard-linked,
corrupt or mismatched files fail closed; keys are never silently regenerated.
An interrupted request resumes with its durable existing key. A failed import
does not replace the current public identity. Errors use fixed redacted sentinels.

Renewal is an operator-mediated token/CSR relay followed by node import. There
is no automatic renewal loop or node-mTLS renewal HTTP endpoint. A new approved
token can bind the same CSR/SPKI; current cloud authority is checked and no key
change is inferred. Renew before expiry and qualify the reload/restart procedure;
VERIFY_ONLY keys receive no new certificate.

The `relay-identity` helper accepts exactly one configured mode. Fixture-only
mode admits only fixture grants; resident mode admits the closed known source
profiles, including Linux host/root. Both modes check current cloud authority,
exact CSR/key/enrollment scope and the configured node CA before returning a
bundle. The [manual enrollment guide](../../guides/resident-enrollment.md) explains
operator steps, retry and import. Neither relay nor import starts a service.

An active TLS key can replay sealed batches
signed by a separately authorized old key only for its exact known old session.
Compromise revocation denies ingress and retrieval before deduplication. No
automatic updates, commands, workload actions or repair authority are introduced.

## Acceptance evidence

Pure tests must prove CSR possession/binding, exact SAN/usages, CA/key mismatch,
foreign key/scope, expiry boundaries, malformed/oversized PEM, insecure/symlink/
hard-link files, crash-resume request identity and failed-import preservation.
Store/transport qualification separately proves atomic consume, concurrent/lost
response replay, token expiry, revocation-before-retrieval, gateway ownership and
optional-issuer failure. Real binaries, renewal flow and exact candidate source/
build materials remain required. No generated fixture CA is a release identity.
