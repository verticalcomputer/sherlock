# V1 assessment fixtures

All asset identifiers here are synthetic. The config uses the versioned
contract example. Each fact body uses canonical JSON, and its content identity
includes the fixture run ID and canonical scope.

The deterministic suite tests source eligibility deferred by a future source
timestamp, entry and expiry with an exact microsecond boundary, a malformed
zero-arm result and trusted fallback, independent urgent escalation, repeated
sample provenance, an immutable late conflict, and qualified telemetry preview
and annotation routing. The test asserts the terminal outcomes for all five
arms and checks additional decisions and evidence separately.

The `unavailable-source-time.json` fixture uses an invented time window and
an unknown label. Its source-time simulation has empty observation and legacy
capture sets, exercising how reports represent unavailable evidence and rule
results.

When updating a fixture, regenerate content identities with the V1
canonical encoding helpers, use a new run ID for policy/config changes, and
state how labels and legacy captures were obtained. Keep real identity
mappings, proprietary observations, and credentials outside the fixtures.
