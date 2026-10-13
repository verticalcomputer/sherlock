# Synthetic GPU process fixtures, contract v1

These files are hand-authored, not captures from a deployed NVIDIA/Linux
version. They test the exact four-column `nvidia.compute_processes.v1` query
contract and the modern Linux 52-field `/proc/PID/stat` layout. Compatibility
with a deployed driver or kernel remains unverified.

`compute.csv` has `gpu_uuid,pid,gpu_instance_id,compute_instance_id`, without a
header. The fixture's local configuration independently asserts MIG disabled,
complete compute-query visibility and the source's PID namespace. `N/A` alone
does not prove those assertions. `42.stat` and `43.stat` put start ticks 100 and
200 in field 22. Their other numeric fields are placeholders. The deliberately
sensitive `comm` string tests that names never reach normalized evidence.

Tests supply the trusted cluster/node/GPU map, boot UUID and namespace, query
interval, before/after read timestamps, and one synthetic scheduler membership
receipt. The receipt names the full job submit/attempt and process incarnation;
it is a fixture of a future trusted producer's evidence, not a claim that Slurm
or this adapter currently produces it. PID 43 has no receipt and is unmanaged.
Test mutations cover reuse, gaps, unknown identities, foreign scope, unsupported
formats, malformed records, limits and redaction.
