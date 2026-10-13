# Hand-authored Slurm data_parser/v0.0.40 fixtures

These scrubbed fixtures are minimal examples authored from the field mappings
in SchedMD Slurm tag `slurm-23-11-10-1`, commit
`d3e78848f72745ceb80e2a6bebdbcf3cfd7462b1`:

- [`parsers.c`](https://github.com/SchedMD/slurm/blob/d3e78848f72745ceb80e2a6bebdbcf3cfd7462b1/src/plugins/data_parser/v0.0.40/parsers.c)
- [`api.c`](https://github.com/SchedMD/slurm/blob/d3e78848f72745ceb80e2a6bebdbcf3cfd7462b1/src/plugins/data_parser/v0.0.40/api.c)

The relevant upstream mappings are `NODE`, `PARTITION_INFO`, `JOB_INFO`,
accounting `JOB`, and `OPENAPI_META`. In particular, partition membership is
`nodes/configured`; current-job lifecycle fields are top-level; accounting
state and times are nested under `state/current` and `time/*`; and the metadata
names the `data_parser/v0.0.40` plugin. Current-job `TIMESTAMP_NO_VAL` fields
use the default `{set,infinite,number}` representation; accounting `TIMESTAMP`
fields remain integer seconds.

These are schema support fixtures, not command captures. They do not establish
compatibility with a deployed Slurm release, site plugins, permissions,
federation settings, accounting visibility, or command output. Deployment
qualification still requires authorized scrubbed captures from that target.
