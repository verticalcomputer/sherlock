# Sherlock documentation

Read [current status and next work](../next.md) first for what exists in this
revision and what remains unqualified. The [roadmap](../implementation.md) owns
checkpoint order; it is not a deployment or acceptance record.

| I want to… | Start here |
| --- | --- |
| Understand the end-to-end system | [Architecture](architecture.md) |
| Build, test or contribute | [Repository README](../README.md), [contributing](../CONTRIBUTING.md) |
| Find reliable context or maintain docs | [Development and knowledge](development.md) |
| Understand the resident agent's permissions | [Resident design](reference/telemetry/overview.md), [Linux sources](reference/telemetry/linux-sources.md) |
| Enroll or renew a resident identity | [Manual enrollment](guides/resident-enrollment.md) |
| Integrate telemetry transport | [Protocol](reference/telemetry/protocol.md), [node identity](reference/telemetry/node-identity.md) |
| Review durability, replay or resource bounds | [Node runtime](reference/telemetry/node-runtime.md), [gateway runtime](reference/telemetry/gateway-runtime.md), [ownership retirement](reference/telemetry/ownership-retirement.md) |
| Prepare or verify a release | [Candidate review](guides/release-review.md), [signing and verification](guides/release-signing.md) |
| Export reviewed private source for publication | [Source export](guides/source-export.md) |
| Use generated API clients | [SDK guide](../sdk/README.md) |
| Understand investigation evidence selection | [Runtime context selection](../internal/investigationcontext/README.md) |
| Report a security problem or check licensing | [Security](../SECURITY.md), [license](../LICENSE), [attribution](../NOTICE), [third-party notices](../THIRD_PARTY_NOTICES.md) |

## How these documents relate

- **Guides** explain a task and its prerequisites.
- **References** own interfaces and failure semantics, with links to implementing code.
- **Current status** separates implemented code, release state and unverified live gates.
- **Planning** preserves the GP sequence and R1/R2/R3 boundaries.
- **History** contains optional dated evidence. It is excluded from default context
  and does not override current reference docs or grant operating authority.

The existing [Linux checkpoint record](history/LINUX_RESIDENT_CHECKPOINT_20261013.md)
is retained as historical evidence. New per-change checkpoint files are not required;
see [what to commit](development.md#what-to-commit).

Use the [scenario test bed](guides/test-bed.md) for repeatable investigation/context
regressions and comparison reports against synthetic incident worlds.
