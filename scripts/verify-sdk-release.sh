#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
require_publishable=false
if [ "${1:-}" = "--require-publishable" ]; then
	require_publishable=true
elif [ "$#" -ne 0 ]; then
	echo "usage: $0 [--require-publishable]" >&2
	exit 2
fi

"$root/scripts/check-sdk-sync.sh"
go test "$root/sdk/go" "$root/test/contract" >/dev/null
npm --prefix "$root/sdk/typescript" run smoke >/dev/null

if command -v sha256sum >/dev/null 2>&1; then
	digest=$(sha256sum "$root/api/openapi/sherlock-v1.yaml" | awk '{print $1}')
else
	digest=$(shasum -a 256 "$root/api/openapi/sherlock-v1.yaml" | awk '{print $1}')
fi
contract_version=$(sed -n 's/.*"version": "\([^"]*\)".*/\1/p' "$root/api/openapi/sherlock-v1.yaml" | head -1)
typescript_version=$(sed -n 's/.*"version": "\([^"]*\)".*/\1/p' "$root/sdk/typescript/package.json" | head -1)
private=$(sed -n 's/.*"private": \([^,]*\).*/\1/p' "$root/sdk/typescript/package.json" | head -1)

if [ -z "$contract_version" ] || [ "$contract_version" != "$typescript_version" ]; then
	echo "OpenAPI and TypeScript package versions differ" >&2
	exit 1
fi
publishable=true
if [ "$private" != "false" ]; then
	publishable=false
fi
if $require_publishable && ! $publishable; then
	echo "TypeScript SDK remains private; external publication is not ready" >&2
	exit 1
fi

commit=$(git -C "$root" rev-parse HEAD)
dirty=false
if [ -n "$(git -C "$root" status --porcelain)" ]; then
	dirty=true
fi
generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
printf '{\n'
printf '  "schema_version": "sherlock.sdk-release-evidence/v1",\n'
printf '  "generated_at": "%s",\n' "$generated_at"
printf '  "git_commit": "%s",\n' "$commit"
printf '  "worktree_dirty": %s,\n' "$dirty"
printf '  "contract_version": "%s",\n' "$contract_version"
printf '  "contract_sha256": "%s",\n' "$digest"
printf '  "go_contract_tests": "PASSED",\n'
printf '  "typescript_build_and_smoke": "PASSED",\n'
printf '  "registry_publishable": %s\n' "$publishable"
printf '}\n'
