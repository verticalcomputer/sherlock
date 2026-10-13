#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
contract="$root/api/openapi/sherlock-v1.yaml"
if command -v sha256sum >/dev/null 2>&1; then
	digest=$(sha256sum "$contract" | awk '{print $1}')
else
	digest=$(shasum -a 256 "$contract" | awk '{print $1}')
fi

for generated in \
	"$root/sdk/go/client.go" \
	"$root/sdk/typescript/src/client.ts" \
	"$root/sdk/typescript/src/types.ts"
do
	if ! grep -Fq "Sherlock-OpenAPI-SHA256: $digest" "$generated"; then
		echo "generated SDK is not synchronized with api/openapi/sherlock-v1.yaml: $generated" >&2
		exit 1
	fi
done
