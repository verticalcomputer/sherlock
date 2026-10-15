#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
container="sherlock-testbed-${RANDOM}-${RANDOM}"
database="sherlock_testbed_${RANDOM}_${RANDOM}"
password=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
build_dir=$(mktemp -d)
report="${TESTBED_OUTPUT:-${TMPDIR:-/tmp}/sherlock-testbed-${RANDOM}.json}"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; rm -rf "$build_dir"; }
trap cleanup EXIT INT TERM
command -v docker >/dev/null
command -v go >/dev/null
docker info >/dev/null 2>&1
printf 'testbed: starting disposable PostgreSQL 17\n'
docker run -d --rm --name "$container" -e POSTGRES_USER=sherlock_fixture -e POSTGRES_PASSWORD="$password" -e POSTGRES_DB="$database" -p 127.0.0.1::5432 postgres:17-alpine >/dev/null
port=$(docker port "$container" 5432/tcp | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p')
[ -n "$port" ]
for attempt in $(seq 1 60); do
 if docker exec "$container" sh -c 'test "$(cat /proc/1/comm)" = postgres' >/dev/null 2>&1 && docker exec "$container" pg_isready -U sherlock_fixture -d "$database" >/dev/null 2>&1; then break; fi
 [ "$attempt" -lt 60 ] || exit 1
 sleep 1
done
dsn="postgres://sherlock_fixture:${password}@127.0.0.1:${port}/${database}?sslmode=disable"
cd "$repo_dir"
SHERLOCK_DATABASE_URL="$dsn" go run ./cmd/sherlock-migrate -dir migrations > "$build_dir/migrations.log" 2>&1
go build -o "$build_dir/testbed" ./cmd/sherlock-testbed
args=(-suite "${TESTBED_SUITE:-test/testbed/v1/scenarios.json}" -output "$report")
if [ -n "${TESTBED_BASELINE:-}" ]; then args+=(-baseline "$TESTBED_BASELINE"); fi
TZ=UTC SHERLOCK_TESTBED_DATABASE_URL="$dsn" "$build_dir/testbed" "${args[@]}"
printf 'testbed: PASS; report: %s\n' "$report"
