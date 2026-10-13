#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
container="sherlock-integration-${RANDOM}-${RANDOM}"
password=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
database="sherlock_test_${RANDOM}_${RANDOM}"
port=""

fail() { echo "isolated integration: $*" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || fail "docker is required"
command -v go >/dev/null 2>&1 || fail "go is required"
docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "isolated integration: starting disposable PostgreSQL 17 container"
docker run -d --rm --name "$container" \
  -e POSTGRES_USER=sherlock_fixture \
  -e POSTGRES_PASSWORD="$password" \
  -e POSTGRES_DB=postgres \
  -p 127.0.0.1::5432 postgres:17-alpine >/dev/null

port=$(docker port "$container" 5432/tcp | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p')
[ -n "$port" ] || fail "could not determine the disposable PostgreSQL port"
for attempt in $(seq 1 60); do
  # The image briefly starts a temporary PostgreSQL server during initdb,
  # then stops it before execing the final postmaster as PID 1. A successful
  # pg_isready against that temporary server is not deployment readiness.
  if docker exec "$container" sh -c 'test "$(cat /proc/1/comm)" = postgres' >/dev/null 2>&1 &&
    docker exec "$container" pg_isready -U sherlock_fixture -d postgres >/dev/null 2>&1; then
    break
  fi
  [ "$attempt" -lt 60 ] || fail "disposable PostgreSQL did not become ready"
  sleep 1
done

dsn="postgres://sherlock_fixture:${password}@127.0.0.1:${port}/${database}?sslmode=disable"
docker exec "$container" createdb -U sherlock_fixture "$database" >/dev/null

echo "isolated integration: applying migrations and running tests"
(cd "$repo_dir" && SHERLOCK_DATABASE_URL="$dsn" go run ./cmd/sherlock-migrate -dir migrations >/dev/null)
(cd "$repo_dir" && SHERLOCK_TEST_DATABASE_URL="$dsn" go test -race -count=1 -tags=integration ./...)
echo "isolated integration: passed; disposable database will be removed"
