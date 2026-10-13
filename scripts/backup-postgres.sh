#!/bin/sh
set -eu

umask 077

if [ "$#" -ne 1 ] || [ -z "${SHERLOCK_DATABASE_URL:-}" ]; then
  echo "usage: SHERLOCK_DATABASE_URL=... $0 /absolute/path/backup.dump" >&2
  exit 2
fi
if ! command -v pg_dump >/dev/null 2>&1 || ! command -v pg_restore >/dev/null 2>&1; then
  echo "pg_dump and pg_restore are required" >&2
  exit 2
fi

output=$1
case "$output" in
  /*) ;;
  *) echo "backup path must be absolute" >&2; exit 2 ;;
esac

checksum_file="${output}.sha256"
if [ -e "$output" ] || [ -e "$checksum_file" ]; then
  echo "backup or checksum already exists; refusing to overwrite" >&2
  exit 2
fi

directory=$(dirname "$output")
if [ ! -d "$directory" ]; then
  echo "backup directory does not exist" >&2
  exit 2
fi

temporary="${output}.tmp.$$"
trap 'rm -f "$temporary"' EXIT HUP INT TERM
PGDATABASE="$SHERLOCK_DATABASE_URL" pg_dump --format=custom --no-owner --no-acl --file "$temporary"
PGDATABASE="$SHERLOCK_DATABASE_URL" pg_restore --list "$temporary" >/dev/null
mv "$temporary" "$output"

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$output" >"$checksum_file"
else
  shasum -a 256 "$output" >"$checksum_file"
fi
chmod 600 "$output" "$checksum_file"
trap - EXIT HUP INT TERM
echo "backup=$output checksum=$checksum_file status=VERIFIED" >&2
