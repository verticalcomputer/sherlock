#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ -z "${SHERLOCK_RESTORE_DATABASE_URL:-}" ]; then
  echo "usage: SHERLOCK_RESTORE_DATABASE_URL=... SHERLOCK_RESTORE_CONFIRM=isolated-empty-database $0 /absolute/path/backup.dump" >&2
  exit 2
fi
if ! command -v pg_restore >/dev/null 2>&1 || ! command -v psql >/dev/null 2>&1; then
  echo "pg_restore and psql are required" >&2
  exit 2
fi
if [ "${SHERLOCK_RESTORE_CONFIRM:-}" != "isolated-empty-database" ]; then
  echo "restore requires explicit isolated-empty-database confirmation" >&2
  exit 2
fi

backup=$1
case "$backup" in
  /*) ;;
  *) echo "backup path must be absolute" >&2; exit 2 ;;
esac
if [ ! -f "$backup" ]; then
  echo "backup does not exist" >&2
  exit 2
fi

checksum_file="${backup}.sha256"
if [ -f "$checksum_file" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$(dirname "$backup")" && sha256sum --check "$(basename "$checksum_file")")
  else
    (cd "$(dirname "$backup")" && shasum -a 256 --check "$(basename "$checksum_file")")
  fi
fi

relation_count=$(PGDATABASE="$SHERLOCK_RESTORE_DATABASE_URL" psql -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_catalog.pg_class AS c JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')")
if [ "$relation_count" != "0" ]; then
	echo "restore target is not empty; refusing destructive restore" >&2
	exit 2
fi

PGDATABASE="$SHERLOCK_RESTORE_DATABASE_URL" pg_restore --exit-on-error --single-transaction --no-owner --no-acl "$backup"
PGDATABASE="$SHERLOCK_RESTORE_DATABASE_URL" psql -X -A -t -v ON_ERROR_STOP=1 <<'SQL'
DO $$
BEGIN
  IF (SELECT count(*) FROM schema_migrations) < 13 THEN
    RAISE EXCEPTION 'restored migration ledger is incomplete';
  END IF;
  IF to_regclass('public.investigations') IS NULL OR to_regclass('public.evidence_envelopes') IS NULL THEN
    RAISE EXCEPTION 'restored core schema is incomplete';
  END IF;
END $$;
SELECT 'restore-schema-verified';
SQL
echo "backup=$backup status=RESTORE_VERIFIED" >&2
