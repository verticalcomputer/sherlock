#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/sherlock-restore-test.XXXXXX")
cleanup() {
	rm -rf -- "$test_dir"
}
trap cleanup EXIT HUP INT TERM

mkdir "$test_dir/bin"
: >"$test_dir/backup.dump"

cat >"$test_dir/bin/psql" <<'EOF'
#!/bin/sh
case " $* " in
  *" -c "*)
    case "$*" in
      *"c.relkind IN ('r','p','v','m','S','f')"*) ;;
      *) echo "restore preflight did not inspect all public relation kinds" >&2; exit 90 ;;
    esac
    printf '%s\n' "${FAKE_RELATION_COUNT:-0}"
    ;;
  *) cat >/dev/null; printf '%s\n' restore-schema-verified ;;
esac
EOF
cat >"$test_dir/bin/pg_restore" <<'EOF'
#!/bin/sh
: >"${FAKE_RESTORE_MARKER:?}"
EOF
chmod +x "$test_dir/bin/psql" "$test_dir/bin/pg_restore"

export PATH="$test_dir/bin:$PATH"
export SHERLOCK_RESTORE_DATABASE_URL=postgres://isolated-test
export SHERLOCK_RESTORE_CONFIRM=isolated-empty-database
export FAKE_RESTORE_MARKER="$test_dir/restored"

FAKE_RELATION_COUNT=0; export FAKE_RELATION_COUNT
"$script_dir/restore-postgres-drill.sh" "$test_dir/backup.dump" >/dev/null 2>&1
test -f "$FAKE_RESTORE_MARKER"
rm "$FAKE_RESTORE_MARKER"

FAKE_RELATION_COUNT=1; export FAKE_RELATION_COUNT
if "$script_dir/restore-postgres-drill.sh" "$test_dir/backup.dump" >"$test_dir/stdout" 2>"$test_dir/stderr"; then
	echo "non-empty restore target was accepted" >&2
	exit 1
fi
test ! -f "$FAKE_RESTORE_MARKER"
grep -q "restore target is not empty" "$test_dir/stderr"

echo "restore preflight regression checks passed"
