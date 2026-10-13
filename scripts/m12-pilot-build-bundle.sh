#!/bin/sh
set -eu

usage() {
	echo "usage: $0 --out ABSOLUTE_NEW_DIR --pack ABSOLUTE_FILE --trust-roots ABSOLUTE_FILE --known-hosts ABSOLUTE_FILE --claimant-public-key ABSOLUTE_FILE" >&2
	exit 2
}

output=
pack=
roots=
known_hosts=
public_key=
while [ "$#" -gt 0 ]; do
	case "$1" in
	--out) output=${2-}; shift 2 ;;
	--pack) pack=${2-}; shift 2 ;;
	--trust-roots) roots=${2-}; shift 2 ;;
	--known-hosts) known_hosts=${2-}; shift 2 ;;
	--claimant-public-key) public_key=${2-}; shift 2 ;;
	*) usage ;;
	esac
done

for value in "$output" "$pack" "$roots" "$known_hosts" "$public_key"; do
	test -n "$value" || usage
	case "$value" in /*) ;; *) echo "all paths must be absolute" >&2; exit 2 ;; esac
done
test ! -e "$output" || { echo "output already exists" >&2; exit 1; }
output_parent=$(dirname -- "$output")
output_name=$(basename -- "$output")
test -d "$output_parent" && test "$output_name" != . && test "$output_name" != .. || { echo "output parent must already exist" >&2; exit 1; }
output_parent=$(CDPATH= cd -- "$output_parent" && pwd -P)
output=$output_parent/$output_name
for input in "$pack" "$roots" "$known_hosts" "$public_key"; do
	test -f "$input" && test ! -L "$input" || { echo "input is not a regular non-symlink file" >&2; exit 1; }
done

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
pack_metadata=$(cd "$root" && go run ./cmd/sherlock-packverify \
	-pack "$pack" \
	-trust-roots "$roots" \
	-runner-version 1.4.0 \
	-require-definition gpu.ecc_counters@1.0.0 \
	-require-definition gpu.row_remap@1.1.0 \
	-require-definition gpu.retired_pages@1.0.0)
if ! ssh-keygen -F 192.0.2.250 -f "$known_hosts" >/dev/null; then
	ssh-keygen -F '[192.0.2.250]:22' -f "$known_hosts" >/dev/null
fi
test "$(awk '!/^[[:space:]]*(#|$)/ {count++} END {print count+0}' "$known_hosts")" -eq 1 || { echo "known-hosts input must contain exactly one target entry" >&2; exit 1; }
ssh-keygen -lf "$public_key" >/dev/null
test "$(awk 'END {print NR}' "$public_key")" -eq 1
key_type=$(awk '{print $1}' "$public_key")
case "$key_type" in ssh-*|ecdsa-*|sk-*) ;; *) echo "claimant public key has an unsupported shape" >&2; exit 1 ;; esac

umask 077
mkdir -- "$output"
complete=false
cleanup() {
	if [ "$complete" != true ]; then
		rm -r -- "$output"
	fi
}
trap cleanup EXIT HUP INT TERM
mkdir -p \
	"$output/head/etc/sherlock/diagnostics" \
	"$output/compute/etc/sherlock/diagnostics" \
	"$output/compute/etc/ssh/authorized_keys" \
	"$output/compute/etc/ssh/sshd_config.d" \
	"$output/compute/usr/local/bin" \
	"$output/compute/usr/local/libexec"

install -m 0644 "$root/deploy/pilot/m12/target-roles.one-node.json" "$output/head/etc/sherlock/diagnostics/target-roles.json"
install -m 0644 "$root/deploy/pilot/m12/ssh-target-auth.one-node.json" "$output/head/etc/sherlock/diagnostics/ssh-target-auth.v1.json"
install -m 0644 "$known_hosts" "$output/head/etc/sherlock/diagnostics/known_hosts"
for destination in "$output/head/etc/sherlock/diagnostics" "$output/compute/etc/sherlock/diagnostics"; do
	install -m 0644 "$pack" "$destination/pack.json"
	install -m 0644 "$roots" "$destination/trust-roots.json"
done
install -m 0755 "$root/deploy/pilot/m12/sherlock-runner-force-command" "$output/compute/usr/local/libexec/sherlock-runner-force-command"
install -m 0644 "$root/deploy/pilot/m12/sshd-sherlock-runner.conf" "$output/compute/etc/ssh/sshd_config.d/90-sherlock-runner.conf"
printf '%s\n' "$pack_metadata" >"$output/PACK_METADATA.json"
chmod 0644 "$output/PACK_METADATA.json"
printf 'restrict,command="/usr/local/libexec/sherlock-runner-force-command" %s\n' "$(cat "$public_key")" >"$output/compute/etc/ssh/authorized_keys/sherlock-runner"
chmod 0644 "$output/compute/etc/ssh/authorized_keys/sherlock-runner"

(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
	-o "$output/compute/usr/local/bin/sherlock-runner" \
	./cmd/sherlock-runner)
chmod 0755 "$output/compute/usr/local/bin/sherlock-runner"

(
	cd "$output"
	find head compute -type f -print | LC_ALL=C sort | while IFS= read -r file; do
		if command -v sha256sum >/dev/null 2>&1; then
			sha256sum "$file"
		else
			shasum -a 256 "$file"
		fi
	done
) >"$output/SHA256SUMS"
chmod 0644 "$output/SHA256SUMS"
complete=true
trap - EXIT HUP INT TERM
echo "prepared $output"
