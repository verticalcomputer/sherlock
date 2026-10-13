#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/sherlock-dev-pki-test.XXXXXX")
cleanup() {
	rm -rf -- "$test_dir"
}
trap cleanup EXIT HUP INT TERM

output="$test_dir/pki"
"$script_dir/generate-dev-pki.sh" "$output" control.example.test 192.0.2.10 >/dev/null 2>&1

file_mode() {
	case "$(uname -s)" in
		Darwin|FreeBSD) stat -f '%Lp' "$1" ;;
		*) stat -c '%a' "$1" ;;
	esac
}

test "$(file_mode "$output")" = "700"
for key in control-server-ca.key control-server.key collector-ca.key; do
	test "$(file_mode "$output/$key")" = "600"
done
for certificate in control-server-ca.crt control-server.crt collector-ca.crt; do
	test "$(file_mode "$output/$certificate")" = "644"
done

openssl verify -CAfile "$output/control-server-ca.crt" \
	-purpose sslserver "$output/control-server.crt" >/dev/null
if openssl verify -CAfile "$output/collector-ca.crt" \
	"$output/control-server.crt" >/dev/null 2>&1; then
	echo "collector CA unexpectedly trusts the control-server identity" >&2
	exit 1
fi
openssl x509 -in "$output/control-server.crt" -noout -text >"$test_dir/server.txt"
grep -q 'CA:FALSE' "$test_dir/server.txt"
grep -q 'DNS:localhost' "$test_dir/server.txt"
grep -q 'DNS:control.example.test' "$test_dir/server.txt"
grep -q 'IP Address:127.0.0.1' "$test_dir/server.txt"
grep -q 'IP Address:192.0.2.10' "$test_dir/server.txt"
openssl x509 -in "$output/collector-ca.crt" -noout -text >"$test_dir/collector-ca.txt"
grep -q 'CA:TRUE' "$test_dir/collector-ca.txt"
grep -q 'Certificate Sign' "$test_dir/collector-ca.txt"

if "$script_dir/generate-dev-pki.sh" "$output" >/dev/null 2>&1; then
	echo "generator overwrote an existing PKI directory" >&2
	exit 1
fi
if "$script_dir/generate-dev-pki.sh" relative-pki >/dev/null 2>&1; then
	echo "generator accepted a relative output directory" >&2
	exit 1
fi
if "$script_dir/generate-dev-pki.sh" "$test_dir/invalid" 'bad/name' >/dev/null 2>&1; then
	echo "generator accepted an unsafe control name" >&2
	exit 1
fi

echo "development PKI generation checks passed"
