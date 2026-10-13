#!/bin/sh
set -eu

# This script is intentionally development-only. Production roots need an
# offline or HSM-backed lifecycle, independently reviewed names and validity,
# and deployment-specific rotation and revocation procedures.
umask 077

usage() {
	echo "usage: $0 /absolute/output/directory [control-dns-or-ip ...]" >&2
}

if [ "$#" -lt 1 ]; then
	usage
	exit 2
fi
if ! command -v openssl >/dev/null 2>&1; then
	echo "openssl is required" >&2
	exit 2
fi

output=$1
shift
case "$output" in
	/*) ;;
	*) echo "PKI output directory must be absolute" >&2; exit 2 ;;
esac
if [ -e "$output" ]; then
	echo "PKI output path already exists; refusing to overwrite" >&2
	exit 2
fi
parent=$(dirname "$output")
if [ ! -d "$parent" ]; then
	echo "PKI output parent directory does not exist" >&2
	exit 2
fi

valid_days=${SHERLOCK_DEV_PKI_VALID_DAYS:-30}
case "$valid_days" in
	''|*[!0-9]*) echo "SHERLOCK_DEV_PKI_VALID_DAYS must be an integer" >&2; exit 2 ;;
esac
if [ "$valid_days" -lt 1 ] || [ "$valid_days" -gt 825 ]; then
	echo "SHERLOCK_DEV_PKI_VALID_DAYS must be between 1 and 825" >&2
	exit 2
fi

for name in "$@"; do
	case "$name" in
		''|-*|*[!A-Za-z0-9._:-]*)
			echo "control names may contain only letters, digits, dot, underscore, colon, and hyphen" >&2
			exit 2
			;;
	esac
done

temporary=$(mktemp -d "${TMPDIR:-/tmp}/sherlock-dev-pki.XXXXXX")
cleanup() {
	rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

cat >"$temporary/control-ca.cnf" <<'EOF'
[req]
distinguished_name = subject
prompt = no
x509_extensions = ca_extensions

[subject]
CN = Sherlock development control-server CA
O = Sherlock development

[ca_extensions]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

cat >"$temporary/collector-ca.cnf" <<'EOF'
[req]
distinguished_name = subject
prompt = no
x509_extensions = ca_extensions

[subject]
CN = Sherlock development collector CA
O = Sherlock development

[ca_extensions]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

cat >"$temporary/control-server.cnf" <<'EOF'
[req]
distinguished_name = subject
prompt = no
req_extensions = request_extensions

[subject]
CN = localhost
O = Sherlock development

[request_extensions]
subjectAltName = @control_names

[server_extensions]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @control_names

[control_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

dns_index=2
ip_index=3
for name in "$@"; do
	case "$name" in
		localhost|127.0.0.1|::1) continue ;;
		*:*|*[!0-9.]*)
			# A colon denotes IPv6. Anything with a non-numeric DNS character is
			# a DNS name. OpenSSL performs the final syntax validation.
			case "$name" in
				*:*) printf 'IP.%s = %s\n' "$ip_index" "$name" >>"$temporary/control-server.cnf"; ip_index=$((ip_index + 1)) ;;
				*) printf 'DNS.%s = %s\n' "$dns_index" "$name" >>"$temporary/control-server.cnf"; dns_index=$((dns_index + 1)) ;;
			esac
			;;
		*) printf 'IP.%s = %s\n' "$ip_index" "$name" >>"$temporary/control-server.cnf"; ip_index=$((ip_index + 1)) ;;
	esac
done

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
	-out "$temporary/control-server-ca.key" >/dev/null 2>&1
openssl req -new -x509 -sha256 -days "$valid_days" \
	-key "$temporary/control-server-ca.key" \
	-config "$temporary/control-ca.cnf" \
	-out "$temporary/control-server-ca.crt"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
	-out "$temporary/control-server.key" >/dev/null 2>&1
openssl req -new -sha256 \
	-key "$temporary/control-server.key" \
	-config "$temporary/control-server.cnf" \
	-out "$temporary/control-server.csr"
openssl x509 -req -sha256 -days "$valid_days" \
	-in "$temporary/control-server.csr" \
	-CA "$temporary/control-server-ca.crt" \
	-CAkey "$temporary/control-server-ca.key" \
	-CAcreateserial \
	-extfile "$temporary/control-server.cnf" \
	-extensions server_extensions \
	-out "$temporary/control-server.crt" >/dev/null 2>&1

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
	-out "$temporary/collector-ca.key" >/dev/null 2>&1
openssl req -new -x509 -sha256 -days "$valid_days" \
	-key "$temporary/collector-ca.key" \
	-config "$temporary/collector-ca.cnf" \
	-out "$temporary/collector-ca.crt"

openssl verify -CAfile "$temporary/control-server-ca.crt" \
	-purpose sslserver "$temporary/control-server.crt" >/dev/null
openssl verify -CAfile "$temporary/collector-ca.crt" \
	"$temporary/collector-ca.crt" >/dev/null

mkdir -m 700 "$output"
for file in control-server-ca.key control-server.key collector-ca.key; do
	mv "$temporary/$file" "$output/$file"
	chmod 600 "$output/$file"
done
for file in control-server-ca.crt control-server.crt collector-ca.crt; do
	mv "$temporary/$file" "$output/$file"
	chmod 644 "$output/$file"
done

trap - EXIT HUP INT TERM
cleanup

echo "development PKI created at $output" >&2
echo "SHERLOCK_CONTROL_CERT_FILE=$output/control-server.crt" >&2
echo "SHERLOCK_CONTROL_KEY_FILE=$output/control-server.key" >&2
echo "SHERLOCK_COLLECTOR_CA_FILE=$output/collector-ca.crt" >&2
echo "SHERLOCK_COLLECTOR_CA_KEY_FILE=$output/collector-ca.key" >&2
echo "copy only $output/control-server-ca.crt to the head node as SHERLOCK_CONTROL_CA_FILE" >&2
echo "development certificates expire after $valid_days days" >&2
