#!/bin/sh
set -eu

mode=dry-run
case "${1-}" in
"") ;;
--execute-read-only) mode=execute ;;
*) echo "usage: $0 [--execute-read-only]" >&2; exit 2 ;;
esac

cat <<'PLAN'
M12 one-node read-only preflight
  operator route:  ssh synthetic-head-gateway
  compute target:  fixture1-zone1-comp001 / 192.0.2.250:22
  admin login:     fixture_user_1 (preflight only)
  runtime login:   sherlock-runner (not created by this script)
  operations:      identity, architecture, executable digests, trusted host-key fingerprint
  mutations:       none
PLAN

if [ "$mode" = dry-run ]; then
	echo "authorization required: rerun with --execute-read-only to contact the head and compute target"
	exit 0
fi

ssh \
	-o BatchMode=yes \
	-o RequestTTY=no \
	-o ClearAllForwardings=yes \
	-- synthetic-head-gateway 'sh -s' <<'REMOTE'
set -eu

digest_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

printf 'head.hostname=%s\n' "$(hostname)"
printf 'head.user=%s\n' "$(id -un)"
printf 'head.arch=%s\n' "$(uname -m)"
printf 'head.ssh.sha256=%s\n' "$(digest_file /usr/bin/ssh)"

known_hosts=$HOME/.ssh/known_hosts
test -f "$known_hosts"
trusted_line=$(ssh-keygen -F fixture1-zone1-comp001 -f "$known_hosts" 2>/dev/null | awk '!/^#/ {print; exit}')
test -n "$trusted_line"
printf 'target.trusted_host_key='
printf '%s\n' "$trusted_line" | ssh-keygen -lf - | awk '{print $2" "$4}'

for public_key in "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_rsa.pub"; do
	if [ -f "$public_key" ]; then
		printf 'head.candidate_claimant_key='
		ssh-keygen -lf "$public_key" | awk '{print $2" "$4}'
	fi
done

ssh \
	-F /dev/null \
	-o BatchMode=yes \
	-o RequestTTY=no \
	-o ClearAllForwardings=yes \
	-o ForwardAgent=no \
	-o ForwardX11=no \
	-o IdentitiesOnly=yes \
	-o KbdInteractiveAuthentication=no \
	-o PasswordAuthentication=no \
	-o ProxyCommand=none \
	-o ProxyJump=none \
	-o StrictHostKeyChecking=yes \
	-o HostKeyAlias=fixture1-zone1-comp001 \
	-o UserKnownHostsFile="$known_hosts" \
	-- fixture_user_1@192.0.2.250 'sh -s' <<'TARGET'
set -eu
digest_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}
printf 'target.hostname=%s\n' "$(hostname)"
printf 'target.user=%s\n' "$(id -un)"
printf 'target.uid=%s\n' "$(id -u)"
printf 'target.arch=%s\n' "$(uname -m)"
for executable in /usr/bin/nvidia-smi /usr/bin/journalctl /usr/bin/env; do
	test -f "$executable"
	printf 'target.executable.%s.sha256=%s\n' "$(basename "$executable")" "$(digest_file "$executable")"
done
if [ -x /usr/sbin/sshd ]; then
	/usr/sbin/sshd -V 2>&1 | head -1 | sed 's/^/target.sshd=/' || true
fi
TARGET
REMOTE
