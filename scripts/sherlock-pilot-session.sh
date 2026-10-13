#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
runtime=${SHERLOCK_PILOT_RUNTIME_DIR:-"$root/.local/pilot-session"}
head_alias=${SHERLOCK_PILOT_HEAD:-synthetic-head-gateway}
cluster_id=${SHERLOCK_PILOT_CLUSTER:-pilot-cluster}
ssh_command=${SHERLOCK_PILOT_SSH:-ssh}
skip_build=${SHERLOCK_PILOT_SKIP_BUILD:-false}

umask 077
mkdir -p "$runtime/bin" "$runtime/logs" "$runtime/run"

usage() {
	cat >&2 <<'USAGE'
usage:
  scripts/sherlock-pilot-session.sh start [worker|control|api|investigator|tunnel|core|all ...]
  scripts/sherlock-pilot-session.sh stop [worker|control|api|investigator|tunnel|all ...]
  scripts/sherlock-pilot-session.sh restart <service ...>
  scripts/sherlock-pilot-session.sh status
  scripts/sherlock-pilot-session.sh enroll-head

Defaults:
  start           starts worker, control, and the reverse SSH tunnel
  stop            stops every session-owned process

Enrollment streams the one-use bootstrap token directly from sherlock-admin to
the remote collector over stdin. It never stores or prints the token.
USAGE
	exit 2
}

service_binary() {
	case "$1" in
	worker|control|api|investigator) printf '%s/bin/sherlock-%s\n' "$runtime" "$1" ;;
	*) return 1 ;;
	esac
}

validate_service() {
	case "$1" in worker|control|api|investigator|tunnel) ;; *) echo "unknown pilot service: $1" >&2; exit 2 ;; esac
}

expand_services() {
	local item
	for item in "$@"; do
		case "$item" in
		core) printf '%s\n' worker control tunnel ;;
		all) printf '%s\n' worker control api investigator tunnel ;;
		*) validate_service "$item"; printf '%s\n' "$item" ;;
		esac
	done
}

build_service() {
	local service=$1 binary
	[ "$service" != tunnel ] || return 0
	binary=$(service_binary "$service")
	if [ "$skip_build" = true ]; then
		test -x "$binary" || { echo "missing prebuilt $binary" >&2; return 1; }
		return 0
	fi
	(
		cd "$root"
		go build -trimpath -o "$binary" "./cmd/sherlock-$service"
	)
	chmod 0700 "$binary"
}

build_admin() {
	local binary="$runtime/bin/sherlock-admin"
	if [ "$skip_build" = true ]; then
		test -x "$binary" || { echo "missing prebuilt $binary" >&2; return 1; }
	else
		(cd "$root" && go build -trimpath -o "$binary" ./cmd/sherlock-admin)
		chmod 0700 "$binary"
	fi
}

pid_file() { printf '%s/run/%s.pid\n' "$runtime" "$1"; }
marker_file() { printf '%s/run/%s.marker\n' "$runtime" "$1"; }
log_file() { printf '%s/logs/%s.log\n' "$runtime" "$1"; }

running_pid() {
	local service=$1 file pid marker command
	file=$(pid_file "$service")
	[ -f "$file" ] || return 1
	read -r pid <"$file"
	case "$pid" in ''|*[!0-9]*) return 1 ;; esac
	kill -0 "$pid" 2>/dev/null || return 1
	marker=$(cat "$(marker_file "$service")" 2>/dev/null || true)
	[ -n "$marker" ] || return 1
	command=$(ps -p "$pid" -o command= 2>/dev/null || true)
	case "$command" in *"$marker"*) printf '%s\n' "$pid"; return 0 ;; *) return 1 ;; esac
}

start_service() {
	local service=$1 binary log pid marker collector_id
	validate_service "$service"
	if pid=$(running_pid "$service"); then
		echo "$service already running pid=$pid"
		return 0
	fi
	rm -f "$(pid_file "$service")" "$(marker_file "$service")"
	build_service "$service"
	log=$(log_file "$service")
	: >"$log"
	chmod 0600 "$log"
	case "$service" in
	worker)
		binary=$(service_binary "$service"); marker=$binary
		nohup "$binary" scheduled >>"$log" 2>&1 </dev/null &
		;;
	control)
		binary=$(service_binary "$service"); marker=$binary
		collector_id=
		[ ! -f "$runtime/collector-id" ] || read -r collector_id <"$runtime/collector-id"
		nohup env SHERLOCK_DIAGNOSTIC_EXECUTION_COLLECTORS="$collector_id" "$binary" >>"$log" 2>&1 </dev/null &
		;;
	api|investigator)
		binary=$(service_binary "$service"); marker=$binary
		nohup "$binary" >>"$log" 2>&1 </dev/null &
		;;
	tunnel)
		# A stale PID file must never make stop target an unrelated SSH session.
		# Match this session's exact reverse-forward tuple, not merely "ssh".
		marker=127.0.0.1:8443:127.0.0.1:8443
		nohup "$ssh_command" -NT \
			-o BatchMode=yes \
			-o ExitOnForwardFailure=yes \
			-o ServerAliveInterval=30 \
			-o ServerAliveCountMax=3 \
			-R 127.0.0.1:8443:127.0.0.1:8443 \
			-- "$head_alias" >>"$log" 2>&1 </dev/null &
		;;
	esac
	pid=$!
	printf '%s\n' "$pid" >"$(pid_file "$service")"
	printf '%s\n' "$marker" >"$(marker_file "$service")"
	sleep 1
	if ! running_pid "$service" >/dev/null; then
		echo "$service failed to start; inspect $log" >&2
		return 1
	fi
	echo "$service started pid=$pid log=$log"
}

stop_service() {
	local service=$1 pid attempt
	validate_service "$service"
	if ! pid=$(running_pid "$service"); then
		rm -f "$(pid_file "$service")" "$(marker_file "$service")"
		echo "$service not running"
		return 0
	fi
	kill -TERM "$pid"
	for attempt in $(seq 1 100); do
		if ! kill -0 "$pid" 2>/dev/null; then
			rm -f "$(pid_file "$service")" "$(marker_file "$service")"
			echo "$service stopped"
			return 0
		fi
		sleep 0.1
	done
	echo "$service did not stop after SIGTERM; pid=$pid was not force-killed" >&2
	return 1
}

status() {
	local service pid
	for service in worker control api investigator tunnel; do
		if pid=$(running_pid "$service"); then
			echo "$service RUNNING pid=$pid log=$(log_file "$service")"
		else
			echo "$service STOPPED"
		fi
	done
	if [ -f "$runtime/collector-id" ]; then
		printf 'collector ENROLLED id='
		cat "$runtime/collector-id"
	else
		echo "collector NOT_ENROLLED_IN_SESSION"
	fi
}

enroll_head() {
	local collector_id temporary remote_enroll remote_id admin
	running_pid control >/dev/null || { echo "control must be running" >&2; return 1; }
	running_pid tunnel >/dev/null || { echo "reverse tunnel must be running" >&2; return 1; }
	build_admin
	admin="$runtime/bin/sherlock-admin"

	"$ssh_command" -T -o BatchMode=yes -- "$head_alias" \
		'test -x "$HOME/.local/bin/sherlock-collector" && test -f "$HOME/.config/sherlock/pki/control-server-ca.crt"'

	remote_enroll='SHERLOCK_CONTROL_URL=https://localhost:8443 SHERLOCK_CONTROL_CA_FILE="$HOME/.config/sherlock/pki/control-server-ca.crt" SHERLOCK_COLLECTOR_IDENTITY_DIR="$HOME/.local/share/sherlock/identity" SHERLOCK_COLLECTOR_DISPLAY_NAME="$(hostname)" "$HOME/.local/bin/sherlock-collector" enroll'
	"$admin" bootstrap "$cluster_id" | \
		"$ssh_command" -T -o BatchMode=yes -- "$head_alias" "$remote_enroll"

	remote_id='cat "$HOME/.local/share/sherlock/identity/current/collector_id"'
	collector_id=$("$ssh_command" -T -o BatchMode=yes -- "$head_alias" "$remote_id")
	case "$collector_id" in ''|*[!A-Za-z0-9._:-]*) echo "remote enrollment returned an invalid collector ID" >&2; return 1 ;; esac
	temporary="$runtime/collector-id.tmp.$$"
	printf '%s\n' "$collector_id" >"$temporary"
	chmod 0600 "$temporary"
	mv -f "$temporary" "$runtime/collector-id"

	stop_service control
	start_service control
	echo "collector enrolled id=$collector_id; control restarted with diagnostic authorization"
}

command=${1-}
[ -n "$command" ] || usage
shift
case "$command" in
start)
	if [ "$#" -eq 0 ]; then set -- core; fi
	while IFS= read -r service; do start_service "$service"; done < <(expand_services "$@")
	;;
stop)
	if [ "$#" -eq 0 ]; then set -- all; fi
	services=()
	while IFS= read -r service; do services+=("$service"); done < <(expand_services "$@")
	for ((index=${#services[@]}-1; index>=0; index--)); do stop_service "${services[index]}"; done
	;;
restart)
	[ "$#" -gt 0 ] || usage
	services=()
	while IFS= read -r service; do services+=("$service"); done < <(expand_services "$@")
	for ((index=${#services[@]}-1; index>=0; index--)); do stop_service "${services[index]}"; done
	for service in "${services[@]}"; do start_service "$service"; done
	;;
status) [ "$#" -eq 0 ] || usage; status ;;
enroll-head) [ "$#" -eq 0 ] || usage; enroll_head ;;
*) usage ;;
esac
