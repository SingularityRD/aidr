#!/bin/sh
set -eu
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/opt/homebrew/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

ACTION="${1:-}"
if [ -z "$ACTION" ]; then
	echo "usage: aidr-fleet.sh verify|install|upgrade|rollback|uninstall|status [options]" >&2
	echo "  machine scope (default): signed standalone bundle, hooks for every user, no Node.js" >&2
	echo "  user scope (--user NAME): signed npm connector package for one account, needs Node.js" >&2
	exit 64
fi
shift

PLATFORM="${AIDR_FLEET_PLATFORM:-linux}"
case "$PLATFORM" in
	linux) DEFAULT_INSTALL_ROOT=/opt/singularity-aidr; DEFAULT_STATE_ROOT=/var/lib/singularity-aidr; DEFAULT_CONFIG_ROOT=/etc/singularity-aidr ;;
	macos) DEFAULT_INSTALL_ROOT="/Library/Application Support/Singularity AIDR"; DEFAULT_STATE_ROOT="/Library/Application Support/Singularity AIDR/state"; DEFAULT_CONFIG_ROOT="/Library/Application Support/Singularity AIDR/config" ;;
	*) echo "unsupported fleet platform: $PLATFORM" >&2; exit 64 ;;
esac

INSTALL_ROOT="${AIDR_FLEET_INSTALL_ROOT:-$DEFAULT_INSTALL_ROOT}"
STATE_ROOT="${AIDR_FLEET_STATE_ROOT:-$DEFAULT_STATE_ROOT}"
CONFIG_ROOT="${AIDR_FLEET_CONFIG_ROOT:-$DEFAULT_CONFIG_ROOT}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f "$SCRIPT_DIR/endpoint-install.mjs" ]; then DEFAULT_ENDPOINT_INSTALLER="$SCRIPT_DIR/endpoint-install.mjs"
else DEFAULT_ENDPOINT_INSTALLER="$SCRIPT_DIR/../../../scripts/endpoint-install.mjs"; fi
ENDPOINT_INSTALLER="${AIDR_ENDPOINT_INSTALLER:-$DEFAULT_ENDPOINT_INSTALLER}"
REMOVE_HELPER="${AIDR_REMOVE_HELPER:-$SCRIPT_DIR/remove-managed-hooks.mjs}"
HEALTH_HELPER="${AIDR_HEALTH_HELPER:-$SCRIPT_DIR/fleet-health.mjs}"
NODE_BIN="${AIDR_NODE_BIN:-$(command -v node || true)}"
ARTIFACT= SHA256= SIGNATURE= PUBLIC_KEY="$CONFIG_ROOT/release-public.pem" TARGET_USER= TARGET_HOME= AGENT_CONFIG=
# Machine scope: the standalone (SEA) bundle, registered through each host's
# system-wide policy by the bundle's own `aidr machine-hooks install`.
SCOPE= BUNDLE_PUBLIC_KEY= LOCK_OTHER_HOOKS= HEARTBEAT=
# Machine policy read by every hook and the CLI (packages/core/src/machine-policy.ts).
DEFAULT_POLICY_DIR=/etc/singularity-aidr
POLICY_DIR="${AIDR_FLEET_POLICY_DIR:-$DEFAULT_POLICY_DIR}"
POLICY_CONTROL_PLANE_URL= POLICY_ENROLLMENT_KEY_FILE= POLICY_PROTECTION_LOCKED=

while [ "$#" -gt 0 ]; do
	case "$1" in
		--artifact) ARTIFACT=${2:?missing value}; shift 2 ;;
		--sha256) SHA256=${2:?missing value}; shift 2 ;;
		--signature) SIGNATURE=${2:?missing value}; shift 2 ;;
		--public-key) PUBLIC_KEY=${2:?missing value}; shift 2 ;;
		--user) TARGET_USER=${2:?missing value}; shift 2 ;;
		--home) TARGET_HOME=${2:?missing value}; shift 2 ;;
		--config) AGENT_CONFIG=${2:?missing value}; shift 2 ;;
		--install-root) INSTALL_ROOT=${2:?missing value}; shift 2 ;;
		--state-root) STATE_ROOT=${2:?missing value}; shift 2 ;;
		--endpoint-installer) ENDPOINT_INSTALLER=${2:?missing value}; shift 2 ;;
		--node) NODE_BIN=${2:?missing value}; shift 2 ;;
		--scope) SCOPE=${2:?missing value}; shift 2 ;;
		--bundle-public-key) BUNDLE_PUBLIC_KEY=${2:?missing value}; shift 2 ;;
		--lock-other-hooks) LOCK_OTHER_HOOKS=1; shift ;;
		--no-lock-other-hooks) LOCK_OTHER_HOOKS=0; shift ;;
		--heartbeat) HEARTBEAT=1; shift ;;
		--no-heartbeat) HEARTBEAT=0; shift ;;
		--control-plane-url) POLICY_CONTROL_PLANE_URL=${2:?missing value}; shift 2 ;;
		--enrollment-key-file) POLICY_ENROLLMENT_KEY_FILE=${2:?missing value}; shift 2 ;;
		--protection-locked) POLICY_PROTECTION_LOCKED=${2:?missing value}; shift 2 ;;
		*) echo "unknown option: $1" >&2; exit 64 ;;
	esac
done

fail() { echo "AIDR fleet: $*" >&2; exit 1; }
if [ -z "$SCOPE" ]; then
	if [ -n "$TARGET_USER" ]; then SCOPE=user; else SCOPE=machine; fi
fi
case "$SCOPE" in
	machine) [ -z "$TARGET_USER" ] || fail "--user selects the per-user scope; omit it for a machine-wide installation" ;;
	user) ;;
	*) echo "--scope must be machine or user" >&2; exit 64 ;;
esac
[ "$SCOPE" = machine ] || [ -z "$BUNDLE_PUBLIC_KEY$LOCK_OTHER_HOOKS$HEARTBEAT" ] || fail "--bundle-public-key, --lock-other-hooks and --heartbeat apply to the machine scope only"
[ "$HEARTBEAT" != 1 ] || [ "$PLATFORM" = linux ] || fail "--heartbeat schedules a systemd timer and is available on Linux only"
case "$POLICY_PROTECTION_LOCKED" in ""|true|false) ;; *) fail "--protection-locked must be true or false" ;; esac
require_file() { [ -f "$1" ] || fail "required file missing: $1"; }
safe_user() { printf '%s' "$1" | grep -Eq '^[A-Za-z0-9_][A-Za-z0-9._-]*$' || fail "unsafe user name"; }
state_key() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
safe_system_root() {
	case "$1" in /*) ;; *) fail "system roots must be absolute paths" ;; esac
	[ "$1" != / ] || fail "filesystem root cannot be used as an AIDR system root"
	case "/$1/" in */../*|*/./*) fail "system roots must be normalized paths" ;; esac
}
sha_file() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
	else fail "sha256sum or shasum is required"
	fi
}

require_root_for_changes() {
	safe_system_root "$INSTALL_ROOT"; safe_system_root "$STATE_ROOT"
	[ "$INSTALL_ROOT" != "$STATE_ROOT" ] || fail "install and state roots must be different"
	# Host hook commands quote the bundle path; these characters cannot be carried.
	case "$INSTALL_ROOT" in *[\"\$\`\\]*|*"
"*) fail "the install root contains characters a hook command cannot carry" ;; esac
	if [ "${AIDR_FLEET_TEST_ROOT:-}" ]; then
		[ "$(id -u)" -ne 0 ] || fail "test-root mode is unavailable to privileged installations"
		case "$INSTALL_ROOT/" in "${AIDR_FLEET_TEST_ROOT%/}"/*) ;; *) fail "test install root escaped AIDR_FLEET_TEST_ROOT" ;; esac
		case "$STATE_ROOT/" in "${AIDR_FLEET_TEST_ROOT%/}"/*) ;; *) fail "test state root escaped AIDR_FLEET_TEST_ROOT" ;; esac
		return
	fi
	[ "$(id -u)" -eq 0 ] || fail "system installation actions require root"
}

# Hooks and the CLI read machine policy from one fixed, root-owned path only;
# test-root mode redirects it into the test tree.
require_policy_dir() {
	if [ "${AIDR_FLEET_TEST_ROOT:-}" ]; then
		case "$POLICY_DIR/" in "${AIDR_FLEET_TEST_ROOT%/}"/*) ;; *) fail "test policy directory escaped AIDR_FLEET_TEST_ROOT" ;; esac
	else
		[ "$POLICY_DIR" = "$DEFAULT_POLICY_DIR" ] || fail "the machine policy directory is fixed at $DEFAULT_POLICY_DIR"
	fi
	[ ! -L "$POLICY_DIR" ] || fail "machine policy directory must not be a symlink"
	mkdir -p "$POLICY_DIR"; chmod 755 "$POLICY_DIR"
	if [ -z "${AIDR_FLEET_TEST_ROOT:-}" ]; then chown 0 "$POLICY_DIR"; fi
}

# The machine policy from --control-plane-url, --enrollment-key-file and
# --protection-locked. With none given an existing managed.json is kept as is
# (upgrade and rollback never drop it). With any given the file is rewritten
# from exactly the given values, so pass the complete policy every time; the
# replaced file is kept as managed.json.previous. Values are validated here
# against the same rules the reader applies; a file the reader refuses would
# be refused as a whole on every endpoint. build_machine_policy validates
# before anything is staged; write_machine_policy writes it.
POLICY_FIELDS=
build_machine_policy() {
	[ -n "$POLICY_CONTROL_PLANE_URL$POLICY_ENROLLMENT_KEY_FILE$POLICY_PROTECTION_LOCKED" ] || return 0
	policy_fields=
	if [ -n "$POLICY_CONTROL_PLANE_URL" ]; then
		[ "${#POLICY_CONTROL_PLANE_URL}" -le 2048 ] || fail "--control-plane-url is longer than 2048 characters"
		printf '%s' "$POLICY_CONTROL_PLANE_URL" | grep -Eq '^https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?(/[A-Za-z0-9._~/%+-]*)?$' || fail "--control-plane-url must be an https:// URL without credentials, query or unusual characters"
		policy_fields="$policy_fields${policy_fields:+,}
  \"control_plane_url\": \"$POLICY_CONTROL_PLANE_URL\""
	fi
	if [ -n "$POLICY_ENROLLMENT_KEY_FILE" ]; then
		[ -f "$POLICY_ENROLLMENT_KEY_FILE" ] && [ ! -L "$POLICY_ENROLLMENT_KEY_FILE" ] || fail "--enrollment-key-file must be a regular file"
		[ "$(wc -l < "$POLICY_ENROLLMENT_KEY_FILE" | tr -d ' ')" -le 1 ] || fail "--enrollment-key-file must hold one line"
		enrollment_key=$(tr -d '\r\n' < "$POLICY_ENROLLMENT_KEY_FILE")
		printf '%s' "$enrollment_key" | grep -Eq '^aidr_fleet_[A-Za-z0-9_-]{16,256}$' || fail "--enrollment-key-file must hold one fleet enrollment key (aidr_fleet_...)"
		policy_fields="$policy_fields${policy_fields:+,}
  \"enrollment_key\": \"$enrollment_key\""
	fi
	if [ -n "$POLICY_PROTECTION_LOCKED" ]; then
		policy_fields="$policy_fields${policy_fields:+,}
  \"protection_locked\": $POLICY_PROTECTION_LOCKED"
	fi
	POLICY_FIELDS=$policy_fields
}
write_machine_policy() {
	[ -n "$POLICY_FIELDS" ] || return 0
	require_policy_dir
	policy_file="$POLICY_DIR/managed.json"
	[ ! -L "$policy_file" ] || fail "machine policy file must not be a symlink"
	policy_tmp="$policy_file.tmp.$$"
	printf '{%s\n}\n' "$POLICY_FIELDS" > "$policy_tmp"
	chmod 644 "$policy_tmp"
	if [ -z "${AIDR_FLEET_TEST_ROOT:-}" ]; then chown 0 "$policy_tmp"; fi
	if [ -f "$policy_file" ] && ! cmp -s "$policy_file" "$policy_tmp"; then cp -p "$policy_file" "$policy_file.previous"; fi
	mv -f "$policy_tmp" "$policy_file"
	echo "AIDR fleet: machine policy written to $policy_file"
}

# Lifecycle mutual exclusion. The lock is a directory (mkdir is atomic) holding
# an "owner" record: pid, boot id, process start time and creation time. A lock
# whose owner was SIGKILLed (or whose host rebooted) is recovered instead of
# blocking every future run: it is stale only when its boot id differs from the
# current boot, its pid is gone (ESRCH; EPERM means alive), or the pid was reused
# (start time differs). A lock without a readable owner record (a crash between
# mkdir and the record write) is stale only after LOCK_GRACE_MINUTES. Recovery is
# serialized by a short-lived ".recovery" guard directory, re-checks staleness
# under it, and atomically renames the stale lock to a unique tombstone before
# deleting it, so a contender only ever deletes the directory it renamed.
LOCK_HELD= STAGING_PATH= LOCK_DIR= STALE_REASON=
LOCK_GRACE_MINUTES=1
boot_id() {
	if [ "${AIDR_FLEET_TEST_ROOT:-}" ] && [ -n "${AIDR_FLEET_TEST_BOOT_ID:-}" ]; then printf '%s\n' "$AIDR_FLEET_TEST_BOOT_ID"; return 0; fi
	if [ -r /proc/sys/kernel/random/boot_id ]; then tr -d ' \n' < /proc/sys/kernel/random/boot_id 2>/dev/null || true; echo
	elif [ "$PLATFORM" = macos ]; then sysctl -n kern.boottime 2>/dev/null | sed -n 's/^.*sec = \([0-9][0-9]*\),.*$/\1/p' | head -n 1
	fi
}
process_start_time() {
	if [ -r "/proc/$1/stat" ]; then sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}'
	elif [ "$PLATFORM" = macos ]; then LC_ALL=C ps -o lstart= -p "$1" 2>/dev/null | tr -s ' ' | sed 's/^ //;s/ $//'
	fi
}
# kill -0 cannot report ESRCH and EPERM apart by exit status; only an explicit
# "No such process" counts as dead, anything else is treated as alive.
pid_alive() {
	kill_error=$(LC_ALL=C kill -0 "$1" 2>&1) && return 0
	case "$kill_error" in *"o such process"*) return 1 ;; esac
	return 0
}
older_than_grace() {
	[ -n "$(find "$1" -prune -mmin +"$LOCK_GRACE_MINUTES" 2>/dev/null)" ]
}
lock_field() { sed -n "s/^$1=//p" "$LOCK_DIR/owner" 2>/dev/null | head -n 1; }
lock_owner_pid() {
	[ -f "$LOCK_DIR/owner" ] && [ ! -L "$LOCK_DIR/owner" ] || return 0
	lock_field pid | sed -n 's/^\([0-9][0-9]*\)$/\1/p'
}
lock_is_stale() {
	STALE_REASON=
	owner_pid=$(lock_owner_pid)
	if [ -z "$owner_pid" ]; then
		if older_than_grace "$LOCK_DIR"; then STALE_REASON="no owner record after the grace period"; return 0; fi
		return 1
	fi
	owner_boot=$(lock_field boot_id); owner_start=$(lock_field start_time); current_boot=$(boot_id)
	if [ -n "$owner_boot" ] && [ -n "$current_boot" ] && [ "$owner_boot" != "$current_boot" ]; then STALE_REASON="owner pid $owner_pid ran in a previous boot"; return 0; fi
	if [ "$owner_pid" = "$$" ]; then STALE_REASON="owner pid $owner_pid was reused by this process"; return 0; fi
	if ! pid_alive "$owner_pid"; then STALE_REASON="owner pid $owner_pid is no longer running"; return 0; fi
	current_start=$(process_start_time "$owner_pid")
	if [ -n "$owner_start" ] && [ -n "$current_start" ] && [ "$owner_start" != "$current_start" ]; then STALE_REASON="owner pid $owner_pid was reused by another process"; return 0; fi
	return 1
}
# Returns 0 when the caller should retry mkdir, 1 when the lock is legitimately held.
recover_stale_lock() {
	recovery_guard="$LOCK_DIR.recovery"
	if ! mkdir -m 700 "$recovery_guard" 2>/dev/null; then
		# A recovery guard is held for milliseconds; one older than the grace
		# period was abandoned by a killed contender and is cleared (it is empty).
		if older_than_grace "$recovery_guard" && rmdir "$recovery_guard" 2>/dev/null; then return 0; fi
		return 1
	fi
	recovered=1
	if [ -d "$LOCK_DIR" ] && lock_is_stale; then
		tombstone="$LOCK_DIR.stale.$$.$(date +%s 2>/dev/null || echo 0)"
		if [ ! -e "$tombstone" ] && mv "$LOCK_DIR" "$tombstone" 2>/dev/null; then
			rm -rf "$tombstone"
			echo "AIDR fleet: recovered a stale lifecycle lock ($STALE_REASON)" >&2
			recovered=0
		fi
	elif [ ! -d "$LOCK_DIR" ]; then recovered=0
	fi
	rmdir "$recovery_guard" 2>/dev/null || true
	return "$recovered"
}
write_lock_owner() {
	owner_tmp="$LOCK_DIR/owner.tmp.$$"
	printf 'pid=%s\nboot_id=%s\nstart_time=%s\ncreated=%s\n' "$$" "$(boot_id)" "$(process_start_time "$$")" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$owner_tmp"
	mv "$owner_tmp" "$LOCK_DIR/owner"
}
release_lock() {
	if [ -n "$STAGING_PATH" ] && [ -d "$STAGING_PATH" ]; then rm -rf "$STAGING_PATH"; STAGING_PATH=; fi
	if [ -n "$LOCK_HELD" ]; then
		# Only release a lock this process owns; a lock that was recovered from
		# under us and re-acquired by another run is left alone.
		if [ "$(lock_owner_pid)" = "$$" ]; then rm -f "$LOCK_DIR/owner" "$LOCK_DIR/owner.tmp.$$"; rmdir "$LOCK_DIR" 2>/dev/null || true; fi
		LOCK_HELD=
	fi
}
acquire_lock() {
	mkdir -p "$INSTALL_ROOT"; chmod 755 "$INSTALL_ROOT"
	LOCK_DIR="$INSTALL_ROOT/.fleet-operation.lock"
	trap release_lock EXIT
	trap 'release_lock; exit 1' HUP INT TERM
	lock_attempts=0
	until mkdir -m 700 "$LOCK_DIR" 2>/dev/null; do
		lock_attempts=$((lock_attempts + 1))
		[ "$lock_attempts" -le 3 ] && recover_stale_lock || fail "another AIDR fleet lifecycle operation is active; retry after it completes"
	done
	LOCK_HELD=1
	write_lock_owner
}

check_public_key_permissions() {
	trust_key=${1:-$PUBLIC_KEY}
	[ ! -L "$trust_key" ] || fail "release public key must not be a symlink"
	[ ! -L "$(dirname "$trust_key")" ] || fail "release public key directory must not be a symlink"
	[ "${AIDR_FLEET_TEST_ROOT:-}" ] && return
	for trust_path in "$trust_key" "$(dirname "$trust_key")"; do
		if [ "$PLATFORM" = macos ]; then owner=$(stat -f '%u' "$trust_path"); mode=$(stat -f '%Lp' "$trust_path")
		else owner=$(stat -c '%u' "$trust_path"); mode=$(stat -c '%a' "$trust_path"); fi
		[ "$owner" = 0 ] || fail "release public key and directory must be owned by root"
		last_two=$(printf '%s' "$mode" | sed 's/.*\(..\)$/\1/')
		case "$last_two" in *[2367]*) fail "release public key and directory must not be group/world writable" ;; esac
	done
}

verify_artifact() {
	require_file "$ARTIFACT"; require_file "$SIGNATURE"; require_file "$PUBLIC_KEY"
	printf '%s' "$SHA256" | grep -Eq '^[a-f0-9]{64}$' || fail "--sha256 must be one lowercase SHA-256 digest"
	check_public_key_permissions
	actual=$(sha_file "$ARTIFACT")
	[ "$actual" = "$SHA256" ] || fail "artifact SHA-256 mismatch"
	command -v openssl >/dev/null 2>&1 || fail "openssl is required for publisher signature verification"
	openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$SIGNATURE" "$ARTIFACT" >/dev/null 2>&1 || fail "artifact publisher signature verification failed"
	bytes=$(wc -c < "$ARTIFACT" | tr -d ' '); [ "$bytes" -le 268435456 ] || fail "artifact exceeds the 256 MiB compressed limit"
	tar -tzf "$ARTIFACT" >/dev/null 2>&1 || fail "artifact is not a valid gzip tar archive"
	entries=$(tar -tzf "$ARTIFACT" | wc -l | tr -d ' '); [ "$entries" -le 5000 ] || fail "artifact exceeds the 5000-entry limit"
	# Reject absolute/traversing names and links before extracting the archive.
	tar -tzf "$ARTIFACT" | awk 'BEGIN{bad=0} /\\/{bad=1} /^\//{bad=1} {n=split($0,a,"/"); for(i=1;i<=n;i++) if(a[i]=="..") bad=1} END{exit bad}' || fail "unsafe archive path"
	# GNU tar lists owner/group in field 2; BSD tar lists a link count there
	# and separate owner/group fields. Both must enforce the same size limit.
	LC_ALL=C tar -tvzf "$ARTIFACT" | awk 'BEGIN{total=0;bad=0} {type=substr($1,1,1); if(type!="-" && type!="d"){bad=1;exit 1} if(type=="d") next; size=($2~/^[0-9]+$/ ? $5 : $3); if(size!~/^[0-9]+$/){bad=1;exit 1} total+=size; if(total>536870912){bad=1;exit 1}} END{if(bad || NR==0 || total>536870912) exit 1}' || fail "archive entries must be regular files/directories and fit within the 512 MiB expanded limit"
	printf '%s\n' "$actual"
}

resolve_identity() {
	[ -n "$NODE_BIN" ] && [ -x "$NODE_BIN" ] || fail "Node.js executable not found"
	[ -n "$TARGET_USER" ] || fail "--user is required"
	safe_user "$TARGET_USER"
	if [ -z "$TARGET_HOME" ]; then
		if [ "$PLATFORM" = macos ]; then TARGET_HOME=$(dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory 2>/dev/null | sed -n 's/^NFSHomeDirectory: //p')
		else TARGET_HOME=$(getent passwd "$TARGET_USER" | awk -F: '{print $6}'); fi
	fi
	[ -n "$TARGET_HOME" ] && [ -d "$TARGET_HOME" ] || fail "target user home does not exist"
}

run_for_user() {
	if [ "${AIDR_FLEET_TEST_ROOT:-}" ] && [ "$(id -u)" -ne 0 ]; then
		env HOME="$TARGET_HOME" USERPROFILE="$TARGET_HOME" "$@"
	elif [ "$(id -un)" = "$TARGET_USER" ]; then
		env HOME="$TARGET_HOME" USERPROFILE="$TARGET_HOME" "$@"
	elif [ "$PLATFORM" = macos ]; then
		uid=$(id -u "$TARGET_USER")
		/bin/launchctl asuser "$uid" /usr/bin/sudo -u "$TARGET_USER" /usr/bin/env HOME="$TARGET_HOME" USERPROFILE="$TARGET_HOME" "$@"
	else
		/usr/sbin/runuser -u "$TARGET_USER" -- /usr/bin/env HOME="$TARGET_HOME" USERPROFILE="$TARGET_HOME" "$@"
	fi
}

activate_release() {
	release_id=$1
	package_path="$INSTALL_ROOT/releases/$release_id/package"
	require_file "$package_path/package.json"; require_file "$package_path/dist/pre-tool-use.cjs"; require_file "$package_path/dist/pre-tool-use.bundle.cjs"; require_file "$ENDPOINT_INSTALLER"
	set -- "$NODE_BIN" "$ENDPOINT_INSTALLER" --package-dir "$package_path" --home "$TARGET_HOME"
	if [ -n "$AGENT_CONFIG" ] && [ ! -f "$TARGET_HOME/.singularity-aidr/config.json" ]; then require_file "$AGENT_CONFIG"; set -- "$@" --config "$AGENT_CONFIG"; fi
	run_for_user "$@"
}


# Machine scope: register the release's own multi-call binary in every host's
# system-wide policy. `aidr machine-hooks install` re-verifies every bundle file
# against the bundle manifest (and the manifest signatures against
# releases/<digest>/config/release-public.pem when present) before it writes,
# and fails without writing when they do not verify. Hook commands point at the
# immutable digest directory, so an upgrade or rollback is one atomic rewrite
# of each host's policy file.
activate_machine_release() {
	release_id=$1
	bundle_path="$INSTALL_ROOT/releases/$release_id/bundle"
	[ ! -L "$bundle_path" ] || fail "retained bundle path must not be a symlink"
	require_file "$bundle_path/aidr-artifact.manifest.json"; require_file "$bundle_path/dist/aidr-artifact.manifest.json"
	[ -f "$bundle_path/bin/aidr" ] && [ -x "$bundle_path/bin/aidr" ] || fail "release $release_id has no executable bin/aidr"
	set -- "$bundle_path/bin/aidr" machine-hooks install --bundle-root "$bundle_path"
	[ "$LOCK_OTHER_HOOKS" != 1 ] || set -- "$@" --lock-other-hooks
	[ "$HEARTBEAT" != 1 ] || set -- "$@" --heartbeat
	"$@" || fail "machine-wide hook registration failed for release $release_id; the previous registration (if any) is unchanged where the host files were not rewritten"
	write_cli_launcher "$bundle_path"
}

# A stable `aidr` for administrators and users: $INSTALL_ROOT/bin/aidr runs the
# active release (a launcher, not a link: the bundle locates its rules relative
# to its own binary).
write_cli_launcher() {
	mkdir -p "$INSTALL_ROOT/bin"; chmod 755 "$INSTALL_ROOT/bin"
	launcher_tmp="$INSTALL_ROOT/bin/.aidr.tmp.$$"
	printf '#!/bin/sh\nexec "%s/bin/aidr" "$@"\n' "$1" > "$launcher_tmp"
	chmod 755 "$launcher_tmp"
	if [ -z "${AIDR_FLEET_TEST_ROOT:-}" ]; then chown 0 "$launcher_tmp"; fi
	mv -f "$launcher_tmp" "$INSTALL_ROOT/bin/aidr"
}

# Device management owns updates of a fleet installation: `aidr update` then
# only checks (packages/core/src/update/environment.ts).
write_mdm_marker() {
	require_policy_dir
	[ ! -L "$POLICY_DIR/mdm-managed" ] || fail "MDM marker must not be a symlink"
	: > "$POLICY_DIR/mdm-managed"; chmod 644 "$POLICY_DIR/mdm-managed"
}

# The release-signing (Ed25519) key the bundle manifests verify against. It is
# copied into the staged release as config/release-public.pem, where both
# `aidr machine-hooks install` and per-user `aidr setup` find it.
check_bundle_public_key() {
	[ -n "$BUNDLE_PUBLIC_KEY" ] || return 0
	require_file "$BUNDLE_PUBLIC_KEY"
	check_public_key_permissions "$BUNDLE_PUBLIC_KEY"
	grep -q 'BEGIN PUBLIC KEY' "$BUNDLE_PUBLIC_KEY" || fail "--bundle-public-key is not a PEM public key"
	! grep -q 'PRIVATE KEY' "$BUNDLE_PUBLIC_KEY" || fail "--bundle-public-key holds private key material"
}

stage_release() {
	require_file "$ARTIFACT"; require_file "$SIGNATURE"; require_file "$PUBLIC_KEY"
	printf '%s' "$SHA256" | grep -Eq '^[a-f0-9]{64}$' || fail "--sha256 must be one lowercase SHA-256 digest"
	[ "$SCOPE" = user ] || check_bundle_public_key
	digest=$SHA256
	release="$INSTALL_ROOT/releases/$digest"
	if [ "$SCOPE" = machine ]; then payload_name=bundle; else payload_name=package; fi
	if [ -L "$release" ]; then fail "release path must not be a symlink"; fi
	if [ -d "$release/$payload_name" ]; then
		[ ! -L "$release/$payload_name" ] || fail "retained $payload_name path must not be a symlink"
		# Verify both the supplied candidate and the retained bytes before reuse.
		verify_artifact >/dev/null
		ARTIFACT="$release/artifact.tgz"; SIGNATURE="$release/artifact.sig"
		verify_artifact >/dev/null
		if [ "$SCOPE" = machine ] && [ -n "$BUNDLE_PUBLIC_KEY" ]; then
			cmp -s "$BUNDLE_PUBLIC_KEY" "$release/config/release-public.pem" || fail "retained release $digest was staged with a different (or no) bundle key; review it before changing trust"
		fi
	elif [ -d "$release/package" ] || [ -d "$release/bundle" ]; then
		fail "release $digest holds a $( [ -d "$release/bundle" ] && echo standalone bundle || echo per-user package ), not the $payload_name the $SCOPE scope installs"
	elif [ -e "$release" ]; then
		# A previous interrupted publish can leave the digest directory behind.
		# Never move a new staging tree into that directory: it would nest the
		# package and make every retry fail at activation.
		fail "existing release directory is incomplete; preserve it for investigation and remove it only after review"
	else
		mkdir -p "$INSTALL_ROOT/releases"
		chmod 755 "$INSTALL_ROOT" "$INSTALL_ROOT/releases"
		temporary="$INSTALL_ROOT/releases/.staging-$digest-$$"
		[ ! -e "$temporary" ] || fail "staging path already exists"
		mkdir -m 700 "$temporary"
		STAGING_PATH=$temporary
		cp "$ARTIFACT" "$temporary/artifact.tgz"
		cp "$SIGNATURE" "$temporary/artifact.sig"
		ARTIFACT="$temporary/artifact.tgz"; SIGNATURE="$temporary/artifact.sig"
		verify_artifact >/dev/null
		printf '%s\n' "$digest" > "$temporary/artifact.sha256"
		mkdir "$temporary/extracted"
		tar -xzf "$temporary/artifact.tgz" --no-same-owner --no-same-permissions -C "$temporary/extracted"
		extracted_kib=$(du -sk "$temporary/extracted" | awk '{print $1}'); [ "$extracted_kib" -le 524288 ] || fail "artifact exceeds the 512 MiB extracted limit"
		if [ "$SCOPE" = machine ]; then
			payload_dir=
			for candidate in "$temporary/extracted/aidr-sea" "$temporary/extracted/bundle" "$temporary/extracted"; do
				if [ -f "$candidate/aidr-artifact.manifest.json" ]; then payload_dir=$candidate; break; fi
			done
			[ -n "$payload_dir" ] || fail "artifact is not a standalone AIDR bundle (no aidr-artifact.manifest.json); a per-user npm connector package installs with --user"
			require_file "$payload_dir/bin/aidr"; require_file "$payload_dir/dist/aidr-artifact.manifest.json"
		else
			if [ -f "$temporary/extracted/package/package.json" ]; then payload_dir="$temporary/extracted/package"
			elif [ -f "$temporary/extracted/package.json" ]; then payload_dir="$temporary/extracted"
			else fail "artifact does not contain package.json"; fi
			require_file "$payload_dir/dist/pre-tool-use.cjs"; require_file "$payload_dir/dist/pre-tool-use.bundle.cjs"; [ -d "$payload_dir/resources" ] || fail "artifact does not contain resources"
		fi
		mv "$payload_dir" "$temporary/$payload_name"
		rm -rf "$temporary/extracted"
		if [ "$SCOPE" = machine ] && [ -n "$BUNDLE_PUBLIC_KEY" ]; then
			mkdir "$temporary/config"
			cp "$BUNDLE_PUBLIC_KEY" "$temporary/config/release-public.pem"
		fi
		find "$temporary" -type d -exec chmod 755 {} \;
		find "$temporary" -type f -exec chmod 644 {} \;
		# The multi-call binary is the only executable a bundle carries.
		if [ "$SCOPE" = machine ]; then chmod 755 "$temporary/bundle/bin/aidr"; fi
		if [ -z "${AIDR_FLEET_TEST_ROOT:-}" ]; then chown -R 0 "$temporary"; fi
		mv "$temporary" "$release"
		STAGING_PATH=
	fi
	STAGED_RELEASE=$digest
}

secure_state_for_health() {
	if [ "$PLATFORM" = linux ] && [ -z "${AIDR_FLEET_TEST_ROOT:-}" ] && getent group aidr-health >/dev/null 2>&1; then
		if [ "$SCOPE" = machine ]; then
			chgrp aidr-health "$STATE_ROOT" "$user_state"; chmod 750 "$STATE_ROOT" "$user_state"
		else
			chgrp aidr-health "$STATE_ROOT" "$STATE_ROOT/users" "$user_state"; chmod 750 "$STATE_ROOT" "$STATE_ROOT/users" "$user_state"
		fi
		for state_file in "$user_state"/*; do
			[ -e "$state_file" ] || continue
			chgrp aidr-health "$state_file"; chmod 640 "$state_file"
		done
	fi
}

# Lifecycle state lives in $STATE_ROOT/machine (machine scope) or
# $STATE_ROOT/users/<hex user name> (user scope); the variable keeps its name.
state_dir() {
	if [ "$SCOPE" = machine ]; then printf '%s\n' "$STATE_ROOT/machine"
	else printf '%s\n' "$STATE_ROOT/users/$(state_key "$TARGET_USER")"; fi
}

prepare_user_state() {
	user_state=$(state_dir)
	mkdir -p "$user_state"
	if [ "$SCOPE" = machine ]; then chmod 700 "$STATE_ROOT" "$user_state" 2>/dev/null || true
	else chmod 700 "$STATE_ROOT" "$STATE_ROOT/users" "$user_state" 2>/dev/null || true; fi
}

write_pending_state() {
	prepare_user_state
	printf 'action=%s\ntarget=%s\n' "$1" "$2" > "$user_state/pending.tmp"
	mv "$user_state/pending.tmp" "$user_state/pending"
	secure_state_for_health
}

clear_pending_state() {
	rm -f "$user_state/pending"
	secure_state_for_health
}

read_release_state() {
	CURRENT_RELEASE=; PREVIOUS_RELEASE=
	[ -f "$user_state/release-state" ] || return 0
	CURRENT_RELEASE=$(sed -n 's/^current=\([a-f0-9]\{64\}\)$/\1/p' "$user_state/release-state" | head -n 1)
	PREVIOUS_RELEASE=$(sed -n 's/^previous=\([a-f0-9]\{64\}\)$/\1/p' "$user_state/release-state" | head -n 1)
	[ -n "$CURRENT_RELEASE" ] || fail "invalid release state"
}

write_release_state() {
	current_release=$1; previous_release=${2:-}
	printf '%s' "$current_release" | grep -Eq '^[a-f0-9]{64}$' || fail "invalid current release state"
	if [ -n "$previous_release" ]; then printf '%s' "$previous_release" | grep -Eq '^[a-f0-9]{64}$' || fail "invalid previous release state"; fi
	printf 'current=%s\nprevious=%s\n' "$current_release" "$previous_release" > "$user_state/release-state.tmp"
	mv "$user_state/release-state.tmp" "$user_state/release-state"
}

write_state() {
	prepare_user_state
	read_release_state
	if [ -n "$CURRENT_RELEASE" ] && [ "$CURRENT_RELEASE" != "$1" ]; then PREVIOUS_RELEASE=$CURRENT_RELEASE; fi
	write_release_state "$1" "$PREVIOUS_RELEASE"
	secure_state_for_health
}

# Machine-scope registration options persist across upgrade and rollback, so a
# later run without --lock-other-hooks does not silently unlock the hosts.
# An explicit --[no-]lock-other-hooks / --[no-]heartbeat changes the record.
load_machine_options() {
	options_file="$user_state/options"
	if [ -f "$options_file" ]; then
		[ -n "$LOCK_OTHER_HOOKS" ] || LOCK_OTHER_HOOKS=$(sed -n 's/^lock_other_hooks=\([01]\)$/\1/p' "$options_file" | head -n 1)
		[ -n "$HEARTBEAT" ] || HEARTBEAT=$(sed -n 's/^heartbeat=\([01]\)$/\1/p' "$options_file" | head -n 1)
	fi
	LOCK_OTHER_HOOKS=${LOCK_OTHER_HOOKS:-0}; HEARTBEAT=${HEARTBEAT:-0}
}

write_machine_options() {
	printf 'lock_other_hooks=%s\nheartbeat=%s\n' "$LOCK_OTHER_HOOKS" "$HEARTBEAT" > "$user_state/options.tmp"
	mv "$user_state/options.tmp" "$user_state/options"
}

# Rollback re-verifies the retained archive against the pinned key.
verify_retained_release() {
	release="$INSTALL_ROOT/releases/$1"
	require_file "$release/artifact.tgz"; require_file "$release/artifact.sig"; require_file "$release/artifact.sha256"
	ARTIFACT="$release/artifact.tgz"; SIGNATURE="$release/artifact.sig"; SHA256=$(cat "$release/artifact.sha256")
	[ "$SHA256" = "$1" ] || fail "retained release $1 records a different digest"
	verify_artifact >/dev/null
}

machine_status() {
	user_state=$(state_dir)
	read_release_state
	pending=no; [ ! -e "$user_state/pending" ] || pending=yes
	present=no
	if [ -n "$CURRENT_RELEASE" ] && [ -x "$INSTALL_ROOT/releases/$CURRENT_RELEASE/bundle/bin/aidr" ]; then present=yes; fi
	printf 'scope=machine\ncurrent=%s\nprevious=%s\nrelease_present=%s\nlifecycle_pending=%s\n' "$CURRENT_RELEASE" "$PREVIOUS_RELEASE" "$present" "$pending"
	[ "$present" = yes ] && [ "$pending" = no ] || exit 2
	"$INSTALL_ROOT/releases/$CURRENT_RELEASE/bundle/bin/aidr" machine-hooks status
}

case "$ACTION" in
	verify)
		verify_artifact >/dev/null
		echo "Artifact SHA-256 and publisher signature verified; archive paths are safe."
		;;
	install|upgrade)
		require_root_for_changes
		if [ "$SCOPE" = user ]; then resolve_identity; fi
		build_machine_policy
		acquire_lock
		stage_release; release_id=$STAGED_RELEASE
		write_pending_state "$ACTION" "$release_id"
		write_machine_policy
		if [ "$SCOPE" = machine ]; then
			load_machine_options
			write_mdm_marker
			activate_machine_release "$release_id"
			write_machine_options
		else
			activate_release "$release_id"
		fi
		write_state "$release_id"
		clear_pending_state
		if [ "$SCOPE" = machine ]; then
			echo "AIDR $ACTION completed machine-wide (Claude Code and Codex system policy) at release $release_id. Host and MDM acceptance remain unverified."
		else
			echo "AIDR $ACTION completed for $TARGET_USER at release $release_id. Host and MDM acceptance remain unverified."
		fi
		;;
	rollback)
		require_root_for_changes
		if [ "$SCOPE" = user ]; then resolve_identity; fi
		acquire_lock
		user_state=$(state_dir)
		read_release_state; [ -n "$PREVIOUS_RELEASE" ] || fail "no prior release is available for rollback"; release_id=$PREVIOUS_RELEASE
		verify_retained_release "$release_id"
		write_pending_state rollback "$release_id"
		if [ "$SCOPE" = machine ]; then
			load_machine_options
			activate_machine_release "$release_id"
			write_machine_options
		else
			activate_release "$release_id"
		fi
		write_release_state "$release_id" "$CURRENT_RELEASE"
		clear_pending_state
		secure_state_for_health
		if [ "$SCOPE" = machine ]; then
			echo "AIDR machine-wide rollback completed at release $release_id. Policy and agent configuration were preserved."
		else
			echo "AIDR rollback completed for $TARGET_USER. Policy and agent configuration were preserved."
		fi
		;;
	uninstall)
		require_root_for_changes
		if [ "$SCOPE" = machine ]; then
			acquire_lock
			user_state=$(state_dir)
			read_release_state; [ -n "$CURRENT_RELEASE" ] || fail "no machine-wide installation is recorded in $user_state"
			load_machine_options
			remover="$INSTALL_ROOT/releases/$CURRENT_RELEASE/bundle/bin/aidr"
			[ -x "$remover" ] || fail "the active release $CURRENT_RELEASE has no executable bin/aidr"
			write_pending_state uninstall "0000000000000000000000000000000000000000000000000000000000000000"
			set -- "$remover" machine-hooks remove
			[ "$HEARTBEAT" != 1 ] || set -- "$@" --heartbeat
			"$@" || fail "machine-wide hook removal did not finish; rerun uninstall"
			rm -f "$INSTALL_ROOT/bin/aidr"
			mv "$user_state/release-state" "$user_state/uninstalled-release-state"
			clear_pending_state
			echo "AIDR machine-wide hooks removed. Shared releases, machine policy, per-user connectors and agent configuration were preserved."
		else
			resolve_identity; acquire_lock; require_file "$REMOVE_HELPER"
			write_pending_state uninstall "0000000000000000000000000000000000000000000000000000000000000000"
			run_for_user "$NODE_BIN" "$REMOVE_HELPER" --home "$TARGET_HOME"
			if [ -d "$user_state" ]; then
				[ ! -f "$user_state/release-state" ] || mv "$user_state/release-state" "$user_state/uninstalled-release-state"
			fi
			clear_pending_state
			echo "AIDR hooks disabled for $TARGET_USER. Shared releases, policy, allowlists and agent configuration were preserved."
		fi
		;;
	status)
		if [ -n "$NODE_BIN" ] && [ -x "$NODE_BIN" ] && [ -f "$HEALTH_HELPER" ]; then
			"$NODE_BIN" "$HEALTH_HELPER" --state-root "$STATE_ROOT" --install-root "$INSTALL_ROOT"
		elif [ "$SCOPE" = machine ]; then
			machine_status
		else
			fail "Node.js executable not found"
		fi
		;;
	*) echo "unknown action: $ACTION" >&2; exit 64 ;;
esac
