#!/bin/sh
set -eu
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/opt/homebrew/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

ACTION="${1:-}"
if [ -z "$ACTION" ]; then
	echo "usage: aidr-fleet.sh verify|install|upgrade|rollback|uninstall|status [options]" >&2
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
		*) echo "unknown option: $1" >&2; exit 64 ;;
	esac
done

fail() { echo "AIDR fleet: $*" >&2; exit 1; }
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
	if [ "${AIDR_FLEET_TEST_ROOT:-}" ]; then
		[ "$(id -u)" -ne 0 ] || fail "test-root mode is unavailable to privileged installations"
		case "$INSTALL_ROOT/" in "${AIDR_FLEET_TEST_ROOT%/}"/*) ;; *) fail "test install root escaped AIDR_FLEET_TEST_ROOT" ;; esac
		case "$STATE_ROOT/" in "${AIDR_FLEET_TEST_ROOT%/}"/*) ;; *) fail "test state root escaped AIDR_FLEET_TEST_ROOT" ;; esac
		return
	fi
	[ "$(id -u)" -eq 0 ] || fail "system installation actions require root"
}

LOCK_HELD= STAGING_PATH=
release_lock() {
	if [ -n "$STAGING_PATH" ] && [ -d "$STAGING_PATH" ]; then rm -rf "$STAGING_PATH"; STAGING_PATH=; fi
	if [ -n "$LOCK_HELD" ]; then rmdir "$INSTALL_ROOT/.fleet-operation.lock" 2>/dev/null || true; LOCK_HELD=; fi
}
acquire_lock() {
	mkdir -p "$INSTALL_ROOT"; chmod 755 "$INSTALL_ROOT"
	mkdir -m 700 "$INSTALL_ROOT/.fleet-operation.lock" 2>/dev/null || fail "another AIDR fleet lifecycle operation is active; retry after it completes"
	LOCK_HELD=1
	trap release_lock EXIT
	trap 'release_lock; exit 1' HUP INT TERM
}

check_public_key_permissions() {
	[ ! -L "$PUBLIC_KEY" ] || fail "release public key must not be a symlink"
	[ ! -L "$(dirname "$PUBLIC_KEY")" ] || fail "release public key directory must not be a symlink"
	[ "${AIDR_FLEET_TEST_ROOT:-}" ] && return
	for trust_path in "$PUBLIC_KEY" "$(dirname "$PUBLIC_KEY")"; do
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
	require_file "$package_path/package.json"; require_file "$package_path/dist/pre-tool-use.cjs"; require_file "$ENDPOINT_INSTALLER"
	set -- "$NODE_BIN" "$ENDPOINT_INSTALLER" --package-dir "$package_path" --home "$TARGET_HOME"
	if [ -n "$AGENT_CONFIG" ] && [ ! -f "$TARGET_HOME/.singularity-aidr/config.json" ]; then require_file "$AGENT_CONFIG"; set -- "$@" --config "$AGENT_CONFIG"; fi
	run_for_user "$@"
}

stage_release() {
	require_file "$ARTIFACT"; require_file "$SIGNATURE"; require_file "$PUBLIC_KEY"
	printf '%s' "$SHA256" | grep -Eq '^[a-f0-9]{64}$' || fail "--sha256 must be one lowercase SHA-256 digest"
	digest=$SHA256
	release="$INSTALL_ROOT/releases/$digest"
	if [ -L "$release" ]; then fail "release path must not be a symlink"; fi
	if [ -d "$release/package" ]; then
		[ ! -L "$release/package" ] || fail "retained package path must not be a symlink"
		# Verify both the supplied candidate and the retained bytes before reuse.
		verify_artifact >/dev/null
		ARTIFACT="$release/artifact.tgz"; SIGNATURE="$release/artifact.sig"
		verify_artifact >/dev/null
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
		if [ -f "$temporary/extracted/package/package.json" ]; then package_dir="$temporary/extracted/package"
		elif [ -f "$temporary/extracted/package.json" ]; then package_dir="$temporary/extracted"
		else fail "artifact does not contain package.json"; fi
		require_file "$package_dir/dist/pre-tool-use.cjs"; [ -d "$package_dir/resources" ] || fail "artifact does not contain resources"
		mv "$package_dir" "$temporary/package"
		rm -rf "$temporary/extracted"
		find "$temporary" -type d -exec chmod 755 {} \;
		find "$temporary" -type f -exec chmod 644 {} \;
		if [ -z "${AIDR_FLEET_TEST_ROOT:-}" ]; then chown -R 0 "$temporary"; fi
		mv "$temporary" "$release"
		STAGING_PATH=
	fi
	STAGED_RELEASE=$digest
}

secure_state_for_health() {
	if [ "$PLATFORM" = linux ] && [ -z "${AIDR_FLEET_TEST_ROOT:-}" ] && getent group aidr-health >/dev/null 2>&1; then
		chgrp aidr-health "$STATE_ROOT" "$STATE_ROOT/users" "$user_state"
		chmod 750 "$STATE_ROOT" "$STATE_ROOT/users" "$user_state"
		for state_file in "$user_state"/*; do
			[ -e "$state_file" ] || continue
			chgrp aidr-health "$state_file"; chmod 640 "$state_file"
		done
	fi
}

prepare_user_state() {
	key=$(state_key "$TARGET_USER")
	user_state="$STATE_ROOT/users/$key"
	mkdir -p "$user_state"; chmod 700 "$STATE_ROOT" "$STATE_ROOT/users" "$user_state" 2>/dev/null || true
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

case "$ACTION" in
	verify)
		verify_artifact >/dev/null
		echo "Artifact SHA-256 and publisher signature verified; archive paths are safe."
		;;
	install|upgrade)
		require_root_for_changes; resolve_identity; acquire_lock
		stage_release; release_id=$STAGED_RELEASE
		write_pending_state "$ACTION" "$release_id"
		activate_release "$release_id"
		write_state "$release_id"
		clear_pending_state
		echo "AIDR $ACTION completed for $TARGET_USER at release $release_id. Host and MDM acceptance remain unverified."
		;;
	rollback)
		require_root_for_changes; resolve_identity; acquire_lock
		key=$(state_key "$TARGET_USER"); user_state="$STATE_ROOT/users/$key"
		read_release_state; [ -n "$PREVIOUS_RELEASE" ] || fail "no prior release is available for rollback"; release_id=$PREVIOUS_RELEASE
		release="$INSTALL_ROOT/releases/$release_id"
		require_file "$release/artifact.tgz"; require_file "$release/artifact.sig"; require_file "$release/artifact.sha256"
		ARTIFACT="$release/artifact.tgz"; SIGNATURE="$release/artifact.sig"; SHA256=$(cat "$release/artifact.sha256")
		verify_artifact >/dev/null
		write_pending_state rollback "$release_id"
		activate_release "$release_id"
		write_release_state "$release_id" "$CURRENT_RELEASE"
		clear_pending_state
		secure_state_for_health
		echo "AIDR rollback completed for $TARGET_USER. Policy and agent configuration were preserved."
		;;
	uninstall)
		require_root_for_changes; resolve_identity; acquire_lock; require_file "$REMOVE_HELPER"
		write_pending_state uninstall "0000000000000000000000000000000000000000000000000000000000000000"
		run_for_user "$NODE_BIN" "$REMOVE_HELPER" --home "$TARGET_HOME"
		if [ -d "$user_state" ]; then
			[ ! -f "$user_state/release-state" ] || mv "$user_state/release-state" "$user_state/uninstalled-release-state"
		fi
		clear_pending_state
		echo "AIDR hooks disabled for $TARGET_USER. Shared releases, policy, allowlists and agent configuration were preserved."
		;;
	status)
		require_file "$HEALTH_HELPER"; [ -n "$NODE_BIN" ] || fail "Node.js executable not found"
		"$NODE_BIN" "$HEALTH_HELPER" --state-root "$STATE_ROOT" --install-root "$INSTALL_ROOT"
		;;
	*) echo "unknown action: $ACTION" >&2; exit 64 ;;
esac
