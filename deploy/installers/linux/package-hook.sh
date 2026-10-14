#!/bin/sh
# Singularity AIDR — Linux package maintainer hook (shared by .deb, .rpm and
# the tarball's install.sh / uninstall.sh).
#
#   package-hook.sh postinstall           run `aidr setup` for the invoking user
#   package-hook.sh preremove <final>     on final removal (final=1) run
#                                         `aidr uninstall --yes --keep-data` for
#                                         the invoking user; an upgrade (0) keeps
#                                         every registration
#
# The invoking user is SUDO_USER (`sudo apt install ./aidr.deb`). Setup never
# runs for root or with root's HOME: without a non-root SUDO_USER the hook only
# prints the one command each user runs. A failed setup does not fail the
# package transaction; it prints the command to rerun.
#
# Environment:
#   AIDR_INSTALL_SKIP_SETUP=1            install files only (images, MDM pre-staging)
#   AIDR_MDM_MANAGED=1                   device-managed install: writes the marker
#                                        `aidr update` reads, so updates are left to
#                                        the MDM / configuration-management tool
#   AIDR_MDM_MARKER                      marker path (default /etc/singularity-aidr/mdm-managed)
#   AIDR_PREFIX                          install prefix (default /opt/singularity-aidr)
#   AIDR_PACKAGE_HOOK_TARGET_HOME        home to configure instead of the user's
#                                        passwd entry (fleet tooling and tests)
#
# Machine policy (packages/core/src/machine-policy.ts): when any AIDR_POLICY_*
# variable is set, postinstall (as root) writes /etc/singularity-aidr/managed.json
# from them, replacing an earlier one; with none set an existing file is kept
# (an upgrade never drops it). Every user's `aidr setup` then connects to the
# company without asking, and every hook reads it:
#   AIDR_POLICY_CONTROL_PLANE_URL         https://... company control plane
#   AIDR_POLICY_ENROLLMENT_KEY            aidr_fleet_... fleet enrollment key
#   AIDR_POLICY_LICENSING_PUBLIC_KEYS     base64 SPKI keys, space/comma separated
#   AIDR_POLICY_LICENSING_PUBLIC_KEYS_FILE  PEM file with the deployment's public keys
#                                        (endpoint-policy/licensing-public-keys.pem)
#   AIDR_POLICY_CA_FILE                   PEM bundle of an internal / TLS-inspection CA
#   AIDR_POLICY_USE_OS_TRUST_STORE        1 | 0: also trust the OS store (/etc/ssl)
#   AIDR_POLICY_HTTPS_PROXY               http://proxy:port
#   AIDR_POLICY_NO_PROXY                  hosts / domain suffixes that go direct
#   AIDR_POLICY_SUPPORT_CONTACT_URL       https:// or mailto: shown to users
#   AIDR_POLICY_PRIVACY_NOTICE_URL        https:// privacy notice shown to users
#   AIDR_POLICY_APPROVALS_MODE            dashboard_only | host_dialog
#   AIDR_POLICY_OFFLINE_POLICY            keep_enforcing_local | block_after_grace
#   AIDR_MACHINE_POLICY                   policy path (default /etc/singularity-aidr/managed.json; tests)
# sudo resets the environment: pass them as `sudo env AIDR_POLICY_...=... apt install ./aidr.deb`.
set -u

PREFIX=${AIDR_PREFIX:-/opt/singularity-aidr}
AIDR="$PREFIX/bundle/bin/aidr"
MDM_MARKER=${AIDR_MDM_MARKER:-/etc/singularity-aidr/mdm-managed}
MACHINE_POLICY=${AIDR_MACHINE_POLICY:-/etc/singularity-aidr/managed.json}
action=${1:-}

say() { printf '%s\n' "Singularity AIDR: $*"; }

# A JSON string from a value that needs no escaping; anything else is refused.
json_text() {
	case "$2" in
	*'"'* | *'\'* | *"$(printf '\t')"* | *"$(printf '\r')"*)
		say "$1 contains a quote, backslash or control character; the machine policy was not written" >&2
		return 1
		;;
	esac
	if [ "$(printf '%s' "$2" | wc -l)" -ne 0 ]; then
		say "$1 contains a line break; the machine policy was not written" >&2
		return 1
	fi
	printf '"%s"' "$2"
}

# The deployment's public keys as a JSON array of base64 SPKI strings.
policy_keys() {
	keys=${AIDR_POLICY_LICENSING_PUBLIC_KEYS:-}
	if [ -n "${AIDR_POLICY_LICENSING_PUBLIC_KEYS_FILE:-}" ]; then
		if [ ! -r "$AIDR_POLICY_LICENSING_PUBLIC_KEYS_FILE" ]; then
			say "AIDR_POLICY_LICENSING_PUBLIC_KEYS_FILE cannot be read; the machine policy was not written" >&2
			return 1
		fi
		keys="$keys $(awk '/-----BEGIN PUBLIC KEY-----/{k="";on=1;next} /-----END PUBLIC KEY-----/{if(on)printf "%s ",k;on=0;next} on{gsub(/[ \t\r]/,"");k=k $0}' "$AIDR_POLICY_LICENSING_PUBLIC_KEYS_FILE")"
	fi
	out=""
	for key in $(printf '%s' "$keys" | tr ',;' '  '); do
		case "$key" in *[!A-Za-z0-9+/=]*)
			say "AIDR_POLICY_LICENSING_PUBLIC_KEYS holds something that is not a base64 public key; the machine policy was not written" >&2
			return 1
			;;
		esac
		out="$out${out:+,}\"$key\""
	done
	[ -z "$out" ] || printf '[%s]' "$out"
}

# Write the machine policy from the AIDR_POLICY_* variables (root only).
write_machine_policy() {
	fields=""
	for pair in control_plane_url:CONTROL_PLANE_URL enrollment_key:ENROLLMENT_KEY ca_file:CA_FILE \
		https_proxy:HTTPS_PROXY no_proxy:NO_PROXY support_contact_url:SUPPORT_CONTACT_URL \
		privacy_notice_url:PRIVACY_NOTICE_URL approvals_mode:APPROVALS_MODE offline_policy:OFFLINE_POLICY; do
		name=AIDR_POLICY_${pair#*:}
		value=$(printenv "$name" || true)
		[ -n "$value" ] || continue
		text=$(json_text "$name" "$value") || return 1
		fields="$fields${fields:+,}
  \"${pair%%:*}\": $text"
	done
	case "${AIDR_POLICY_USE_OS_TRUST_STORE:-}" in
	"") ;;
	1 | true | yes) fields="$fields${fields:+,}
  \"use_os_trust_store\": true" ;;
	0 | false | no) fields="$fields${fields:+,}
  \"use_os_trust_store\": false" ;;
	*)
		say "AIDR_POLICY_USE_OS_TRUST_STORE must be 1 or 0; the machine policy was not written" >&2
		return 1
		;;
	esac
	keys=$(policy_keys) || return 1
	[ -z "$keys" ] || fields="$fields${fields:+,}
  \"licensing_public_keys_pem\": $keys"
	[ -n "$fields" ] || return 0
	if [ "$(id -u)" -ne 0 ] && [ -z "${AIDR_MACHINE_POLICY:-}" ]; then
		say "the machine policy needs root; it was not written" >&2
		return 1
	fi
	dir=$(dirname "$MACHINE_POLICY")
	umask 022
	mkdir -p "$dir" && chmod 755 "$dir" || return 1
	tmp="$MACHINE_POLICY.tmp.$$"
	if ! { printf '{%s\n}\n' "$fields" > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$MACHINE_POLICY"; }; then
		rm -f "$tmp"
		return 1
	fi
	say "machine policy written to $MACHINE_POLICY (every user's 'aidr setup' applies it)"
}

target_user() {
	user=${SUDO_USER:-}
	[ -n "$user" ] || return 1
	[ "$user" != "root" ] || return 1
	case "$user" in *[!A-Za-z0-9._-]*) return 1 ;; esac
	getent passwd "$user" >/dev/null 2>&1 || id "$user" >/dev/null 2>&1 || return 1
	printf '%s' "$user"
}

user_home() {
	if [ -n "${AIDR_PACKAGE_HOOK_TARGET_HOME:-}" ]; then
		printf '%s' "$AIDR_PACKAGE_HOOK_TARGET_HOME"
		return 0
	fi
	getent passwd "$1" 2>/dev/null | cut -d: -f6
}

# Run the bundle's aidr as <user> with that user's HOME, never root's.
run_as() {
	user=$1; home=$2; shift 2
	if [ "$(id -u)" -ne 0 ]; then
		env HOME="$home" "$@"
	elif command -v runuser >/dev/null 2>&1; then
		runuser -u "$user" -- env HOME="$home" "$@"
	else
		su -s /bin/sh "$user" -c 'HOME="$0"; export HOME; shift; exec "$@"' "$home" "$@"
	fi
}

case "$action" in
postinstall)
	if [ ! -x "$AIDR" ]; then
		say "$AIDR is missing; the package is incomplete. Reinstall it." >&2
		exit 1
	fi
	# Before any setup runs: setup reads it.
	if ! write_machine_policy; then
		say "fix the AIDR_POLICY_* values and reinstall, or write $MACHINE_POLICY by hand (docs/installation/desktop-installers.md)" >&2
	fi
	if [ "${AIDR_MDM_MANAGED:-}" = "1" ]; then
		if mkdir -p "$(dirname "$MDM_MARKER")" && : > "$MDM_MARKER"; then
			say "device-managed install: update it with your device management tool ('aidr update' only checks)"
		else
			say "could not write $MDM_MARKER; automatic updates stay on" >&2
		fi
	fi
	if [ "${AIDR_INSTALL_SKIP_SETUP:-}" = "1" ]; then
		say "installed (setup skipped: AIDR_INSTALL_SKIP_SETUP=1). Each user runs once: aidr setup"
		exit 0
	fi
	if ! user=$(target_user); then
		say "installed. Each user runs once (as themselves, not root): aidr setup, or opens 'Singularity AIDR Setup Assistant' from the applications menu"
		exit 0
	fi
	home=$(user_home "$user")
	if [ -z "$home" ] || [ ! -d "$home" ]; then
		say "installed, but the home of $user was not found. Run as $user: aidr setup"
		exit 0
	fi
	say "running 'aidr setup' for $user ($home)"
	# aidr setup exits 3 when it found no supported AI tool to protect yet:
	# that is not a failure, and the package install still succeeds.
	run_as "$user" "$home" "$AIDR" setup
	rc=$?
	case "$rc" in
	0)
		run_as "$user" "$home" "$AIDR" status >/dev/null 2>&1 || true
		say "done. Restart your AI tools, then run: aidr status && aidr verify"
		say "to check or change it step by step, open 'Singularity AIDR Setup Assistant' from the applications menu, or run: aidr assistant"
		;;
	3)
		say "installed. No AI tool (Claude Code, Cursor, VS Code, Codex, OpenCode, OpenClaw) was found for $user yet."
		say "after installing one, $user runs once: aidr setup (or opens 'Singularity AIDR Setup Assistant' from the applications menu)"
		;;
	*)
		say "setup did not finish for $user (see the lines above). Run as $user: aidr setup, or open 'Singularity AIDR Setup Assistant' from the applications menu" >&2
		;;
	esac
	exit 0
	;;
preremove)
	final=${2:-1}
	[ "$final" = "1" ] || exit 0
	rm -f "$MDM_MARKER"
	[ -x "$AIDR" ] || exit 0
	if user=$(target_user); then
		home=$(user_home "$user")
		if [ -n "$home" ] && [ -d "$home" ]; then
			say "removing the AIDR connectors of $user (local data kept)"
			if ! run_as "$user" "$home" env AIDR_OPERATOR_NONINTERACTIVE=1 "$AIDR" uninstall --yes --keep-data; then
				say "uninstall for $user was incomplete; see the lines above." >&2
			fi
		fi
	fi
	say "other users who ran 'aidr setup' must run 'aidr uninstall' before the package is removed;"
	say "otherwise their ~/.claude/settings.json keeps hook entries marked 'Singularity AIDR managed installation' that point at a removed binary; delete those entries."
	exit 0
	;;
*)
	say "usage: package-hook.sh postinstall | preremove <final:1|0>" >&2
	exit 64
	;;
esac
