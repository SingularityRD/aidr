#!/bin/sh
# Singularity AIDR — Linux package maintainer hook (shared by .deb, .rpm and
# the tarball's install.sh / uninstall.sh).
#
#   package-hook.sh postinstall           as root: deploy the hooks through each
#                                         AI tool's system-wide policy
#                                         (`aidr machine-hooks install --heartbeat`);
#                                         then run `aidr setup` for the invoking user
#   package-hook.sh preremove <final>     on final removal (final=1) run
#                                         `aidr uninstall --yes --keep-data` for
#                                         the invoking user and
#                                         `aidr machine-hooks remove --heartbeat`;
#                                         an upgrade (0) keeps every registration
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
#   AIDR_MACHINE_HOOKS=0                 do not deploy system-wide hooks (default: deploy
#                                        when run as root): Claude Code managed-settings.d,
#                                        Codex /etc/codex/hooks.json, hourly heartbeat
#   AIDR_LOCK_OTHER_HOOKS=1              also make the hosts run only managed hooks
#   AIDR_PACKAGE_HOOK_TARGET_HOME        home to configure instead of the user's
#                                        passwd entry (fleet tooling and tests)
set -u

PREFIX=${AIDR_PREFIX:-/opt/singularity-aidr}
AIDR="$PREFIX/bundle/bin/aidr"
MDM_MARKER=${AIDR_MDM_MARKER:-/etc/singularity-aidr/mdm-managed}
action=${1:-}

say() { printf '%s\n' "Singularity AIDR: $*"; }

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

# System-wide hooks need root and never block the package transaction.
machine_hooks() {
	[ "${AIDR_MACHINE_HOOKS:-1}" != "0" ] || return 0
	if [ "$(id -u)" -ne 0 ]; then
		say "system-wide hooks not deployed (not root). An administrator runs: aidr machine-hooks $1 --heartbeat"
		return 0
	fi
	lock=""
	[ "$1" != "install" ] || [ "${AIDR_LOCK_OTHER_HOOKS:-}" != "1" ] || lock="--lock-other-hooks"
	# shellcheck disable=SC2086 # $lock is one optional flag
	if ! "$AIDR" machine-hooks "$1" --heartbeat $lock; then
		say "system-wide hooks: 'aidr machine-hooks $1' did not finish (see above); per-user hooks still apply." >&2
	fi
}

case "$action" in
postinstall)
	if [ ! -x "$AIDR" ]; then
		say "$AIDR is missing; the package is incomplete. Reinstall it." >&2
		exit 1
	fi
	machine_hooks install
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
	machine_hooks remove
	say "other users who ran 'aidr setup' must run 'aidr uninstall' before the package is removed;"
	say "otherwise their ~/.claude/settings.json keeps hook entries marked 'Singularity AIDR managed installation' that point at a removed binary; delete those entries."
	exit 0
	;;
*)
	say "usage: package-hook.sh postinstall | preremove <final:1|0>" >&2
	exit 64
	;;
esac
