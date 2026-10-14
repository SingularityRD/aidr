#!/bin/sh
# Singularity AIDR — Linux package maintainer hook (shared by .deb, .rpm and
# the tarball's install.sh / uninstall.sh).
#
#   package-hook.sh postinstall           run `aidr setup` for the invoking user
#   package-hook.sh preremove <final>     on final removal (final=1) run
#                                         `aidr uninstall --yes --keep-data` for
#                                         EVERY local account that ran `aidr setup`;
#                                         an upgrade (0) keeps every registration
#   package-hook.sh deregister-all        the same machine-wide removal without
#                                         removing the package (fleet removal:
#                                         run it as root from configuration
#                                         management, then remove the package)
#
# Machine-wide removal: an account is included when its home holds a
# ~/.singularity-aidr directory it owns (not a link). `aidr uninstall` then runs
# AS THAT USER (runuser), never as root on a user's files, so a user cannot make
# root write through a planted link. Accounts the passwd database does not
# enumerate (some LDAP/SSSD setups) are not seen: run `aidr uninstall` for them,
# or `deregister-all` with AIDR_PACKAGE_HOOK_PASSWD naming a passwd-format list.
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
#   AIDR_PACKAGE_HOOK_PASSWD             passwd-format account list for the
#                                        machine-wide removal (default: getent passwd)
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

# name:home of every account that ran `aidr setup`: it owns ~/.singularity-aidr.
registered_users() {
	if [ -n "${AIDR_PACKAGE_HOOK_PASSWD:-}" ]; then
		cat "$AIDR_PACKAGE_HOOK_PASSWD"
	else
		getent passwd 2>/dev/null || cat /etc/passwd
	fi | while IFS=: read -r name _ uid _ _ home _; do
		case "$name" in '' | *[!A-Za-z0-9._-]*) continue ;; esac
		case "$uid" in '' | *[!0-9]*) continue ;; esac
		case "$home" in /*) ;; *) continue ;; esac
		# Without root only the caller's own account can be changed.
		[ "$(id -u)" -eq 0 ] || [ "$uid" = "$(id -u)" ] || continue
		state="$home/.singularity-aidr"
		[ -d "$state" ] && [ ! -L "$state" ] && [ ! -L "$home" ] || continue
		[ "$(stat -c %u "$state" 2>/dev/null)" = "$uid" ] || continue
		printf '%s:%s\n' "$name" "$home"
	done
}

# `aidr uninstall --yes --keep-data` for every registered account, as that account.
deregister_all() {
	count=0
	failed=0
	list=$(mktemp) || return 1
	registered_users | sort -u > "$list"
	exec 3< "$list"
	rm -f "$list"
	while IFS= read -r entry <&3; do
		user=${entry%%:*}
		home=${entry#*:}
		count=$((count + 1))
		say "removing the AIDR connectors of $user ($home; local data kept)"
		if ! run_as "$user" "$home" env AIDR_OPERATOR_NONINTERACTIVE=1 "$AIDR" uninstall --yes --keep-data < /dev/null; then
			failed=$((failed + 1))
			say "uninstall for $user was incomplete; see the lines above. As $user: aidr uninstall" >&2
		fi
	done
	exec 3<&-
	if [ "$count" -eq 0 ]; then
		say "no account on this machine has AIDR connectors registered"
	else
		say "connectors removed for $((count - failed)) of $count account(s)"
	fi
	[ "$failed" -eq 0 ]
}

case "$action" in
postinstall)
	if [ ! -x "$AIDR" ]; then
		say "$AIDR is missing; the package is incomplete. Reinstall it." >&2
		exit 1
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
	# A failed account never fails the package transaction; it is named above.
	deregister_all || true
	exit 0
	;;
deregister-all)
	if [ ! -x "$AIDR" ]; then
		say "$AIDR is missing; reinstall the package, then run this again." >&2
		exit 1
	fi
	deregister_all
	;;
*)
	say "usage: package-hook.sh postinstall | preremove <final:1|0> | deregister-all" >&2
	exit 64
	;;
esac
