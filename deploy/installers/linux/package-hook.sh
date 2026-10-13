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
#   AIDR_PREFIX                          install prefix (default /opt/singularity-aidr)
#   AIDR_PACKAGE_HOOK_TARGET_HOME        home to configure instead of the user's
#                                        passwd entry (fleet tooling and tests)
set -u

PREFIX=${AIDR_PREFIX:-/opt/singularity-aidr}
AIDR="$PREFIX/bundle/bin/aidr"
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

case "$action" in
postinstall)
	if [ ! -x "$AIDR" ]; then
		say "$AIDR is missing; the package is incomplete. Reinstall it." >&2
		exit 1
	fi
	if [ "${AIDR_INSTALL_SKIP_SETUP:-}" = "1" ]; then
		say "installed (setup skipped: AIDR_INSTALL_SKIP_SETUP=1). Each user runs once: aidr setup"
		exit 0
	fi
	if ! user=$(target_user); then
		say "installed. Each user runs once (as themselves, not root): aidr setup"
		exit 0
	fi
	home=$(user_home "$user")
	if [ -z "$home" ] || [ ! -d "$home" ]; then
		say "installed, but the home of $user was not found. Run as $user: aidr setup"
		exit 0
	fi
	say "running 'aidr setup' for $user ($home)"
	if run_as "$user" "$home" "$AIDR" setup; then
		run_as "$user" "$home" "$AIDR" status >/dev/null 2>&1 || true
		say "done. Restart your AI tools, then run: aidr status && aidr verify"
	else
		say "setup did not finish for $user. Run as $user: aidr setup" >&2
	fi
	exit 0
	;;
preremove)
	final=${2:-1}
	[ "$final" = "1" ] || exit 0
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
