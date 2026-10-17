#!/bin/sh
# Jamf script parameters.
#
# Machine-wide (standalone bundle; hooks for every user; no Node.js):
#   $4  action: install | upgrade | rollback | uninstall
#   $5  artifact, $6 SHA-256 (install/upgrade), $7 signature, $8 pinned public key
#   $9  machine policy control-plane URL (optional)
#   $10 machine policy enrollment-key FILE (optional): a root-owned file holding
#       the aidr_fleet_... key, delivered by MDM; never the key itself here
#   $11 comma-separated switches (optional): protection_locked,
#       protection_unlocked, lock_other_hooks, unlock_other_hooks
#   Giving $9, $10 or a protection switch rewrites managed.json from exactly
#   those values; leave all three empty to keep the existing machine policy.
#
# Per-user (npm connector package; one account; needs Node.js):
#   $4  action: install-user | upgrade-user | rollback-user | uninstall-user
#   $5-$8 as above, $9 agent config (optional), $10 target user (console user
#   when empty)
set -eu
SCRIPT_DIR=${AIDR_JAMF_SCRIPT_DIR:-"/Library/Application Support/Singularity AIDR/fleet/macos"}
CONFIG_DIR=${AIDR_JAMF_CONFIG_DIR:-"/Library/Application Support/Singularity AIDR/config"}
ACTION=${4:-install}
ARTIFACT=${5:-"/Library/Application Support/Singularity AIDR/payload/connector.tgz"}
SHA256=${6:-}
SIGNATURE=${7:-"$ARTIFACT.sig"}
PUBLIC_KEY=${8:-"$CONFIG_DIR/release-public.pem"}
PARAM9=${9:-}
PARAM10=${10:-}
PARAM11=$(printf '%s' "${11:-}" | tr -d ' \t')

require_sha() { [ -n "$SHA256" ] || { echo "Jamf SHA-256 parameter is required" >&2; exit 64; }; }

console_user() {
	target=$PARAM10
	if [ -z "$target" ] || [ "$target" = root ] || [ "$target" = loginwindow ]; then
		target=$(stat -f '%Su' /dev/console)
	fi
	case "$target" in ""|root|loginwindow|_*) echo "No eligible interactive target user" >&2; exit 1 ;; esac
	TARGET_USER=$target
}

case "$ACTION" in
	install|upgrade|rollback|uninstall)
		set -- --scope machine
		case "$ACTION" in
			install|upgrade)
				require_sha
				set -- "$@" --artifact "$ARTIFACT" --sha256 "$SHA256" --signature "$SIGNATURE" --public-key "$PUBLIC_KEY"
				[ ! -f "$CONFIG_DIR/bundle-release-public.pem" ] || set -- "$@" --bundle-public-key "$CONFIG_DIR/bundle-release-public.pem"
				[ -z "$PARAM9" ] || set -- "$@" --control-plane-url "$PARAM9"
				[ -z "$PARAM10" ] || set -- "$@" --enrollment-key-file "$PARAM10"
				;;
			rollback) set -- "$@" --public-key "$PUBLIC_KEY" ;;
		esac
		old_ifs=$IFS; IFS=,
		for switch in $PARAM11; do
			IFS=$old_ifs
			case "$switch" in
				protection_locked) set -- "$@" --protection-locked true ;;
				protection_unlocked) set -- "$@" --protection-locked false ;;
				lock_other_hooks) set -- "$@" --lock-other-hooks ;;
				unlock_other_hooks) set -- "$@" --no-lock-other-hooks ;;
				"") ;;
				*) echo "Unsupported Jamf switch: $switch" >&2; exit 64 ;;
			esac
		done
		IFS=$old_ifs
		exec "$SCRIPT_DIR/$ACTION.sh" "$@"
		;;
	install-user|upgrade-user)
		require_sha; console_user
		set -- --artifact "$ARTIFACT" --sha256 "$SHA256" --signature "$SIGNATURE" --public-key "$PUBLIC_KEY" --user "$TARGET_USER"
		[ -z "$PARAM9" ] || set -- "$@" --config "$PARAM9"
		exec "$SCRIPT_DIR/${ACTION%-user}.sh" "$@"
		;;
	rollback-user) console_user; exec "$SCRIPT_DIR/rollback.sh" --public-key "$PUBLIC_KEY" --user "$TARGET_USER" ;;
	uninstall-user) console_user; exec "$SCRIPT_DIR/uninstall.sh" --user "$TARGET_USER" ;;
	*) echo "Unsupported Jamf action: $ACTION" >&2; exit 64 ;;
esac
