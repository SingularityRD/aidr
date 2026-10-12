#!/bin/sh
# Jamf script parameters: $4 action, $5 artifact, $6 SHA-256, $7 signature,
# $8 pinned public key, $9 agent config (optional), $10 target user (optional).
set -eu
SCRIPT_DIR=${AIDR_JAMF_SCRIPT_DIR:-"/Library/Application Support/Singularity AIDR/fleet/macos"}
ACTION=${4:-install}
ARTIFACT=${5:-"/Library/Application Support/Singularity AIDR/payload/connector.tgz"}
SHA256=${6:-}
SIGNATURE=${7:-"$ARTIFACT.sig"}
PUBLIC_KEY=${8:-"/Library/Application Support/Singularity AIDR/config/release-public.pem"}
AGENT_CONFIG=${9:-}
TARGET_USER=${10:-}

if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = root ] || [ "$TARGET_USER" = loginwindow ]; then
	TARGET_USER=$(stat -f '%Su' /dev/console)
fi
case "$TARGET_USER" in ""|root|loginwindow|_*) echo "No eligible interactive target user" >&2; exit 1 ;; esac

case "$ACTION" in
	install|upgrade)
		[ -n "$SHA256" ] || { echo "Jamf SHA-256 parameter is required" >&2; exit 64; }
		set -- --artifact "$ARTIFACT" --sha256 "$SHA256" --signature "$SIGNATURE" --public-key "$PUBLIC_KEY" --user "$TARGET_USER"
		[ -z "$AGENT_CONFIG" ] || set -- "$@" --config "$AGENT_CONFIG"
		exec "$SCRIPT_DIR/$ACTION.sh" "$@"
		;;
	rollback) exec "$SCRIPT_DIR/rollback.sh" --public-key "$PUBLIC_KEY" --user "$TARGET_USER" ;;
	uninstall) exec "$SCRIPT_DIR/uninstall.sh" --user "$TARGET_USER" ;;
	*) echo "Unsupported Jamf action: $ACTION" >&2; exit 64 ;;
esac
