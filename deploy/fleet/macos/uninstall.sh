#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export AIDR_FLEET_PLATFORM=macos
export AIDR_REMOVE_HELPER="${AIDR_REMOVE_HELPER:-$SCRIPT_DIR/../unix/remove-managed-hooks.mjs}"
export AIDR_HEALTH_HELPER="${AIDR_HEALTH_HELPER:-$SCRIPT_DIR/../unix/fleet-health.mjs}"
exec "$SCRIPT_DIR/../unix/aidr-fleet.sh" uninstall "$@"
