#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export AIDR_FLEET_PLATFORM=macos
exec "$SCRIPT_DIR/../unix/aidr-fleet.sh" verify "$@"
