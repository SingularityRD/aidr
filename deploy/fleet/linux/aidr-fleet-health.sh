#!/bin/sh
set -eu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
NODE_BIN=$(command -v node || true)
[ -n "$NODE_BIN" ] || { echo "Node.js is required for AIDR fleet health" >&2; exit 1; }
exec "$NODE_BIN" /opt/singularity-aidr/libexec/fleet-health.mjs "$@"
