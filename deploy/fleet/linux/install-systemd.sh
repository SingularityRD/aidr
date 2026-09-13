#!/bin/sh
set -eu
umask 027
[ "$(id -u)" -eq 0 ] || { echo "install-systemd.sh requires root" >&2; exit 1; }
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INSTALL_ROOT=/opt/singularity-aidr
STATE_ROOT=/var/lib/singularity-aidr
[ "${AIDR_FLEET_INSTALL_ROOT:-$INSTALL_ROOT}" = "$INSTALL_ROOT" ] || { echo "systemd template requires $INSTALL_ROOT" >&2; exit 1; }
[ "${AIDR_FLEET_STATE_ROOT:-$STATE_ROOT}" = "$STATE_ROOT" ] || { echo "systemd template requires $STATE_ROOT" >&2; exit 1; }

if ! getent group aidr-health >/dev/null 2>&1; then groupadd --system aidr-health; fi
if ! getent passwd aidr-health >/dev/null 2>&1; then
	useradd --system --gid aidr-health --home-dir /nonexistent --shell /usr/sbin/nologin aidr-health
fi
install -d -o root -g root -m 0755 "$INSTALL_ROOT/libexec" "$INSTALL_ROOT/share/fleet"
install -d -o root -g aidr-health -m 0750 "$STATE_ROOT" "$STATE_ROOT/users"
install -d -o root -g aidr-health -m 0770 "$STATE_ROOT/health"
install -o root -g root -m 0755 "$SCRIPT_DIR/../unix/aidr-fleet.sh" "$INSTALL_ROOT/libexec/aidr-fleet.sh"
install -o root -g root -m 0755 "$SCRIPT_DIR/../unix/remove-managed-hooks.mjs" "$INSTALL_ROOT/libexec/remove-managed-hooks.mjs"
install -o root -g root -m 0755 "$SCRIPT_DIR/../unix/fleet-health.mjs" "$INSTALL_ROOT/libexec/fleet-health.mjs"
install -o root -g root -m 0755 "$SCRIPT_DIR/aidr-fleet-health.sh" "$INSTALL_ROOT/libexec/aidr-fleet-health"
install -o root -g root -m 0755 "$SCRIPT_DIR/../../../scripts/endpoint-install.mjs" "$INSTALL_ROOT/libexec/endpoint-install.mjs"
install -o root -g root -m 0644 "$SCRIPT_DIR/README.md" "$INSTALL_ROOT/share/fleet/README.md"
install -o root -g root -m 0644 "$SCRIPT_DIR/systemd/aidr-fleet-health.service" /etc/systemd/system/aidr-fleet-health.service
install -o root -g root -m 0644 "$SCRIPT_DIR/systemd/aidr-fleet-health.timer" /etc/systemd/system/aidr-fleet-health.timer
systemctl daemon-reload
systemctl enable --now aidr-fleet-health.timer
echo "AIDR health timer installed. This reports release presence; it does not attest host hook execution."
