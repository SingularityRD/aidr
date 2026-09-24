#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then echo "run as root" >&2; exit 1; fi
deployment=/srv/aidr
with_backup=false
if [ "${1:-}" = "--with-backup" ]; then with_backup=true; elif [ "$#" -ne 0 ]; then echo "usage: install-systemd.sh [--with-backup]" >&2; exit 1; fi

readiness_env="$deployment/.env.readiness"
function_env="$deployment/.env.functions"
[ -f "$readiness_env" ] && [ -f "$function_env" ] || { echo "prepared readiness configuration is missing" >&2; exit 1; }
[ -f "$deployment/maintenance/aidr-siem-delivery.service" ] && [ -f "$deployment/maintenance/aidr-siem-delivery.timer" ] && [ -f "$deployment/maintenance/readiness-evidence-worker.mjs" ] || { echo "prepared readiness units or runtime are missing" >&2; exit 1; }
grep -Eq '^AIDR_SIGNING_KEY_EXPIRES_AT=[0-9]{4}-' "$readiness_env" || { echo "signing key expiry is missing" >&2; exit 1; }
grep -Eq '^AIDR_DELEGATION_SIGNING_KEY_EXPIRES_AT=[0-9]{4}-' "$readiness_env" || { echo "delegation signing key expiry is missing" >&2; exit 1; }
if grep -Eq '^(AIDR_TELEMETRY_QUEUE_ROOTS|AIDR_SIGNING_KEY_EXPIRES_AT|AIDR_DELEGATION_SIGNING_KEY_EXPIRES_AT)=.*REPLACE_' "$readiness_env"; then
	echo "replace readiness placeholders before activation" >&2; exit 1
fi
if ! grep -Eq '^AIDR_TELEMETRY_QUEUE_ROOTS=/.+' "$readiness_env" && ! grep -Eq '^SINGULARITY_AIDR_SIEM_CONFIG_PATH=/.+' "$readiness_env"; then
	echo "configure at least one real durable queue source" >&2; exit 1
fi

telemetry_roots=$(sed -n 's/^AIDR_TELEMETRY_QUEUE_ROOTS=//p' "$readiness_env")
if [ -n "$telemetry_roots" ]; then
	old_ifs=$IFS
	IFS=,
	for queue_root in $telemetry_roots; do
		case "$queue_root" in
			/var/lib/aidr-telemetry|/var/lib/aidr-telemetry/*) ;;
			*) echo "telemetry queue roots must be under /var/lib/aidr-telemetry" >&2; exit 1 ;;
		esac
	done
	IFS=$old_ifs
	/usr/bin/node -e '
		const { lstatSync, readdirSync } = require("node:fs");
		for (const root of process.argv[1].split(",")) {
			const info = lstatSync(root);
			if (!info.isDirectory() || info.isSymbolicLink()) process.exit(1);
			if (!readdirSync(root, { withFileTypes: true }).some((entry) => entry.isDirectory() && /^[a-f0-9]{64}$/.test(entry.name))) process.exit(1);
		}
	' "$telemetry_roots" || { echo "telemetry queue roots must already contain a real fleet-aggregated queue namespace" >&2; exit 1; }
fi

siem_config=$(sed -n 's/^SINGULARITY_AIDR_SIEM_CONFIG_PATH=//p' "$readiness_env")
if [ -n "$siem_config" ]; then
	[ -f "$siem_config" ] || { echo "SIEM configuration is missing" >&2; exit 1; }
	/usr/bin/node -e '
		const { readFileSync } = require("node:fs");
		const { resolve } = require("node:path");
		const stateFile = resolve(JSON.parse(readFileSync(process.argv[1], "utf8")).state_file || "");
		if (stateFile !== "/var/lib/aidr-siem" && !stateFile.startsWith("/var/lib/aidr-siem/")) process.exit(1);
	' "$siem_config" || { echo "SIEM state_file must be under /var/lib/aidr-siem" >&2; exit 1; }
fi

if [ "$with_backup" = true ]; then
	[ -f /etc/aidr/backup-offsite.env ] && [ -f /etc/aidr/aidr-recovery.key ] || { echo "backup environment or recovery key is missing" >&2; exit 1; }
	[ -f "$deployment/backup/aidr-backup-offsite.service" ] && [ -f "$deployment/backup/aidr-backup-offsite.timer" ] && [ -f "$deployment/backup/aidr-backup-recover.service" ] && [ -f "$deployment/backup/aidr-backup-health-failed.service" ] && [ -f "$deployment/backup/deployment-backup-health-failed.mjs" ] && [ -f "$deployment/backup/deployment-backup-offsite.mjs" ] && [ -f "$deployment/backup/deployment-backup.mjs" ] || { echo "prepared backup units or runtime are missing" >&2; exit 1; }
fi

install -m 0644 "$deployment/maintenance/aidr-siem-delivery.service" /etc/systemd/system/aidr-siem-delivery.service
install -m 0644 "$deployment/maintenance/aidr-siem-delivery.timer" /etc/systemd/system/aidr-siem-delivery.timer
systemctl daemon-reload
systemctl start aidr-siem-delivery.service
systemctl enable --now aidr-siem-delivery.timer

if [ "$with_backup" = true ]; then
	install -m 0644 "$deployment/backup/aidr-backup-offsite.service" /etc/systemd/system/aidr-backup-offsite.service
	install -m 0644 "$deployment/backup/aidr-backup-offsite.timer" /etc/systemd/system/aidr-backup-offsite.timer
	install -m 0644 "$deployment/backup/aidr-backup-recover.service" /etc/systemd/system/aidr-backup-recover.service
	install -m 0644 "$deployment/backup/aidr-backup-health-failed.service" /etc/systemd/system/aidr-backup-health-failed.service
	systemctl daemon-reload
	systemctl enable aidr-backup-recover.service
	echo "Backup units installed; run and verify one backup cycle before enabling aidr-backup-offsite.timer."
fi
