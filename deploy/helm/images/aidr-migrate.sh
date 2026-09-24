#!/bin/sh
# Applies the AIDR schema plan baked into the migrations image.
#
# The plan (/opt/aidr/migrate.sql) is one transaction behind an advisory lock:
# already-applied migrations are skipped by name and SHA-256, a changed or
# unknown migration aborts the whole run, and nothing is partially applied.
# Connection settings come from the standard libpq variables (PGHOST, PGPORT,
# PGDATABASE, PGUSER, PGPASSWORD, PGSSLMODE).
set -eu

AIDR_ROOT="${AIDR_MIGRATION_ROOT:-/opt/aidr}"
: "${PGHOST:?PGHOST is required}"
: "${PGPASSWORD:?PGPASSWORD is required}"
wait_seconds="${AIDR_MIGRATION_STORAGE_WAIT_SECONDS:-600}"
case "$wait_seconds" in
	'' | *[!0-9]*) echo "AIDR_MIGRATION_STORAGE_WAIT_SECONDS must be a whole number of seconds" >&2; exit 2 ;;
esac

expected="$(sed -n 's/.*"plan_sha256": *"\([a-f0-9]\{64\}\)".*/\1/p' "$AIDR_ROOT/migrations.manifest.json")"
actual="$(sha256sum "$AIDR_ROOT/migrate.sql" | cut -d ' ' -f 1)"
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
	echo "migration plan checksum mismatch: refusing to apply" >&2
	exit 1
fi

# Storage creates storage.buckets on its first boot and the AIDR migrations
# depend on it; wait for that exact prerequisite.
deadline=$(( $(date +%s) + wait_seconds ))
until [ "$(psql -X -tAc "SELECT to_regclass('storage.buckets') IS NOT NULL" 2>/dev/null || true)" = "t" ]; do
	if [ "$(date +%s)" -ge "$deadline" ]; then
		echo "storage schema (storage.buckets) did not appear within ${wait_seconds}s; check the storage and database pods" >&2
		exit 1
	fi
	sleep 3
done

psql -X -v ON_ERROR_STOP=1 -f "$AIDR_ROOT/migrate.sql"
count="$(sed -n 's/.*"migration_count": *\([0-9][0-9]*\).*/\1/p' "$AIDR_ROOT/migrations.manifest.json")"
echo "Verified/applied ${count} migrations atomically. Existing matching migrations were skipped."
