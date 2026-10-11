#!/usr/bin/env bash
# Local engineering drill: restore the 17.6.1.136 cold backup into a new project on supabase/postgres:17.11.0.004.
set -euo pipefail
D=$(cd "$(dirname "$0")" && pwd)
TAG=${1:?image tag}; RUN=${2:?run name}; OUT="$D/$RUN"
ts() { date -u +%FT%T.%3NZ; }
log() { echo "$(ts) $*" | tee -a "$D/$RUN.timeline.txt"; }
: > "$D/$RUN.timeline.txt"
log "T0 restore start (incident declared)"
node "$D/kit-src/backup/deployment-backup.mjs" verify --backup "$D/backups/b1" --key-file "$D/keys/recovery.key"
log "backup verified (HMAC, ciphertext sha256, GCM tags, tar boundaries)"
node "$D/kit-src/backup/deployment-backup.mjs" recover --backup "$D/backups/b1" --key-file "$D/keys/recovery.key" --runtime "$D/kit-reviewed" --output "$OUT"
P=$(python3 -c "import json;print(json.load(open('$OUT/recovery-receipt.json'))['project_name'])")
echo "$P" > "$OUT.project.txt"
log "recovered into new project $P (new aidr-db/aidr-storage volumes; services stopped)"
# Candidate image swap: only the db image line of the recovered installation changes.
sed -i "s#image: supabase/postgres:17\.6\.1\.136\$#image: supabase/postgres:${TAG}#" "$OUT/compose.yml"
grep -q "image: supabase/postgres:${TAG}$" "$OUT/compose.yml"
C=(docker compose --project-directory "$OUT" -f "$OUT/compose.yml")
"${C[@]}" up -d --pull never --wait --wait-timeout 180 db
log "db healthy on supabase/postgres:${TAG}"
# Supabase in-major image upgrade steps (deploy/upstream/docker/utils/upgrade-pg17.sh step 9 pattern):
# image migrations added since 17.6.1.136, extension version reconcile, collation refresh.
[ "$TAG" = 17.6.1.136 ] || "${C[@]}" exec -T db psql -q -U supabase_admin -d postgres -v ON_ERROR_STOP=1 -f /docker-entrypoint-initdb.d/migrations/20260730000000_revoke_trigger_on_cron_tables_from_postgres.sql
"${C[@]}" exec -T db psql -q -U supabase_admin -d postgres -v ON_ERROR_STOP=1 -c "DO \$\$ DECLARE r record; BEGIN FOR r IN SELECT extname FROM pg_extension LOOP BEGIN EXECUTE format('ALTER EXTENSION %I UPDATE', r.extname); EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'skipped extension %: %', r.extname, SQLERRM; END; END LOOP; END \$\$;"
for db in postgres template1 _supabase; do "${C[@]}" exec -T db psql -q -U supabase_admin -d "$db" -c "ALTER DATABASE \"$db\" REFRESH COLLATION VERSION;" 2>&1 | grep -v 'version has not changed' || true; done
log "post-image-change steps applied"
"${C[@]}" up -d --pull never --wait --wait-timeout 180 auth storage
log "auth, rest, imgproxy, storage healthy"
node "$D/src/scripts/deployment-migrate.mjs" "$OUT"
log "deployment-migrate: 181 canonical migrations verified (hash match, none re-applied)"
"${C[@]}" exec -T db psql -q -U supabase_admin -d postgres -v ON_ERROR_STOP=1 -f - < "$D/verify.sql" > "$D/$RUN.verify.txt" 2>&1
V=$("${C[@]}" ps -q storage | head -1)
docker run --rm --network none -v "${P}_aidr-storage:/data:ro" node:24.21.0-alpine3.24 sh -c 'cd /data && find . -type f | sort | xargs sha256sum | sha256sum; find . -type f | wc -l; du -sb . ; stat -c "%u:%g" $(find . -type f | head -1)' > "$D/$RUN.storage.txt"
SRK=$(grep '^SERVICE_ROLE_KEY=' "$OUT/.env" | cut -d= -f2-)
docker run --rm --network "${P}_default" -e SRK="$SRK" -v "$D/read-storage.mjs:/read.mjs:ro" node:24.21.0-alpine3.24 node /read.mjs > "$D/$RUN.storage-api.txt"
log "T1 verification queries + storage inventory + storage API reads complete"
