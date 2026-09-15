#!/bin/sh
# Runs inside a disposable postgres container with this checkout mounted at /work.
set -eu
for attempt in $(seq 1 30); do
  if pg_isready -U postgres >/dev/null 2>&1; then break; fi
  sleep 1
done
psql -U postgres -v ON_ERROR_STOP=1 -f /work/supabase/functions/__tests__/dlp-policy-storage.sql

# Two real sessions race the same CAS. Exactly one commits; the other must be
# rejected by PT409. No sleeps or advisory-lock mocks decide the winner.
set +e
psql -U postgres -v ON_ERROR_STOP=1 -v VERBOSITY=verbose -c 'select public.test_dlp_save(1)' >/tmp/dlp-race-one.log 2>&1 &
one=$!
psql -U postgres -v ON_ERROR_STOP=1 -v VERBOSITY=verbose -c 'select public.test_dlp_save(1)' >/tmp/dlp-race-two.log 2>&1 &
two=$!
wait "$one"; first=$?
wait "$two"; second=$?
set -e
if ! { [ "$first" -eq 0 ] && [ "$second" -eq 1 ]; } && ! { [ "$first" -eq 1 ] && [ "$second" -eq 0 ]; }; then
  printf 'Unexpected concurrent results: %s %s\n' "$first" "$second"
  exit 1
fi
loser=/tmp/dlp-race-one.log
if [ "$first" -eq 0 ]; then loser=/tmp/dlp-race-two.log; fi
conflict=false
while IFS= read -r line; do
  case "$line" in *'PT409: policy_version_conflict'*) conflict=true ;; esac
done < "$loser"
if [ "$conflict" != true ]; then
  printf 'Concurrent loser did not return the expected PT409 SQLSTATE\n'
  exit 1
fi
psql -U postgres -v ON_ERROR_STOP=1 <<'SQL'
do $$ begin
  if (select version from public.tenant_dlp_policies) <> 2
    or (select count(*) from public.dlp_policy_revisions) <> 2
    or (select count(*) from public.admin_audit_logs) <> 2 then
    raise exception 'concurrent CAS did not commit exactly one revision/audit';
  end if;
end $$;
select 'DLP concurrent CAS passed' as result;
SQL
psql -U postgres -v ON_ERROR_STOP=1 -f /work/supabase/functions/__tests__/dlp-policy-offboarding.sql
