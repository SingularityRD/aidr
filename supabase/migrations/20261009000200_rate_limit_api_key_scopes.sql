-- Admit the remaining Edge Function counters to the reviewed rate-limit RPC.
--
-- _shared/api-key-auth.ts charges `api-key:v1:unresolved:<endpoint>` for every
-- unresolved tenant API key (url-check, file-check, ingest, policy, policy-ack,
-- packs-manifest, packs-download, revocations, browser-guard-policy), and
-- version-check counts `version-check:*`. Neither scope was in the allowlist
-- from 20260913000005, so increment_rate_limit raised invalid_rate_limit_scope:
-- a rejected or expired key got 503 rate_limit_unavailable instead of 401, the
-- unresolved-credential budget never accrued, and version-check always answered
-- 503 (found by scripts/deployment-smoke.mjs on a self-hosted installation).
-- Same in-place extension as 20261005220000_oidc_administration_hardening.
do $migration$
declare
  v_definition text;
  v_old text := '''oidc-callback'', ''oidc-break-glass''';
begin
  select pg_get_functiondef('public.increment_rate_limit(text,bigint,integer)'::regprocedure) into v_definition;
  if position('''api-key''' in v_definition) > 0 then return; end if;
  if cardinality(string_to_array(v_definition, v_old)) <> 2 then
    raise exception 'unexpected_rate_limit_scope_definition';
  end if;
  execute replace(v_definition, v_old, v_old || ', ''api-key'', ''version-check''');
end
$migration$;
