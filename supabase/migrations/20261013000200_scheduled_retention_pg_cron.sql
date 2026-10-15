-- Scheduled retention maintenance inside the database (CP-3).
--
-- Compose installs run scripts/deployment-maintenance.mjs from a systemd timer
-- and Helm installs from the maintenance CronJob. Supabase Cloud has neither,
-- so without this migration telemetry, approval requests, expired invitations,
-- billing webhooks, GA trial subjects, public waitlist rows and rate-limit
-- counters were never deleted there and governance digests never sent.
--
-- app.run_retention_job(job) runs ONE bounded apply batch of one existing
-- retention RPC (the same functions the HTTP worker calls, with their
-- tenant-lock and legal-hold semantics) in its own transaction and records the
-- receipt in public.retention_job_runs. app.schedule_retention_maintenance()
-- registers one pg_cron job per data class; it is idempotent (cron.schedule
-- upserts by job name) and does nothing where pg_cron is not installed. This
-- migration calls it when pg_cron is present; after enabling pg_cron later,
-- an operator runs `select app.schedule_retention_maintenance();` once.
--
-- Not covered here, because they need the Storage API's exact-deletion
-- protocol: expired temporary audit-export objects. Run the HTTP worker for
-- those (docs/control-plane.md, "Retention maintenance"). The governance
-- digest is posted through pg_net only when the operator stored
-- aidr_project_url and aidr_service_role_key in Vault; otherwise its run is
-- recorded as not_configured.

create schema if not exists app;

create table if not exists public.retention_job_runs (
  id bigint generated always as identity primary key,
  job text not null check (length(job) between 1 and 64),
  ran_at timestamptz not null default clock_timestamp(),
  ok boolean not null,
  result jsonb not null
);
create index if not exists retention_job_runs_job_ran_at_idx on public.retention_job_runs (job, ran_at desc);
alter table public.retention_job_runs enable row level security;
revoke all on public.retention_job_runs from public, anon, authenticated;
grant select on public.retention_job_runs to service_role;

-- Latest run and latest successful run per job, for monitoring/alerting on a
-- stale schedule ("retention maintenance last ran at").
create or replace view public.retention_job_status
with (security_invoker = true) as
select job,
       max(ran_at) as last_run_at,
       max(ran_at) filter (where ok) as last_success_at,
       (array_agg(ok order by ran_at desc))[1] as last_ok
  from public.retention_job_runs
 group by job;
revoke all on public.retention_job_status from public, anon, authenticated;
grant select on public.retention_job_status to service_role;

create or replace function app.dispatch_governance_digest_via_pg_net()
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, pg_temp
as $$
declare
  v_url text;
  v_key text;
  v_request bigint;
begin
  if to_regprocedure('net.http_post(text,jsonb,jsonb,jsonb,integer)') is null
     or to_regclass('vault.decrypted_secrets') is null then
    return jsonb_build_object('status', 'not_configured', 'reason', 'pg_net and Supabase Vault are required');
  end if;
  execute $q$select (select decrypted_secret from vault.decrypted_secrets where name = 'aidr_project_url' limit 1),
                    (select decrypted_secret from vault.decrypted_secrets where name = 'aidr_service_role_key' limit 1)$q$
    into v_url, v_key;
  if v_url is null or v_key is null or v_url !~ '^https://[^/?#@]+$' then
    return jsonb_build_object('status', 'not_configured',
      'reason', 'store aidr_project_url (https://<host>, no path) and aidr_service_role_key in Vault');
  end if;
  execute 'select net.http_post(url := $1, body := $2, params := ''{}''::jsonb, headers := $3, timeout_milliseconds := 60000)'
    into v_request
    using v_url || '/functions/v1/governance-digest',
          jsonb_build_object('action', 'dispatch', 'apply', true, 'limit', 50),
          jsonb_build_object('Content-Type', 'application/json', 'Authorization', 'Bearer ' || v_key);
  -- pg_net is asynchronous: the function records each digest outcome itself.
  return jsonb_build_object('status', 'queued', 'request_id', v_request);
end;
$$;
revoke all on function app.dispatch_governance_digest_via_pg_net() from public, anon, authenticated, service_role;

create or replace function app.run_retention_job(p_job text)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_result jsonb;
  v_ok boolean;
begin
  begin
    if p_job = 'billing' then
      v_result := public.prune_expired_billing_records(1000, true);
    elsif p_job = 'telemetry' then
      v_result := public.prune_expired_telemetry_events(1000, true, now());
    elsif p_job = 'trial_subjects' then
      v_result := public.purge_expired_ga_trial_subjects(1000, true);
    elsif p_job = 'waitlist' then
      v_result := public.purge_expired_waitlist_signups(1000, true);
    elsif p_job = 'team_invitations' then
      v_result := public.prune_expired_team_invitations(1000, true);
    elsif p_job = 'approval_requests' then
      v_result := public.prune_expired_approval_requests(1000, true);
    elsif p_job = 'ai_governance' then
      v_result := public.run_ai_governance_maintenance(1000, true);
    elsif p_job = 'rate_limits' then
      v_result := public.prune_expired_rate_limits(1000, true);
    elsif p_job = 'governance_digest' then
      v_result := app.dispatch_governance_digest_via_pg_net();
    else
      raise exception 'unknown_retention_job' using errcode = '22023';
    end if;
    v_ok := v_result is not null and coalesce(v_result->>'status', '') <> 'not_configured';
  exception when others then
    -- The batch rolled back; keep a failure receipt so a stale or failing
    -- schedule is visible in retention_job_status.
    v_ok := false;
    v_result := jsonb_build_object('error', sqlstate, 'message', left(sqlerrm, 300));
  end;
  insert into public.retention_job_runs(job, ok, result) values (left(coalesce(p_job, '?'), 64), v_ok, coalesce(v_result, '{}'::jsonb));
  delete from public.retention_job_runs where ran_at < clock_timestamp() - interval '30 days';
  return jsonb_build_object('job', p_job, 'ok', v_ok, 'result', v_result);
end;
$$;
revoke all on function app.run_retention_job(text) from public, anon, authenticated, service_role;

create or replace function app.schedule_retention_maintenance()
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, pg_temp
as $$
declare
  v_job record;
  v_names text[] := '{}';
begin
  if to_regprocedure('cron.schedule(text,text,text)') is null then
    return jsonb_build_object('scheduled', false, 'reason', 'pg_cron is not installed');
  end if;
  for v_job in
    select * from (values
      ('aidr-retention-telemetry', '*/10 * * * *', 'telemetry'),
      ('aidr-retention-billing', '7 * * * *', 'billing'),
      ('aidr-retention-trial-subjects', '12 * * * *', 'trial_subjects'),
      ('aidr-retention-waitlist', '17 * * * *', 'waitlist'),
      ('aidr-retention-team-invitations', '22 * * * *', 'team_invitations'),
      ('aidr-retention-approval-requests', '27 * * * *', 'approval_requests'),
      ('aidr-retention-ai-governance', '32 * * * *', 'ai_governance'),
      ('aidr-retention-rate-limits', '*/15 * * * *', 'rate_limits'),
      ('aidr-governance-digest', '47 * * * *', 'governance_digest')
    ) as jobs(name, schedule, job)
  loop
    execute 'select cron.schedule($1, $2, $3)'
      using v_job.name, v_job.schedule, format('select app.run_retention_job(%L)', v_job.job);
    v_names := v_names || v_job.name;
  end loop;
  return jsonb_build_object('scheduled', true, 'jobs', to_jsonb(v_names));
end;
$$;
revoke all on function app.schedule_retention_maintenance() from public, anon, authenticated, service_role;

create or replace function app.unschedule_retention_maintenance()
returns integer
language plpgsql
security definer
set search_path = pg_catalog, pg_temp
as $$
declare
  v_removed integer := 0;
begin
  if to_regclass('cron.job') is null then
    return 0;
  end if;
  execute $q$select count(cron.unschedule(jobid))::integer from cron.job
             where jobname like 'aidr-retention-%' or jobname = 'aidr-governance-digest'$q$ into v_removed;
  return v_removed;
end;
$$;
revoke all on function app.unschedule_retention_maintenance() from public, anon, authenticated, service_role;

do $$
begin
  if to_regprocedure('cron.schedule(text,text,text)') is not null then
    perform app.schedule_retention_maintenance();
  end if;
end;
$$;
