-- Retention, expiry and offboarding for AI governance
-- (20260927000040_ai_governance_register.sql, 20260927000041_policy_change_control.sql).
--
-- Data classes (the ten classes of 20260912140000 are unchanged):
--   tenant_ai_governance_settings, ai_governance_reviewers,
--   ai_assets, ai_asset_evidence                      policy_configuration
--   ai_intake_requests, ai_governance_exceptions,
--   policy_change_requests (closed decision records)  security_audit
--
-- Offboarding
--   * Request time: in the transaction that creates the offboarding run,
--     pending intake, exception and policy change requests are cancelled and
--     active exceptions are revoked, so nothing can be approved or waived
--     after closure is requested. Every RPC already refuses a non-active
--     tenant.
--   * Deletion rides on the existing `tenant_runtime_policies`
--     (policy_configuration) phase: when it completes, every governance row of
--     the tenant is deleted under the same tenant lock and legal-hold check,
--     and the phase receipt counts the rows.
--   * A residue guard refuses to close a tenant, or complete its run, while
--     any governance row remains.
--
-- Expiry and retention (run_ai_governance_maintenance, called by the
-- deployment maintenance worker)
--   * Lapsed pending requests and exceptions past their end date are marked
--     `expired` with an audit row. Enforcement never waits for this sweep: the
--     policy overlay ignores an exception from its expires_at on.
--   * Closed requests and exceptions older than the tenant's security_audit
--     retention are deleted for active tenants without an active legal hold.
--     Register entries are configuration and stay until offboarding.

-- ── Request-time revocation ────────────────────────────────────────────────

create or replace function app.revoke_ai_governance_on_offboarding()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_intake bigint;
  v_exceptions bigint;
  v_revoked bigint;
  v_changes bigint;
begin
  update public.ai_intake_requests set status = 'cancelled', closed_at = v_now
   where tenant_id = new.tenant_id and status = 'pending';
  get diagnostics v_intake = row_count;
  update public.ai_governance_exceptions set status = 'cancelled', closed_at = v_now
   where tenant_id = new.tenant_id and status = 'pending';
  get diagnostics v_exceptions = row_count;
  update public.ai_governance_exceptions
     set status = 'revoked', revoked_by = new.requested_by, revoked_at = v_now,
         revoke_reason = 'Tenant offboarding requested', closed_at = v_now
   where tenant_id = new.tenant_id and status = 'approved';
  get diagnostics v_revoked = row_count;
  update public.policy_change_requests set status = 'cancelled', closed_at = v_now
   where tenant_id = new.tenant_id and status = 'pending';
  get diagnostics v_changes = row_count;
  if v_intake + v_exceptions + v_revoked + v_changes > 0 then
    insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
    values (new.requested_by, new.tenant_id, 'ai_governance.offboarding_revoked',
      jsonb_build_object('run_id', new.id, 'intake_cancelled', v_intake,
        'exceptions_cancelled', v_exceptions, 'exceptions_revoked', v_revoked,
        'policy_changes_cancelled', v_changes));
  end if;
  return new;
end;
$$;
revoke all on function app.revoke_ai_governance_on_offboarding() from public, anon, authenticated, service_role;

drop trigger if exists tenant_offboarding_revoke_ai_governance on public.tenant_offboarding_runs;
create trigger tenant_offboarding_revoke_ai_governance
  after insert on public.tenant_offboarding_runs
  for each row execute function app.revoke_ai_governance_on_offboarding();

-- ── Deletion at the policy_configuration phase ─────────────────────────────

create or replace function app.purge_ai_governance_at_offboarding_phase()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_tenant uuid;
  v_status text;
  v_rows bigint := 0;
  v_count bigint;
begin
  if new.phase <> 'tenant_runtime_policies'
     or new.status <> 'completed' or old.status = 'completed' then
    return new;
  end if;
  select r.tenant_id, r.status into v_tenant, v_status
    from public.tenant_offboarding_runs r where r.id = new.run_id;
  if v_tenant is null or v_status <> 'running' or new.eligible_at > now() then
    raise exception 'ai_governance_offboarding_phase_invalid' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant::text, 2606));
  if exists (
    select 1 from public.tenant_legal_holds h
     where h.tenant_id = v_tenant and h.released_at is null
  ) then
    raise exception 'ai_governance_offboarding_legal_hold' using errcode = '42501';
  end if;
  delete from public.policy_change_requests where tenant_id = v_tenant;
  get diagnostics v_count = row_count; v_rows := v_rows + v_count;
  delete from public.ai_governance_exceptions where tenant_id = v_tenant;
  get diagnostics v_count = row_count; v_rows := v_rows + v_count;
  delete from public.ai_intake_requests where tenant_id = v_tenant;
  get diagnostics v_count = row_count; v_rows := v_rows + v_count;
  delete from public.ai_asset_evidence where tenant_id = v_tenant;
  get diagnostics v_count = row_count; v_rows := v_rows + v_count;
  delete from public.ai_assets where tenant_id = v_tenant;
  get diagnostics v_count = row_count; v_rows := v_rows + v_count;
  delete from public.ai_governance_reviewers where tenant_id = v_tenant;
  get diagnostics v_count = row_count; v_rows := v_rows + v_count;
  delete from public.tenant_ai_governance_settings where tenant_id = v_tenant;
  get diagnostics v_count = row_count; v_rows := v_rows + v_count;
  if v_rows > 0 then
    update public.tenant_offboarding_phase_receipts
       set rows_deleted = rows_deleted + v_rows
     where run_id = new.run_id and phase = new.phase and status = 'completed';
  end if;
  return new;
end;
$$;
revoke all on function app.purge_ai_governance_at_offboarding_phase() from public, anon, authenticated, service_role;

drop trigger if exists tenant_offboarding_purge_ai_governance on public.tenant_offboarding_phase_receipts;
create trigger tenant_offboarding_purge_ai_governance
  after update of status on public.tenant_offboarding_phase_receipts
  for each row execute function app.purge_ai_governance_at_offboarding_phase();

-- ── Residue guard ──────────────────────────────────────────────────────────

create or replace function app.assert_no_ai_governance_offboarding_residue()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare v_tenant uuid;
begin
  if tg_table_name = 'tenants' then
    if new.status <> 'closed' then return new; end if;
    v_tenant := new.id;
  else
    if new.status <> 'completed' then return new; end if;
    v_tenant := new.tenant_id;
  end if;
  if exists (select 1 from public.ai_assets where tenant_id = v_tenant)
     or exists (select 1 from public.ai_asset_evidence where tenant_id = v_tenant)
     or exists (select 1 from public.ai_intake_requests where tenant_id = v_tenant)
     or exists (select 1 from public.ai_governance_exceptions where tenant_id = v_tenant)
     or exists (select 1 from public.ai_governance_reviewers where tenant_id = v_tenant)
     or exists (select 1 from public.tenant_ai_governance_settings where tenant_id = v_tenant)
     or exists (select 1 from public.policy_change_requests where tenant_id = v_tenant) then
    raise exception 'ai_governance_offboarding_residue' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.assert_no_ai_governance_offboarding_residue() from public, anon, authenticated, service_role;

drop trigger if exists tenants_ai_governance_offboarding_residue on public.tenants;
create trigger tenants_ai_governance_offboarding_residue
  before update of status on public.tenants
  for each row execute function app.assert_no_ai_governance_offboarding_residue();

drop trigger if exists offboarding_runs_ai_governance_residue on public.tenant_offboarding_runs;
create trigger offboarding_runs_ai_governance_residue
  before update of status on public.tenant_offboarding_runs
  for each row execute function app.assert_no_ai_governance_offboarding_residue();

-- ── Expiry sweep and retention ─────────────────────────────────────────────

create index if not exists ai_intake_requests_closed_idx
  on public.ai_intake_requests (tenant_id, closed_at) where status <> 'pending';
create index if not exists ai_governance_exceptions_closed_idx
  on public.ai_governance_exceptions (tenant_id, closed_at) where closed_at is not null;
create index if not exists policy_change_requests_closed_idx
  on public.policy_change_requests (tenant_id, closed_at) where status <> 'pending';

create or replace function public.run_ai_governance_maintenance(
  p_limit integer default 100,
  p_apply boolean default true
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_item record;
  v_tenant uuid;
  v_days integer;
  v_count integer;
  v_expired integer := 0;
  v_expiry_remaining boolean := false;
  v_eligible integer := 0;
  v_deleted integer := 0;
  v_contended integer := 0;
  v_hold_race_skips integer := 0;
  v_held integer := 0;
  v_missing_policy integer := 0;
  v_remaining integer := 0;
begin
  if p_limit is null or p_limit not between 1 and 1000 or p_apply is null then
    raise exception 'invalid_ai_governance_maintenance_batch' using errcode = '22023';
  end if;
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'ai_governance_maintenance_requires_read_committed' using errcode = '25001';
  end if;

  -- 1. Close what has lapsed (active tenants only; offboarding handles the rest).
  for v_item in
    select * from (
      select 'intake'::text as kind, r.id, r.tenant_id, r.expires_at
        from public.ai_intake_requests r join public.tenants t on t.id = r.tenant_id and t.status = 'active'
       where r.status = 'pending' and r.expires_at <= v_now
      union all
      select 'exception', e.id, e.tenant_id, e.expires_at
        from public.ai_governance_exceptions e join public.tenants t on t.id = e.tenant_id and t.status = 'active'
       where e.status in ('pending', 'approved') and e.expires_at <= v_now
      union all
      select 'policy_change', c.id, c.tenant_id, c.expires_at
        from public.policy_change_requests c join public.tenants t on t.id = c.tenant_id and t.status = 'active'
       where c.status = 'pending' and c.expires_at <= v_now
    ) lapsed
    order by expires_at, id
    limit p_limit + 1
  loop
    if v_expired >= p_limit then
      v_expiry_remaining := true;
      exit;
    end if;
    if not p_apply then
      v_expired := v_expired + 1;
      continue;
    end if;
    if v_item.kind = 'intake' then
      update public.ai_intake_requests set status = 'expired', closed_at = v_now
       where id = v_item.id and status = 'pending';
    elsif v_item.kind = 'exception' then
      update public.ai_governance_exceptions set status = 'expired', closed_at = v_now
       where id = v_item.id and status in ('pending', 'approved') and expires_at <= v_now;
    else
      update public.policy_change_requests set status = 'expired', closed_at = v_now
       where id = v_item.id and status = 'pending';
    end if;
    if found then
      v_expired := v_expired + 1;
      perform app.ai_governance_audit(v_item.tenant_id, null,
        case v_item.kind when 'intake' then 'ai_intake.expired'
          when 'exception' then 'ai_exception.expired' else 'policy_change.expired' end,
        jsonb_build_object('id', v_item.id, 'expires_at', v_item.expires_at));
    end if;
  end loop;

  -- 2. Retention: closed decision records past the security_audit window.
  select count(*) into v_missing_policy from (
    select distinct c.tenant_id
      from (
        select tenant_id from public.ai_intake_requests where status <> 'pending'
        union select tenant_id from public.ai_governance_exceptions where closed_at is not null
        union select tenant_id from public.policy_change_requests where status <> 'pending'
      ) c
      join public.tenants t on t.id = c.tenant_id and t.status = 'active'
     where not exists (
       select 1 from public.tenant_data_retention_policies p
        where p.tenant_id = c.tenant_id and p.data_class = 'security_audit')
     limit (p_limit + 1)
  ) missing;

  select count(*) into v_held from (
    select distinct p.tenant_id
      from public.tenant_data_retention_policies p
     where p.data_class = 'security_audit'
       and exists (select 1 from public.tenant_legal_holds h
                    where h.tenant_id = p.tenant_id and h.released_at is null)
       and (exists (select 1 from public.ai_intake_requests r where r.tenant_id = p.tenant_id and r.status <> 'pending'
                     and r.closed_at <= v_now - make_interval(days => p.retention_days))
         or exists (select 1 from public.ai_governance_exceptions e where e.tenant_id = p.tenant_id
                     and e.closed_at <= v_now - make_interval(days => p.retention_days))
         or exists (select 1 from public.policy_change_requests c where c.tenant_id = p.tenant_id and c.status <> 'pending'
                     and c.closed_at <= v_now - make_interval(days => p.retention_days)))
     limit (p_limit + 1)
  ) held;

  for v_tenant, v_days in
    select p.tenant_id, p.retention_days
      from public.tenant_data_retention_policies p
      join public.tenants t on t.id = p.tenant_id and t.status = 'active'
     where p.data_class = 'security_audit'
       and not exists (select 1 from public.tenant_legal_holds h
                        where h.tenant_id = p.tenant_id and h.released_at is null)
       and (exists (select 1 from public.ai_intake_requests r where r.tenant_id = p.tenant_id and r.status <> 'pending'
                     and r.closed_at <= v_now - make_interval(days => p.retention_days))
         or exists (select 1 from public.ai_governance_exceptions e where e.tenant_id = p.tenant_id
                     and e.closed_at <= v_now - make_interval(days => p.retention_days))
         or exists (select 1 from public.policy_change_requests c where c.tenant_id = p.tenant_id and c.status <> 'pending'
                     and c.closed_at <= v_now - make_interval(days => p.retention_days)))
     order by p.tenant_id
     limit p_limit
  loop
    exit when v_eligible >= p_limit;
    if not pg_try_advisory_xact_lock(hashtextextended(v_tenant::text, 2606)) then
      v_contended := v_contended + 1;
      continue;
    end if;
    if exists (select 1 from public.tenant_legal_holds h
                where h.tenant_id = v_tenant and h.released_at is null) then
      v_hold_race_skips := v_hold_race_skips + 1;
      continue;
    end if;
    if p_apply then
      with due as (
        select 'intake'::text as kind, r.id, r.closed_at from public.ai_intake_requests r
         where r.tenant_id = v_tenant and r.status <> 'pending'
           and r.closed_at <= v_now - make_interval(days => v_days)
        union all
        select 'exception', e.id, e.closed_at from public.ai_governance_exceptions e
         where e.tenant_id = v_tenant and e.closed_at <= v_now - make_interval(days => v_days)
        union all
        select 'policy_change', c.id, c.closed_at from public.policy_change_requests c
         where c.tenant_id = v_tenant and c.status <> 'pending'
           and c.closed_at <= v_now - make_interval(days => v_days)
        order by closed_at, id
        limit (p_limit - v_eligible)
      ),
      d1 as (delete from public.ai_intake_requests r using due
              where due.kind = 'intake' and r.id = due.id and r.tenant_id = v_tenant returning 1),
      d2 as (delete from public.ai_governance_exceptions e using due
              where due.kind = 'exception' and e.id = due.id and e.tenant_id = v_tenant returning 1),
      d3 as (delete from public.policy_change_requests c using due
              where due.kind = 'policy_change' and c.id = due.id and c.tenant_id = v_tenant returning 1)
      select (select count(*) from d1) + (select count(*) from d2) + (select count(*) from d3) into v_count;
      v_deleted := v_deleted + v_count;
    else
      select count(*) into v_count from (
        select 1 from public.ai_intake_requests r
         where r.tenant_id = v_tenant and r.status <> 'pending'
           and r.closed_at <= v_now - make_interval(days => v_days)
        union all
        select 1 from public.ai_governance_exceptions e
         where e.tenant_id = v_tenant and e.closed_at <= v_now - make_interval(days => v_days)
        union all
        select 1 from public.policy_change_requests c
         where c.tenant_id = v_tenant and c.status <> 'pending'
           and c.closed_at <= v_now - make_interval(days => v_days)
        limit (p_limit - v_eligible)
      ) due;
    end if;
    v_eligible := v_eligible + v_count;
  end loop;

  select 1 into v_remaining
    from public.tenant_data_retention_policies p
    join public.tenants t on t.id = p.tenant_id and t.status = 'active'
   where p.data_class = 'security_audit'
     and not exists (select 1 from public.tenant_legal_holds h
                      where h.tenant_id = p.tenant_id and h.released_at is null)
     and (exists (select 1 from public.ai_intake_requests r where r.tenant_id = p.tenant_id and r.status <> 'pending'
                   and r.closed_at <= v_now - make_interval(days => p.retention_days))
       or exists (select 1 from public.ai_governance_exceptions e where e.tenant_id = p.tenant_id
                   and e.closed_at <= v_now - make_interval(days => p.retention_days))
       or exists (select 1 from public.policy_change_requests c where c.tenant_id = p.tenant_id and c.status <> 'pending'
                   and c.closed_at <= v_now - make_interval(days => p.retention_days)))
   limit 1;

  return jsonb_build_object(
    'applied', p_apply,
    'cutoff', v_now,
    'expired', v_expired,
    'expiry_remaining', v_expiry_remaining,
    'eligible', v_eligible,
    'deleted', v_deleted,
    'remaining', coalesce(v_remaining, 0),
    'contended_tenants', v_contended,
    'hold_race_skips', v_hold_race_skips,
    'active_tenants_missing_policy', least(v_missing_policy, p_limit),
    'missing_policy_tenants_truncated', v_missing_policy > p_limit,
    'held_tenants_present', least(v_held, p_limit),
    'held_tenants_truncated', v_held > p_limit
  );
end;
$$;
revoke all on function public.run_ai_governance_maintenance(integer, boolean) from public, anon, authenticated;
grant execute on function public.run_ai_governance_maintenance(integer, boolean) to service_role;
