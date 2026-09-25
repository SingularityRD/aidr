-- Retention and offboarding for managed-mode dashboard approvals
-- (20260926000001_dashboard_approval_requests.sql).
--
-- Data classes (the ten classes of 20260912140000 are unchanged):
--   approval_requests             telemetry          (tenant telemetry retention)
--   tenant_approval_signing_keys  access_credentials
--
-- Offboarding
--   * Request time: the tenant's approval signing keys are revoked and every
--     pending request is expired, in the same transaction that creates the
--     offboarding run, so nothing can be approved or signed after closure is
--     requested. The create/decide/install RPCs already refuse a non-active
--     tenant.
--   * Deletion rides on existing phases instead of new phase numbers: the rows
--     are deleted when the `events` (telemetry) phase completes and the keys
--     when the `api_keys` (access_credentials) phase completes, under the same
--     tenant lock and legal-hold check, and the phase receipt counts them.
--   * A residue guard refuses to close a tenant, or complete its run, while any
--     approval row or key remains.
--
-- Retention
--   prune_expired_approval_requests deletes final (decided or expired) requests
--   older than the tenant's telemetry retention, for active tenants without an
--   active legal hold. The deployment maintenance worker calls it.

-- ── Request-time revocation ────────────────────────────────────────────────

create or replace function app.revoke_approvals_on_offboarding()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_keys bigint;
  v_requests bigint;
begin
  update public.tenant_approval_signing_keys
     set revoked_at = clock_timestamp()
   where tenant_id = new.tenant_id and revoked_at is null;
  get diagnostics v_keys = row_count;
  update public.approval_requests
     set status = 'expired'
   where tenant_id = new.tenant_id and status = 'pending';
  get diagnostics v_requests = row_count;
  if v_keys > 0 or v_requests > 0 then
    insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
    values (new.requested_by, new.tenant_id, 'approval.offboarding_revoked',
      jsonb_build_object('run_id', new.id, 'keys_revoked', v_keys, 'requests_expired', v_requests));
  end if;
  return new;
end;
$$;
revoke all on function app.revoke_approvals_on_offboarding() from public, anon, authenticated, service_role;

drop trigger if exists tenant_offboarding_revoke_approvals on public.tenant_offboarding_runs;
create trigger tenant_offboarding_revoke_approvals
  after insert on public.tenant_offboarding_runs
  for each row execute function app.revoke_approvals_on_offboarding();

-- In-flight or completed runs created before this migration.
update public.tenant_approval_signing_keys k
   set revoked_at = clock_timestamp()
 where k.revoked_at is null
   and exists (select 1 from public.tenant_offboarding_runs r where r.tenant_id = k.tenant_id);
update public.approval_requests a
   set status = 'expired'
 where a.status = 'pending'
   and exists (select 1 from public.tenant_offboarding_runs r where r.tenant_id = a.tenant_id);

-- ── Deletion at the telemetry / access-credential phases ────────────────────

create or replace function app.purge_approvals_at_offboarding_phase()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_tenant uuid;
  v_status text;
  v_rows bigint;
begin
  if new.phase not in ('events', 'api_keys')
     or new.status <> 'completed' or old.status = 'completed' then
    return new;
  end if;
  select r.tenant_id, r.status into v_tenant, v_status
    from public.tenant_offboarding_runs r where r.id = new.run_id;
  if v_tenant is null or v_status <> 'running' or new.eligible_at > now() then
    raise exception 'approval_offboarding_phase_invalid' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant::text, 2606));
  if exists (
    select 1 from public.tenant_legal_holds h
     where h.tenant_id = v_tenant and h.released_at is null
  ) then
    raise exception 'approval_offboarding_legal_hold' using errcode = '42501';
  end if;
  if new.phase = 'events' then
    delete from public.approval_requests where tenant_id = v_tenant;
  else
    delete from public.tenant_approval_signing_keys where tenant_id = v_tenant;
  end if;
  get diagnostics v_rows = row_count;
  if v_rows > 0 then
    update public.tenant_offboarding_phase_receipts
       set rows_deleted = rows_deleted + v_rows
     where run_id = new.run_id and phase = new.phase and status = 'completed';
  end if;
  return new;
end;
$$;
revoke all on function app.purge_approvals_at_offboarding_phase() from public, anon, authenticated, service_role;

drop trigger if exists tenant_offboarding_purge_approvals on public.tenant_offboarding_phase_receipts;
create trigger tenant_offboarding_purge_approvals
  after update of status on public.tenant_offboarding_phase_receipts
  for each row execute function app.purge_approvals_at_offboarding_phase();

-- ── Residue guard ──────────────────────────────────────────────────────────

create or replace function app.assert_no_approval_offboarding_residue()
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
  if exists (select 1 from public.approval_requests where tenant_id = v_tenant)
     or exists (select 1 from public.tenant_approval_signing_keys where tenant_id = v_tenant) then
    raise exception 'approval_offboarding_residue' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.assert_no_approval_offboarding_residue() from public, anon, authenticated, service_role;

drop trigger if exists tenants_approval_offboarding_residue on public.tenants;
create trigger tenants_approval_offboarding_residue
  before update of status on public.tenants
  for each row execute function app.assert_no_approval_offboarding_residue();

drop trigger if exists offboarding_runs_approval_residue on public.tenant_offboarding_runs;
create trigger offboarding_runs_approval_residue
  before update of status on public.tenant_offboarding_runs
  for each row execute function app.assert_no_approval_offboarding_residue();

-- ── Retention ──────────────────────────────────────────────────────────────

create index if not exists approval_requests_retention_idx
  on public.approval_requests (tenant_id, created_at, id)
  where status <> 'pending';

create or replace function public.prune_expired_approval_requests(
  p_limit integer default 100,
  p_apply boolean default true
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_cutoff timestamptz := clock_timestamp();
  v_tenant uuid;
  v_days integer;
  v_count integer;
  v_eligible integer := 0;
  v_deleted integer := 0;
  v_contended integer := 0;
  v_hold_race_skips integer := 0;
  v_missing_policy integer := 0;
  v_held integer := 0;
  v_remaining integer := 0;
begin
  if p_limit is null or p_limit not between 1 and 1000 or p_apply is null then
    raise exception 'invalid_approval_retention_batch' using errcode = '22023';
  end if;
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'approval_retention_requires_read_committed' using errcode = '25001';
  end if;

  -- A missing telemetry policy is a visible hold, never an implicit zero days.
  select count(*) into v_missing_policy from (
    select distinct a.tenant_id
      from public.approval_requests a
      join public.tenants t on t.id = a.tenant_id and t.status = 'active'
     where not exists (
       select 1 from public.tenant_data_retention_policies p
        where p.tenant_id = a.tenant_id and p.data_class = 'telemetry')
     limit (p_limit + 1)
  ) missing;

  select count(*) into v_held from (
    select distinct a.tenant_id
      from public.approval_requests a
      join public.tenant_data_retention_policies p
        on p.tenant_id = a.tenant_id and p.data_class = 'telemetry'
     where (a.status <> 'pending' or a.expires_at <= v_cutoff)
       and a.created_at <= v_cutoff - make_interval(days => p.retention_days)
       and exists (select 1 from public.tenant_legal_holds h
                    where h.tenant_id = a.tenant_id and h.released_at is null)
     limit (p_limit + 1)
  ) held;

  for v_tenant in
    select p.tenant_id
      from public.tenant_data_retention_policies p
      join public.tenants t on t.id = p.tenant_id and t.status = 'active'
     where p.data_class = 'telemetry'
       and exists (
         select 1 from public.approval_requests a
          where a.tenant_id = p.tenant_id
            and (a.status <> 'pending' or a.expires_at <= v_cutoff)
            and a.created_at <= v_cutoff - make_interval(days => p.retention_days))
       and not exists (select 1 from public.tenant_legal_holds h
                        where h.tenant_id = p.tenant_id and h.released_at is null)
     order by p.tenant_id
     limit p_limit
  loop
    exit when v_eligible >= p_limit;
    if not pg_try_advisory_xact_lock(hashtextextended(v_tenant::text, 2606)) then
      v_contended := v_contended + 1;
      continue;
    end if;
    select p.retention_days into v_days
      from public.tenant_data_retention_policies p
      join public.tenants t on t.id = p.tenant_id and t.status = 'active'
     where p.tenant_id = v_tenant and p.data_class = 'telemetry'
     for share of p, t;
    if not found then continue; end if;
    if exists (select 1 from public.tenant_legal_holds h
                where h.tenant_id = v_tenant and h.released_at is null) then
      v_hold_race_skips := v_hold_race_skips + 1;
      continue;
    end if;

    if p_apply then
      delete from public.approval_requests a using (
        select c.id from public.approval_requests c
         where c.tenant_id = v_tenant
           and (c.status <> 'pending' or c.expires_at <= v_cutoff)
           and c.created_at <= v_cutoff - make_interval(days => v_days)
         order by c.created_at, c.id
         limit (p_limit - v_eligible)
         for update
      ) due
      where a.id = due.id and a.tenant_id = v_tenant;
      get diagnostics v_count = row_count;
      v_deleted := v_deleted + v_count;
    else
      select count(*) into v_count from (
        select 1 from public.approval_requests c
         where c.tenant_id = v_tenant
           and (c.status <> 'pending' or c.expires_at <= v_cutoff)
           and c.created_at <= v_cutoff - make_interval(days => v_days)
         limit (p_limit - v_eligible)
      ) due;
    end if;
    v_eligible := v_eligible + v_count;
  end loop;

  select 1 into v_remaining
    from public.approval_requests a
    join public.tenants t on t.id = a.tenant_id and t.status = 'active'
    join public.tenant_data_retention_policies p
      on p.tenant_id = a.tenant_id and p.data_class = 'telemetry'
   where (a.status <> 'pending' or a.expires_at <= v_cutoff)
     and a.created_at <= v_cutoff - make_interval(days => p.retention_days)
     and not exists (select 1 from public.tenant_legal_holds h
                      where h.tenant_id = a.tenant_id and h.released_at is null)
   limit 1;

  return jsonb_build_object(
    'applied', p_apply,
    'cutoff', v_cutoff,
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
revoke all on function public.prune_expired_approval_requests(integer, boolean)
  from public, anon, authenticated;
grant execute on function public.prune_expired_approval_requests(integer, boolean)
  to service_role;
