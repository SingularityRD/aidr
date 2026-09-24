-- Forward-only closure for owner, device-session and audit boundaries.

-- A verified access-token issuance time is part of the database authorization
-- decision. The shared user lock orders bind and global revocation so an old
-- JWT cannot bind a pending device session after its revocation barrier.
drop function if exists public.authorize_device_session(text, uuid, uuid);
create or replace function public.authorize_device_session(
  p_user_code text,
  p_user_id uuid,
  p_tenant_id uuid,
  p_access_token_issued_at timestamptz
)
returns table (id uuid, user_id uuid, tenant_id uuid, expires_at timestamptz)
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare v_revoked_before timestamptz;
begin
  if nullif(trim(p_user_code), '') is null
     or p_user_id is null
     or p_access_token_issued_at is null
     or p_access_token_issued_at > clock_timestamp() + interval '5 minutes' then
    return;
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 2611));
  select s.revoked_before into v_revoked_before
    from public.identity_user_session_state s
    where s.user_id = p_user_id;
  if v_revoked_before is not null
     and p_access_token_issued_at <= v_revoked_before then
    return;
  end if;

  return query
    update public.device_sessions d
       set user_id = p_user_id,
           tenant_id = coalesce(p_tenant_id, p_user_id),
           authorized_at = clock_timestamp(),
           status = 'authorized'
     where d.user_code = upper(trim(p_user_code))
       and d.authorized_at is null
       and d.expires_at > clock_timestamp()
    returning d.id, d.user_id, d.tenant_id, d.expires_at;
end;
$$;
revoke all on function public.authorize_device_session(text, uuid, uuid, timestamptz)
  from public, anon, authenticated;
grant execute on function public.authorize_device_session(text, uuid, uuid, timestamptz)
  to service_role;

-- Never remove the final active owner from an active tenant, including through
-- auth.users cascades or a trusted service-role mutation. Offboarding must move
-- the tenant out of active state before removing that owner.
create or replace function app.preserve_active_tenant_owner()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  v_old_tenant_id uuid;
  v_new_tenant_id uuid;
  v_old_user_id uuid;
  v_new_user_id uuid;
  v_old_role text;
  v_new_role text;
  v_old_expires_at timestamptz;
  v_new_expires_at timestamptz;
  v_now timestamptz;
  v_removes_owner boolean := false;
begin
  if tg_table_schema <> 'public'
     or tg_table_name not in ('team_members', 'tenant_members') then
    raise exception 'active owner guard attached to unsupported table'
      using errcode = '55000';
  end if;

  if tg_table_name = 'team_members' then
    v_old_tenant_id := old.team_id;
    v_old_user_id := old.user_id;
    v_old_role := old.role;
    if tg_op <> 'DELETE' then
      v_new_tenant_id := new.team_id;
      v_new_user_id := new.user_id;
      v_new_role := new.role;
    end if;
  else
    v_old_tenant_id := old.tenant_id;
    v_old_user_id := old.user_id;
    v_old_role := old.role;
    v_old_expires_at := old.expires_at;
    if tg_op <> 'DELETE' then
      v_new_tenant_id := new.tenant_id;
      v_new_user_id := new.user_id;
      v_new_role := new.role;
      v_new_expires_at := new.expires_at;
    end if;
  end if;

  if v_old_role <> 'owner' then
    if tg_op = 'DELETE' then return old; end if;
    return new;
  end if;

  if v_new_tenant_id is not null
     and v_new_tenant_id is distinct from v_old_tenant_id then
    if v_old_tenant_id < v_new_tenant_id then
      perform pg_advisory_xact_lock(hashtextextended(v_old_tenant_id::text, 2612));
      perform pg_advisory_xact_lock(hashtextextended(v_new_tenant_id::text, 2612));
    else
      perform pg_advisory_xact_lock(hashtextextended(v_new_tenant_id::text, 2612));
      perform pg_advisory_xact_lock(hashtextextended(v_old_tenant_id::text, 2612));
    end if;
  else
    perform pg_advisory_xact_lock(hashtextextended(v_old_tenant_id::text, 2612));
  end if;
  v_now := clock_timestamp();
  v_removes_owner := (v_old_expires_at is null or v_old_expires_at > v_now)
    and (
      tg_op = 'DELETE'
      or v_new_role is distinct from 'owner'
      or v_new_tenant_id is distinct from v_old_tenant_id
      or v_new_user_id is distinct from v_old_user_id
      or (v_new_expires_at is not null and v_new_expires_at <= v_now)
    );

  if v_removes_owner
     and exists (
       select 1 from public.tenants t
       where t.id = v_old_tenant_id and t.status = 'active'
     )
     and not exists (
       select 1 from public.tenant_members m
       where m.tenant_id = v_old_tenant_id
         and m.user_id <> v_old_user_id
         and m.role = 'owner'
         and (m.expires_at is null or m.expires_at > v_now)
     ) then
    raise exception 'active tenant must retain at least one owner'
      using errcode = '23514';
  end if;

  if tg_op = 'DELETE' then return old; end if;
  return new;
end;
$$;
revoke all on function app.preserve_active_tenant_owner()
  from public, anon, authenticated, service_role;

drop trigger if exists team_members_active_owner_guard on public.team_members;
create trigger team_members_active_owner_guard
before update or delete on public.team_members
for each row execute function app.preserve_active_tenant_owner();

drop trigger if exists tenant_members_active_owner_guard on public.tenant_members;
create trigger tenant_members_active_owner_guard
before update or delete on public.tenant_members
for each row execute function app.preserve_active_tenant_owner();

-- Serialize the inverse transition too: an ownerless closing/suspended tenant
-- cannot race an owner removal and become active again.
create or replace function app.require_owner_for_active_tenant()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if new.status = 'active' and old.status is distinct from 'active' then
    perform pg_advisory_xact_lock(hashtextextended(new.id::text, 2612));
    if not exists (
      select 1 from public.tenant_members member
      where member.tenant_id = new.id
        and member.role = 'owner'
        and (member.expires_at is null or member.expires_at > clock_timestamp())
    ) then
      raise exception 'active tenant must retain at least one owner'
        using errcode = '23514';
    end if;
  end if;
  return new;
end;
$$;
revoke all on function app.require_owner_for_active_tenant()
  from public, anon, authenticated, service_role;

drop trigger if exists tenants_active_owner_guard on public.tenants;
create trigger tenants_active_owner_guard
before update of status on public.tenants
for each row execute function app.require_owner_for_active_tenant();

-- Repair only the exact historical RPC shape: the recorded creator is the same
-- active admin in both membership models and no active owner exists. Anything
-- else is ambiguous and aborts the upgrade for reviewed remediation.
with promoted as (
  update public.team_members tm
     set role = 'owner'
    from public.teams team
    join public.tenants tenant on tenant.id = team.tenant_id
    join public.tenant_members canonical
      on canonical.tenant_id = tenant.id
     and canonical.user_id = tenant.created_by
   where tm.team_id = team.id
     and tm.tenant_id = tenant.id
     and tm.user_id = tenant.created_by
     and tm.role = 'admin'
     and canonical.role = 'admin'
     and (canonical.expires_at is null or canonical.expires_at > clock_timestamp())
     and tenant.status = 'active'
     and not exists (
       select 1 from public.tenant_members owner_member
       where owner_member.tenant_id = tenant.id
         and owner_member.role = 'owner'
         and (owner_member.expires_at is null
           or owner_member.expires_at > clock_timestamp())
     )
  returning tm.team_id, tm.user_id
)
insert into public.admin_audit_logs(
  actor_user_id, tenant_id, target_user_id, action, detail
)
select null, team_id, user_id, 'tenant.owner.reconciled',
  jsonb_build_object('source', 'legacy_create_team_tenant_admin')
from promoted;

do $$
begin
  if exists (
    select 1
    from public.teams team
    join public.tenants tenant on tenant.id = team.tenant_id
    where tenant.status = 'active'
      and not exists (
        select 1 from public.tenant_members owner_member
        where owner_member.tenant_id = tenant.id
          and owner_member.role = 'owner'
          and (owner_member.expires_at is null
            or owner_member.expires_at > clock_timestamp())
      )
  ) then
    raise exception 'team_owner_reconciliation_ambiguous' using errcode = '23514';
  end if;
end;
$$;

-- Paid labels created through the old browser RPC are not authoritative. Stop
-- the upgrade if a non-closed paid team has no non-free entitlement evidence.
do $$
begin
  if exists (
    select 1
    from public.teams team
    join public.tenants tenant on tenant.id = team.tenant_id
    left join public.entitlements entitlement on entitlement.tenant_id = tenant.id
    where team.plan in ('pro', 'enterprise')
      and tenant.status in ('active', 'suspended')
      and (
        entitlement.tenant_id is null
        or not (
          entitlement.included_agents > 1
          or entitlement.extra_agents > 0
          or entitlement.premium_intel
          or entitlement.premium_correlation
          or entitlement.premium_pkg_plugin
        )
      )
  ) then
    raise exception 'unentitled_paid_team_plan_requires_reconciliation'
      using errcode = '23514';
  end if;
end;
$$;

-- Rows predating the browser-write cutoff cannot be distinguished reliably.
-- Mark them conservatively; rows inserted after this migration receive the
-- service-boundary provenance default.
alter table public.audit_logs
  add column write_provenance text not null default 'pre_boundary_unverified';
alter table public.audit_logs
  alter column write_provenance set default 'service_boundary_v1';
alter table public.audit_logs
  add constraint audit_logs_write_provenance_check
  check (write_provenance in ('pre_boundary_unverified', 'service_boundary_v1'))
  not valid;
alter table public.audit_logs
  validate constraint audit_logs_write_provenance_check;
comment on column public.audit_logs.write_provenance is
  'pre_boundary_unverified marks rows created before browser INSERT was revoked; service_boundary_v1 marks later service-only writes.';

-- Preserve append-only evidence while permitting only the nested FK action
-- produced by auth.users ON DELETE SET NULL to anonymize audit_logs.user_id.
create or replace function public.reject_audit_mutation()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_run_id text := current_setting('app.aidr_offboarding_run_id', true);
  v_trusted_offboarding_caller boolean :=
    auth.role() = 'service_role'
    or session_user in ('postgres', 'service_role', 'supabase_admin');
  v_trusted_auth_caller boolean :=
    session_user in ('postgres', 'supabase_admin', 'supabase_auth_admin');
begin
  if tg_op = 'UPDATE'
     and pg_trigger_depth() > 1
     and v_trusted_auth_caller
     and old.user_id is not null
     and new.user_id is null
     and (to_jsonb(new) - 'user_id') = (to_jsonb(old) - 'user_id') then
    return new;
  end if;

  if tg_op = 'DELETE'
     and v_trusted_offboarding_caller
     and v_run_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     and exists (
       select 1
       from public.tenant_offboarding_runs run
       join public.tenants tenant on tenant.id = run.tenant_id
       where run.id = v_run_id::uuid
         and run.tenant_id = old.tenant_id
         and run.status = 'running'
         and tenant.status = 'closing'
         and not exists (
           select 1 from public.tenant_legal_holds hold_row
           where hold_row.tenant_id = run.tenant_id
             and hold_row.released_at is null
         )
     ) then
    return old;
  end if;

  raise exception 'audit_logs are append-only' using errcode = '42501';
end;
$$;
revoke all on function public.reject_audit_mutation()
  from public, anon, authenticated, service_role;

create or replace function app.reject_admin_audit_mutation()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_trusted_offboarding_caller boolean :=
    auth.role() = 'service_role'
    or session_user in ('postgres', 'service_role', 'supabase_admin');
begin
  if tg_op = 'DELETE'
     and v_trusted_offboarding_caller
     and old.tenant_id is not null
     and exists (
       select 1
       from public.tenant_offboarding_runs run
       join public.tenant_offboarding_phase_receipts receipt
         on receipt.run_id = run.id
        and receipt.phase = 'admin_audit_logs'
        and receipt.status = 'running'
       join public.tenants tenant on tenant.id = run.tenant_id
       where run.tenant_id = old.tenant_id
         and run.status = 'running'
         and tenant.status = 'closing'
         and not exists (
           select 1 from public.tenant_legal_holds hold_row
           where hold_row.tenant_id = run.tenant_id
             and hold_row.released_at is null
         )
     ) then
    return old;
  end if;
  raise exception 'admin_audit_logs are append-only' using errcode = '42501';
end;
$$;
revoke all on function app.reject_admin_audit_mutation()
  from public, anon, authenticated, service_role;

create or replace function app.reject_audit_truncate()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog
as $$
begin
  raise exception 'audit tables cannot be truncated' using errcode = '42501';
end;
$$;
revoke all on function app.reject_audit_truncate()
  from public, anon, authenticated, service_role;

drop trigger if exists admin_audit_logs_append_only on public.admin_audit_logs;
create trigger admin_audit_logs_append_only
before update or delete on public.admin_audit_logs
for each row execute function app.reject_admin_audit_mutation();

drop trigger if exists audit_logs_no_truncate on public.audit_logs;
create trigger audit_logs_no_truncate
before truncate on public.audit_logs
for each statement execute function app.reject_audit_truncate();

drop trigger if exists admin_audit_logs_no_truncate on public.admin_audit_logs;
create trigger admin_audit_logs_no_truncate
before truncate on public.admin_audit_logs
for each statement execute function app.reject_audit_truncate();

revoke update, delete, truncate on public.audit_logs, public.admin_audit_logs
  from public, anon, authenticated, service_role;
