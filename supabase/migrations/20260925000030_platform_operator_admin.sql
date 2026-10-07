-- Platform operator surface for the `operator-admin` Edge Function.
--
-- The GA admission RPCs (configure_tenant_admission_mode,
-- configure_ga_legal_documents, grant_licensed_tenant_admission,
-- revoke_licensed_tenant_admission) are service-role only and previously had
-- no accountable caller: the first two record an audit row without an actor.
-- This migration adds a named, expiring platform-operator allowlist and thin
-- service-role wrappers that (1) re-check that allowlist inside the same
-- transaction, (2) delegate to the existing RPC unchanged, and (3) write an
-- actor-attributed audit receipt atomically with the change. A failure at any
-- step rolls back the whole operation, so no change is ever unattributed.
--
-- Licensed grants still require the tenant-scoped `admission_operators` row
-- and the non-member separation-of-duty check enforced by
-- grant_licensed_tenant_admission; platform-operator status alone never admits.

create table if not exists public.platform_operators (
  user_id uuid primary key references auth.users(id) on delete cascade,
  change_reference text not null
    check (length(trim(change_reference)) between 1 and 200
      and change_reference !~ '[[:cntrl:]]'),
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null
    default (transaction_timestamp() + interval '30 days')
    check (isfinite(expires_at)),
  revoked_at timestamptz
);
alter table public.platform_operators enable row level security;
-- No policies: browsers never read or write this table. The Edge Function
-- pre-checks it with the service role; every wrapper re-checks it in SQL.
revoke all on public.platform_operators from public, anon, authenticated, service_role;
grant select on public.platform_operators to service_role;

-- Commercial plan recorded with a licensed grant. Nullable: trials and grants
-- made before this migration carry no plan.
alter table public.tenant_admissions add column if not exists plan_id text;
do $plan_format$
begin
  if not exists (
    select 1 from pg_constraint
     where conname = 'tenant_admissions_plan_id_format'
       and conrelid = 'public.tenant_admissions'::regclass
  ) then
    alter table public.tenant_admissions
      add constraint tenant_admissions_plan_id_format
      check (plan_id is null or plan_id ~ '^[a-z][a-z0-9_-]{0,31}$');
  end if;
end;
$plan_format$;

create or replace function app.require_platform_operator(p_actor_user_id uuid)
returns void
language plpgsql security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if p_actor_user_id is null then
    raise exception 'platform_operator_forbidden' using errcode = '42501';
  end if;
  perform 1 from public.platform_operators o
   where o.user_id = p_actor_user_id
     and o.revoked_at is null
     and o.expires_at > clock_timestamp()
   for share;
  if not found then
    raise exception 'platform_operator_forbidden' using errcode = '42501';
  end if;
end;
$$;
revoke all on function app.require_platform_operator(uuid)
  from public, anon, authenticated, service_role;

-- A plan id is accepted when the commercial catalog lists it as active. Until a
-- catalog table exists, only the published list-price plan ids are accepted.
create or replace function app.operator_plan_known(p_plan_id text)
returns boolean
language plpgsql stable security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare v_known boolean;
begin
  if p_plan_id is null or p_plan_id !~ '^[a-z][a-z0-9_-]{0,31}$' then
    return false;
  end if;
  if to_regclass('public.plans') is not null then
    execute 'select exists (select 1 from public.plans where id = $1 and active)'
      into v_known using p_plan_id;
    return coalesce(v_known, false);
  end if;
  return p_plan_id in ('free', 'team', 'business', 'enterprise');
end;
$$;
revoke all on function app.operator_plan_known(text)
  from public, anon, authenticated, service_role;

create or replace function public.operator_configure_admission_mode(
  p_actor_user_id uuid,
  p_mode text
)
returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare v_result jsonb;
begin
  perform app.require_platform_operator(p_actor_user_id);
  v_result := public.configure_tenant_admission_mode(p_mode);
  insert into public.admin_audit_logs(actor_user_id, action, detail)
  values (p_actor_user_id, 'operator.admission_mode_configured',
    jsonb_build_object('mode', v_result ->> 'mode',
      'status', v_result ->> 'status'));
  return v_result;
end;
$$;
revoke all on function public.operator_configure_admission_mode(uuid, text)
  from public, anon, authenticated;
grant execute on function public.operator_configure_admission_mode(uuid, text)
  to service_role;

create or replace function public.operator_configure_legal_documents(
  p_actor_user_id uuid,
  p_terms_version text,
  p_terms_sha256 text,
  p_terms_url text,
  p_privacy_version text,
  p_privacy_sha256 text,
  p_privacy_url text,
  p_approval_reference text
)
returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare v_result jsonb;
begin
  perform app.require_platform_operator(p_actor_user_id);
  -- The table CHECK constraints behind this RPC are the authoritative bounds.
  v_result := public.configure_ga_legal_documents(p_terms_version,
    p_terms_sha256, p_terms_url, p_privacy_version, p_privacy_sha256,
    p_privacy_url, p_approval_reference);
  insert into public.admin_audit_logs(actor_user_id, action, detail)
  values (p_actor_user_id, 'operator.legal_documents_configured',
    jsonb_build_object(
      'terms', jsonb_build_object('version', p_terms_version,
        'sha256', p_terms_sha256, 'url', p_terms_url),
      'privacy', jsonb_build_object('version', p_privacy_version,
        'sha256', p_privacy_sha256, 'url', p_privacy_url),
      'approval_reference', trim(p_approval_reference)));
  return v_result;
end;
$$;
revoke all on function public.operator_configure_legal_documents(
  uuid, text, text, text, text, text, text, text)
  from public, anon, authenticated;
grant execute on function public.operator_configure_legal_documents(
  uuid, text, text, text, text, text, text, text)
  to service_role;

create or replace function public.operator_grant_license(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_plan_id text,
  p_seats integer,
  p_expires_at timestamptz,
  p_grant_reference text,
  p_owner_user_id uuid default null
)
returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_owner uuid := p_owner_user_id;
  v_owners uuid[];
  v_result jsonb;
begin
  perform app.require_platform_operator(p_actor_user_id);
  if p_tenant_id is null then
    raise exception 'invalid_admission_grant' using errcode = '22023';
  end if;
  if not app.operator_plan_known(p_plan_id) then
    raise exception 'invalid_plan' using errcode = '22023';
  end if;
  perform 1 from public.tenants where id = p_tenant_id;
  if not found then
    raise exception 'tenant_not_found' using errcode = 'P0002';
  end if;
  if v_owner is null then
    -- Only an unambiguous current owner may be inferred.
    select array_agg(m.user_id order by m.user_id) into v_owners
      from public.tenant_members m
     where m.tenant_id = p_tenant_id and m.role = 'owner'
       and (m.expires_at is null or m.expires_at > clock_timestamp());
    if coalesce(cardinality(v_owners), 0) = 0 then
      raise exception 'admission_owner_forbidden' using errcode = '42501';
    end if;
    if cardinality(v_owners) > 1 then
      raise exception 'owner_required' using errcode = '22023';
    end if;
    v_owner := v_owners[1];
  end if;

  -- Tenant-scoped admission operator, separation of duty, mode, owner and
  -- seat/expiry bounds are all enforced by the existing RPC.
  v_result := public.grant_licensed_tenant_admission(p_actor_user_id,
    p_tenant_id, v_owner, p_seats, p_expires_at, p_grant_reference);
  update public.tenant_admissions
     set plan_id = p_plan_id
   where tenant_id = p_tenant_id and kind = 'licensed' and revoked_at is null;
  if not found then
    raise exception 'admission_grant_conflict' using errcode = '40001';
  end if;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id,
    action, detail)
  values (p_actor_user_id, p_tenant_id, v_owner, 'operator.license_granted',
    jsonb_build_object('plan_id', p_plan_id, 'seats', p_seats,
      'expires_at', p_expires_at, 'reference', trim(p_grant_reference)));
  return v_result || jsonb_build_object('plan_id', p_plan_id,
    'owner_user_id', v_owner);
end;
$$;
revoke all on function public.operator_grant_license(
  uuid, uuid, text, integer, timestamptz, text, uuid)
  from public, anon, authenticated;
grant execute on function public.operator_grant_license(
  uuid, uuid, text, integer, timestamptz, text, uuid)
  to service_role;

create or replace function public.operator_revoke_license(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_reason text
)
returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare v_result jsonb;
begin
  perform app.require_platform_operator(p_actor_user_id);
  v_result := public.revoke_licensed_tenant_admission(p_actor_user_id,
    p_tenant_id, p_reason);
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
  values (p_actor_user_id, p_tenant_id, 'operator.license_revoked',
    jsonb_build_object('status', v_result ->> 'status',
      'reason', trim(p_reason)));
  return v_result;
end;
$$;
revoke all on function public.operator_revoke_license(uuid, uuid, text)
  from public, anon, authenticated;
grant execute on function public.operator_revoke_license(uuid, uuid, text)
  to service_role;

-- Keyset-paged tenant directory with minimal fields. Personal workspace names
-- are commonly derived from a person's name or email, so they are withheld.
create or replace function public.operator_list_tenants(
  p_actor_user_id uuid,
  p_limit integer,
  p_after uuid default null
)
returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_rows jsonb;
  v_count integer;
  v_next uuid;
begin
  perform app.require_platform_operator(p_actor_user_id);
  if p_limit is null or p_limit not between 1 and 200 then
    raise exception 'invalid_page' using errcode = '22023';
  end if;
  with page as (
    select t.id, t.kind, t.status, t.created_at,
      case when t.kind = 'personal' then null else t.name end as name,
      a.kind as admission_kind, a.plan_id, a.seats, a.expires_at,
      (a.tenant_id is not null and a.revoked_at is null
        and a.starts_at <= v_now and a.expires_at > v_now) as admission_active
    from public.tenants t
    left join public.tenant_admissions a on a.tenant_id = t.id
    where p_after is null or t.id > p_after
    order by t.id
    limit p_limit
  )
  select coalesce(jsonb_agg(jsonb_build_object(
      'id', id, 'name', name, 'kind', kind, 'status', status,
      'created_at', created_at, 'admission', case when admission_kind is null
        then null else jsonb_build_object('kind', admission_kind,
          'plan_id', plan_id, 'seats', seats, 'expires_at', expires_at,
          'active', admission_active) end)
      order by id), '[]'::jsonb),
    count(*), (array_agg(id order by id desc))[1]
    into v_rows, v_count, v_next
  from page;
  if v_count < p_limit or not exists (
    select 1 from public.tenants t where t.id > v_next
  ) then
    v_next := null;
  end if;
  insert into public.admin_audit_logs(actor_user_id, action, detail)
  values (p_actor_user_id, 'operator.tenants_listed',
    jsonb_build_object('limit', p_limit, 'after', p_after, 'count', v_count));
  return jsonb_build_object('tenants', v_rows, 'next_cursor', v_next);
end;
$$;
revoke all on function public.operator_list_tenants(uuid, integer, uuid)
  from public, anon, authenticated;
grant execute on function public.operator_list_tenants(uuid, integer, uuid)
  to service_role;

-- Aggregate usage for one tenant: counts only, no member identities.
create or replace function public.operator_tenant_usage(
  p_actor_user_id uuid,
  p_tenant_id uuid
)
returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_tenant public.tenants%rowtype;
  v_admission public.tenant_admissions%rowtype;
  v_mode text;
  v_capacity integer;
  v_agents integer;
  v_agents_active integer;
  v_members integer;
begin
  perform app.require_platform_operator(p_actor_user_id);
  if p_tenant_id is null then
    raise exception 'tenant_not_found' using errcode = 'P0002';
  end if;
  select * into v_tenant from public.tenants where id = p_tenant_id;
  if not found then
    raise exception 'tenant_not_found' using errcode = 'P0002';
  end if;
  select mode into v_mode from app.tenant_admission_config where singleton;
  select * into v_admission from public.tenant_admissions
   where tenant_id = p_tenant_id;
  v_capacity := public.tenant_admission_capacity(p_tenant_id);
  select count(*)::int,
      (count(*) filter (where a.last_seen > v_now - interval '7 days'))::int
    into v_agents, v_agents_active
    from public.agents a where a.tenant_id = p_tenant_id;
  select count(*)::int into v_members from public.tenant_members m
   where m.tenant_id = p_tenant_id
     and (m.expires_at is null or m.expires_at > v_now);
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
  values (p_actor_user_id, p_tenant_id, 'operator.tenant_usage_read',
    '{}'::jsonb);
  return jsonb_build_object(
    'tenant', jsonb_build_object('id', v_tenant.id, 'kind', v_tenant.kind,
      'status', v_tenant.status, 'created_at', v_tenant.created_at),
    'admission_mode', coalesce(v_mode, 'unconfigured'),
    'admission', case when v_admission.tenant_id is null then null
      else jsonb_build_object('kind', v_admission.kind,
        'plan_id', v_admission.plan_id, 'seats', v_admission.seats,
        'starts_at', v_admission.starts_at,
        'expires_at', v_admission.expires_at,
        'revoked_at', v_admission.revoked_at,
        'active', v_admission.revoked_at is null
          and v_admission.starts_at <= v_now
          and v_admission.expires_at > v_now) end,
    'allowed_agents', v_capacity,
    'agents', jsonb_build_object('enrolled', v_agents,
      'active_7d', v_agents_active),
    'members', v_members);
end;
$$;
revoke all on function public.operator_tenant_usage(uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.operator_tenant_usage(uuid, uuid)
  to service_role;
