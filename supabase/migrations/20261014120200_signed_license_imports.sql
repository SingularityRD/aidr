-- Signed license import, license status and usage facts (C11, B9, A3).
--
-- Before this migration a renewed or enlarged on-prem license had to be typed
-- into `grant_licensed_tenant_admission` by an admission operator; nothing in
-- the product read the signed file, and tenants saw no expiry warning.
--
-- Flow (separation of duty is unchanged):
--   1. A tenant owner/admin uploads the vendor-signed `aidr-license-v1` file
--      in the dashboard. The license-admin Edge function verifies the
--      signature against the deployment's trust registry and calls
--      `submit_license_import`, which stores the verified document as a
--      PENDING import. Submitting never changes seats or expiry.
--   2. A platform operator who is also the tenant's admission operator, and
--      NOT a member of the tenant, applies it from the Operator console
--      (or `scripts/operator-admin.mjs license-apply`). operator-admin
--      re-verifies the document at that moment and calls
--      `operator_apply_license`, which takes seats, plan, license id and the
--      admission end (`expires_at + grace_days`) from the stored signed
--      payload and applies them through the existing `operator_grant_license`
--      -> `grant_licensed_tenant_admission` path, with every check that path
--      already enforces (admission operator row, non-member actor, mode,
--      owner).
--   An operator may also apply a verified file directly (no tenant submission).
--
-- The database stores what the Edge function verified; it does not re-verify
-- Ed25519 signatures (docs/operations/licensing.md, "What the license can and
-- cannot enforce"). It does cross-check that the stored terms are the payload
-- of the stored document and that the canonical digest matches.

create table if not exists public.license_imports (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  status text not null check (status in ('pending', 'applied', 'superseded', 'withdrawn')),
  source text not null check (source in ('tenant_submission', 'operator_upload')),
  license_id text not null check (license_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
  key_id text not null check (key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
  customer text not null check (length(customer) between 1 and 120 and customer !~ '[[:cntrl:]]'),
  customer_id text check (customer_id is null or customer_id ~ '^[a-z0-9][a-z0-9-]{1,31}$'),
  plan_id text not null check (plan_id in ('free', 'team', 'business', 'enterprise')),
  seats integer not null check (seats between 1 and 100000),
  deployment text not null check (deployment in ('onprem', 'airgap')),
  issued_at timestamptz not null,
  not_before timestamptz not null,
  expires_at timestamptz not null,
  grace_days integer not null check (grace_days between 0 and 90),
  grace_ends_at timestamptz not null,
  document jsonb not null check (jsonb_typeof(document) = 'object' and octet_length(document::text) <= 65536),
  canonical_sha256 text not null check (canonical_sha256 ~ '^[a-f0-9]{64}$'),
  submitted_by uuid references auth.users(id) on delete set null,
  submitted_at timestamptz not null default clock_timestamp(),
  applied_by uuid references auth.users(id) on delete set null,
  applied_at timestamptz,
  check (expires_at > not_before and expires_at > issued_at),
  check (grace_ends_at = expires_at + make_interval(days => grace_days)),
  check ((status = 'applied') = (applied_at is not null) or status = 'superseded')
);
create unique index if not exists license_imports_one_pending
  on public.license_imports (tenant_id) where status = 'pending';
create unique index if not exists license_imports_one_applied
  on public.license_imports (tenant_id) where status = 'applied';
create index if not exists license_imports_license_id_idx on public.license_imports (license_id);
create index if not exists license_imports_pending_idx
  on public.license_imports (submitted_at) where status = 'pending';
alter table public.license_imports enable row level security;
revoke all on public.license_imports from public, anon, authenticated, service_role;
-- No browser grant or permissive policy: every read and write goes through the
-- SECURITY DEFINER functions below. The restrictive identity barrier still
-- applies should a policy ever be added.
create policy tenant_identity_access_restrict on public.license_imports
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- Terms are read from the stored document's payload, never from a second,
-- caller-supplied copy, so what is applied is what was verified.
create or replace function app.license_terms(p_document jsonb)
returns jsonb
language plpgsql
stable
set search_path = pg_catalog, pg_temp
as $$
declare
  v_payload jsonb := p_document -> 'payload';
  v_expires timestamptz;
  v_grace integer;
begin
  if jsonb_typeof(p_document) is distinct from 'object'
     or p_document ->> 'format' is distinct from 'aidr-license-v1'
     or jsonb_typeof(v_payload) is distinct from 'object'
     or jsonb_typeof(v_payload -> 'seats') is distinct from 'number'
     or jsonb_typeof(v_payload -> 'grace_days') is distinct from 'number'
     or jsonb_typeof(v_payload -> 'features') is distinct from 'array' then
    raise exception 'invalid_license_document' using errcode = '22023';
  end if;
  v_expires := (v_payload ->> 'expires_at')::timestamptz;
  v_grace := (v_payload ->> 'grace_days')::integer;
  return jsonb_build_object(
    'license_id', v_payload ->> 'license_id',
    'key_id', p_document ->> 'key_id',
    'customer', v_payload ->> 'customer',
    'customer_id', v_payload ->> 'customer_id',
    'plan_id', v_payload ->> 'plan_id',
    'seats', (v_payload ->> 'seats')::integer,
    'deployment', v_payload ->> 'deployment',
    'issued_at', (v_payload ->> 'issued_at')::timestamptz,
    'not_before', (v_payload ->> 'not_before')::timestamptz,
    'expires_at', v_expires,
    'grace_days', v_grace,
    'grace_ends_at', v_expires + make_interval(days => v_grace));
exception when invalid_text_representation or datetime_field_overflow or invalid_datetime_format
  or numeric_value_out_of_range then
  raise exception 'invalid_license_document' using errcode = '22023';
end;
$$;
revoke all on function app.license_terms(jsonb) from public, anon, authenticated, service_role;

create or replace function app.license_import_row(p_import public.license_imports)
returns jsonb
language sql
stable
set search_path = pg_catalog, pg_temp
as $$
  select jsonb_build_object(
    'id', p_import.id, 'tenant_id', p_import.tenant_id, 'status', p_import.status,
    'source', p_import.source, 'license_id', p_import.license_id, 'key_id', p_import.key_id,
    'customer', p_import.customer, 'customer_id', p_import.customer_id,
    'plan_id', p_import.plan_id, 'seats', p_import.seats, 'deployment', p_import.deployment,
    'not_before', p_import.not_before, 'expires_at', p_import.expires_at,
    'grace_days', p_import.grace_days, 'grace_ends_at', p_import.grace_ends_at,
    'canonical_sha256', p_import.canonical_sha256,
    'submitted_at', p_import.submitted_at, 'applied_at', p_import.applied_at)
$$;
revoke all on function app.license_import_row(public.license_imports) from public, anon, authenticated, service_role;

-- Step 1 (tenant owner/admin, through license-admin): stage a verified license.
create or replace function public.submit_license_import(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_document jsonb,
  p_canonical_sha256 text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_terms jsonb;
  v_existing public.license_imports%rowtype;
  v_row public.license_imports%rowtype;
begin
  if p_actor_user_id is null or p_tenant_id is null or p_document is null
     or p_canonical_sha256 is null or p_canonical_sha256 !~ '^[a-f0-9]{64}$' then
    raise exception 'invalid_license_import' using errcode = '22023';
  end if;
  v_terms := app.license_terms(p_document);
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
  perform 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
     and m.role in ('owner', 'admin')
     and (m.expires_at is null or m.expires_at > clock_timestamp())
     and t.status = 'active'
   for share of m;
  if not found then
    raise exception 'license_import_forbidden' using errcode = '42501';
  end if;
  if exists (select 1 from public.license_imports i
              where i.license_id = v_terms ->> 'license_id' and i.tenant_id <> p_tenant_id
                and i.status in ('applied', 'superseded')) then
    raise exception 'license_bound_to_other_tenant' using errcode = '42501';
  end if;
  select * into v_existing from public.license_imports
   where tenant_id = p_tenant_id and status = 'pending' for update;
  if found and v_existing.canonical_sha256 = p_canonical_sha256 then
    return jsonb_build_object('status', 'pending', 'import', app.license_import_row(v_existing));
  end if;
  if found then
    update public.license_imports set status = 'withdrawn' where id = v_existing.id;
  end if;
  insert into public.license_imports(tenant_id, status, source, license_id, key_id, customer,
    customer_id, plan_id, seats, deployment, issued_at, not_before, expires_at, grace_days,
    grace_ends_at, document, canonical_sha256, submitted_by)
  values (p_tenant_id, 'pending', 'tenant_submission', v_terms ->> 'license_id',
    v_terms ->> 'key_id', v_terms ->> 'customer', v_terms ->> 'customer_id',
    v_terms ->> 'plan_id', (v_terms ->> 'seats')::integer, v_terms ->> 'deployment',
    (v_terms ->> 'issued_at')::timestamptz, (v_terms ->> 'not_before')::timestamptz,
    (v_terms ->> 'expires_at')::timestamptz, (v_terms ->> 'grace_days')::integer,
    (v_terms ->> 'grace_ends_at')::timestamptz, p_document, p_canonical_sha256, p_actor_user_id)
  returning * into v_row;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
  values (p_actor_user_id, p_tenant_id, 'license.import_submitted',
    jsonb_build_object('import_id', v_row.id, 'license_id', v_row.license_id,
      'key_id', v_row.key_id, 'seats', v_row.seats, 'expires_at', v_row.expires_at,
      'grace_ends_at', v_row.grace_ends_at, 'canonical_sha256', v_row.canonical_sha256,
      'replaced_import_id', v_existing.id));
  return jsonb_build_object('status', 'pending', 'import', app.license_import_row(v_row));
exception when unique_violation then
  raise exception 'license_import_conflict' using errcode = '40001';
end;
$$;
revoke all on function public.submit_license_import(uuid, uuid, jsonb, text) from public, anon, authenticated;
grant execute on function public.submit_license_import(uuid, uuid, jsonb, text) to service_role;

-- Operator console: pending imports, with the signed document so operator-admin
-- can re-verify it before applying.
create or replace function public.operator_list_license_imports(p_actor_user_id uuid, p_limit integer default 50)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_items jsonb;
begin
  perform app.require_platform_operator(p_actor_user_id);
  if p_limit is null or p_limit not between 1 and 200 then
    raise exception 'invalid_page' using errcode = '22023';
  end if;
  select coalesce(jsonb_agg(app.license_import_row(i) || jsonb_build_object('document', i.document)
           order by i.submitted_at, i.id), '[]'::jsonb)
    into v_items
    from (select * from public.license_imports where status = 'pending'
           order by submitted_at, id limit p_limit) i;
  return jsonb_build_object('imports', v_items);
end;
$$;
revoke all on function public.operator_list_license_imports(uuid, integer) from public, anon, authenticated;
grant execute on function public.operator_list_license_imports(uuid, integer) to service_role;

-- Step 2 (platform + admission operator, through operator-admin): apply.
create or replace function public.operator_apply_license(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_import_id uuid,
  p_document jsonb,
  p_canonical_sha256 text,
  p_owner_user_id uuid default null
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz;
  v_terms jsonb;
  v_import public.license_imports%rowtype;
  v_previous uuid;
  v_grant jsonb;
begin
  perform app.require_platform_operator(p_actor_user_id);
  if p_tenant_id is null or p_document is null
     or p_canonical_sha256 is null or p_canonical_sha256 !~ '^[a-f0-9]{64}$' then
    raise exception 'invalid_license_import' using errcode = '22023';
  end if;
  v_terms := app.license_terms(p_document);
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
  v_now := clock_timestamp();
  if (v_terms ->> 'not_before')::timestamptz > v_now then
    raise exception 'license_not_yet_valid' using errcode = '22023';
  end if;
  if (v_terms ->> 'grace_ends_at')::timestamptz <= v_now then
    raise exception 'license_expired' using errcode = '22023';
  end if;
  if exists (select 1 from public.license_imports i
              where i.license_id = v_terms ->> 'license_id' and i.tenant_id <> p_tenant_id
                and i.status in ('applied', 'superseded')) then
    raise exception 'license_bound_to_other_tenant' using errcode = '42501';
  end if;
  if p_import_id is not null then
    select * into v_import from public.license_imports
     where id = p_import_id and tenant_id = p_tenant_id for update;
    if not found or v_import.status <> 'pending' then
      raise exception 'license_import_not_pending' using errcode = '55000';
    end if;
    if v_import.canonical_sha256 <> p_canonical_sha256 or v_import.document <> p_document then
      raise exception 'license_import_mismatch' using errcode = '22023';
    end if;
  end if;

  -- The existing grant path enforces the tenant-scoped admission operator,
  -- the non-member actor (separation of duty), the deployment mode and the
  -- owner. Admission ends when the license's grace period ends.
  v_grant := public.operator_grant_license(p_actor_user_id, p_tenant_id, v_terms ->> 'plan_id',
    (v_terms ->> 'seats')::integer, (v_terms ->> 'grace_ends_at')::timestamptz,
    v_terms ->> 'license_id', p_owner_user_id);

  update public.license_imports set status = 'superseded'
   where tenant_id = p_tenant_id and status = 'applied'
  returning id into v_previous;
  if p_import_id is not null then
    update public.license_imports
       set status = 'applied', applied_by = p_actor_user_id, applied_at = v_now
     where id = p_import_id
    returning * into v_import;
  else
    update public.license_imports set status = 'withdrawn'
     where tenant_id = p_tenant_id and status = 'pending'
       and canonical_sha256 = p_canonical_sha256;
    insert into public.license_imports(tenant_id, status, source, license_id, key_id, customer,
      customer_id, plan_id, seats, deployment, issued_at, not_before, expires_at, grace_days,
      grace_ends_at, document, canonical_sha256, submitted_by, applied_by, applied_at)
    values (p_tenant_id, 'applied', 'operator_upload', v_terms ->> 'license_id',
      v_terms ->> 'key_id', v_terms ->> 'customer', v_terms ->> 'customer_id',
      v_terms ->> 'plan_id', (v_terms ->> 'seats')::integer, v_terms ->> 'deployment',
      (v_terms ->> 'issued_at')::timestamptz, (v_terms ->> 'not_before')::timestamptz,
      (v_terms ->> 'expires_at')::timestamptz, (v_terms ->> 'grace_days')::integer,
      (v_terms ->> 'grace_ends_at')::timestamptz, p_document, p_canonical_sha256,
      p_actor_user_id, p_actor_user_id, v_now)
    returning * into v_import;
  end if;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
  values (p_actor_user_id, p_tenant_id, 'license.applied',
    jsonb_build_object('import_id', v_import.id, 'source', v_import.source,
      'license_id', v_import.license_id, 'key_id', v_import.key_id,
      'seats', v_import.seats, 'plan_id', v_import.plan_id,
      'expires_at', v_import.expires_at, 'grace_ends_at', v_import.grace_ends_at,
      'canonical_sha256', v_import.canonical_sha256, 'superseded_import_id', v_previous));
  return v_grant || jsonb_build_object('import', app.license_import_row(v_import));
end;
$$;
revoke all on function public.operator_apply_license(uuid, uuid, uuid, jsonb, text, uuid) from public, anon, authenticated;
grant execute on function public.operator_apply_license(uuid, uuid, uuid, jsonb, text, uuid) to service_role;

-- Usage facts for one tenant (A3 usage report). Counts only.
create or replace function app.tenant_usage_facts(p_tenant_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_admission public.tenant_admissions%rowtype;
  v_license public.license_imports%rowtype;
  v_enrolled integer;
  v_active integer;
  v_retired integer;
begin
  select * into v_admission from public.tenant_admissions where tenant_id = p_tenant_id;
  select * into v_license from public.license_imports
   where tenant_id = p_tenant_id and status = 'applied';
  select count(*) filter (where a.retired_at is null)::int,
         count(*) filter (where a.retired_at is null and a.last_seen > v_now - interval '30 days')::int,
         count(*) filter (where a.retired_at is not null)::int
    into v_enrolled, v_active, v_retired
    from public.agents a where a.tenant_id = p_tenant_id;
  return jsonb_build_object(
    'tenant_id', p_tenant_id,
    'generated_at', v_now,
    'mode', (select mode from app.tenant_admission_config where singleton),
    'seats_licensed', case when v_admission.tenant_id is not null and v_admission.revoked_at is null
      then v_admission.seats else 0 end,
    'admission', case when v_admission.tenant_id is null then null else jsonb_build_object(
      'kind', v_admission.kind, 'seats', v_admission.seats,
      'expires_at', v_admission.expires_at, 'revoked_at', v_admission.revoked_at,
      'reference', v_admission.grant_reference) end,
    'license', case when v_license.id is null then null else app.license_import_row(v_license) end,
    'devices_enrolled', v_enrolled,
    'devices_active_30d', v_active,
    'devices_retired', v_retired);
end;
$$;
revoke all on function app.tenant_usage_facts(uuid) from public, anon, authenticated, service_role;

-- Script/maintenance read (service role). With a null tenant the only licensed
-- tenant is chosen; several licensed tenants require an explicit id.
create or replace function public.usage_report_facts(p_tenant_id uuid default null)
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_tenants uuid[];
  v_tenant uuid := p_tenant_id;
begin
  if v_tenant is null then
    select array_agg(a.tenant_id order by a.tenant_id) into v_tenants
      from public.tenant_admissions a
      join public.tenants t on t.id = a.tenant_id and t.status = 'active'
     where a.kind = 'licensed' and a.revoked_at is null;
    if coalesce(cardinality(v_tenants), 0) = 0 then
      raise exception 'no_licensed_tenant' using errcode = 'P0002';
    end if;
    if cardinality(v_tenants) > 1 then
      raise exception 'tenant_required' using errcode = '22023';
    end if;
    v_tenant := v_tenants[1];
  elsif not exists (select 1 from public.tenants where id = v_tenant) then
    raise exception 'tenant_not_found' using errcode = 'P0002';
  end if;
  return app.tenant_usage_facts(v_tenant);
end;
$$;
revoke all on function public.usage_report_facts(uuid) from public, anon, authenticated;
grant execute on function public.usage_report_facts(uuid) to service_role;

-- Dashboard: license status for the expiry banner (any active member) and, for
-- owners/admins, the pending import and the usage facts behind the report.
create or replace function public.tenant_license_status(p_tenant_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_role text;
  v_admission public.tenant_admissions%rowtype;
  v_license public.license_imports%rowtype;
  v_pending public.license_imports%rowtype;
  v_manage boolean;
begin
  if auth.role() is distinct from 'authenticated'
     or auth.uid() is null
     or p_tenant_id is null
     or not app.is_tenant_member(p_tenant_id)
     or not public.tenant_identity_access_allowed(p_tenant_id) then
    raise exception 'license_status_access_denied' using errcode = '42501';
  end if;
  select m.role into v_role from public.tenant_members m
   where m.tenant_id = p_tenant_id and m.user_id = auth.uid()
     and (m.expires_at is null or m.expires_at > clock_timestamp());
  v_manage := v_role in ('owner', 'admin');
  select * into v_admission from public.tenant_admissions where tenant_id = p_tenant_id;
  select * into v_license from public.license_imports
   where tenant_id = p_tenant_id and status = 'applied';
  if v_manage then
    select * into v_pending from public.license_imports
     where tenant_id = p_tenant_id and status = 'pending';
  end if;
  return jsonb_build_object(
    'mode', (select mode from app.tenant_admission_config where singleton),
    'can_manage', v_manage,
    'admission', case when v_admission.tenant_id is null then null else jsonb_build_object(
      'kind', v_admission.kind, 'seats', v_admission.seats,
      'expires_at', v_admission.expires_at,
      'revoked', v_admission.revoked_at is not null) end,
    'license', case when v_license.id is null then null else jsonb_build_object(
      'license_id', v_license.license_id, 'plan_id', v_license.plan_id,
      'seats', v_license.seats, 'not_before', v_license.not_before,
      'expires_at', v_license.expires_at, 'grace_ends_at', v_license.grace_ends_at,
      'applied_at', v_license.applied_at) end,
    'pending', case when v_pending.id is null then null else jsonb_build_object(
      'id', v_pending.id, 'license_id', v_pending.license_id, 'seats', v_pending.seats,
      'expires_at', v_pending.expires_at, 'grace_ends_at', v_pending.grace_ends_at,
      'submitted_at', v_pending.submitted_at) end);
end;
$$;
revoke all on function public.tenant_license_status(uuid) from public, anon, authenticated, service_role;
grant execute on function public.tenant_license_status(uuid) to authenticated;

create or replace function public.tenant_usage_report(p_tenant_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
begin
  if auth.role() is distinct from 'authenticated'
     or auth.uid() is null
     or p_tenant_id is null
     or not public.tenant_identity_access_allowed(p_tenant_id)
     or not exists (
       select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
        where m.tenant_id = p_tenant_id and m.user_id = auth.uid()
          and m.role in ('owner', 'admin')
          and (m.expires_at is null or m.expires_at > clock_timestamp())
          and t.status = 'active') then
    raise exception 'usage_report_access_denied' using errcode = '42501';
  end if;
  return app.tenant_usage_facts(p_tenant_id);
end;
$$;
revoke all on function public.tenant_usage_report(uuid) from public, anon, authenticated, service_role;
grant execute on function public.tenant_usage_report(uuid) to authenticated;

-- Monitoring (service role, deployment-maintenance): the earliest-ending
-- active licensed admission, for the license-expiry evidence file.
create or replace function public.license_expiry_summary()
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_row record;
  v_count integer;
begin
  select count(*)::int into v_count
    from public.tenant_admissions a
    join public.tenants t on t.id = a.tenant_id and t.status = 'active'
   where a.kind = 'licensed' and a.revoked_at is null;
  select a.tenant_id, a.expires_at as admission_ends_at,
         coalesce(i.expires_at, a.expires_at) as license_expires_at,
         coalesce(i.grace_ends_at, a.expires_at) as grace_ends_at,
         (i.id is not null) as signed
    into v_row
    from public.tenant_admissions a
    join public.tenants t on t.id = a.tenant_id and t.status = 'active'
    left join public.license_imports i on i.tenant_id = a.tenant_id and i.status = 'applied'
   where a.kind = 'licensed' and a.revoked_at is null
   order by a.expires_at, a.tenant_id
   limit 1;
  return jsonb_build_object('checked_at', v_now, 'licensed_tenants', v_count,
    'license_expires_at', v_row.license_expires_at,
    'grace_ends_at', v_row.grace_ends_at,
    'signed', coalesce(v_row.signed, false));
end;
$$;
revoke all on function public.license_expiry_summary() from public, anon, authenticated;
grant execute on function public.license_expiry_summary() to service_role;
