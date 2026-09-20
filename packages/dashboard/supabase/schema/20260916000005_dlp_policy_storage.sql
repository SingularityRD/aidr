-- DLP authoring storage is NOT signed detector provisioning or delivery evidence.
-- Engine-schema validation runs in policy-management before this service-only RPC.
create table public.tenant_dlp_policies (
  tenant_id uuid primary key references public.tenants(id),
  version bigint not null check (version between 1 and 9007199254740991),
  policy jsonb not null check (jsonb_typeof(policy) = 'object'),
  updated_by uuid not null references auth.users(id),
  updated_at timestamptz not null default now(),
  check ((policy->>'tenantId') is not distinct from tenant_id::text),
  check ((policy->>'version') is not distinct from version::text)
);
create table public.dlp_policy_revisions (
  tenant_id uuid not null references public.tenants(id),
  version bigint not null check (version between 1 and 9007199254740991),
  policy jsonb not null check (jsonb_typeof(policy) = 'object'),
  updated_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  primary key (tenant_id, version),
  check ((policy->>'tenantId') is not distinct from tenant_id::text),
  check ((policy->>'version') is not distinct from version::text)
);
alter table public.tenant_dlp_policies enable row level security;
alter table public.dlp_policy_revisions enable row level security;
-- Only the definer RPC may write; no browser access, even for tenant owners.
revoke all on public.tenant_dlp_policies, public.dlp_policy_revisions from public, anon, authenticated, service_role;
grant select on public.tenant_dlp_policies, public.dlp_policy_revisions to service_role;

create function public.publish_dlp_policy(
  p_tenant_id uuid, p_user_id uuid, p_expected_version bigint, p_policy jsonb
)
returns public.tenant_dlp_policies
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_current bigint;
  v_result public.tenant_dlp_policies;
begin
  -- Serializes first inserts as well as updates (there may not yet be a row).
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 91605));
  -- Recheck membership/status inside the writing transaction and retain row
  -- locks so a concurrent revocation/suspension cannot slip past the check.
  perform 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = p_tenant_id and m.user_id = p_user_id
      and m.role in ('owner', 'admin') and (m.expires_at is null or m.expires_at > now())
      and t.status = 'active'
    for share of m, t;
  if not found then raise exception 'policy_forbidden' using errcode = '42501'; end if;
  if p_expected_version is null or p_expected_version < 0 or p_expected_version >= 9007199254740991
     or p_policy is null or jsonb_typeof(p_policy) <> 'object'
     or octet_length(p_policy::text) > 65536
     or (p_policy->>'tenantId') is distinct from p_tenant_id::text
     or (p_policy->>'version') is distinct from (p_expected_version + 1)::text then
    raise exception 'invalid_dlp_policy' using errcode = '22023';
  end if;
  -- Defense in depth: no foreign-tenant labels, rules or exceptions may be stored.
  if jsonb_typeof(p_policy->'labels') is distinct from 'array'
     or jsonb_typeof(p_policy->'rules') is distinct from 'array'
     or jsonb_typeof(p_policy->'exceptions') is distinct from 'array' then
    raise exception 'invalid_dlp_policy' using errcode = '22023';
  end if;
  if exists (
    select 1 from jsonb_array_elements((p_policy->'labels') || (p_policy->'rules') || (p_policy->'exceptions')) item
      where (item->>'tenantId') is distinct from p_tenant_id::text
  ) then raise exception 'dlp_tenant_mismatch' using errcode = '22023'; end if;
  select version into v_current from public.tenant_dlp_policies where tenant_id = p_tenant_id;
  if coalesce(v_current, 0) <> p_expected_version then
    raise exception 'policy_version_conflict' using errcode = 'PT409';
  end if;
  insert into public.tenant_dlp_policies(tenant_id, version, policy, updated_by)
    values(p_tenant_id, p_expected_version + 1, p_policy, p_user_id)
    on conflict (tenant_id) do update set version = excluded.version, policy = excluded.policy,
      updated_by = excluded.updated_by, updated_at = now()
    returning * into v_result;
  insert into public.dlp_policy_revisions(tenant_id, version, policy, updated_by)
    values(v_result.tenant_id, v_result.version, v_result.policy, v_result.updated_by);
  -- Metadata only: sensitive keyword values and regexes are not duplicated in logs.
  -- Any history/audit failure aborts the whole transaction; never acknowledge a partial save.
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
    values(p_user_id, p_tenant_id, 'dlp_policy.save', jsonb_build_object(
      'version', v_result.version, 'previous_version', p_expected_version,
      'delivery_status', 'not_delivered'));
  return v_result;
end;
$$;
revoke all on function public.publish_dlp_policy(uuid, uuid, bigint, jsonb) from public, anon, authenticated;
grant execute on function public.publish_dlp_policy(uuid, uuid, bigint, jsonb) to service_role;
