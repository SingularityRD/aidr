-- Published runtime policy is distinct from the historical team YAML draft.
-- Publication, optimistic concurrency and immutable revision history are atomic.
create table public.tenant_runtime_policies (
  tenant_id uuid primary key references public.tenants(id),
  version bigint not null check (version > 0),
  policy jsonb not null check (jsonb_typeof(policy) = 'object'),
  updated_by uuid not null references auth.users(id),
  updated_at timestamptz not null default now()
);
create table public.runtime_policy_revisions (
  tenant_id uuid not null references public.tenants(id),
  version bigint not null,
  policy jsonb not null,
  updated_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  primary key (tenant_id, version)
);
alter table public.tenant_runtime_policies enable row level security;
alter table public.runtime_policy_revisions enable row level security;
revoke all on public.tenant_runtime_policies, public.runtime_policy_revisions from anon, authenticated;
grant select, insert, update on public.tenant_runtime_policies to service_role;
grant select, insert on public.runtime_policy_revisions to service_role;

create function public.publish_runtime_policy(p_tenant_id uuid, p_user_id uuid, p_expected_version bigint, p_policy jsonb)
returns public.tenant_runtime_policies
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  result public.tenant_runtime_policies;
  current_version bigint;
begin
  if not exists (
    select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = p_tenant_id and m.user_id = p_user_id
      and m.role in ('owner', 'admin') and (m.expires_at is null or m.expires_at > now())
      and t.status = 'active'
  ) then raise exception 'policy_forbidden' using errcode = '42501'; end if;
  if p_expected_version is null or p_expected_version < 0 or p_policy is null
     or jsonb_typeof(p_policy) <> 'object' or octet_length(p_policy::text) > 65536 then
    raise exception 'invalid_policy' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 911));
  select version into current_version from public.tenant_runtime_policies where tenant_id = p_tenant_id;
  if coalesce(current_version, 0) <> p_expected_version then
    raise exception 'policy_version_conflict' using errcode = '40001';
  end if;
  insert into public.tenant_runtime_policies(tenant_id, version, policy, updated_by)
  values(p_tenant_id, p_expected_version + 1, p_policy, p_user_id)
  on conflict (tenant_id) do update set version = excluded.version, policy = excluded.policy,
    updated_by = excluded.updated_by, updated_at = now()
  returning * into result;
  insert into public.runtime_policy_revisions(tenant_id, version, policy, updated_by)
  values(result.tenant_id, result.version, result.policy, result.updated_by);
  return result;
end;
$$;
revoke all on function public.publish_runtime_policy(uuid, uuid, bigint, jsonb) from public, anon, authenticated;
grant execute on function public.publish_runtime_policy(uuid, uuid, bigint, jsonb) to service_role;
