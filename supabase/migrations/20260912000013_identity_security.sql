-- Enterprise identity recovery, immediate session barriers, and tenant MFA policy.
-- Auth-provider email delivery and IdP policy remain deployment responsibilities.

create table public.tenant_identity_policies (
  tenant_id uuid primary key references public.tenants(id) on delete cascade,
  require_mfa boolean not null default false,
  break_glass_enabled boolean not null default false,
  updated_by uuid references auth.users(id) on delete set null,
  updated_at timestamptz not null default now()
);

create table public.identity_user_session_state (
  user_id uuid primary key references auth.users(id) on delete cascade,
  revoked_before timestamptz,
  reason text check (reason in ('user_global_signout', 'password_recovery', 'break_glass')),
  updated_at timestamptz not null default now()
);

create table public.identity_recovery_codes (
  id uuid primary key default gen_random_uuid(),
  batch_id uuid not null,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  code_hash text not null unique check (code_hash ~ '^[0-9a-f]{64}$'),
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_at timestamptz,
  used_request_id text check (used_request_id is null or used_request_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
  check (expires_at > created_at),
  check ((used_at is null) = (used_request_id is null))
);
create index identity_recovery_codes_user_active
  on public.identity_recovery_codes(tenant_id, user_id, expires_at desc)
  where used_at is null;

create table public.identity_password_recovery_grants (
  id uuid primary key,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  source text not null check (source = 'break_glass'),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_at timestamptz,
  check (expires_at > created_at)
);
create index identity_password_recovery_grants_user_active
  on public.identity_password_recovery_grants(user_id, expires_at desc)
  where used_at is null;

alter table public.tenant_identity_policies enable row level security;
alter table public.identity_user_session_state enable row level security;
alter table public.identity_recovery_codes enable row level security;
alter table public.identity_password_recovery_grants enable row level security;

revoke all on public.tenant_identity_policies, public.identity_user_session_state,
  public.identity_recovery_codes, public.identity_password_recovery_grants
  from public, anon, authenticated;
grant select, insert, update, delete on public.tenant_identity_policies,
  public.identity_user_session_state, public.identity_recovery_codes,
  public.identity_password_recovery_grants to service_role;

create trigger tenant_identity_policies_touch_updated_at
before update on public.tenant_identity_policies
for each row execute procedure public.touch_updated_at();

create trigger identity_user_session_state_touch_updated_at
before update on public.identity_user_session_state
for each row execute procedure public.touch_updated_at();

-- Restrictive RLS predicate for browser/PostgREST traffic. A global revocation
-- barrier rejects already-issued JWTs immediately; tenant MFA policy requires
-- the Auth-issued aal2 claim. Service-role Edge Functions must additionally
-- call the same checks because service_role bypasses RLS.
create or replace function public.tenant_identity_access_allowed(p_tenant_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select
    auth.uid() is not null
    and not exists (
      select 1 from public.identity_user_session_state s
      where s.user_id = auth.uid()
        and s.revoked_before is not null
        and (
          coalesce(auth.jwt()->>'iat', '') !~ '^[0-9]+(\.[0-9]+)?$'
          or to_timestamp((auth.jwt()->>'iat')::double precision) <= s.revoked_before
        )
    )
    and not exists (
      select 1 from public.tenant_identity_policies p
      where p.tenant_id = p_tenant_id
        and p.require_mfa
        and coalesce(auth.jwt()->>'aal', 'aal1') <> 'aal2'
    );
$$;
revoke all on function public.tenant_identity_access_allowed(uuid) from public, anon;
grant execute on function public.tenant_identity_access_allowed(uuid) to authenticated, service_role;

-- Apply the identity predicate as a restrictive policy to every currently
-- exposed tenant table with RLS. Existing permissive membership policies still
-- decide which rows a caller may access.
do $$
declare v_table record;
begin
  for v_table in
    select distinct c.table_name
    from information_schema.columns c
    join pg_class pc on pc.relname = c.table_name
    join pg_namespace pn on pn.oid = pc.relnamespace and pn.nspname = c.table_schema
    where c.table_schema = 'public' and c.column_name = 'tenant_id'
      and pc.relkind in ('r', 'p') and pc.relrowsecurity
  loop
    execute format('drop policy if exists tenant_identity_access_restrict on public.%I', v_table.table_name);
    execute format(
      'create policy tenant_identity_access_restrict on public.%I as restrictive for all to authenticated using (public.tenant_identity_access_allowed(tenant_id)) with check (public.tenant_identity_access_allowed(tenant_id))',
      v_table.table_name
    );
  end loop;
end;
$$;

drop policy if exists tenant_identity_access_restrict on public.tenants;
create policy tenant_identity_access_restrict on public.tenants
as restrictive for all to authenticated
using (public.tenant_identity_access_allowed(id))
with check (public.tenant_identity_access_allowed(id));

create or replace function public.set_tenant_identity_policy(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_require_mfa boolean,
  p_break_glass_enabled boolean
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if p_tenant_id is null or p_actor_user_id is null
    or p_require_mfa is null or p_break_glass_enabled is null
  then raise exception 'invalid_identity_policy' using errcode = '22023'; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2607));
  if not exists(
    select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id and m.role = 'owner'
      and (m.expires_at is null or m.expires_at > now()) and t.status = 'active'
  ) then raise exception 'identity_policy_forbidden' using errcode = '42501'; end if;
  insert into public.tenant_identity_policies(tenant_id, require_mfa, break_glass_enabled, updated_by)
    values(p_tenant_id, p_require_mfa, p_break_glass_enabled, p_actor_user_id)
    on conflict(tenant_id) do update set require_mfa = excluded.require_mfa,
      break_glass_enabled = excluded.break_glass_enabled, updated_by = excluded.updated_by;
  if not p_break_glass_enabled then
    delete from public.identity_recovery_codes where tenant_id = p_tenant_id and used_at is null;
  end if;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
    values(p_actor_user_id, p_tenant_id, p_actor_user_id, 'identity.policy.updated',
      jsonb_build_object('require_mfa', p_require_mfa, 'break_glass_enabled', p_break_glass_enabled));
  return jsonb_build_object('tenant_id', p_tenant_id, 'require_mfa', p_require_mfa,
    'break_glass_enabled', p_break_glass_enabled);
end;
$$;
revoke all on function public.set_tenant_identity_policy(uuid, uuid, boolean, boolean) from public, anon, authenticated;
grant execute on function public.set_tenant_identity_policy(uuid, uuid, boolean, boolean) to service_role;

create or replace function public.issue_identity_recovery_codes(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_target_user_id uuid,
  p_code_hashes text[],
  p_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_actor_role text;
  v_target_role text;
  v_batch_id uuid := gen_random_uuid();
begin
  if p_tenant_id is null or p_actor_user_id is null or p_target_user_id is null
    or coalesce(cardinality(p_code_hashes), 0) not between 4 and 16
    or p_expires_at <= now() + interval '1 day'
    or p_expires_at > now() + interval '180 days'
    or exists(select 1 from unnest(p_code_hashes) h where h !~ '^[0-9a-f]{64}$')
    or (select count(distinct h) from unnest(p_code_hashes) h) <> cardinality(p_code_hashes)
  then raise exception 'invalid_recovery_code_batch' using errcode = '22023'; end if;

  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':' || p_target_user_id::text, 2607));
  select m.role into v_actor_role from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
      and m.role in ('owner', 'admin') and (m.expires_at is null or m.expires_at > now())
      and t.status = 'active';
  if v_actor_role is null then raise exception 'recovery_code_issue_forbidden' using errcode = '42501'; end if;

  select role into v_target_role from public.tenant_members
    where tenant_id = p_tenant_id and user_id = p_target_user_id
      and (expires_at is null or expires_at > now());
  if v_target_role is null then raise exception 'recovery_target_not_active' using errcode = '42501'; end if;
  if p_actor_user_id <> p_target_user_id and
     (v_actor_role <> 'owner' or v_target_role = 'owner')
  then raise exception 'recovery_target_role_forbidden' using errcode = '42501'; end if;
  if not exists(select 1 from public.tenant_identity_policies where tenant_id = p_tenant_id and break_glass_enabled)
  then raise exception 'break_glass_disabled' using errcode = '42501'; end if;

  delete from public.identity_recovery_codes
    where tenant_id = p_tenant_id and user_id = p_target_user_id and used_at is null;
  insert into public.identity_recovery_codes(batch_id, tenant_id, user_id, code_hash, created_by, expires_at)
    select v_batch_id, p_tenant_id, p_target_user_id, h, p_actor_user_id, p_expires_at
    from unnest(p_code_hashes) h;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
    values(p_actor_user_id, p_tenant_id, p_target_user_id, 'identity.recovery_codes.rotated',
      jsonb_build_object('batch_id', v_batch_id, 'count', cardinality(p_code_hashes), 'expires_at', p_expires_at));
  return jsonb_build_object('batch_id', v_batch_id, 'count', cardinality(p_code_hashes), 'expires_at', p_expires_at);
end;
$$;
revoke all on function public.issue_identity_recovery_codes(uuid, uuid, uuid, text[], timestamptz) from public, anon, authenticated;
grant execute on function public.issue_identity_recovery_codes(uuid, uuid, uuid, text[], timestamptz) to service_role;

create or replace function public.consume_identity_recovery_code(
  p_email text,
  p_code_hash text,
  p_request_id text
)
returns jsonb
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $$
declare v_code public.identity_recovery_codes;
begin
  if p_email is null or length(p_email) > 254 or p_code_hash !~ '^[0-9a-f]{64}$'
    or p_request_id !~ '^[A-Za-z0-9._:-]{1,128}$'
  then return null; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_code_hash, 2607));
  select c.* into v_code
    from public.identity_recovery_codes c
    join auth.users u on u.id = c.user_id
    join public.tenants t on t.id = c.tenant_id and t.status = 'active'
    join public.tenant_members m on m.tenant_id = c.tenant_id and m.user_id = c.user_id
      and (m.expires_at is null or m.expires_at > now())
    join public.tenant_identity_policies p on p.tenant_id = c.tenant_id and p.break_glass_enabled
    where c.code_hash = p_code_hash and c.used_at is null and c.expires_at > now()
      and lower(u.email) = lower(trim(p_email))
    for update of c;
  if not found then return null; end if;
  update public.identity_recovery_codes set used_at = now(), used_request_id = p_request_id where id = v_code.id;
  insert into public.identity_user_session_state(user_id, revoked_before, reason)
    values(v_code.user_id, now(), 'break_glass')
    on conflict(user_id) do update set revoked_before = excluded.revoked_before, reason = excluded.reason;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
    values(null, v_code.tenant_id, v_code.user_id, 'identity.break_glass.consumed',
      jsonb_build_object('recovery_code_id', v_code.id, 'request_id', p_request_id));
  return jsonb_build_object('tenant_id', v_code.tenant_id, 'user_id', v_code.user_id, 'recovery_code_id', v_code.id);
end;
$$;
revoke all on function public.consume_identity_recovery_code(text, text, text) from public, anon, authenticated;
grant execute on function public.consume_identity_recovery_code(text, text, text) to service_role;

create or replace function public.consume_identity_password_recovery_grant(p_grant_id uuid, p_user_id uuid)
returns uuid
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare v_tenant_id uuid;
begin
  if p_grant_id is null or p_user_id is null then return null; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_grant_id::text, 2607));
  update public.identity_password_recovery_grants
    set used_at = now()
    where id = p_grant_id and user_id = p_user_id and used_at is null and expires_at > now()
    returning tenant_id into v_tenant_id;
  return v_tenant_id;
end;
$$;
revoke all on function public.consume_identity_password_recovery_grant(uuid, uuid) from public, anon, authenticated;
grant execute on function public.consume_identity_password_recovery_grant(uuid, uuid) to service_role;

create or replace function public.mark_identity_session_revoked(
  p_user_id uuid,
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_reason text
)
returns timestamptz
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare v_barrier timestamptz := now();
begin
  if p_user_id is null or p_actor_user_id is null or p_user_id <> p_actor_user_id
    or p_reason not in ('user_global_signout', 'password_recovery')
  then raise exception 'session_revoke_forbidden' using errcode = '42501'; end if;
  insert into public.identity_user_session_state(user_id, revoked_before, reason)
    values(p_user_id, v_barrier, p_reason)
    on conflict(user_id) do update set revoked_before = excluded.revoked_before, reason = excluded.reason;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
    values(p_actor_user_id, p_tenant_id, p_user_id, 'identity.sessions.revoked',
      jsonb_build_object('reason', p_reason, 'revoked_before', v_barrier));
  return v_barrier;
end;
$$;
revoke all on function public.mark_identity_session_revoked(uuid, uuid, uuid, text) from public, anon, authenticated;
grant execute on function public.mark_identity_session_revoked(uuid, uuid, uuid, text) to service_role;
