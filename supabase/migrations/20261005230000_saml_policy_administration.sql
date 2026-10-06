-- Two current owners approve one exact SAML enable/disable transition.
-- Provider registration remains a GoTrue operator operation. This does not
-- bypass required SAML during an IdP outage or change recovery-code behavior.
create table public.tenant_saml_policy_change_requests (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id),
  audit_log_id bigint not null unique references public.admin_audit_logs(id) on delete cascade,
  requested_by uuid not null,
  validated_session jsonb not null check (jsonb_typeof(validated_session) = 'object'),
  old_provider_id uuid,
  new_provider_id uuid,
  expected_oidc_provider_id uuid,
  reason text not null check (char_length(reason) between 12 and 500 and reason !~ '[[:cntrl:]]'),
  change_ref text not null check (char_length(change_ref) between 1 and 200 and change_ref !~ '[[:cntrl:]]'),
  created_at timestamptz not null,
  expires_at timestamptz not null,
  approved_by uuid,
  approved_at timestamptz,
  check ((old_provider_id is null) <> (new_provider_id is null)),
  check (expires_at > created_at and expires_at <= created_at + interval '5 minutes'),
  check ((approved_by is null and approved_at is null)
    or (approved_by is not null and approved_at is not null and approved_by <> requested_by))
);
create index tenant_saml_policy_requests_tenant_idx
  on public.tenant_saml_policy_change_requests(tenant_id, created_at desc);
alter table public.tenant_saml_policy_change_requests enable row level security;
create policy tenant_identity_access_restrict on public.tenant_saml_policy_change_requests
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));
revoke all on public.tenant_saml_policy_change_requests from public, anon, authenticated, service_role;
grant select on public.tenant_saml_policy_change_requests to service_role;

-- The request is security-audit evidence. Its parent audit row already has the
-- legal-hold/offboarding deletion guard and security-audit retention receipt.
-- Cascade removes the proof ledger only when that audited erasure is allowed.
create function app.saml_policy_request_immutable()
returns trigger language plpgsql security definer set search_path = pg_catalog, public, pg_temp as $$
begin
  if (to_jsonb(new) - 'approved_by' - 'approved_at')
      is distinct from (to_jsonb(old) - 'approved_by' - 'approved_at')
     or old.approved_at is not null
     or new.approved_by is null or new.approved_at is null then
    raise exception 'saml_policy_request_immutable' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.saml_policy_request_immutable() from public, anon, authenticated, service_role;
create trigger tenant_saml_policy_request_immutable
before update on public.tenant_saml_policy_change_requests
for each row execute function app.saml_policy_request_immutable();

create function app.saml_policy_request_delete_guard()
returns trigger language plpgsql security definer set search_path = pg_catalog, public, pg_temp as $$
begin
  -- Only the nested FK cascade of an allowed parent-audit purge erases proof.
  -- A privileged direct delete must not circumvent the parent's hold guard.
  if pg_trigger_depth() < 2 or exists (select 1 from public.admin_audit_logs where id = old.audit_log_id) then
    raise exception 'saml_policy_request_immutable' using errcode = '42501';
  end if;
  return old;
end;
$$;
revoke all on function app.saml_policy_request_delete_guard() from public, anon, authenticated, service_role;
create trigger tenant_saml_policy_request_delete_guard
before delete on public.tenant_saml_policy_change_requests
for each row execute function app.saml_policy_request_delete_guard();
create trigger tenant_saml_policy_request_no_truncate
before truncate on public.tenant_saml_policy_change_requests
for each statement execute function app.reject_audit_truncate();

create function app.saml_policy_require_owner(p_tenant_id uuid, p_actor_user_id uuid)
returns void language plpgsql security definer set search_path = pg_catalog, public, pg_temp as $$
begin
  -- Auth user deletion locks this parent before cascading to memberships and
  -- identities. Follow that order so approval cannot hold a child it needs.
  perform 1 from auth.users u where u.id = p_actor_user_id for share;
  perform 1 from public.tenants t join public.tenant_members m on m.tenant_id = t.id
    where t.id = p_tenant_id and m.user_id = p_actor_user_id for share of t, m;
  -- Evaluate time-sensitive authority after any row-lock wait.
  if not exists (
    select 1 from public.tenants t join public.tenant_members m on m.tenant_id = t.id
    where t.id = p_tenant_id and t.status = 'active'
      and m.user_id = p_actor_user_id and m.role = 'owner'
      and (m.expires_at is null or m.expires_at > clock_timestamp())
  ) then raise exception 'saml_policy_owner_required' using errcode = '42501'; end if;
end;
$$;
revoke all on function app.saml_policy_require_owner(uuid,uuid) from public, anon, authenticated, service_role;

create function app.saml_policy_require_session(p_actor_user_id uuid, p_session jsonb, p_provider_id uuid)
returns void language plpgsql security definer set search_path = pg_catalog, public, auth, pg_temp as $$
declare
  v_session uuid;
  v_provider uuid;
  v_issued timestamptz;
  v_expires timestamptz;
begin
  if p_session->>'aal' is distinct from 'aal2' then
    raise exception 'saml_policy_aal2_required' using errcode = '42501';
  end if;
  begin
    v_session := (p_session->>'session_id')::uuid;
    v_provider := (p_session->>'saml_provider_id')::uuid;
    v_issued := (p_session->>'issued_at')::timestamptz;
    v_expires := (p_session->>'expires_at')::timestamptz;
  exception when others then
    raise exception 'saml_policy_session_invalid' using errcode = '42501';
  end;
  if v_session is null or v_issued is null or v_expires is null
     or v_issued <= to_timestamp(0) or v_issued > clock_timestamp() + interval '1 minute'
     or v_expires <= v_issued then
    raise exception 'saml_policy_session_invalid' using errcode = '42501';
  end if;
  if p_provider_id is null or v_provider is distinct from p_provider_id then
    raise exception 'saml_policy_provider_session_required' using errcode = '42501';
  end if;
  -- These claims came from auth.getUser-validated JWTs, not request JSON.
  -- Callers hold the corresponding user 2611 lock before checking barriers.
  perform 1 from auth.sessions s where s.id = v_session and s.user_id = p_actor_user_id for share;
  if v_expires <= clock_timestamp() or not exists (
    select 1 from auth.sessions s where s.id = v_session and s.user_id = p_actor_user_id
      and s.aal = 'aal2' and (s.not_after is null or s.not_after > clock_timestamp())
  ) then raise exception 'saml_policy_session_invalid' using errcode = '42501'; end if;
  if exists (select 1 from public.identity_user_session_state s
    where s.user_id = p_actor_user_id and (s.global_revoke_pending_session_id is not null
      or (s.revoked_before is not null and v_issued <= s.revoked_before))) then
    raise exception 'saml_policy_session_revoked' using errcode = '42501';
  end if;
end;
$$;
revoke all on function app.saml_policy_require_session(uuid,jsonb,uuid) from public, anon, authenticated, service_role;

create function app.saml_policy_require_target(p_tenant_id uuid, p_provider_id uuid)
returns void language plpgsql security definer set search_path = pg_catalog, public, auth, pg_temp as $$
declare v_owner_count integer;
begin
  -- GoTrue v2.196.0's registration source, also used by signInWithSSO.
  -- disabled=NULL is enabled. Auth, not a caller-supplied allow-list, owns it.
  perform 1 from auth.sso_providers p join auth.saml_providers s on s.sso_provider_id = p.id
    where p.id = p_provider_id for share of p, s;
  if not exists (select 1 from auth.sso_providers p
    join auth.saml_providers s on s.sso_provider_id = p.id
    where p.id = p_provider_id and not coalesce(p.disabled, false))
    or exists (select 1 from public.tenant_identity_policies p
      where p.tenant_id <> p_tenant_id and p.required_saml_provider_id = p_provider_id) then
    raise exception 'saml_policy_provider_unavailable' using errcode = '42501';
  end if;
  -- Row locks protect owner demotion without taking 2612 before the rows:
  -- owner UPDATE triggers already own their row before requesting that lock.
  perform 1 from auth.users u join public.tenant_members m on m.user_id = u.id
    where m.tenant_id = p_tenant_id and m.role = 'owner'
    order by u.id for share of u;
  perform 1 from public.tenant_members m where m.tenant_id = p_tenant_id and m.role = 'owner'
    order by m.user_id for share;
  perform 1 from auth.identities i join public.tenant_members m on m.user_id = i.user_id
    where m.tenant_id = p_tenant_id and m.role = 'owner'
      and (m.expires_at is null or m.expires_at > clock_timestamp())
      and i.provider = 'sso:' || p_provider_id::text
    order by m.user_id, i.id for share of i;
  select count(*) into v_owner_count from public.tenant_members m
    where m.tenant_id = p_tenant_id and m.role = 'owner'
      and (m.expires_at is null or m.expires_at > clock_timestamp());
  if v_owner_count < 2 or exists (
    select 1 from public.tenant_members m
    where m.tenant_id = p_tenant_id and m.role = 'owner'
      and (m.expires_at is null or m.expires_at > clock_timestamp())
      and ((select count(*) from auth.identities i where i.user_id = m.user_id
        and i.provider = 'sso:' || p_provider_id::text and i.provider_id <> ''
        and i.identity_data->>'sub' = i.provider_id and position('@' in i.provider_id) = 0) <> 1
        or exists (select 1 from public.scim_managed_memberships sm
          where sm.tenant_id = p_tenant_id and sm.auth_user_id = m.user_id))
  ) then raise exception 'saml_policy_owners_not_verified' using errcode = '42501'; end if;
  if exists (select 1 from public.scim_users su where su.tenant_id = p_tenant_id
    and su.auth_user_id is not null and not exists (
      select 1 from auth.identities i where i.user_id = su.auth_user_id
        and i.provider = 'sso:' || p_provider_id::text and i.provider_id = su.external_id
        and i.identity_data->>'sub' = i.provider_id and position('@' in i.provider_id) = 0
    )) then raise exception 'saml_policy_scim_identity_conflict' using errcode = '23505'; end if;
end;
$$;
revoke all on function app.saml_policy_require_target(uuid,uuid) from public, anon, authenticated, service_role;

-- Owner insertion/promotion must not slip past activation's existing-owner
-- snapshot. Role updates already own their row (including the legacy mirror's
-- upsert), so never wait on 2607 here: reject a concurrent change for retry.
create function app.saml_policy_guard_owner_write()
returns trigger language plpgsql security definer set search_path = pg_catalog, public, auth, pg_temp as $$
declare v_provider uuid;
begin
  if new.role is distinct from 'owner' then return new; end if;
  if not pg_try_advisory_xact_lock(hashtextextended(new.tenant_id::text, 2607)) then
    raise exception 'saml_policy_policy_conflict' using errcode = '23505';
  end if;
  select required_saml_provider_id into v_provider from public.tenant_identity_policies
    where tenant_id = new.tenant_id;
  if v_provider is not null and (
    (select count(*) from auth.identities i where i.user_id = new.user_id
      and i.provider = 'sso:' || v_provider::text and i.provider_id <> ''
      and i.identity_data->>'sub' = i.provider_id and position('@' in i.provider_id) = 0) <> 1
    or exists (select 1 from public.scim_managed_memberships sm
      where sm.tenant_id = new.tenant_id and sm.auth_user_id = new.user_id)
  ) then raise exception 'saml_policy_owners_not_verified' using errcode = '42501'; end if;
  return new;
end;
$$;
revoke all on function app.saml_policy_guard_owner_write() from public, anon, authenticated, service_role;
create trigger tenant_saml_policy_owner_guard
before insert or update on public.tenant_members
for each row execute function app.saml_policy_guard_owner_write();

create function app.saml_policy_request_json(p_row public.tenant_saml_policy_change_requests)
returns jsonb language sql immutable set search_path = pg_catalog, public, pg_temp as $$
  select jsonb_build_object('request_id', p_row.id, 'tenant_id', p_row.tenant_id,
    'requested_by', p_row.requested_by, 'old_provider_id', p_row.old_provider_id,
    'new_provider_id', p_row.new_provider_id, 'reason', p_row.reason,
    'change_ref', p_row.change_ref, 'created_at', p_row.created_at,
    'expires_at', p_row.expires_at, 'approved_by', p_row.approved_by,
    'approved_at', p_row.approved_at);
$$;
revoke all on function app.saml_policy_request_json(public.tenant_saml_policy_change_requests)
  from public, anon, authenticated, service_role;

create function public.request_tenant_saml_policy_change(
  p_tenant_id uuid, p_actor_user_id uuid, p_new_provider_id uuid,
  p_reason text, p_change_ref text, p_validated_session jsonb
)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public, auth, app, pg_temp as $$
declare
  v_policy public.tenant_identity_policies;
  v_row public.tenant_saml_policy_change_requests;
  v_provider uuid;
  v_now timestamptz;
  v_expires timestamptz;
  v_audit bigint;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_reason is null or p_change_ref is null
     or p_reason <> btrim(p_reason) or p_change_ref <> btrim(p_change_ref)
     or char_length(p_reason) not between 12 and 500 or char_length(p_change_ref) not between 1 and 200
     or p_reason ~ '[[:cntrl:]]' or p_change_ref ~ '[[:cntrl:]]'
     or jsonb_typeof(p_validated_session) is distinct from 'object' then
    raise exception 'saml_policy_invalid_request' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2607));
  perform pg_advisory_xact_lock(hashtextextended(p_actor_user_id::text, 2611));
  perform app.saml_policy_require_owner(p_tenant_id, p_actor_user_id);
  select * into v_policy from public.tenant_identity_policies where tenant_id = p_tenant_id;
  if v_policy.required_oidc_provider_id is not null then
    raise exception 'saml_policy_policy_conflict' using errcode = '23505';
  end if;
  if (v_policy.required_saml_provider_id is null) = (p_new_provider_id is null) then
    raise exception 'saml_policy_unsupported_transition' using errcode = '22023';
  end if;
  v_provider := coalesce(p_new_provider_id, v_policy.required_saml_provider_id);
  perform app.saml_policy_require_session(p_actor_user_id, p_validated_session, v_provider);
  if p_new_provider_id is not null then perform app.saml_policy_require_target(p_tenant_id, p_new_provider_id); end if;
  if (select count(*) from public.tenant_saml_policy_change_requests
      where tenant_id = p_tenant_id and approved_at is null and expires_at > clock_timestamp()) >= 10 then
    raise exception 'saml_policy_request_pending_limit' using errcode = '54000';
  end if;
  -- Target/authority lock waits must not turn an expired proof into a request.
  perform app.saml_policy_require_session(p_actor_user_id, p_validated_session, v_provider);
  v_now := clock_timestamp();
  v_expires := least(v_now + interval '5 minutes', (p_validated_session->>'expires_at')::timestamptz);
  if v_expires <= v_now then raise exception 'saml_policy_session_invalid' using errcode = '42501'; end if;
  v_row.id := gen_random_uuid();
  insert into public.admin_audit_logs(actor_user_id,tenant_id,action,detail)
    values(p_actor_user_id,p_tenant_id,'identity.saml.policy_change_requested',jsonb_build_object(
      'request_id',v_row.id,'old_provider_id',v_policy.required_saml_provider_id,'new_provider_id',p_new_provider_id,
      'requester_session_id',p_validated_session->>'session_id','reason',p_reason,
      'change_ref',p_change_ref,'expires_at',v_expires)) returning id into v_audit;
  insert into public.tenant_saml_policy_change_requests(id,tenant_id,audit_log_id,requested_by,validated_session,
    old_provider_id,new_provider_id,expected_oidc_provider_id,reason,change_ref,created_at,expires_at)
    values(v_row.id,p_tenant_id,v_audit,p_actor_user_id,p_validated_session,v_policy.required_saml_provider_id,
      p_new_provider_id,v_policy.required_oidc_provider_id,p_reason,p_change_ref,v_now,v_expires) returning * into v_row;
  return app.saml_policy_request_json(v_row);
end;
$$;
revoke all on function public.request_tenant_saml_policy_change(uuid,uuid,uuid,text,text,jsonb) from public, anon, authenticated;
grant execute on function public.request_tenant_saml_policy_change(uuid,uuid,uuid,text,text,jsonb) to service_role;

create function public.get_tenant_saml_policy_change(p_tenant_id uuid, p_actor_user_id uuid, p_request_id uuid)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public, app, pg_temp as $$
declare v_row public.tenant_saml_policy_change_requests;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_request_id is null then
    raise exception 'saml_policy_invalid_request' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));
  perform app.saml_policy_require_owner(p_tenant_id,p_actor_user_id);
  select * into v_row from public.tenant_saml_policy_change_requests
    where id = p_request_id and tenant_id = p_tenant_id;
  if not found then raise exception 'saml_policy_request_not_found' using errcode = 'P0002'; end if;
  return app.saml_policy_request_json(v_row);
end;
$$;
revoke all on function public.get_tenant_saml_policy_change(uuid,uuid,uuid) from public, anon, authenticated;
grant execute on function public.get_tenant_saml_policy_change(uuid,uuid,uuid) to service_role;

create function public.approve_tenant_saml_policy_change(
  p_tenant_id uuid, p_actor_user_id uuid, p_request_id uuid, p_validated_session jsonb
)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public, auth, app, pg_temp as $$
declare
  v_row public.tenant_saml_policy_change_requests;
  v_policy public.tenant_identity_policies;
  v_provider uuid;
  v_user uuid;
  v_applied timestamptz;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_request_id is null
     or jsonb_typeof(p_validated_session) is distinct from 'object' then
    raise exception 'saml_policy_invalid_request' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2607));
  select * into v_row from public.tenant_saml_policy_change_requests where id = p_request_id and tenant_id = p_tenant_id;
  if not found then raise exception 'saml_policy_request_not_found' using errcode = 'P0002'; end if;
  if v_row.requested_by = p_actor_user_id then
    raise exception 'saml_policy_distinct_owner_required' using errcode = '42501';
  end if;
  for v_user in select user_id from (values(v_row.requested_by),(p_actor_user_id)) u(user_id) order by user_id loop
    perform pg_advisory_xact_lock(hashtextextended(v_user::text, 2611));
  end loop;
  perform app.saml_policy_require_owner(p_tenant_id,v_row.requested_by);
  perform app.saml_policy_require_owner(p_tenant_id,p_actor_user_id);
  select * into v_row from public.tenant_saml_policy_change_requests
    where id = p_request_id and tenant_id = p_tenant_id for update;
  if v_row.approved_at is not null then raise exception 'saml_policy_request_consumed' using errcode = '23505'; end if;
  if v_row.expires_at <= clock_timestamp() then raise exception 'saml_policy_request_expired' using errcode = '42501'; end if;
  select * into v_policy from public.tenant_identity_policies where tenant_id = p_tenant_id for update;
  if v_policy.required_saml_provider_id is distinct from v_row.old_provider_id
     or v_policy.required_oidc_provider_id is distinct from v_row.expected_oidc_provider_id
     or v_policy.required_oidc_provider_id is not null then
    raise exception 'saml_policy_policy_conflict' using errcode = '23505';
  end if;
  v_provider := coalesce(v_row.new_provider_id,v_row.old_provider_id);
  perform app.saml_policy_require_session(v_row.requested_by,v_row.validated_session,v_provider);
  perform app.saml_policy_require_session(p_actor_user_id,p_validated_session,v_provider);
  if v_row.new_provider_id is not null then perform app.saml_policy_require_target(p_tenant_id,v_row.new_provider_id); end if;
  -- Recheck deadlines after target/owner/Auth row locks, immediately before mutation.
  perform app.saml_policy_require_owner(p_tenant_id,v_row.requested_by);
  perform app.saml_policy_require_owner(p_tenant_id,p_actor_user_id);
  perform app.saml_policy_require_session(v_row.requested_by,v_row.validated_session,v_provider);
  perform app.saml_policy_require_session(p_actor_user_id,p_validated_session,v_provider);
  v_applied := clock_timestamp();
  if v_row.expires_at <= v_applied then raise exception 'saml_policy_request_expired' using errcode = '42501'; end if;
  insert into public.tenant_identity_policies(tenant_id,required_saml_provider_id,updated_by)
    values(p_tenant_id,v_row.new_provider_id,p_actor_user_id)
    on conflict(tenant_id) do update set required_saml_provider_id = excluded.required_saml_provider_id,
      updated_by = p_actor_user_id;
  v_applied := clock_timestamp();
  if v_row.expires_at <= v_applied then raise exception 'saml_policy_request_expired' using errcode = '42501'; end if;
  update public.tenant_saml_policy_change_requests set approved_by = p_actor_user_id,approved_at = v_applied
    where id = p_request_id returning * into v_row;
  insert into public.admin_audit_logs(actor_user_id,tenant_id,action,detail)
    values(p_actor_user_id,p_tenant_id,'identity.saml.policy_change_applied',jsonb_build_object(
      'request_id',v_row.id,'requested_by',v_row.requested_by,'approved_by',p_actor_user_id,
      'requester_session_id',v_row.validated_session->>'session_id','approver_session_id',p_validated_session->>'session_id',
      'old_provider_id',v_row.old_provider_id,'new_provider_id',v_row.new_provider_id,
      'reason',v_row.reason,'change_ref',v_row.change_ref));
  return app.saml_policy_request_json(v_row);
end;
$$;
revoke all on function public.approve_tenant_saml_policy_change(uuid,uuid,uuid,jsonb) from public, anon, authenticated;
grant execute on function public.approve_tenant_saml_policy_change(uuid,uuid,uuid,jsonb) to service_role;
