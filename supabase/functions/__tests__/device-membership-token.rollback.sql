-- Run against an isolated fully migrated database. Every fixture is rolled back.
begin;
do $checks$
declare
  v_owner uuid := gen_random_uuid();
  v_member uuid := gen_random_uuid();
  v_tenant uuid := gen_random_uuid();
  v_device_hash text := encode(gen_random_bytes(32), 'hex');
  v_pending_hash text := encode(gen_random_bytes(32), 'hex');
  v_token_hash text := encode(gen_random_bytes(32), 'hex');
  v_result jsonb;
begin
  insert into auth.users(id, email)
  values (v_owner, 'device-owner-' || v_owner || '@test.invalid'),
         (v_member, 'device-member-' || v_member || '@test.invalid');
  update app.tenant_admission_config set mode = 'pilot' where singleton;
  insert into public.tenants(id, name, kind, created_by)
  values (v_tenant, 'Device member test', 'team', v_owner);
  insert into public.teams(id, tenant_id, name, plan)
  values (v_tenant, v_tenant, 'Device member test', 'free');
  insert into public.tenant_members(tenant_id, user_id, role)
  values (v_tenant, v_owner, 'owner'), (v_tenant, v_member, 'member');
  insert into public.entitlements(user_id, tenant_id, included_agents, extra_agents)
  values (v_owner, v_tenant, 2, 0);
  insert into public.pilot_applications(user_id, tenant_id, status)
  values (v_owner, v_tenant, 'approved');
  insert into public.device_sessions
    (device_code_hash, user_code, status, user_id, tenant_id, authorized_at, expires_at)
  values (v_device_hash, 'A' || upper(left(replace(v_device_hash, '-', ''), 12)),
            'authorized', v_member, v_tenant, now(), now() + interval '10 minutes'),
         (v_pending_hash, 'B' || upper(left(replace(v_pending_hash, '-', ''), 12)),
            'authorized', v_member, v_tenant, now(), now() + interval '10 minutes');

  v_result := public.issue_device_enrollment_token(
    v_device_hash, v_token_hash, now() + interval '1 hour');
  if v_result ->> 'status' <> 'issued' then
    raise exception 'initial device issue failed: %', v_result;
  end if;
  delete from public.tenant_members
   where tenant_id = v_tenant and user_id = v_member;
  if exists (select 1 from public.enrollment_tokens
              where token_hash = v_token_hash and expires_at > clock_timestamp())
     or exists (select 1 from public.device_sessions
                 where device_code_hash = v_pending_hash
                   and expires_at > clock_timestamp()) then
    raise exception 'removed member retained a live token or approved device code';
  end if;

  begin
    insert into public.enrollment_tokens
      (user_id, tenant_id, token_hash, expires_at)
    values (v_member, v_tenant, encode(gen_random_bytes(32), 'hex'),
      now() + interval '1 hour');
    raise exception 'removed member issued an enrollment token';
  exception when insufficient_privilege then null;
  end;

  insert into public.tenant_members(tenant_id, user_id, role)
  values (v_tenant, v_member, 'member');
  v_result := public.issue_device_enrollment_token(
    v_pending_hash, encode(gen_random_bytes(32), 'hex'),
    now() + interval '1 hour');
  if v_result ->> 'status' <> 'already_exchanged_or_invalid' then
    raise exception 'old device code revived after rejoin: %', v_result;
  end if;
  if public.resolve_enrollment_token(v_token_hash) is not null then
    raise exception 'expired token revived after rejoin';
  end if;
  raise notice 'DEVICE_MEMBERSHIP_TOKEN_ROLLBACK_OK';
end;
$checks$;
rollback;
