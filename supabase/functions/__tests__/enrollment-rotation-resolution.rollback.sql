-- Run only on an isolated, fully migrated PostgreSQL fixture. No rows survive.
\set ON_ERROR_STOP on
begin;
update app.tenant_admission_config set mode = 'pilot' where singleton;

do $checks$
declare
  u uuid := gen_random_uuid();
  survivor uuid := gen_random_uuid();
  old_hash text;
  new_hash text;
  v_key_hash text;
  v_replacement_key_hash text;
  v_agent_id uuid;
  v_old_key_id uuid;
  result jsonb;
begin
  old_hash := encode(digest(u::text || ':old', 'sha256'), 'hex');
  new_hash := encode(digest(u::text || ':new', 'sha256'), 'hex');
  v_key_hash := encode(digest(u::text || ':key', 'sha256'), 'hex');
  insert into auth.users(id, email) values (u, 'enroll-rotation-' || u || '@test.invalid');
  insert into public.pilot_applications(user_id, tenant_id, status)
    values (u, u, 'approved');
  insert into public.enrollment_tokens
    (user_id, tenant_id, token_hash, previous_hash, rotated_at,
     previous_hash_expires_at, expires_at)
    values (u, u, new_hash, old_hash, now(), now() + interval '15 minutes',
            now() + interval '1 hour');

  if public.resolve_enrollment_token(old_hash)->>'tenant_id' is distinct from u::text
     or public.resolve_enrollment_token(new_hash)->>'tenant_id' is distinct from u::text then
    raise exception 'active and bounded retired hash must resolve to same tenant';
  end if;
  update public.enrollment_tokens
     set rotated_at = now() - interval '2 minutes',
         previous_hash_expires_at = now() - interval '1 second'
   where token_hash = new_hash;
  if public.resolve_enrollment_token(old_hash) is not null
     or public.resolve_enrollment_token(new_hash)->>'tenant_id' is distinct from u::text then
    raise exception 'retired hash survived overlap expiry or active hash disappeared';
  end if;
  update public.enrollment_tokens
     set rotated_at = now(), previous_hash_expires_at = now() + interval '15 minutes'
   where token_hash = new_hash;
  update public.tenants set status = 'suspended' where id = u;
  if public.resolve_enrollment_token(old_hash) is not null then
    raise exception 'retired hash resolved for suspended tenant';
  end if;
  update public.tenants set status = 'active' where id = u;
  -- The membership-loss probe must not remove the active tenant's sole owner.
  insert into auth.users(id, email)
    values (survivor, 'enroll-rotation-owner-' || survivor || '@test.invalid');
  insert into public.tenant_members(tenant_id, user_id, role)
    values (u, survivor, 'owner');
  update public.tenant_members set expires_at = now() - interval '1 second'
   where tenant_id = u and user_id = u;
  if public.resolve_enrollment_token(old_hash) is not null then
    raise exception 'retired hash resolved after membership expiry';
  end if;
  update public.tenant_members set expires_at = null
   where tenant_id = u and user_id = u;
  if public.resolve_enrollment_token(old_hash) is not null
     or public.resolve_enrollment_token(new_hash) is not null
     or (public.exchange_enrollment_token(old_hash, 'revived', null, null, v_key_hash))->>'status' <> 'invalid_token' then
    raise exception 'removed member revived pre-removal enrollment token';
  end if;

  -- Membership restoration permits a new token, never the revoked old one.
  old_hash := encode(digest(u::text || ':fresh-old', 'sha256'), 'hex');
  new_hash := encode(digest(u::text || ':fresh-new', 'sha256'), 'hex');
  insert into public.enrollment_tokens
    (user_id, tenant_id, token_hash, previous_hash, rotated_at,
     previous_hash_expires_at, expires_at)
    values (u, u, new_hash, old_hash, now(), now() + interval '15 minutes',
            now() + interval '1 hour');

  result := public.exchange_enrollment_token(old_hash, 'rotation-test', 'test', '1', v_key_hash);
  if result->>'status' <> 'enrolled' then
    raise exception 'bounded retired hash did not exchange atomically: %', result;
  end if;
  if public.resolve_enrollment_token(old_hash) is not null
     or public.resolve_enrollment_token(new_hash) is not null
     or (public.exchange_enrollment_token(new_hash, 'replay', null, null,
          encode(digest(u::text || ':replay', 'sha256'), 'hex')))->>'status' <> 'invalid_token'
     or (select count(*) from public.api_keys where tenant_id = u and key_hash = v_key_hash) <> 1 then
    raise exception 'consumed rotation token replayed or exchange did not commit key';
  end if;

  -- An unknown committed enrollment is repaired by operator revocation and a
  -- newly authorized token, keeping the original installation identity.
  v_agent_id := (result->>'agent_id')::uuid;
  select id into strict v_old_key_id from public.api_keys
    where tenant_id = u and key_hash = v_key_hash;
  result := public.revoke_api_key_with_audit(u, u, v_old_key_id);
  if result->>'status' is distinct from 'revoked'
     or not exists (select 1 from public.api_keys
                    where id = v_old_key_id and revoked)
     or (select count(*) from public.admin_audit_logs
          where tenant_id = u and action = 'api_key.revoke'
            and detail->>'id' = v_old_key_id::text) <> 1 then
    raise exception 'operator did not revoke the committed enrollment key: %', result;
  end if;
  old_hash := encode(digest(u::text || ':operator-repair-token', 'sha256'), 'hex');
  v_replacement_key_hash := encode(digest(u::text || ':operator-repair-key', 'sha256'), 'hex');
  result := public.issue_enrollment_token_with_audit(u, u, 'operator-repair', 1, old_hash);
  if result->>'status' is distinct from 'issued'
     or public.resolve_enrollment_token(old_hash)->>'tenant_id' is distinct from u::text then
    raise exception 'operator repair token was not authorized: %', result;
  end if;
  result := public.exchange_enrollment_token(old_hash, 'rotation-test', 'test', '2', v_replacement_key_hash);
  if result->>'status' is distinct from 'enrolled'
     or result->>'agent_id' is distinct from v_agent_id::text
     or (select count(*) from public.agents where tenant_id = u) <> 1
     or (select count(*) from public.api_keys where tenant_id = u) <> 2
     or (select count(*) from public.api_keys where tenant_id = u and not revoked) <> 1
     or not exists (select 1 from public.api_keys
                    where tenant_id = u and key_hash = v_replacement_key_hash
                      and agent_id = v_agent_id and not revoked)
     or not exists (select 1 from public.api_keys where id = v_old_key_id and revoked) then
    raise exception 'operator repair changed device cardinality or revived the old key: %', result;
  end if;
  if public.resolve_enrollment_token(old_hash) is not null
     or (public.exchange_enrollment_token(old_hash, 'repair-replay', null, null,
          encode(digest(u::text || ':repair-replay', 'sha256'), 'hex')))->>'status' is distinct from 'invalid_token'
     or (select count(*) from public.agents where tenant_id = u) <> 1
     or (select count(*) from public.api_keys where tenant_id = u) <> 2
     or (select count(*) from public.api_keys where tenant_id = u and not revoked) <> 1 then
    raise exception 'operator repair token replay created a device or key';
  end if;
  perform set_config('aidr.fixture.rotation_tenant', u::text, true);
  raise notice 'ENROLLMENT_ROTATION_RESOLUTION_OK';
end;
$checks$;

select set_config('request.jwt.claim.sub', current_setting('aidr.fixture.rotation_tenant'), true);
select set_config('request.jwt.claim.role', 'authenticated', true);
set local role authenticated;
do $seat_check$
begin
  if (select current_agents from public.seat_usage
       where tenant_id = current_setting('aidr.fixture.rotation_tenant')::uuid) is distinct from 1 then
    raise exception 'operator repair consumed more than one browser-visible seat';
  end if;
  raise notice 'ENROLLMENT_OPERATOR_REPAIR_ONE_SEAT_OK';
end;
$seat_check$;
reset role;
rollback;
