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
  raise notice 'ENROLLMENT_ROTATION_RESOLUTION_OK';
end;
$checks$;
rollback;
