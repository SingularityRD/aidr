-- Run after applying 20260912000017_enrollment_exchange_atomic.sql in a
-- transaction that is rolled back. This uses a throwaway Auth user and all
-- assertions are rolled back with that user.
do $checks$
declare
  u uuid := gen_random_uuid();
  th1 text;
  th2 text;
  th3 text;
  kh1 text;
  kh2 text;
  dh1 text;
  dh2 text;
  result jsonb;
  code1 text;
  code2 text;
begin
  th1 := encode(digest(u::text || ':token1','sha256'),'hex');
  th2 := encode(digest(u::text || ':token2','sha256'),'hex');
  th3 := encode(digest(u::text || ':token3','sha256'),'hex');
  kh1 := encode(digest(u::text || ':key1','sha256'),'hex');
  kh2 := encode(digest(u::text || ':key2','sha256'),'hex');
  dh1 := encode(digest(u::text || ':device1','sha256'),'hex');
  dh2 := encode(digest(u::text || ':device2','sha256'),'hex');
  code1 := 'D' || upper(substr(replace(u::text,'-',''),1,12));
  code2 := 'E' || upper(substr(replace(u::text,'-',''),1,12));

  insert into auth.users(id,email) values(u,'enrollment-atomic-' || u || '@test.invalid');
  update public.entitlements set included_agents=2 where tenant_id=u;
  insert into public.enrollment_tokens(user_id,tenant_id,token_hash,expires_at)
  values(u,u,th1,now()+interval '1 hour'),
        (u,u,th2,now()+interval '1 hour'),
        (u,u,th3,now()+interval '1 hour');

  update public.tenants set status='suspended' where id=u;
  result := public.exchange_enrollment_token(th1,'iid-1','test','1',kh1);
  if result->>'status' <> 'tenant_not_authorized' or
     exists(select 1 from public.enrollment_tokens where token_hash=th1 and consumed_at is not null) then
    raise exception 'suspended tenant consumed enrollment token: %', result;
  end if;
  update public.tenants set status='active' where id=u;

  result := public.exchange_enrollment_token(th1,'iid-1','test','1',kh1);
  if result->>'status' <> 'enrolled' then raise exception 'first exchange failed: %',result; end if;
  if (public.exchange_enrollment_token(th1,'iid-replay',null,null,kh2))->>'status' <> 'invalid_token' then
    raise exception 'consumed token replay succeeded';
  end if;

  begin
    perform public.exchange_enrollment_token(th2,'iid-2',null,null,kh1);
    raise exception 'duplicate key hash unexpectedly accepted';
  exception when unique_violation then null;
  end;
  if exists(select 1 from public.agents where tenant_id=u and iid='iid-2') or
     exists(select 1 from public.enrollment_tokens where token_hash=th2 and consumed_at is not null) then
    raise exception 'failed key insert burned seat or token';
  end if;
  result := public.exchange_enrollment_token(th2,'iid-2',null,null,kh2);
  if result->>'status' <> 'enrolled' then raise exception 'retry after rollback failed: %',result; end if;
  result := public.exchange_enrollment_token(
    th3,'iid-3',null,null,encode(digest(u::text || ':key3','sha256'),'hex')
  );
  if result->>'status' <> 'seat_exceeded' then raise exception 'seat limit not enforced: %',result; end if;
  if exists(select 1 from public.enrollment_tokens where token_hash=th3 and consumed_at is not null) then
    raise exception 'seat failure consumed token';
  end if;

  insert into public.pilot_applications(user_id,tenant_id,status) values(u,u,'approved');
  insert into public.device_sessions(device_code_hash,user_code,user_id,tenant_id,authorized_at,expires_at,status)
  values(dh1,code1,u,u,now(),now()+interval '10 minutes','authorized'),
        (dh2,code2,u,u,now(),now()+interval '10 minutes','authorized');
  result := public.issue_device_enrollment_token(
    dh1,encode(digest(u::text || ':device-token','sha256'),'hex'),now()+interval '24 hours'
  );
  if result->>'status' <> 'issued' then raise exception 'device token issue failed: %',result; end if;
  if (public.issue_device_enrollment_token(
    dh1,encode(digest(u::text || ':device-token2','sha256'),'hex'),now()+interval '24 hours'
  ))->>'status' <> 'already_exchanged_or_invalid' then
    raise exception 'device replay succeeded';
  end if;
  update public.pilot_applications set status='pending' where user_id=u;
  result := public.issue_device_enrollment_token(
    dh2,encode(digest(u::text || ':device-token2','sha256'),'hex'),now()+interval '24 hours'
  );
  if result->>'status' <> 'pilot_not_approved' or
     exists(select 1 from public.device_sessions where device_code_hash=dh2 and exchanged_at is not null) then
    raise exception 'unapproved pilot consumed device session: %', result;
  end if;
  update public.pilot_applications set status='approved' where user_id=u;
  begin
    perform public.issue_device_enrollment_token(
      dh2,encode(digest(u::text || ':device-token','sha256'),'hex'),now()+interval '24 hours'
    );
    raise exception 'duplicate device token hash unexpectedly accepted';
  exception when unique_violation then null;
  end;
  if exists(select 1 from public.device_sessions where device_code_hash=dh2 and exchanged_at is not null) then
    raise exception 'device insert failure consumed session';
  end if;
  raise notice 'ENROLLMENT_ATOMICITY_OK user=%',u;
end;
$checks$;
