-- Bind every password reset to a short-lived, one-time server-side grant.
-- GoTrue v2.196.0 records recovery verification as AMR `otp`, so possession
-- of a matching grant and verified session is the recovery-specific proof.

alter table public.identity_password_recovery_grants
  alter column tenant_id drop not null,
  add column session_id uuid,
  add column bound_at timestamptz;

alter table public.identity_password_recovery_grants
  drop constraint if exists identity_password_recovery_grants_source_check;
alter table public.identity_password_recovery_grants
  add constraint identity_password_recovery_grants_source_check
  check (source in ('email', 'break_glass'));
alter table public.identity_password_recovery_grants
  add constraint identity_password_recovery_grants_session_binding_check
  check ((session_id is null) = (bound_at is null));

create or replace function public.issue_identity_password_recovery_grant(
  p_email text,
  p_grant_id uuid,
  p_expires_at timestamptz
)
returns boolean
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $$
declare v_user_id uuid;
begin
  if p_grant_id is null or p_expires_at <= now() or p_expires_at > now() + interval '15 minutes'
  then raise exception 'invalid_recovery_grant' using errcode = '22023'; end if;
  if p_email is null or length(p_email) > 254 then return false; end if;
  select id into v_user_id
    from auth.users
    where lower(email) = lower(trim(p_email))
    order by created_at
    limit 1;
  if v_user_id is null then return false; end if;
  insert into public.identity_password_recovery_grants(
    id, tenant_id, user_id, source, expires_at
  ) values (
    p_grant_id, null, v_user_id, 'email', p_expires_at
  );
  return true;
end;
$$;
revoke all on function public.issue_identity_password_recovery_grant(text, uuid, timestamptz)
  from public, anon, authenticated;
grant execute on function public.issue_identity_password_recovery_grant(text, uuid, timestamptz)
  to service_role;

create or replace function public.bind_identity_password_recovery_grant(
  p_grant_id uuid,
  p_user_id uuid,
  p_session_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare v_bound_id uuid;
begin
  if p_grant_id is null or p_user_id is null or p_session_id is null then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_grant_id::text, 2607));
  update public.identity_password_recovery_grants
    set session_id = p_session_id, bound_at = coalesce(bound_at, now())
    where id = p_grant_id
      and user_id = p_user_id
      and used_at is null
      and expires_at > now()
      and (session_id is null or session_id = p_session_id)
    returning id into v_bound_id;
  return v_bound_id is not null;
end;
$$;
revoke all on function public.bind_identity_password_recovery_grant(uuid, uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.bind_identity_password_recovery_grant(uuid, uuid, uuid)
  to service_role;

drop function if exists public.consume_identity_password_recovery_grant(uuid, uuid);
create function public.consume_identity_password_recovery_grant(
  p_grant_id uuid,
  p_user_id uuid,
  p_session_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare v_grant public.identity_password_recovery_grants;
begin
  if p_grant_id is null or p_user_id is null or p_session_id is null then return null; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_grant_id::text, 2607));
  update public.identity_password_recovery_grants
    set used_at = now()
    where id = p_grant_id
      and user_id = p_user_id
      and session_id = p_session_id
      and bound_at is not null
      and used_at is null
      and expires_at > now()
    returning * into v_grant;
  if v_grant.id is null then return null; end if;
  return jsonb_build_object('source', v_grant.source, 'tenant_id', v_grant.tenant_id);
end;
$$;
revoke all on function public.consume_identity_password_recovery_grant(uuid, uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.consume_identity_password_recovery_grant(uuid, uuid, uuid)
  to service_role;
