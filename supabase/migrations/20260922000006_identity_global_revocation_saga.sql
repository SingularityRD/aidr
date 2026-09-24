-- Retryable global sign-out without granting completed access tokens a replay
-- path. A pending operation is bound to the Auth session that began it; normal
-- tenant access remains fail-closed until Auth revocation and the final barrier
-- both complete.

alter table public.identity_user_session_state
  add column global_revoke_pending_session_id uuid,
  add column global_revoke_pending_at timestamptz,
  add constraint identity_user_session_state_global_revoke_pending_pair
    check (
      (global_revoke_pending_session_id is null and global_revoke_pending_at is null)
      or
      (global_revoke_pending_session_id is not null and global_revoke_pending_at is not null)
    );

-- A pending revoke denies every access token, including one minted after the
-- pre-Auth barrier. Completion publishes a final barrier before clearing the
-- pending marker in the same transaction.
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
        and (
          s.global_revoke_pending_session_id is not null
          or (
            s.revoked_before is not null
            and (
              coalesce(auth.jwt()->>'iat', '') !~ '^[0-9]+(\.[0-9]+)?$'
              or to_timestamp((auth.jwt()->>'iat')::double precision) <= s.revoked_before
            )
          )
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

create or replace function public.begin_identity_global_revocation(
  p_user_id uuid,
  p_actor_user_id uuid,
  p_session_id uuid,
  p_access_token_issued_at timestamptz
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_state public.identity_user_session_state%rowtype;
  v_barrier timestamptz;
  v_pending_at timestamptz;
begin
  if p_user_id is null
     or p_actor_user_id is null
     or p_user_id <> p_actor_user_id
     or p_session_id is null
     or p_access_token_issued_at is null
     or p_access_token_issued_at > clock_timestamp() + interval '5 minutes' then
    raise exception 'global_revoke_forbidden' using errcode = '42501';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 2611));
  select s.* into v_state
    from public.identity_user_session_state s
    where s.user_id = p_user_id
    for update;

  -- Only the session recorded by an unfinished operation may retry with an
  -- already-barred JWT. A different session must be newly issued after the
  -- prior barrier; this lets a legitimate fresh login take over a stuck op.
  if found
     and v_state.global_revoke_pending_session_id is distinct from p_session_id
     and v_state.revoked_before is not null
     and p_access_token_issued_at <= v_state.revoked_before then
    return false;
  end if;

  v_pending_at := case
    when found and v_state.global_revoke_pending_session_id = p_session_id
      then coalesce(v_state.global_revoke_pending_at, clock_timestamp())
    else clock_timestamp()
  end;
  v_barrier := public.mark_identity_session_revoked(
    p_user_id,
    null,
    p_actor_user_id,
    'user_global_signout'
  );
  update public.identity_user_session_state
    set global_revoke_pending_session_id = p_session_id,
        global_revoke_pending_at = v_pending_at
    where user_id = p_user_id and revoked_before = v_barrier;
  if not found then
    raise exception 'global_revoke_state_unavailable';
  end if;
  return true;
end;
$$;
revoke all on function public.begin_identity_global_revocation(uuid, uuid, uuid, timestamptz)
  from public, anon, authenticated;
grant execute on function public.begin_identity_global_revocation(uuid, uuid, uuid, timestamptz)
  to service_role;

create or replace function public.complete_identity_global_revocation(
  p_user_id uuid,
  p_actor_user_id uuid,
  p_session_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_pending_session_id uuid;
  v_barrier timestamptz;
begin
  if p_user_id is null
     or p_actor_user_id is null
     or p_user_id <> p_actor_user_id
     or p_session_id is null then
    raise exception 'global_revoke_forbidden' using errcode = '42501';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 2611));
  select s.global_revoke_pending_session_id into v_pending_session_id
    from public.identity_user_session_state s
    where s.user_id = p_user_id
    for update;
  if not found or v_pending_session_id is distinct from p_session_id then
    return false;
  end if;

  v_barrier := public.mark_identity_session_revoked(
    p_user_id,
    null,
    p_actor_user_id,
    'user_global_signout'
  );
  update public.identity_user_session_state
    set global_revoke_pending_session_id = null,
        global_revoke_pending_at = null
    where user_id = p_user_id
      and revoked_before = v_barrier
      and global_revoke_pending_session_id = p_session_id;
  if not found then
    raise exception 'global_revoke_state_unavailable';
  end if;
  return true;
end;
$$;
revoke all on function public.complete_identity_global_revocation(uuid, uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.complete_identity_global_revocation(uuid, uuid, uuid)
  to service_role;
