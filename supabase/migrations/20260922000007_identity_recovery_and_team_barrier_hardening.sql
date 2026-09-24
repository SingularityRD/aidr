-- Bind password recovery to the exact GoTrue recovery event and a browser-held
-- proof. Generic OTP assurance is not recovery authorization: the verified
-- session must have been created by the current recovery event and must still
-- pass the user's committed global revocation barrier.

alter table public.identity_password_recovery_grants
  add column proof_challenge_hash text,
  add column auth_recovery_sent_at timestamptz;

-- Grants created before proof binding cannot be safely completed. Keep the
-- rows for audit evidence, but make them terminal before making proof required.
update public.identity_password_recovery_grants
set used_at = coalesce(used_at, clock_timestamp()),
    proof_challenge_hash = encode(extensions.digest('invalidated:' || id::text, 'sha256'), 'hex'),
    auth_recovery_sent_at = created_at
where proof_challenge_hash is null or auth_recovery_sent_at is null;

alter table public.identity_password_recovery_grants
  alter column proof_challenge_hash set not null,
  alter column auth_recovery_sent_at set not null,
  add constraint identity_password_recovery_grants_proof_hash_format
    check (proof_challenge_hash ~ '^[0-9a-f]{64}$');

create unique index identity_password_recovery_grants_proof_challenge
  on public.identity_password_recovery_grants(proof_challenge_hash);

drop function if exists public.issue_identity_password_recovery_grant(text, uuid, timestamptz);
create function public.issue_identity_password_recovery_grant(
  p_email text,
  p_grant_id uuid,
  p_expires_at timestamptz,
  p_proof_challenge_hash text,
  p_recovery_requested_after timestamptz
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, auth, pg_temp
as $$
declare
  v_user_id uuid;
  v_recovery_sent_at timestamptz;
begin
  if p_grant_id is null
     or p_expires_at <= clock_timestamp()
     or p_expires_at > clock_timestamp() + interval '15 minutes'
     or p_proof_challenge_hash !~ '^[0-9a-f]{64}$'
     or p_recovery_requested_after is null
     or p_recovery_requested_after > clock_timestamp() + interval '5 minutes'
     or p_email is null
     or length(p_email) > 254 then
    raise exception 'invalid_recovery_grant' using errcode = '22023';
  end if;

  select u.id, u.recovery_sent_at
    into v_user_id, v_recovery_sent_at
    from auth.users u
    where lower(u.email) = lower(trim(p_email))
      and nullif(u.recovery_token, '') is not null
      and u.recovery_sent_at >= p_recovery_requested_after
      and u.recovery_sent_at <= clock_timestamp() + interval '5 minutes'
    order by u.created_at
    limit 1;
  if v_user_id is null then return false; end if;

  insert into public.identity_password_recovery_grants(
    id, tenant_id, user_id, source, expires_at,
    proof_challenge_hash, auth_recovery_sent_at
  ) values (
    p_grant_id, null, v_user_id, 'email', p_expires_at,
    p_proof_challenge_hash, v_recovery_sent_at
  );
  return true;
end;
$$;
revoke all on function public.issue_identity_password_recovery_grant(
  text, uuid, timestamptz, text, timestamptz
) from public, anon, authenticated;
grant execute on function public.issue_identity_password_recovery_grant(
  text, uuid, timestamptz, text, timestamptz
) to service_role;

create function public.issue_identity_break_glass_password_recovery_grant(
  p_user_id uuid,
  p_tenant_id uuid,
  p_grant_id uuid,
  p_expires_at timestamptz,
  p_proof_challenge_hash text,
  p_recovery_requested_after timestamptz
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, auth, pg_temp
as $$
declare v_recovery_sent_at timestamptz;
begin
  if p_user_id is null
     or p_tenant_id is null
     or p_grant_id is null
     or p_expires_at <= clock_timestamp()
     or p_expires_at > clock_timestamp() + interval '15 minutes'
     or p_proof_challenge_hash !~ '^[0-9a-f]{64}$'
     or p_recovery_requested_after is null
     or p_recovery_requested_after > clock_timestamp() + interval '5 minutes' then
    raise exception 'invalid_recovery_grant' using errcode = '22023';
  end if;

  select u.recovery_sent_at into v_recovery_sent_at
    from auth.users u
    where u.id = p_user_id
      and nullif(u.recovery_token, '') is not null
      and u.recovery_sent_at >= p_recovery_requested_after
      and u.recovery_sent_at <= clock_timestamp() + interval '5 minutes';
  if v_recovery_sent_at is null then return false; end if;

  insert into public.identity_password_recovery_grants(
    id, tenant_id, user_id, source, expires_at,
    proof_challenge_hash, auth_recovery_sent_at
  ) values (
    p_grant_id, p_tenant_id, p_user_id, 'break_glass', p_expires_at,
    p_proof_challenge_hash, v_recovery_sent_at
  );
  return true;
end;
$$;
revoke all on function public.issue_identity_break_glass_password_recovery_grant(
  uuid, uuid, uuid, timestamptz, text, timestamptz
) from public, anon, authenticated;
grant execute on function public.issue_identity_break_glass_password_recovery_grant(
  uuid, uuid, uuid, timestamptz, text, timestamptz
) to service_role;

drop function if exists public.bind_identity_password_recovery_grant(uuid, uuid, uuid);
create function public.bind_identity_password_recovery_grant(
  p_proof_verifier text,
  p_user_id uuid,
  p_session_id uuid,
  p_access_token_issued_at timestamptz
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, auth, pg_temp
as $$
declare
  v_proof_hash text;
  v_grant public.identity_password_recovery_grants%rowtype;
  v_session_created_at timestamptz;
  v_state public.identity_user_session_state%rowtype;
begin
  if p_proof_verifier !~ '^[A-Za-z0-9_-]{43}$'
     or p_user_id is null
     or p_session_id is null
     or p_access_token_issued_at is null
     or p_access_token_issued_at > clock_timestamp() + interval '5 minutes' then
    return false;
  end if;
  v_proof_hash := encode(extensions.digest(p_proof_verifier, 'sha256'), 'hex');

  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 2611));
  perform pg_advisory_xact_lock(hashtextextended(v_proof_hash, 2607));
  select g.* into v_grant
    from public.identity_password_recovery_grants g
    join auth.users u on u.id = g.user_id
    where g.proof_challenge_hash = v_proof_hash
      and g.user_id = p_user_id
      and g.used_at is null
      and g.expires_at > clock_timestamp()
      and coalesce(u.recovery_token, '') = ''
      and u.recovery_sent_at = g.auth_recovery_sent_at
    for update of g;
  if not found then return false; end if;

  select s.created_at into v_session_created_at
    from auth.sessions s
    where s.id = p_session_id and s.user_id = p_user_id;
  if v_session_created_at is null
     or v_session_created_at < v_grant.auth_recovery_sent_at
     or p_access_token_issued_at < date_trunc('second', v_grant.auth_recovery_sent_at) then
    return false;
  end if;

  select s.* into v_state
    from public.identity_user_session_state s
    where s.user_id = p_user_id;
  if found and (
    v_state.global_revoke_pending_session_id is not null
    or (
      v_state.revoked_before is not null
      and v_session_created_at <= v_state.revoked_before
    )
  ) then return false; end if;

  update public.identity_password_recovery_grants
    set session_id = p_session_id,
        bound_at = coalesce(bound_at, clock_timestamp())
    where id = v_grant.id
      and (session_id is null or session_id = p_session_id);
  return found;
end;
$$;
revoke all on function public.bind_identity_password_recovery_grant(
  text, uuid, uuid, timestamptz
) from public, anon, authenticated;
grant execute on function public.bind_identity_password_recovery_grant(
  text, uuid, uuid, timestamptz
) to service_role;

drop function if exists public.consume_identity_password_recovery_grant(uuid, uuid, uuid);
create function public.consume_identity_password_recovery_grant(
  p_proof_verifier text,
  p_user_id uuid,
  p_session_id uuid,
  p_access_token_issued_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, auth, pg_temp
as $$
declare
  v_proof_hash text;
  v_grant public.identity_password_recovery_grants%rowtype;
  v_session_created_at timestamptz;
  v_state public.identity_user_session_state%rowtype;
begin
  if p_proof_verifier !~ '^[A-Za-z0-9_-]{43}$'
     or p_user_id is null
     or p_session_id is null
     or p_access_token_issued_at is null
     or p_access_token_issued_at > clock_timestamp() + interval '5 minutes' then
    return null;
  end if;
  v_proof_hash := encode(extensions.digest(p_proof_verifier, 'sha256'), 'hex');

  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 2611));
  perform pg_advisory_xact_lock(hashtextextended(v_proof_hash, 2607));
  select g.* into v_grant
    from public.identity_password_recovery_grants g
    join auth.users u on u.id = g.user_id
    where g.proof_challenge_hash = v_proof_hash
      and g.user_id = p_user_id
      and g.session_id = p_session_id
      and g.bound_at is not null
      and g.used_at is null
      and g.expires_at > clock_timestamp()
      and coalesce(u.recovery_token, '') = ''
      and u.recovery_sent_at = g.auth_recovery_sent_at
    for update of g;
  if not found then return null; end if;

  select s.created_at into v_session_created_at
    from auth.sessions s
    where s.id = p_session_id and s.user_id = p_user_id;
  if v_session_created_at is null
     or v_session_created_at < v_grant.auth_recovery_sent_at
     or p_access_token_issued_at < date_trunc('second', v_grant.auth_recovery_sent_at) then
    return null;
  end if;

  select s.* into v_state
    from public.identity_user_session_state s
    where s.user_id = p_user_id;
  if found and (
    v_state.global_revoke_pending_session_id is not null
    or (
      v_state.revoked_before is not null
      and v_session_created_at <= v_state.revoked_before
    )
  ) then return null; end if;

  update public.identity_password_recovery_grants
    set used_at = clock_timestamp()
    where id = v_grant.id and used_at is null;
  if not found then return null; end if;
  return jsonb_build_object('source', v_grant.source, 'tenant_id', v_grant.tenant_id);
end;
$$;
revoke all on function public.consume_identity_password_recovery_grant(
  text, uuid, uuid, timestamptz
) from public, anon, authenticated;
grant execute on function public.consume_identity_password_recovery_grant(
  text, uuid, uuid, timestamptz
) to service_role;

-- SECURITY DEFINER bypasses table RLS, so team creation must explicitly join
-- the same per-user serialization domain and identity barrier as revocation.
create or replace function public.create_team_tenant(
  p_name text,
  p_plan text default 'free'
)
returns public.teams
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_user_id uuid := auth.uid();
  v_team_id uuid := gen_random_uuid();
  v_team public.teams;
begin
  if v_user_id is null or auth.role() is distinct from 'authenticated' then
    raise exception 'authentication required' using errcode = '28000';
  end if;
  if nullif(trim(p_name), '') is null or length(trim(p_name)) > 200 then
    raise exception 'team name is required and must not exceed 200 characters'
      using errcode = '22023';
  end if;
  if p_plan is distinct from 'free' then
    raise exception 'team plan is managed by billing' using errcode = '42501';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(v_user_id::text, 2611));
  if not public.tenant_identity_access_allowed(v_team_id) then
    raise exception 'identity barrier rejected' using errcode = '42501';
  end if;

  insert into public.tenants (id, name, kind, created_by)
  values (v_team_id, trim(p_name), 'team', v_user_id);
  insert into public.teams (id, tenant_id, name, plan)
  values (v_team_id, v_team_id, trim(p_name), 'free');
  insert into public.team_members (team_id, tenant_id, user_id, role)
  values (v_team_id, v_team_id, v_user_id, 'owner');

  select * into strict v_team from public.teams where id = v_team_id;
  return v_team;
end;
$$;
revoke all on function public.create_team_tenant(text, text) from public, anon;
grant execute on function public.create_team_tenant(text, text) to authenticated;
