-- Reserve recovery credentials while non-transactional Auth effects run, and
-- consume them only after those effects succeed. Retries remain bound to the
-- same browser proof and (for password completion) the same Auth session.

alter table public.identity_recovery_codes
  add column recovery_proof_challenge_hash text,
  add column recovery_started_at timestamptz,
  add column recovery_request_id text;

update public.identity_recovery_codes
set recovery_proof_challenge_hash = encode(
      extensions.digest('completed:' || id::text, 'sha256'),
      'hex'
    ),
    recovery_started_at = used_at,
    recovery_request_id = used_request_id
where used_at is not null;

alter table public.identity_recovery_codes
  add constraint identity_recovery_codes_operation_proof_format
    check (
      recovery_proof_challenge_hash is null
      or recovery_proof_challenge_hash ~ '^[0-9a-f]{64}$'
    ),
  add constraint identity_recovery_codes_operation_request_format
    check (
      recovery_request_id is null
      or recovery_request_id ~ '^[A-Za-z0-9._:-]{1,128}$'
    ),
  add constraint identity_recovery_codes_operation_state
    check (
      (recovery_proof_challenge_hash is null and recovery_started_at is null and recovery_request_id is null)
      or
      (recovery_proof_challenge_hash is not null and recovery_started_at is not null and recovery_request_id is not null)
    );

create unique index identity_recovery_codes_operation_proof
  on public.identity_recovery_codes(recovery_proof_challenge_hash)
  where recovery_proof_challenge_hash is not null;

alter table public.identity_password_recovery_grants
  add column completion_started_at timestamptz,
  add column completion_session_created_at timestamptz;

update public.identity_password_recovery_grants
set completion_started_at = used_at,
    completion_session_created_at = coalesce(bound_at, created_at)
where used_at is not null;

alter table public.identity_password_recovery_grants
  add constraint identity_password_recovery_grants_completion_state
    check (
      (completion_started_at is null and completion_session_created_at is null)
      or
      (completion_started_at is not null and completion_session_created_at is not null)
    ),
  add constraint identity_password_recovery_grants_completed_after_start
    check (used_at is null or completion_started_at is not null);

drop function if exists public.consume_identity_recovery_code(text, text, text);
create function public.begin_identity_break_glass_recovery(
  p_email text,
  p_code_hash text,
  p_proof_challenge_hash text,
  p_request_id text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, auth, pg_temp
as $$
declare v_code public.identity_recovery_codes%rowtype;
begin
  if p_email is null
     or length(p_email) > 254
     or p_code_hash !~ '^[0-9a-f]{64}$'
     or p_proof_challenge_hash !~ '^[0-9a-f]{64}$'
     or p_request_id !~ '^[A-Za-z0-9._:-]{1,128}$' then
    return null;
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_code_hash, 2607));
  select c.* into v_code
    from public.identity_recovery_codes c
    join auth.users u on u.id = c.user_id
    join public.tenants t on t.id = c.tenant_id and t.status = 'active'
    join public.tenant_members m
      on m.tenant_id = c.tenant_id
     and m.user_id = c.user_id
     and (m.expires_at is null or m.expires_at > clock_timestamp())
    join public.tenant_identity_policies p
      on p.tenant_id = c.tenant_id and p.break_glass_enabled
    where c.code_hash = p_code_hash
      and c.expires_at > clock_timestamp()
      and lower(u.email) = lower(trim(p_email))
    for update of c;
  if not found then return null; end if;

  if v_code.used_at is not null then
    if v_code.recovery_proof_challenge_hash is distinct from p_proof_challenge_hash
       or v_code.recovery_started_at <= clock_timestamp() - interval '15 minutes' then
      return null;
    end if;
    return jsonb_build_object(
      'status', 'completed',
      'tenant_id', v_code.tenant_id,
      'user_id', v_code.user_id
    );
  end if;

  if v_code.recovery_started_at is null
     or v_code.recovery_started_at <= clock_timestamp() - interval '15 minutes' then
    update public.identity_recovery_codes
      set recovery_proof_challenge_hash = p_proof_challenge_hash,
          recovery_started_at = clock_timestamp(),
          recovery_request_id = p_request_id
      where id = v_code.id;
  elsif v_code.recovery_proof_challenge_hash is distinct from p_proof_challenge_hash then
    return null;
  end if;
  return jsonb_build_object(
    'status', 'pending',
    'tenant_id', v_code.tenant_id,
    'user_id', v_code.user_id
  );
end;
$$;
revoke all on function public.begin_identity_break_glass_recovery(text, text, text, text)
  from public, anon, authenticated;
grant execute on function public.begin_identity_break_glass_recovery(text, text, text, text)
  to service_role;

create function public.complete_identity_break_glass_recovery(
  p_code_hash text,
  p_proof_challenge_hash text
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_code public.identity_recovery_codes%rowtype;
  v_barrier timestamptz;
begin
  if p_code_hash !~ '^[0-9a-f]{64}$'
     or p_proof_challenge_hash !~ '^[0-9a-f]{64}$' then
    return false;
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_code_hash, 2607));
  select c.* into v_code
    from public.identity_recovery_codes c
    where c.code_hash = p_code_hash
      and c.recovery_proof_challenge_hash = p_proof_challenge_hash
      and c.recovery_started_at is not null
      and c.recovery_started_at > clock_timestamp() - interval '15 minutes'
    for update;
  if not found then return false; end if;
  if v_code.used_at is not null then return true; end if;
  if v_code.expires_at <= clock_timestamp() then return false; end if;

  perform pg_advisory_xact_lock(hashtextextended(v_code.user_id::text, 2611));
  v_barrier := clock_timestamp();
  insert into public.identity_user_session_state(user_id, revoked_before, reason)
    values(v_code.user_id, v_barrier, 'break_glass')
    on conflict(user_id) do update
      set revoked_before = excluded.revoked_before,
          reason = excluded.reason;
  update public.device_sessions
    set expires_at = least(expires_at, v_barrier)
    where user_id = v_code.user_id
      and exchanged_at is null
      and expires_at > v_barrier;
  update public.enrollment_tokens
    set expires_at = least(expires_at, v_barrier)
    where user_id = v_code.user_id
      and label like 'device:%'
      and consumed_at is null
      and expires_at > v_barrier;
  update public.identity_recovery_codes
    set used_at = v_barrier,
        used_request_id = recovery_request_id
    where id = v_code.id and used_at is null;
  if not found then return false; end if;
  insert into public.admin_audit_logs(
    actor_user_id, tenant_id, target_user_id, action, detail
  ) values (
    null, v_code.tenant_id, v_code.user_id, 'identity.break_glass.consumed',
    jsonb_build_object(
      'recovery_code_id', v_code.id,
      'request_id', v_code.recovery_request_id,
      'revoked_before', v_barrier
    )
  );
  return true;
end;
$$;
revoke all on function public.complete_identity_break_glass_recovery(text, text)
  from public, anon, authenticated;
grant execute on function public.complete_identity_break_glass_recovery(text, text)
  to service_role;

-- Generating a replacement GoTrue recovery event during a retry updates the
-- same challenge-bound grant instead of failing its uniqueness constraint.
create or replace function public.issue_identity_password_recovery_grant(
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
  v_grant public.identity_password_recovery_grants%rowtype;
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

  perform pg_advisory_xact_lock(hashtextextended(p_proof_challenge_hash, 2607));
  select g.* into v_grant
    from public.identity_password_recovery_grants g
    where g.proof_challenge_hash = p_proof_challenge_hash
    for update;
  if found then
    if v_grant.user_id is distinct from v_user_id
       or v_grant.tenant_id is not null
       or v_grant.source is distinct from 'email'
       or v_grant.session_id is not null
       or v_grant.used_at is not null then
      return false;
    end if;
    update public.identity_password_recovery_grants
      set expires_at = p_expires_at,
          auth_recovery_sent_at = v_recovery_sent_at
      where id = v_grant.id;
    return true;
  end if;

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

create or replace function public.issue_identity_break_glass_password_recovery_grant(
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
declare
  v_recovery_sent_at timestamptz;
  v_grant public.identity_password_recovery_grants%rowtype;
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

  perform pg_advisory_xact_lock(hashtextextended(p_proof_challenge_hash, 2607));
  select g.* into v_grant
    from public.identity_password_recovery_grants g
    where g.proof_challenge_hash = p_proof_challenge_hash
    for update;
  if found then
    if v_grant.user_id is distinct from p_user_id
       or v_grant.tenant_id is distinct from p_tenant_id
       or v_grant.source is distinct from 'break_glass'
       or v_grant.session_id is not null
       or v_grant.used_at is not null then
      return false;
    end if;
    update public.identity_password_recovery_grants
      set expires_at = p_expires_at,
          auth_recovery_sent_at = v_recovery_sent_at
      where id = v_grant.id;
    return true;
  end if;

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

drop function if exists public.consume_identity_password_recovery_grant(
  text, uuid, uuid, timestamptz
);
create function public.begin_identity_password_recovery_completion(
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
    where g.proof_challenge_hash = v_proof_hash
      and g.user_id = p_user_id
      and g.session_id = p_session_id
      and g.bound_at is not null
    for update;
  if not found then return null; end if;
  if v_grant.used_at is not null and v_grant.completion_started_at is not null then
    return jsonb_build_object(
      'status', 'completed',
      'source', v_grant.source,
      'tenant_id', v_grant.tenant_id
    );
  end if;
  if v_grant.used_at is not null or v_grant.expires_at <= clock_timestamp() then
    return null;
  end if;

  if v_grant.completion_started_at is null then
    if not exists (
      select 1 from auth.users u
      where u.id = p_user_id
        and coalesce(u.recovery_token, '') = ''
        and u.recovery_sent_at = v_grant.auth_recovery_sent_at
    ) then return null; end if;
    select s.created_at into v_session_created_at
      from auth.sessions s
      where s.id = p_session_id and s.user_id = p_user_id;
    if v_session_created_at is null
       or v_session_created_at < v_grant.auth_recovery_sent_at
       or p_access_token_issued_at < date_trunc('second', v_grant.auth_recovery_sent_at) then
      return null;
    end if;
  else
    v_session_created_at := v_grant.completion_session_created_at;
  end if;

  select s.* into v_state
    from public.identity_user_session_state s
    where s.user_id = p_user_id;
  if found and (
    v_state.global_revoke_pending_session_id is not null
    or (
      v_grant.completion_started_at is null
      and v_state.revoked_before is not null
      and v_session_created_at <= v_state.revoked_before
    )
  ) then return null; end if;

  if v_grant.completion_started_at is null then
    update public.identity_password_recovery_grants
      set completion_started_at = clock_timestamp(),
          completion_session_created_at = v_session_created_at
      where id = v_grant.id and completion_started_at is null;
    if not found then return null; end if;
  end if;
  return jsonb_build_object(
    'status', 'pending',
    'source', v_grant.source,
    'tenant_id', v_grant.tenant_id
  );
end;
$$;
revoke all on function public.begin_identity_password_recovery_completion(
  text, uuid, uuid, timestamptz
) from public, anon, authenticated;
grant execute on function public.begin_identity_password_recovery_completion(
  text, uuid, uuid, timestamptz
) to service_role;

create function public.complete_identity_password_recovery_completion(
  p_proof_verifier text,
  p_user_id uuid,
  p_session_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_proof_hash text;
  v_grant public.identity_password_recovery_grants%rowtype;
  v_barrier timestamptz;
begin
  if p_proof_verifier !~ '^[A-Za-z0-9_-]{43}$'
     or p_user_id is null
     or p_session_id is null then
    return false;
  end if;
  v_proof_hash := encode(extensions.digest(p_proof_verifier, 'sha256'), 'hex');

  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 2611));
  perform pg_advisory_xact_lock(hashtextextended(v_proof_hash, 2607));
  select g.* into v_grant
    from public.identity_password_recovery_grants g
    where g.proof_challenge_hash = v_proof_hash
      and g.user_id = p_user_id
      and g.session_id = p_session_id
      and g.bound_at is not null
      and g.completion_started_at is not null
    for update;
  if not found then return false; end if;
  if v_grant.used_at is not null then return true; end if;

  v_barrier := public.mark_identity_session_revoked(
    p_user_id,
    v_grant.tenant_id,
    p_user_id,
    'password_recovery'
  );
  update public.identity_password_recovery_grants
    set used_at = v_barrier
    where id = v_grant.id and used_at is null;
  return found;
end;
$$;
revoke all on function public.complete_identity_password_recovery_completion(
  text, uuid, uuid
) from public, anon, authenticated;
grant execute on function public.complete_identity_password_recovery_completion(
  text, uuid, uuid
) to service_role;
