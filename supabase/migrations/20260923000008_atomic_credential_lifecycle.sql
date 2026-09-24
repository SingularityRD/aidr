-- Keep credential changes and their audit evidence in the same transaction.
-- The secret itself is supplied only as a SHA-256 hash; retries reuse that
-- hash so a committed RPC whose response was lost remains idempotent.

create or replace function public.issue_api_key_with_audit(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_label text,
  p_key_hash text
) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_id uuid;
begin
  if p_actor_user_id is null or p_tenant_id is null
     or p_key_hash is null or p_key_hash !~ '^[a-f0-9]{64}$' then
    raise exception 'invalid_api_key_issue' using errcode = '22023';
  end if;
  if not exists (
    select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
     where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
       and m.role in ('owner', 'admin', 'member')
       and (m.expires_at is null or m.expires_at > clock_timestamp())
       and t.status = 'active'
  ) then return jsonb_build_object('status', 'forbidden'); end if;

  select id into v_id from public.api_keys
   where key_hash = p_key_hash and user_id = p_actor_user_id and tenant_id = p_tenant_id
     and revoked = false;
  if v_id is not null then return jsonb_build_object('status', 'issued', 'id', v_id); end if;

  insert into public.api_keys(user_id, tenant_id, label, key_hash)
    values (p_actor_user_id, p_tenant_id, p_label, p_key_hash)
    on conflict (key_hash) do nothing returning id into v_id;
  if v_id is null then
    select id into v_id from public.api_keys
     where key_hash = p_key_hash and user_id = p_actor_user_id and tenant_id = p_tenant_id
       and revoked = false;
    if v_id is not null then return jsonb_build_object('status', 'issued', 'id', v_id); end if;
    return jsonb_build_object('status', 'hash_conflict');
  end if;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
    values (p_actor_user_id, p_tenant_id, 'api_key.create', p_actor_user_id,
      jsonb_build_object('label', p_label, 'id', v_id));
  return jsonb_build_object('status', 'issued', 'id', v_id);
end;
$$;

create or replace function public.renew_api_key_with_audit(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_id uuid,
  p_expected_hash text,
  p_new_hash text,
  p_overlap_hours integer
) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_role text;
  v_key public.api_keys%rowtype;
  v_rotated_at timestamptz;
  v_previous_expires_at timestamptz;
  v_updated_id uuid;
begin
  if p_actor_user_id is null or p_tenant_id is null or p_id is null
     or p_expected_hash is null or p_expected_hash !~ '^[a-f0-9]{64}$'
     or p_new_hash is null or p_new_hash !~ '^[a-f0-9]{64}$'
     or p_overlap_hours is null or p_overlap_hours not between 1 and 168 then
    raise exception 'invalid_api_key_renewal' using errcode = '22023';
  end if;
  select m.role into v_role from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
     and (m.expires_at is null or m.expires_at > clock_timestamp()) and t.status = 'active';
  if not found or v_role not in ('owner', 'admin', 'member') then
    return jsonb_build_object('status', 'forbidden');
  end if;

  select k.* into v_key from public.api_keys k
   where k.id = p_id and k.tenant_id = p_tenant_id
     and (v_role <> 'member' or k.user_id = p_actor_user_id)
   for update;
  if not found then return jsonb_build_object('status', 'not_found'); end if;
  if v_key.revoked then return jsonb_build_object('status', 'revoked'); end if;
  if v_key.key_hash = p_new_hash and v_key.previous_hash = p_expected_hash then
    return jsonb_build_object('status', 'rotated', 'id', v_key.id,
      'previous_secret_valid_until', v_key.previous_hash_expires_at);
  end if;
  if v_key.key_hash <> p_expected_hash then return jsonb_build_object('status', 'conflict'); end if;

  v_rotated_at := clock_timestamp();
  v_previous_expires_at := v_rotated_at + make_interval(hours => p_overlap_hours);
  begin
    update public.api_keys set key_hash = p_new_hash, previous_hash = p_expected_hash,
      previous_hash_expires_at = v_previous_expires_at, rotated_at = v_rotated_at
     where id = p_id and tenant_id = p_tenant_id and key_hash = p_expected_hash
     returning id into v_updated_id;
  exception when unique_violation then
    return jsonb_build_object('status', 'hash_conflict');
  end;
  if v_updated_id is null then return jsonb_build_object('status', 'conflict'); end if;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
    values (p_actor_user_id, p_tenant_id, 'api_key.renew', v_key.user_id,
      jsonb_build_object('id', p_id, 'previous_secret_valid_until', v_previous_expires_at));
  return jsonb_build_object('status', 'rotated', 'id', p_id,
    'previous_secret_valid_until', v_previous_expires_at);
end;
$$;

create or replace function public.issue_enrollment_token_with_audit(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_label text,
  p_ttl_hours integer,
  p_token_hash text
) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_id uuid; v_expires_at timestamptz;
begin
  if p_actor_user_id is null or p_tenant_id is null
     or p_token_hash is null or p_token_hash !~ '^[a-f0-9]{64}$'
     or p_ttl_hours is null or p_ttl_hours not between 1 and 720 then
    raise exception 'invalid_enrollment_token_issue' using errcode = '22023';
  end if;
  if not exists (
    select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
     where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
       and m.role in ('owner', 'admin', 'member')
       and (m.expires_at is null or m.expires_at > clock_timestamp())
       and t.status = 'active'
  ) then return jsonb_build_object('status', 'forbidden'); end if;

  select id, expires_at into v_id, v_expires_at from public.enrollment_tokens
   where token_hash = p_token_hash and user_id = p_actor_user_id and tenant_id = p_tenant_id
     and consumed_at is null and expires_at > clock_timestamp();
  if v_id is not null then
    return jsonb_build_object('status', 'issued', 'id', v_id, 'expires_at', v_expires_at);
  end if;

  v_expires_at := clock_timestamp() + make_interval(hours => p_ttl_hours);
  insert into public.enrollment_tokens(user_id, tenant_id, label, token_hash, expires_at)
    values (p_actor_user_id, p_tenant_id, p_label, p_token_hash, v_expires_at)
    on conflict (token_hash) do nothing returning id into v_id;
  if v_id is null then
    select id, expires_at into v_id, v_expires_at from public.enrollment_tokens
     where token_hash = p_token_hash and user_id = p_actor_user_id and tenant_id = p_tenant_id
       and consumed_at is null and expires_at > clock_timestamp();
    if v_id is not null then
      return jsonb_build_object('status', 'issued', 'id', v_id, 'expires_at', v_expires_at);
    end if;
    return jsonb_build_object('status', 'hash_conflict');
  end if;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
    values (p_actor_user_id, p_tenant_id, 'enrollment_token.create', p_actor_user_id,
      jsonb_build_object('id', v_id, 'label', p_label, 'ttl_hours', p_ttl_hours));
  return jsonb_build_object('status', 'issued', 'id', v_id, 'expires_at', v_expires_at);
end;
$$;

create or replace function public.renew_enrollment_token_with_audit(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_id uuid,
  p_expected_hash text,
  p_new_hash text,
  p_ttl_hours integer,
  p_overlap_hours integer
) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_role text;
  v_token public.enrollment_tokens%rowtype;
  v_now timestamptz;
  v_expires_at timestamptz;
  v_previous_expires_at timestamptz;
  v_previous_hash text;
  v_updated_id uuid;
begin
  if p_actor_user_id is null or p_tenant_id is null or p_id is null
     or p_expected_hash is null or p_expected_hash !~ '^[a-f0-9]{64}$'
     or p_new_hash is null or p_new_hash !~ '^[a-f0-9]{64}$'
     or p_ttl_hours is null or p_ttl_hours not between 1 and 720
     or p_overlap_hours is null or p_overlap_hours not between 1 and 168 then
    raise exception 'invalid_enrollment_token_renewal' using errcode = '22023';
  end if;
  select m.role into v_role from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
     and (m.expires_at is null or m.expires_at > clock_timestamp()) and t.status = 'active';
  if not found or v_role not in ('owner', 'admin', 'member') then
    return jsonb_build_object('status', 'forbidden');
  end if;

  select e.* into v_token from public.enrollment_tokens e
   where e.id = p_id and e.tenant_id = p_tenant_id
     and (v_role <> 'member' or e.user_id = p_actor_user_id)
   for update;
  if not found then return jsonb_build_object('status', 'not_found'); end if;
  if v_token.consumed_at is not null then return jsonb_build_object('status', 'consumed'); end if;
  if v_token.token_hash = p_new_hash then
    return jsonb_build_object('status', 'rotated', 'id', v_token.id,
      'expires_at', v_token.expires_at,
      'previous_secret_valid_until', v_token.previous_hash_expires_at);
  end if;
  if v_token.token_hash <> p_expected_hash then return jsonb_build_object('status', 'conflict'); end if;

  v_now := clock_timestamp();
  v_expires_at := v_now + make_interval(hours => p_ttl_hours);
  v_previous_expires_at := least(v_now + make_interval(hours => p_overlap_hours), v_token.expires_at);
  v_previous_hash := case when v_previous_expires_at > v_now then p_expected_hash else null end;
  if v_previous_hash is null then v_previous_expires_at := null; end if;
  begin
    update public.enrollment_tokens set token_hash = p_new_hash, expires_at = v_expires_at,
      previous_hash = v_previous_hash, previous_hash_expires_at = v_previous_expires_at,
      rotated_at = v_now
     where id = p_id and tenant_id = p_tenant_id and token_hash = p_expected_hash
     returning id into v_updated_id;
  exception when unique_violation then
    return jsonb_build_object('status', 'hash_conflict');
  end;
  if v_updated_id is null then return jsonb_build_object('status', 'conflict'); end if;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
    values (p_actor_user_id, p_tenant_id, 'enrollment_token.renew', v_token.user_id,
      jsonb_build_object('id', p_id, 'ttl_hours', p_ttl_hours,
        'expires_at', v_expires_at, 'previous_secret_valid_until', v_previous_expires_at));
  return jsonb_build_object('status', 'rotated', 'id', p_id, 'expires_at', v_expires_at,
    'previous_secret_valid_until', v_previous_expires_at);
end;
$$;

create or replace function public.revoke_api_key_with_audit(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_id uuid
) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_role text;
  v_key public.api_keys%rowtype;
  v_updated_id uuid;
begin
  if p_actor_user_id is null or p_tenant_id is null or p_id is null then
    raise exception 'invalid_api_key_revocation' using errcode = '22023';
  end if;
  select m.role into v_role from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
     and (m.expires_at is null or m.expires_at > clock_timestamp()) and t.status = 'active';
  if not found or v_role not in ('owner', 'admin', 'member') then
    return jsonb_build_object('status', 'forbidden');
  end if;

  select k.* into v_key from public.api_keys k
   where k.id = p_id and k.tenant_id = p_tenant_id
     and (v_role <> 'member' or k.user_id = p_actor_user_id)
   for update;
  if not found then return jsonb_build_object('status', 'not_found'); end if;

  if v_key.revoked then
    if exists (
      select 1 from public.admin_audit_logs a
       where a.tenant_id = p_tenant_id and a.action = 'api_key.revoke'
         and a.detail ->> 'id' = p_id::text
    ) then return jsonb_build_object('status', 'revoked', 'id', p_id); end if;
  else
    update public.api_keys set revoked = true
     where id = p_id and tenant_id = p_tenant_id and revoked = false
     returning id into v_updated_id;
    if v_updated_id is null then return jsonb_build_object('status', 'conflict'); end if;
  end if;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
    values (p_actor_user_id, p_tenant_id, 'api_key.revoke', v_key.user_id,
      jsonb_build_object('id', p_id));
  return jsonb_build_object('status', 'revoked', 'id', p_id);
end;
$$;

create or replace function public.delete_enrollment_token_with_audit(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_id uuid
) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_role text;
  v_token public.enrollment_tokens%rowtype;
  v_deleted_id uuid;
begin
  if p_actor_user_id is null or p_tenant_id is null or p_id is null then
    raise exception 'invalid_enrollment_token_deletion' using errcode = '22023';
  end if;
  select m.role into v_role from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
     and (m.expires_at is null or m.expires_at > clock_timestamp()) and t.status = 'active';
  if not found or v_role not in ('owner', 'admin', 'member') then
    return jsonb_build_object('status', 'forbidden');
  end if;

  select e.* into v_token from public.enrollment_tokens e
   where e.id = p_id and e.tenant_id = p_tenant_id
     and (v_role <> 'member' or e.user_id = p_actor_user_id)
   for update;
  if not found then
    if exists (
      select 1 from public.admin_audit_logs a
       where a.actor_user_id = p_actor_user_id and a.tenant_id = p_tenant_id
         and a.action = 'enrollment_token.delete' and a.detail ->> 'id' = p_id::text
         and (v_role <> 'member' or a.target_user_id = p_actor_user_id)
    ) then return jsonb_build_object('status', 'deleted', 'id', p_id); end if;
    return jsonb_build_object('status', 'not_found');
  end if;

  delete from public.enrollment_tokens where id = p_id and tenant_id = p_tenant_id
    returning id into v_deleted_id;
  if v_deleted_id is null then return jsonb_build_object('status', 'conflict'); end if;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
    values (p_actor_user_id, p_tenant_id, 'enrollment_token.delete', v_token.user_id,
      jsonb_build_object('id', p_id));
  return jsonb_build_object('status', 'deleted', 'id', p_id);
end;
$$;

revoke all on function public.issue_api_key_with_audit(uuid, uuid, text, text) from public, anon, authenticated;
revoke all on function public.renew_api_key_with_audit(uuid, uuid, uuid, text, text, integer) from public, anon, authenticated;
revoke all on function public.issue_enrollment_token_with_audit(uuid, uuid, text, integer, text) from public, anon, authenticated;
revoke all on function public.renew_enrollment_token_with_audit(uuid, uuid, uuid, text, text, integer, integer) from public, anon, authenticated;
revoke all on function public.revoke_api_key_with_audit(uuid, uuid, uuid) from public, anon, authenticated;
revoke all on function public.delete_enrollment_token_with_audit(uuid, uuid, uuid) from public, anon, authenticated;
grant execute on function public.issue_api_key_with_audit(uuid, uuid, text, text) to service_role;
grant execute on function public.renew_api_key_with_audit(uuid, uuid, uuid, text, text, integer) to service_role;
grant execute on function public.issue_enrollment_token_with_audit(uuid, uuid, text, integer, text) to service_role;
grant execute on function public.renew_enrollment_token_with_audit(uuid, uuid, uuid, text, text, integer, integer) to service_role;
grant execute on function public.revoke_api_key_with_audit(uuid, uuid, uuid) to service_role;
grant execute on function public.delete_enrollment_token_with_audit(uuid, uuid, uuid) to service_role;
