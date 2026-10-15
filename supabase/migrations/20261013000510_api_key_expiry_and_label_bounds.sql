-- API key hygiene (CP-8).
--
--   * `api_keys.expires_at`: optional expiry. /v1/api-keys sets a default
--     lifetime for dashboard-issued keys (AIDR_APIKEY_DEFAULT_TTL_DAYS) unless the
--     issuer explicitly asks for a non-expiring key, and every API-key guard
--     (supabase/functions/_shared/api-key-auth.ts, packs-download) refuses a key
--     whose expiry has passed. NULL keeps the previous "until revoked" behaviour,
--     so existing keys and enrollment-minted agent keys are unchanged.
--   * Labels are bounded to 1..100 characters without control characters, so an
--     8 KiB control-character label can no longer be stored or copied into the
--     audit log. Existing labels are normalized first so the constraint can be
--     validated (and renewing an old key cannot trip it).
--   * Issue/renew RPCs take the expiry and refuse to rotate an expired key; a
--     renewal that does not pass `p_set_expiry` keeps the key's current expiry,
--     so an edge function deployed before this migration keeps working.

alter table public.api_keys add column if not exists expires_at timestamptz;

update public.api_keys
   set label = nullif(left(btrim(regexp_replace(label, '[[:cntrl:]]+', ' ', 'g')), 100), '')
 where label is not null
   and (char_length(label) > 100 or label ~ '[[:cntrl:]]' or btrim(label) = '' or label <> btrim(label));

alter table public.api_keys drop constraint if exists api_keys_label_check;
alter table public.api_keys add constraint api_keys_label_check check (
  label is null or (char_length(label) between 1 and 100 and label !~ '[[:cntrl:]]')
);

alter table public.api_keys drop constraint if exists api_keys_expiry_check;
alter table public.api_keys add constraint api_keys_expiry_check check (
  expires_at is null or expires_at > created_at
);

create index if not exists api_keys_expires_at_idx on public.api_keys (tenant_id, expires_at)
  where expires_at is not null and not revoked;

-- Shared label rule for the RPCs (the table constraint is the backstop).
create or replace function app.api_key_label_valid(p_label text)
returns boolean
language sql immutable
set search_path = pg_catalog, pg_temp
as $$
  select p_label is null or (char_length(p_label) between 1 and 100 and p_label !~ '[[:cntrl:]]');
$$;
revoke all on function app.api_key_label_valid(text) from public, anon, authenticated;

-- ── Tenant key issuance ─────────────────────────────────────────────────────
drop function if exists public.issue_api_key_with_audit(uuid, uuid, text, text);
create or replace function public.issue_api_key_with_audit(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_label text,
  p_key_hash text,
  p_expires_at timestamptz default null
) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_id uuid;
begin
  if p_actor_user_id is null or p_tenant_id is null
     or p_key_hash is null or p_key_hash !~ '^[a-f0-9]{64}$'
     or not app.api_key_label_valid(p_label)
     or (p_expires_at is not null and p_expires_at <= clock_timestamp()) then
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

  insert into public.api_keys(user_id, tenant_id, label, key_hash, expires_at)
    values (p_actor_user_id, p_tenant_id, p_label, p_key_hash, p_expires_at)
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
      jsonb_build_object('label', p_label, 'id', v_id, 'scope', 'tenant', 'expires_at', p_expires_at));
  return jsonb_build_object('status', 'issued', 'id', v_id);
end;
$$;
revoke all on function public.issue_api_key_with_audit(uuid, uuid, text, text, timestamptz)
  from public, anon, authenticated;
grant execute on function public.issue_api_key_with_audit(uuid, uuid, text, text, timestamptz)
  to service_role;

-- ── Browser Guard ingest key issuance ───────────────────────────────────────
drop function if exists public.issue_scoped_api_key_with_audit(uuid, uuid, text, text, text, integer);
create or replace function public.issue_scoped_api_key_with_audit(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_label text,
  p_key_hash text,
  p_scope text,
  p_install_limit integer,
  p_expires_at timestamptz default null
) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, pg_temp as $$
declare v_id uuid;
begin
  if p_actor_user_id is null or p_tenant_id is null
     or p_key_hash is null or p_key_hash !~ '^[a-f0-9]{64}$'
     or p_scope is distinct from 'ingest:browser_guard'
     or p_install_limit is null or p_install_limit not between 1 and 100000
     or not app.api_key_label_valid(p_label)
     or (p_expires_at is not null and p_expires_at <= clock_timestamp()) then
    raise exception 'invalid_api_key_issue' using errcode = '22023';
  end if;
  -- An ingest key is an organisation deployment credential: owners and admins.
  perform 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
     and m.role in ('owner', 'admin')
     and (m.expires_at is null or m.expires_at > clock_timestamp())
     and t.status = 'active'
   for share of m;
  if not found then return jsonb_build_object('status', 'forbidden'); end if;

  -- A retried call whose response was lost resolves to the same key.
  select k.id into v_id from public.api_keys k
   where k.key_hash = p_key_hash and k.user_id = p_actor_user_id and k.tenant_id = p_tenant_id
     and k.scope = p_scope and k.install_limit = p_install_limit and k.revoked = false;
  if v_id is not null then return jsonb_build_object('status', 'issued', 'id', v_id); end if;

  insert into public.api_keys(user_id, tenant_id, label, key_hash, scope, install_limit, expires_at)
    values (p_actor_user_id, p_tenant_id, p_label, p_key_hash, p_scope, p_install_limit, p_expires_at)
    on conflict (key_hash) do nothing returning id into v_id;
  if v_id is null then
    select k.id into v_id from public.api_keys k
     where k.key_hash = p_key_hash and k.user_id = p_actor_user_id and k.tenant_id = p_tenant_id
       and k.scope = p_scope and k.install_limit = p_install_limit and k.revoked = false;
    if v_id is not null then return jsonb_build_object('status', 'issued', 'id', v_id); end if;
    return jsonb_build_object('status', 'hash_conflict');
  end if;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
    values (p_actor_user_id, p_tenant_id, 'api_key.create', p_actor_user_id,
      jsonb_build_object('label', p_label, 'id', v_id, 'scope', p_scope,
        'install_limit', p_install_limit, 'expires_at', p_expires_at));
  return jsonb_build_object('status', 'issued', 'id', v_id);
end;
$$;
revoke all on function public.issue_scoped_api_key_with_audit(uuid, uuid, text, text, text, integer, timestamptz)
  from public, anon, authenticated;
grant execute on function public.issue_scoped_api_key_with_audit(uuid, uuid, text, text, text, integer, timestamptz)
  to service_role;

-- ── Rotation ────────────────────────────────────────────────────────────────
drop function if exists public.renew_api_key_with_audit(uuid, uuid, uuid, text, text, integer);
create or replace function public.renew_api_key_with_audit(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_id uuid,
  p_expected_hash text,
  p_new_hash text,
  p_overlap_hours integer,
  p_set_expiry boolean default false,
  p_expires_at timestamptz default null
) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_role text;
  v_key public.api_keys%rowtype;
  v_rotated_at timestamptz;
  v_previous_expires_at timestamptz;
  v_expires_at timestamptz;
  v_updated_id uuid;
begin
  if p_actor_user_id is null or p_tenant_id is null or p_id is null
     or p_expected_hash is null or p_expected_hash !~ '^[a-f0-9]{64}$'
     or p_new_hash is null or p_new_hash !~ '^[a-f0-9]{64}$'
     or p_overlap_hours is null or p_overlap_hours not between 1 and 168
     or p_set_expiry is null
     or (not p_set_expiry and p_expires_at is not null)
     or (p_expires_at is not null and p_expires_at <= clock_timestamp()) then
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
      'previous_secret_valid_until', v_key.previous_hash_expires_at,
      'expires_at', v_key.expires_at);
  end if;
  -- An expired key is not revived by rotation: its retired secret would
  -- otherwise become valid again for the overlap window. Issue a new key.
  if v_key.expires_at is not null and v_key.expires_at <= clock_timestamp() then
    return jsonb_build_object('status', 'expired');
  end if;
  if v_key.key_hash <> p_expected_hash then return jsonb_build_object('status', 'conflict'); end if;

  v_rotated_at := clock_timestamp();
  v_previous_expires_at := v_rotated_at + make_interval(hours => p_overlap_hours);
  v_expires_at := case when p_set_expiry then p_expires_at else v_key.expires_at end;
  -- The retired secret never outlives the key itself.
  if v_expires_at is not null and v_expires_at < v_previous_expires_at then
    v_previous_expires_at := greatest(v_expires_at, v_rotated_at + interval '1 hour');
  end if;
  begin
    update public.api_keys set key_hash = p_new_hash, previous_hash = p_expected_hash,
      previous_hash_expires_at = v_previous_expires_at, rotated_at = v_rotated_at,
      expires_at = v_expires_at
     where id = p_id and tenant_id = p_tenant_id and key_hash = p_expected_hash
     returning id into v_updated_id;
  exception when unique_violation then
    return jsonb_build_object('status', 'hash_conflict');
  end;
  if v_updated_id is null then return jsonb_build_object('status', 'conflict'); end if;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
    values (p_actor_user_id, p_tenant_id, 'api_key.renew', v_key.user_id,
      jsonb_build_object('id', p_id, 'scope', v_key.scope,
        'previous_secret_valid_until', v_previous_expires_at, 'expires_at', v_expires_at));
  return jsonb_build_object('status', 'rotated', 'id', p_id,
    'previous_secret_valid_until', v_previous_expires_at, 'expires_at', v_expires_at);
end;
$$;
revoke all on function public.renew_api_key_with_audit(uuid, uuid, uuid, text, text, integer, boolean, timestamptz)
  from public, anon, authenticated;
grant execute on function public.renew_api_key_with_audit(uuid, uuid, uuid, text, text, integer, boolean, timestamptz)
  to service_role;
