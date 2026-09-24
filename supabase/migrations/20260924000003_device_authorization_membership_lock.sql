-- Recheck and lock the canonical member/tenant rows inside the device bind.
-- The Edge preflight is useful for a quick response, but membership removal
-- must serialize with authorization to prevent an old device code reviving
-- after the same user is later re-added.
create or replace function public.authorize_device_session(
  p_user_code text,
  p_user_id uuid,
  p_tenant_id uuid,
  p_access_token_issued_at timestamptz
)
returns table (id uuid, user_id uuid, tenant_id uuid, expires_at timestamptz)
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_revoked_before timestamptz;
  v_tenant_id uuid;
begin
  if nullif(trim(p_user_code), '') is null
     or p_user_id is null
     or p_access_token_issued_at is null
     or p_access_token_issued_at > clock_timestamp() + interval '5 minutes' then
    return;
  end if;

  v_tenant_id := coalesce(p_tenant_id, p_user_id);
  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 2611));
  select s.revoked_before into v_revoked_before
    from public.identity_user_session_state s
    where s.user_id = p_user_id;
  if v_revoked_before is not null
     and p_access_token_issued_at <= v_revoked_before then
    return;
  end if;

  -- FOR SHARE conflicts with membership removal, demotion and expiry updates.
  -- Whichever transaction wins, the device cannot be left authorized across
  -- the membership boundary.
  perform 1
    from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = v_tenant_id
     and m.user_id = p_user_id
     and m.role in ('owner', 'admin', 'member')
     and (m.expires_at is null or m.expires_at > clock_timestamp())
     and t.status = 'active'
   for share of m, t;
  if not found then return; end if;

  update public.device_sessions d
     set user_id = p_user_id,
         tenant_id = v_tenant_id,
         authorized_at = clock_timestamp(),
         status = 'authorized'
   where d.user_code = upper(trim(p_user_code))
     and (d.tenant_id is null or d.tenant_id = v_tenant_id)
     and d.authorized_at is null
     and d.expires_at > clock_timestamp()
  returning d.id, d.user_id, d.tenant_id, d.expires_at
       into id, user_id, tenant_id, expires_at;
  if not found then return; end if;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
  values (p_user_id, tenant_id, 'device.verify', p_user_id,
          jsonb_build_object('device_session_id', id));
  return next;
end;
$$;

revoke all on function public.authorize_device_session(text, uuid, uuid, timestamptz)
  from public, anon, authenticated;
grant execute on function public.authorize_device_session(text, uuid, uuid, timestamptz)
  to service_role;
