-- New SCIM credentials are finite. Existing tokens (including legacy rows with
-- NULL expires_at) remain valid until an owner explicitly rotates/revokes them.
create or replace function public.scim_admin_create_token(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_token_hash text,
  p_label text,
  p_expires_at timestamptz,
  p_rotated_from_id uuid default null
) returns uuid
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_token_id uuid;
  v_now timestamptz := clock_timestamp();
  v_expires_at timestamptz := coalesce(p_expires_at, v_now + interval '90 days');
begin
  perform app.scim_assert_tenant_owner(p_tenant_id, p_actor_user_id);
  if p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$'
     or p_label is null or p_label <> trim(p_label)
     or length(p_label) not between 1 and 120
     or p_label ~ '[[:cntrl:]]'
     or v_expires_at <= v_now
     or v_expires_at > v_now + interval '365 days' then
    raise exception 'scim_admin_invalid_token' using errcode = '22023';
  end if;
  if p_rotated_from_id is not null and not exists (
    select 1 from public.scim_tokens st
     where st.tenant_id = p_tenant_id and st.id = p_rotated_from_id
       and st.revoked_at is null and (st.expires_at is null or st.expires_at > v_now)
  ) then
    raise exception 'scim_admin_rotation_parent_unavailable' using errcode = 'P0002';
  end if;

  insert into public.scim_tokens(tenant_id, token_hash, label, expires_at, rotated_from)
    values (p_tenant_id, p_token_hash, p_label, v_expires_at, p_rotated_from_id)
    returning id into v_token_id;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
    values (p_actor_user_id, p_tenant_id,
      case when p_rotated_from_id is null then 'scim.token.created' else 'scim.token.rotated' end,
      jsonb_build_object('token_id', v_token_id, 'rotated_from', p_rotated_from_id, 'expires_at', v_expires_at));
  return v_token_id;
end;
$$;

revoke all on function public.scim_admin_create_token(uuid, uuid, text, text, timestamptz, uuid) from public, anon, authenticated;
grant execute on function public.scim_admin_create_token(uuid, uuid, text, text, timestamptz, uuid) to service_role;
