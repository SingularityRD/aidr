-- Redeem against the current invitation and inviter state, not a transaction's
-- start-time snapshot. Locks serialize redemption with link rotation/revocation,
-- membership removal and tenant suspension.
create or replace function public.accept_team_invitation(p_hash text, p_user_id uuid)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_invite public.team_invitations;
  v_invite_id uuid;
  v_verified_email text;
  v_issuer_expires_at timestamptz;
  v_now timestamptz;
begin
  if p_hash is null or p_hash !~ '^[0-9a-f]{64}$' or p_user_id is null then
    raise exception 'invalid_invitation' using errcode = '42501';
  end if;

  select lower(email) into v_verified_email
    from auth.users
   where id = p_user_id and email_confirmed_at is not null
   for share;
  -- Discover the issuer without locking yet. Mutation takes the issuer lock
  -- before the invitation lock; preserve that order to avoid a deadlock with
  -- a simultaneous resend or revoke. Re-read the token under lock below.
  select * into v_invite
    from public.team_invitations
   where token_hash = p_hash;
  if v_invite.id is null or v_verified_email is null
     or v_verified_email <> lower(v_invite.email) then
    raise exception 'invalid_invitation' using errcode = '42501';
  end if;
  v_invite_id := v_invite.id;

  select m.expires_at into v_issuer_expires_at
    from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
    join public.teams team on team.id = t.id
   where m.tenant_id = v_invite.tenant_id
     and m.user_id = v_invite.created_by
     and m.role in ('owner', 'admin')
     and (m.expires_at is null or m.expires_at > clock_timestamp())
     and t.status = 'active'
   for share of m, t, team;
  if not found then
    raise exception 'invitation_revoked' using errcode = '42501';
  end if;

  select * into v_invite
    from public.team_invitations
   where id = v_invite_id and token_hash = p_hash
   for update;
  v_now := clock_timestamp();
  if v_issuer_expires_at is not null and v_issuer_expires_at <= v_now then
    raise exception 'invitation_revoked' using errcode = '42501';
  end if;
  if v_invite.id is null or v_invite.accepted_at is not null
     or v_invite.expires_at <= v_now then
    raise exception 'invalid_invitation' using errcode = '42501';
  end if;

  -- Existing membership never gains a higher role from an old link.
  insert into public.team_members(team_id, tenant_id, user_id, role, invited_by)
  values(v_invite.tenant_id, v_invite.tenant_id, p_user_id, v_invite.role, v_invite.created_by)
  on conflict(team_id, user_id) do nothing;
  update public.team_invitations set accepted_at = v_now where id = v_invite.id;
  insert into public.audit_logs(team_id, tenant_id, user_id, action, verdict)
  values(v_invite.tenant_id, v_invite.tenant_id, p_user_id, 'member.invitation_accepted',
         jsonb_build_object('invitation_id', v_invite.id));
  return v_invite.tenant_id;
end;
$$;

revoke all on function public.accept_team_invitation(text, uuid) from public, anon, authenticated;
grant execute on function public.accept_team_invitation(text, uuid) to service_role;
