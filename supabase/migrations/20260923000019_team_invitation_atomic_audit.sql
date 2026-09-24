-- Invitation mutations and both admin/tenant audit records commit together.
-- The Edge Function may read invitations but cannot bypass this function with
-- direct service-role DML. Acceptance retains its existing audited DB RPC.
-- The earlier live-slot trigger used transaction-start now(), while mutation
-- expiry checks use wall-clock time. A long transaction could re-mark a
-- revoked or expired row live. Keep both sides on the same DB clock.
create or replace function public.sync_team_invitation_live_slot()
returns trigger
language plpgsql
set search_path = pg_catalog, public, pg_temp
as $$
begin
  new.live_slot := new.accepted_at is null and new.expires_at > clock_timestamp();
  return new;
end;
$$;

create function public.mutate_team_invitation(
  p_action text,
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_email text,
  p_role text,
  p_invitation_id uuid,
  p_token_hash text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_invite public.team_invitations;
  v_now timestamptz;
  v_event_id uuid := gen_random_uuid();
  v_action text;
  v_result jsonb;
  v_detail jsonb;
begin
  if p_action is null or p_action not in ('create', 'resend', 'revoke')
     or p_tenant_id is null or p_actor_user_id is null then
    raise exception 'invalid_invitation_request' using errcode = '22023';
  end if;

  -- Lock the authorization rows so role removal or tenant suspension cannot
  -- commit between this check and the invitation mutation.
  perform 1
    from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
    join public.teams team on team.id = t.id
   where m.tenant_id = p_tenant_id
     and m.user_id = p_actor_user_id
     and m.role in ('owner', 'admin')
     and (m.expires_at is null or m.expires_at > clock_timestamp())
     and t.status = 'active'
   for share of m, t, team;
  if not found then
    raise exception 'invitation_forbidden' using errcode = '42501';
  end if;
  v_now := clock_timestamp();

  if p_action = 'create' then
    if p_email is null or length(p_email) > 254
       or p_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
       or p_role is null or p_role not in ('admin', 'member', 'viewer')
       or p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$' then
      raise exception 'invalid_invitation_request' using errcode = '22023';
    end if;
    update public.team_invitations
       set live_slot = false
     where tenant_id = p_tenant_id
       and lower(email) = lower(p_email)
       and accepted_at is null
       and expires_at <= v_now
       and live_slot;
    insert into public.team_invitations
      (tenant_id, email, role, token_hash, created_by, expires_at, live_slot)
    values
      (p_tenant_id, lower(p_email), p_role, p_token_hash, p_actor_user_id,
       v_now + interval '7 days', true)
    returning * into v_invite;
    v_action := 'team.invitation_created';
    v_result := jsonb_build_object('id', v_invite.id, 'expires_at', v_invite.expires_at);
  elsif p_action = 'resend' then
    if p_invitation_id is null then
      raise exception 'invalid_invitation_request' using errcode = '22023';
    end if;
    if p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$' then
      raise exception 'invalid_invitation_request' using errcode = '22023';
    end if;
    update public.team_invitations
       set token_hash = p_token_hash,
           expires_at = v_now + interval '7 days',
           created_by = p_actor_user_id,
           live_slot = true
     where tenant_id = p_tenant_id
       and id = p_invitation_id
       and accepted_at is null
       and expires_at > v_now
    returning * into v_invite;
    if not found then return null; end if;
    v_action := 'team.invitation_link_replaced';
    v_result := jsonb_build_object('id', v_invite.id, 'email', v_invite.email,
                                   'role', v_invite.role, 'expires_at', v_invite.expires_at);
  else
    if p_invitation_id is null then
      raise exception 'invalid_invitation_request' using errcode = '22023';
    end if;
    update public.team_invitations
       set expires_at = v_now, live_slot = false
     where tenant_id = p_tenant_id
       and id = p_invitation_id
       and accepted_at is null
       and expires_at > v_now
    returning * into v_invite;
    if not found then return null; end if;
    v_action := 'team.invitation_revoked';
    v_result := jsonb_build_object('id', v_invite.id);
  end if;

  v_detail := jsonb_build_object('event_id', v_event_id,
                                 'invitation_id', v_invite.id, 'role', v_invite.role);
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
  values (p_actor_user_id, p_tenant_id, v_action, v_detail);
  insert into public.audit_logs(team_id, tenant_id, user_id, action, verdict)
  values (p_tenant_id, p_tenant_id, p_actor_user_id, v_action, v_detail);
  return v_result;
end;
$$;

revoke all on function public.mutate_team_invitation(text, uuid, uuid, text, text, uuid, text)
  from public, anon, authenticated;
grant execute on function public.mutate_team_invitation(text, uuid, uuid, text, text, uuid, text)
  to service_role;

revoke insert, update, delete, truncate on public.team_invitations from service_role;
