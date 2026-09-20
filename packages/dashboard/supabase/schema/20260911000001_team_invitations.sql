create table public.team_invitations (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id),
  email text not null,
  role text not null check(role in ('admin', 'member', 'viewer')),
  token_hash text not null unique,
  created_by uuid not null references auth.users(id),
  expires_at timestamptz not null default now() + interval '7 days',
  accepted_at timestamptz,
  created_at timestamptz not null default now()
);
alter table public.team_invitations enable row level security;
revoke all on public.team_invitations from anon, authenticated;
grant select, insert, update on public.team_invitations to service_role;

create function public.accept_team_invitation(p_hash text, p_user_id uuid)
returns uuid language plpgsql security definer set search_path = public, pg_temp as $$
declare invite public.team_invitations; verified_email text;
begin
  select lower(email) into verified_email from auth.users where id = p_user_id and email_confirmed_at is not null;
  select * into invite from public.team_invitations where token_hash = p_hash for update;
  if invite.id is null or verified_email is null or verified_email <> invite.email or invite.accepted_at is not null or invite.expires_at <= now() then
    raise exception 'invalid_invitation' using errcode = '42501';
  end if;
  if not exists(select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = invite.tenant_id and m.user_id = invite.created_by and m.role in ('owner','admin')
      and (m.expires_at is null or m.expires_at > now()) and t.status = 'active') then
    raise exception 'invitation_revoked' using errcode = '42501';
  end if;
  -- An existing member never acquires a higher role from a duplicate invitation.
  insert into public.team_members(team_id, tenant_id, user_id, role, invited_by)
  values(invite.tenant_id, invite.tenant_id, p_user_id, invite.role, invite.created_by)
  on conflict(team_id, user_id) do nothing;
  update public.team_invitations set accepted_at = now() where id = invite.id;
  insert into public.audit_logs(team_id, tenant_id, user_id, action, verdict)
  values(invite.tenant_id, invite.tenant_id, p_user_id, 'member.invitation_accepted', jsonb_build_object('invitation_id', invite.id));
  return invite.tenant_id;
end;
$$;
revoke all on function public.accept_team_invitation(text, uuid) from public, anon, authenticated;
grant execute on function public.accept_team_invitation(text, uuid) to service_role;

insert into storage.buckets(id, name, public) values ('aidr-audit-exports','aidr-audit-exports',false) on conflict(id) do nothing;
