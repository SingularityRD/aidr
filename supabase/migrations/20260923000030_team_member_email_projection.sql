-- The browser cannot join public.team_members to auth.users. Expose only the
-- selected team's member contact fields to its active owner/administrators.
create function public.list_team_members_with_email(p_team_id uuid)
returns table (
  id uuid,
  user_id uuid,
  role text,
  email text,
  avatar_url text,
  invited_by uuid,
  joined_at timestamptz
)
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_tenant_id uuid;
begin
  select t.tenant_id into v_tenant_id
  from public.teams t
  join public.tenants tenant on tenant.id = t.tenant_id
  where t.id = p_team_id and tenant.status = 'active';

  if auth.role() is distinct from 'authenticated'
     or auth.uid() is null
     or v_tenant_id is null
     or not exists (
       select 1 from public.team_members caller
       where caller.team_id = p_team_id
         and caller.tenant_id = v_tenant_id
         and caller.user_id = auth.uid()
         and caller.role in ('owner', 'admin')
     )
     or not exists (
       select 1 from public.tenant_members caller
       where caller.tenant_id = v_tenant_id
         and caller.user_id = auth.uid()
         and caller.role in ('owner', 'admin')
         and (caller.expires_at is null or caller.expires_at > now())
     )
     or not public.tenant_identity_access_allowed(v_tenant_id)
  then
    raise exception 'team_member_email_access_denied' using errcode = '42501';
  end if;

  return query
    select m.id, m.user_id, m.role, u.email::text,
      nullif(u.raw_user_meta_data ->> 'avatar_url', ''),
      m.invited_by, m.joined_at
    from public.team_members m
    join auth.users u on u.id = m.user_id
    where m.team_id = p_team_id and m.tenant_id = v_tenant_id
    order by m.joined_at, m.id;
end;
$$;

revoke all on function public.list_team_members_with_email(uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.list_team_members_with_email(uuid) to authenticated;
