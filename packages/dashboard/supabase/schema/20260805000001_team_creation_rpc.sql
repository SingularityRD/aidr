-- Atomic team/tenant creation for the hybrid tenancy model.
--
-- The dashboard must not create a tenant, team, and first membership in
-- separate client-side requests: a partial failure would leave an orphaned
-- tenant or a team that cannot be selected.  This invoker function keeps all
-- three writes in one transaction and derives the creator from auth.uid().

create or replace function public.create_team_tenant(
  p_name text,
  p_plan text default 'free'
)
returns public.teams
language plpgsql
security invoker
set search_path = public
as $$
declare
  v_user_id uuid := auth.uid();
  v_team_id uuid := gen_random_uuid();
  v_team public.teams;
begin
  if v_user_id is null then
    raise exception 'authentication required' using errcode = '28000';
  end if;

  if nullif(trim(p_name), '') is null then
    raise exception 'team name is required' using errcode = '22023';
  end if;

  if p_plan not in ('free', 'pro', 'enterprise') then
    raise exception 'unsupported team plan' using errcode = '22023';
  end if;

  insert into public.tenants (id, name, kind, created_by)
  values (v_team_id, trim(p_name), 'team', v_user_id);

  insert into public.teams (id, tenant_id, name, plan)
  values (v_team_id, v_team_id, trim(p_name), p_plan);

  insert into public.team_members (team_id, tenant_id, user_id, role)
  values (v_team_id, v_team_id, v_user_id, 'admin');

  select * into strict v_team
  from public.teams
  where id = v_team_id;

  return v_team;
end;
$$;

revoke all on function public.create_team_tenant(text, text) from public, anon;
grant execute on function public.create_team_tenant(text, text) to authenticated;
