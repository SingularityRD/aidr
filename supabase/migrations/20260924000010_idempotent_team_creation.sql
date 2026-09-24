-- A lost RPC response must not create a second workspace when onboarding is
-- retried. Idempotency is scoped to one explicit request, not one user: the
-- same user may create any number of workspaces using distinct request IDs.
create table if not exists public.team_creation_requests (
  actor_user_id uuid not null references auth.users (id) on delete cascade,
  request_id uuid not null,
  requested_name text not null,
  team_id uuid not null references public.teams (id) on delete cascade,
  created_at timestamptz not null default clock_timestamp(),
  primary key (actor_user_id, request_id)
);

alter table public.team_creation_requests enable row level security;
revoke all on table public.team_creation_requests from public, anon, authenticated, service_role;

-- Replace the old two-argument entry point so every caller supplies the
-- idempotency key. The defaulted plan remains third for PostgREST callers.
drop function if exists public.create_team_tenant(text, text);
create function public.create_team_tenant(
  p_name text,
  p_request_id uuid,
  p_plan text default 'free'
)
returns public.teams
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_user_id uuid := auth.uid();
  v_team_id uuid;
  v_existing_name text;
  v_team public.teams;
begin
  if v_user_id is null or auth.role() is distinct from 'authenticated' then
    raise exception 'authentication required' using errcode = '28000';
  end if;
  if nullif(trim(p_name), '') is null or length(trim(p_name)) > 200 then
    raise exception 'team name is required and must not exceed 200 characters'
      using errcode = '22023';
  end if;
  if p_request_id is null then
    raise exception 'team creation request ID is required' using errcode = '22023';
  end if;
  if p_plan is distinct from 'free' then
    raise exception 'team plan is managed by billing' using errcode = '42501';
  end if;

  -- This lock also serializes creation with identity revocation. It does not
  -- make the user unique: only a replay of the same request ID is deduplicated.
  perform pg_advisory_xact_lock(hashtextextended(v_user_id::text, 2611));

  select r.team_id, r.requested_name
    into v_team_id, v_existing_name
    from public.team_creation_requests r
   where r.actor_user_id = v_user_id and r.request_id = p_request_id;
  if found then
    if v_existing_name <> trim(p_name) then
      raise exception 'team creation request ID was reused with a different name'
        using errcode = '22023';
    end if;
    if not public.tenant_identity_access_allowed(v_team_id) then
      raise exception 'identity barrier rejected' using errcode = '42501';
    end if;
    select * into v_team from public.teams where id = v_team_id;
    if not found then
      raise exception 'team creation request has no live workspace' using errcode = '55000';
    end if;
    return v_team;
  end if;

  v_team_id := gen_random_uuid();
  if not public.tenant_identity_access_allowed(v_team_id) then
    raise exception 'identity barrier rejected' using errcode = '42501';
  end if;

  insert into public.tenants (id, name, kind, created_by)
  values (v_team_id, trim(p_name), 'team', v_user_id);
  insert into public.teams (id, tenant_id, name, plan)
  values (v_team_id, v_team_id, trim(p_name), 'free');
  insert into public.team_members (team_id, tenant_id, user_id, role)
  values (v_team_id, v_team_id, v_user_id, 'owner');
  insert into public.team_creation_requests (actor_user_id, request_id, requested_name, team_id)
  values (v_user_id, p_request_id, trim(p_name), v_team_id);

  select * into strict v_team from public.teams where id = v_team_id;
  return v_team;
end;
$$;
revoke all on function public.create_team_tenant(text, uuid, text) from public, anon;
grant execute on function public.create_team_tenant(text, uuid, text) to authenticated;
