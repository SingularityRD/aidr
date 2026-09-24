-- Cloud self-signup supplies a display name for the auto-created team.
-- Keep SCIM/SAML bootstrap closed and leave non-cloud naming unchanged.
create or replace function public.handle_new_user_team()
returns trigger language plpgsql security definer set search_path = public, pg_catalog as $$
declare
  v_team_id uuid := gen_random_uuid();
  v_name text;
begin
  if new.raw_app_meta_data ->> 'aidr_scim_provisioned' = 'true'
     or new.raw_app_meta_data ->> 'provider' like 'sso:%' then return new; end if;

  v_name := coalesce(nullif(new.raw_user_meta_data ->> 'full_name', ''), 'Personal');
  if (select mode from app.tenant_admission_config where singleton) = 'cloud'
     and coalesce(new.raw_user_meta_data, '{}'::jsonb) ? 'workspace_name' then
    if jsonb_typeof(new.raw_user_meta_data -> 'workspace_name') <> 'string'
       or length(btrim(new.raw_user_meta_data ->> 'workspace_name')) not between 1 and 200
       or (new.raw_user_meta_data ->> 'workspace_name') ~ '[[:cntrl:]]' then
      raise exception 'invalid_workspace_name' using errcode = '22023';
    end if;
    v_name := btrim(new.raw_user_meta_data ->> 'workspace_name');
  end if;

  insert into public.tenants (id, name, kind, created_by)
  values (v_team_id, v_name, 'team', new.id);
  insert into public.teams (id, tenant_id, name)
  values (v_team_id, v_team_id, v_name);
  insert into public.team_members (team_id, tenant_id, user_id, role)
  values (v_team_id, v_team_id, new.id, 'owner');
  return new;
end;
$$;
revoke all on function public.handle_new_user_team() from public, anon, authenticated;
