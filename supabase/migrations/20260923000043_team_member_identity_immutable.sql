-- team_members is mirrored to tenant_members. Rebinding a row's identity would
-- upsert the new canonical member while leaving the old member authorized.
-- A role change or removal must retain the same team/user key; use explicit
-- delete + insert for any legitimate membership lifecycle operation.
create or replace function app.prevent_team_member_identity_change()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if tg_table_schema <> 'public' or tg_table_name <> 'team_members'
     or tg_op <> 'UPDATE' then
    raise exception 'team member identity guard attached to unsupported operation'
      using errcode = '55000';
  end if;
  if old.team_id is distinct from new.team_id
     or old.tenant_id is distinct from new.tenant_id
     or old.user_id is distinct from new.user_id then
    raise exception 'team membership identity is immutable'
      using errcode = '42501';
  end if;
  return new;
end;
$$;

revoke all on function app.prevent_team_member_identity_change()
  from public, anon, authenticated, service_role;

drop trigger if exists team_members_identity_immutable on public.team_members;
create trigger team_members_identity_immutable
before update on public.team_members
for each row execute function app.prevent_team_member_identity_change();
