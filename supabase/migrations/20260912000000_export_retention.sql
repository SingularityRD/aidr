-- Private export files have a bounded lifecycle independent of immutable audit records.
create table public.audit_export_objects (
  path text primary key,
  tenant_id uuid not null references public.tenants(id),
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '1 day',
  check (path ~ '^[0-9a-f-]{36}/[0-9a-f-]{36}\.(csv|json)$'),
  check (split_part(path, '/', 1) = tenant_id::text)
);
create index audit_export_objects_expiry on public.audit_export_objects(expires_at, path);
create index audit_logs_export_cursor on public.audit_logs(tenant_id, created_at, id);
alter table public.audit_export_objects enable row level security;
revoke all on public.audit_export_objects from public, anon, authenticated;
grant select, insert, delete on public.audit_export_objects to service_role;

-- Publication/rollback audit participates in the same transaction as the policy.
create function app.audit_runtime_policy_publication() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  insert into public.audit_logs(team_id,tenant_id,user_id,action,verdict)
  select new.tenant_id,new.tenant_id,new.updated_by,'policy.publish',jsonb_build_object('version',new.version)
  where exists(select 1 from public.teams where id=new.tenant_id);
  insert into public.admin_audit_logs(actor_user_id,tenant_id,action,detail)
  values(new.updated_by,new.tenant_id,'policy.publish',jsonb_build_object('version',new.version));
  return new;
end;
$$;
revoke all on function app.audit_runtime_policy_publication() from public, anon, authenticated;
create trigger runtime_policy_publication_audit after insert or update on public.tenant_runtime_policies
for each row execute function app.audit_runtime_policy_publication();
