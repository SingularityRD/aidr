-- Run only in a disposable PostgreSQL database, never a deployed project.
-- Minimal dependencies isolate this migration from unrelated platform migrations.
\set ON_ERROR_STOP on
create role anon;
create role authenticated;
create role service_role;
create schema auth;
create table auth.users(id uuid primary key);
create table public.tenants(id uuid primary key, status text not null);
create table public.tenant_members(tenant_id uuid references public.tenants, user_id uuid references auth.users, role text, expires_at timestamptz, primary key(tenant_id,user_id));
create table public.admin_audit_logs(actor_user_id uuid references auth.users, tenant_id uuid references public.tenants, action text, detail jsonb);
\ir ../../migrations/20260916000005_dlp_policy_storage.sql

insert into auth.users values ('11111111-1111-4111-8111-111111111111'), ('44444444-4444-4444-8444-444444444444');
insert into public.tenants values ('22222222-2222-4222-8222-222222222222', 'active'), ('33333333-3333-4333-8333-333333333333', 'active');
insert into public.tenant_members values
  ('22222222-2222-4222-8222-222222222222', '11111111-1111-4111-8111-111111111111', 'owner', null),
  ('22222222-2222-4222-8222-222222222222', '44444444-4444-4444-8444-444444444444', 'viewer', null);

-- Test helper emits the normalized shape that the Edge schema sends to SQL.
create function public.test_dlp_policy(v bigint) returns jsonb language sql as $$
select jsonb_build_object('version', v, 'tenantId', '22222222-2222-4222-8222-222222222222',
  'maxContentBytes', 1048576, 'supportedFormats', jsonb_build_array('text/*','application/json'),
  'unavailableAction', 'block', 'labels', jsonb_build_array(jsonb_build_object(
    'id','secret','tenantId','22222222-2222-4222-8222-222222222222', 'name','Secret',
    'sensitivity','restricted','redactionToken','[REDACTED]')), 'rules','[]'::jsonb,'exceptions','[]'::jsonb);
$$;
create function public.test_dlp_save(expected bigint) returns public.tenant_dlp_policies language sql as $$
select public.publish_dlp_policy('22222222-2222-4222-8222-222222222222', '11111111-1111-4111-8111-111111111111', expected, public.test_dlp_policy(expected+1));
$$;

do $$
declare r public.tenant_dlp_policies; role_name text; table_name text;
begin
  foreach role_name in array array['anon','authenticated'] loop
    if has_function_privilege(role_name, 'public.publish_dlp_policy(uuid,uuid,bigint,jsonb)', 'EXECUTE') then raise exception 'browser RPC privilege'; end if;
    foreach table_name in array array['tenant_dlp_policies','dlp_policy_revisions'] loop
      if has_table_privilege(role_name, table_name, 'SELECT,INSERT,UPDATE,DELETE') then raise exception 'browser table privilege'; end if;
    end loop;
  end loop;
  if has_table_privilege('service_role','dlp_policy_revisions','INSERT,UPDATE,DELETE') then raise exception 'history mutable outside RPC'; end if;
  if has_table_privilege('service_role','tenant_dlp_policies','INSERT,UPDATE,DELETE') then raise exception 'current mutable outside RPC'; end if;
  if not has_function_privilege('service_role','public.publish_dlp_policy(uuid,uuid,bigint,jsonb)','EXECUTE') then raise exception 'RPC not granted'; end if;
  if (select count(*) from pg_class where relname in ('tenant_dlp_policies','dlp_policy_revisions') and relrowsecurity) <> 2 then raise exception 'RLS missing'; end if;
  select * into r from public.test_dlp_save(0);
  if r.version <> 1 or r.policy <> public.test_dlp_policy(1) then raise exception 'wrong v1'; end if;
  if (select count(*) from public.dlp_policy_revisions) <> 1 then raise exception 'missing history'; end if;
  if (select count(*) from public.admin_audit_logs where action='dlp_policy.save' and detail->>'delivery_status'='not_delivered') <> 1 then raise exception 'missing audit'; end if;
  begin
    perform public.test_dlp_save(0);
    raise exception 'stale CAS accepted';
  exception when sqlstate 'PT409' then null; end;
  begin
    perform public.publish_dlp_policy('33333333-3333-4333-8333-333333333333','11111111-1111-4111-8111-111111111111',0,public.test_dlp_policy(1));
    raise exception 'foreign tenant accepted';
  exception when insufficient_privilege then null; end;
  begin
    perform public.publish_dlp_policy('22222222-2222-4222-8222-222222222222','44444444-4444-4444-8444-444444444444',1,public.test_dlp_policy(2));
    raise exception 'viewer accepted';
  exception when insufficient_privilege then null; end;
  begin
    perform public.publish_dlp_policy('22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111',1,
      jsonb_set(public.test_dlp_policy(2),'{labels,0,tenantId}','"33333333-3333-4333-8333-333333333333"'));
    raise exception 'foreign label accepted';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.publish_dlp_policy('22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111',1,public.test_dlp_policy(500));
    raise exception 'client version jump accepted';
  exception when invalid_parameter_value then null; end;
  update public.tenant_members set expires_at = now() - interval '1 second' where role='owner';
  begin
    perform public.test_dlp_save(1);
    raise exception 'expired membership accepted';
  exception when insufficient_privilege then null; end;
  update public.tenant_members set expires_at = null where role='owner';
  update public.tenants set status='suspended';
  begin
    perform public.test_dlp_save(1);
    raise exception 'suspended tenant accepted';
  exception when insufficient_privilege then null; end;
  update public.tenants set status='active';
  if (select count(*) from public.dlp_policy_revisions) <> 1 then raise exception 'denied write left history'; end if;
end;
$$;

-- Force failures AFTER the current-row upsert: each must roll back everything.
create function public.test_dlp_write_failure() returns trigger language plpgsql as $$
begin raise exception 'injected_write_failure' using errcode='P0002'; end;
$$;
create trigger reject_history before insert on public.dlp_policy_revisions for each row execute function public.test_dlp_write_failure();
do $$ begin
  begin perform public.test_dlp_save(1); raise exception 'history failure succeeded';
  exception when sqlstate 'P0002' then null; end;
  if (select version from public.tenant_dlp_policies) <> 1 or (select count(*) from public.dlp_policy_revisions) <> 1 or (select count(*) from public.admin_audit_logs) <> 1 then raise exception 'history failure partially committed'; end if;
end $$;
drop trigger reject_history on public.dlp_policy_revisions;
create trigger reject_audit before insert on public.admin_audit_logs for each row execute function public.test_dlp_write_failure();
do $$ begin
  begin perform public.test_dlp_save(1); raise exception 'audit failure succeeded';
  exception when sqlstate 'P0002' then null; end;
  if (select version from public.tenant_dlp_policies) <> 1 or (select count(*) from public.dlp_policy_revisions) <> 1 or (select count(*) from public.admin_audit_logs) <> 1 then raise exception 'audit failure partially committed'; end if;
end $$;
drop trigger reject_audit on public.admin_audit_logs;
select 'DLP migration SQL contracts passed' as result;
