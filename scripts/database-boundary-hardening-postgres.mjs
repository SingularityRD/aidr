// Run after `supabase start && supabase db reset --local --no-seed`:
//   AIDR_RLS_TEST_DB_CONTAINER=supabase_db_aidr node scripts/database-boundary-hardening-postgres.mjs
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";

const container = process.env.AIDR_RLS_TEST_DB_CONTAINER;
assert.ok(container, "AIDR_RLS_TEST_DB_CONTAINER must name the disposable Supabase db container");
assert.match(container, /^[A-Za-z0-9_.-]+$/, "invalid Docker container name");

const user = randomUUID();
const member = randomUUID();
const outsider = randomUUID();
const teamAgent = randomUUID();
const personalAgent = randomUUID();
const outsideAgent = randomUUID();
const pendingSession = randomUUID();
const marker = randomUUID().replaceAll("-", "");
const now = Math.floor(Date.now() / 1000);
const sql = String.raw`
\set ON_ERROR_STOP on
begin;
select public.configure_tenant_admission_mode('pilot');

do $$ begin
  if has_table_privilege('authenticated', 'public.teams', 'INSERT')
    or has_table_privilege('authenticated', 'public.teams', 'UPDATE')
    or has_table_privilege('authenticated', 'public.teams', 'DELETE')
    or has_table_privilege('authenticated', 'public.teams', 'TRUNCATE')
    or has_table_privilege('authenticated', 'public.audit_logs', 'INSERT')
    or has_table_privilege('authenticated', 'public.audit_logs', 'TRUNCATE')
    or has_table_privilege('authenticated', 'public.team_members', 'TRUNCATE')
    or has_table_privilege('authenticated', 'public.team_policies', 'TRUNCATE')
  then raise exception 'browser role retains a forbidden table privilege'; end if;
  if not has_table_privilege('authenticated', 'public.teams', 'SELECT')
    or not has_table_privilege('authenticated', 'public.audit_logs', 'SELECT')
    or not has_table_privilege('authenticated', 'public.team_members', 'SELECT')
    or not has_column_privilege('authenticated', 'public.team_members', 'role', 'UPDATE')
  then raise exception 'browser allowlist is incomplete'; end if;
  if has_schema_privilege('authenticated', 'public', 'CREATE')
    or has_schema_privilege('authenticated', 'app', 'CREATE')
  then raise exception 'browser role can create objects in a trusted schema'; end if;
  if has_function_privilege('authenticated', 'public.increment_rate_limit(text,bigint,integer)', 'EXECUTE')
    or has_function_privilege('anon', 'public.create_team_tenant(text,uuid,text)', 'EXECUTE')
  then raise exception 'browser role retains a forbidden function privilege'; end if;
  if not has_function_privilege('authenticated', 'public.create_team_tenant(text,uuid,text)', 'EXECUTE')
    or not has_function_privilege('authenticated', 'public.tenant_identity_access_allowed(uuid)', 'EXECUTE')
    or not has_function_privilege('authenticated', 'app.current_tenant_id()', 'EXECUTE')
  then raise exception 'browser function allowlist is incomplete'; end if;
  if not exists (
    select 1 from pg_constraint
    where conrelid = 'public.teams'::regclass and conname = 'teams_tenant_matches_id'
      and pg_get_constraintdef(oid) ~ 'tenant_id = id'
  ) then raise exception 'teams tenant identity constraint is missing'; end if;
  if not exists (
    select 1 from pg_policies
    where schemaname = 'storage' and tablename = 'objects'
      and policyname = 'audit_exports_read_own_tenant'
      and qual like '%tenant_identity_access_allowed%'
  ) then raise exception 'audit export identity barrier is missing'; end if;
end $$;

insert into auth.users(id, email, aud, role, instance_id, raw_app_meta_data, raw_user_meta_data)
values ('${user}', 'db-boundary-${marker}@example.invalid', 'authenticated', 'authenticated',
  '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb);
select set_config('request.jwt.claim.sub', '${user}', true);
select set_config('request.jwt.claims', '{"sub":"${user}","role":"authenticated","aal":"aal2","iat":${now}}', true);
set session authorization authenticator;
set role authenticated;

do $$ begin
  begin
    perform public.create_team_tenant('Paid ${marker}', gen_random_uuid(), 'enterprise');
    raise exception 'authenticated caller self-selected a paid plan';
  exception when insufficient_privilege then null;
  end;
  begin
    truncate public.audit_logs;
    raise exception 'authenticated caller truncated audit logs';
  exception when insufficient_privilege then null;
  end;
end $$;

select set_config('aidr.test.create_request', gen_random_uuid()::text, true);
select set_config(
  'aidr.test.new_team',
  (public.create_team_tenant('Free ${marker}', current_setting('aidr.test.create_request')::uuid, 'free')).id::text,
  true
);
do $$ declare v_replay public.teams; v_second public.teams; begin
  v_replay := public.create_team_tenant(
    'Free ${marker}', current_setting('aidr.test.create_request')::uuid, 'free'
  );
  if v_replay.id::text <> current_setting('aidr.test.new_team') then
    raise exception 'same request ID created a second workspace';
  end if;
  begin
    perform public.create_team_tenant(
      'Different ${marker}', current_setting('aidr.test.create_request')::uuid, 'free'
    );
    raise exception 'request ID with a changed name was accepted';
  exception when invalid_parameter_value then null;
  end;
  v_second := public.create_team_tenant('Second ${marker}', gen_random_uuid(), 'free');
  if v_second.id = v_replay.id then raise exception 'a distinct request ID was deduplicated'; end if;
end $$;
reset role;
reset session authorization;
select set_config('request.jwt.claim.role', '', true);
select set_config('request.jwt.claim.sub', '', true);
select set_config('request.jwt.claims', '{}', true);

-- Exercise an ordinary Auth JWT without a tenant_id claim. It still selects
-- the member's personal tenant, while team reads must use row membership.
insert into auth.users(id, email, aud, role, instance_id, raw_app_meta_data, raw_user_meta_data)
values
  ('${member}', 'db-team-member-${marker}@example.invalid', 'authenticated', 'authenticated',
   '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${outsider}', 'db-team-outsider-${marker}@example.invalid', 'authenticated', 'authenticated',
   '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb);
select set_config('aidr.test.outside_team', (
  select team_id::text from public.team_members where user_id = '${outsider}' limit 1
), true);
insert into public.team_members(team_id, tenant_id, user_id, role)
values (current_setting('aidr.test.new_team')::uuid,
        current_setting('aidr.test.new_team')::uuid, '${member}', 'viewer');
insert into public.pilot_applications(user_id, tenant_id, status, cohort) values
  ('${user}', current_setting('aidr.test.new_team')::uuid, 'approved', 'fixture'),
  ('${member}', '${member}', 'approved', 'fixture'),
  ('${outsider}', current_setting('aidr.test.outside_team')::uuid, 'approved', 'fixture')
on conflict (user_id, tenant_id) do update set status = 'approved';
insert into public.agents(id, user_id, tenant_id, iid) values
  ('${teamAgent}', '${user}', current_setting('aidr.test.new_team')::uuid, 'team-${marker}'),
  ('${personalAgent}', '${member}', '${member}', 'personal-${marker}'),
  ('${outsideAgent}', '${outsider}', current_setting('aidr.test.outside_team')::uuid, 'outside-${marker}');
insert into public.events(user_id, tenant_id, agent_id, event_id, type, payload) values
  ('${user}', current_setting('aidr.test.new_team')::uuid, '${teamAgent}', 'team:${marker}', 'incident_record', '{}'::jsonb),
  ('${member}', '${member}', '${personalAgent}', 'personal:${marker}', 'rls-test', '{}'::jsonb),
  ('${outsider}', current_setting('aidr.test.outside_team')::uuid, '${outsideAgent}', 'outside:${marker}', 'incident_record', '{}'::jsonb);
insert into public.team_policies(team_id, tenant_id, content, updated_by) values
  (current_setting('aidr.test.new_team')::uuid, current_setting('aidr.test.new_team')::uuid, 'team-${marker}', '${user}'),
  (current_setting('aidr.test.outside_team')::uuid, current_setting('aidr.test.outside_team')::uuid, 'outside-${marker}', '${outsider}');
insert into public.audit_logs(team_id, tenant_id, user_id, action) values
  (current_setting('aidr.test.new_team')::uuid, current_setting('aidr.test.new_team')::uuid, '${user}', 'rls.team'),
  (current_setting('aidr.test.outside_team')::uuid, current_setting('aidr.test.outside_team')::uuid, '${outsider}', 'rls.outside');

select set_config('request.jwt.claim.tenant_id', '', true);
select set_config('request.jwt.claim.sub', '${member}', true);
select set_config('request.jwt.claims', '{"sub":"${member}","role":"authenticated","aal":"aal2","iat":${now}}', true);
set session authorization authenticator;
set role authenticated;
do $$ begin
  if app.current_tenant_id() is distinct from '${member}'::uuid
    or (select count(*) from public.agents where tenant_id = current_setting('aidr.test.new_team')::uuid) <> 1
    or (select count(*) from public.events where tenant_id = current_setting('aidr.test.new_team')::uuid) <> 1
    or (select count(*) from public.incident_events where tenant_id = current_setting('aidr.test.new_team')::uuid) <> 1
    or (select count(*) from public.team_policies where tenant_id = current_setting('aidr.test.new_team')::uuid) <> 1
    or (select count(*) from public.audit_logs where tenant_id = current_setting('aidr.test.new_team')::uuid and action = 'rls.team') <> 1
  then raise exception 'ordinary member JWT cannot read selected team'; end if;
  if (select count(*) from public.agents where tenant_id = '${member}') <> 1
    or (select count(*) from public.events where tenant_id = '${member}') <> 1
    or exists (select 1 from public.agents where tenant_id = current_setting('aidr.test.outside_team')::uuid)
    or exists (select 1 from public.events where tenant_id = current_setting('aidr.test.outside_team')::uuid)
    or exists (select 1 from public.incident_events where tenant_id = current_setting('aidr.test.outside_team')::uuid)
    or exists (select 1 from public.team_policies where tenant_id = current_setting('aidr.test.outside_team')::uuid)
    or exists (select 1 from public.audit_logs where tenant_id = current_setting('aidr.test.outside_team')::uuid)
  then raise exception 'personal or foreign tenant isolation failed'; end if;
end $$;
reset role;
reset session authorization;

select set_config('request.jwt.claim.sub', '${outsider}', true);
select set_config('request.jwt.claims', '{"sub":"${outsider}","role":"authenticated","aal":"aal2","iat":${now}}', true);
set session authorization authenticator;
set role authenticated;
do $$ begin
  if exists (select 1 from public.agents where tenant_id = current_setting('aidr.test.new_team')::uuid)
    or exists (select 1 from public.events where tenant_id = current_setting('aidr.test.new_team')::uuid)
    or exists (select 1 from public.incident_events where tenant_id = current_setting('aidr.test.new_team')::uuid)
    or exists (select 1 from public.team_policies where tenant_id = current_setting('aidr.test.new_team')::uuid)
    or exists (select 1 from public.audit_logs where tenant_id = current_setting('aidr.test.new_team')::uuid)
    or (select count(*) from public.agents where tenant_id = current_setting('aidr.test.outside_team')::uuid) <> 1
  then raise exception 'nonmember gained team data or lost own data'; end if;
end $$;
reset role;
reset session authorization;

select set_config('request.jwt.claim.sub', '${member}', true);
insert into public.tenant_identity_policies(tenant_id, require_mfa)
values (current_setting('aidr.test.new_team')::uuid, true);
select set_config('request.jwt.claims', '{"sub":"${member}","role":"authenticated","aal":"aal1","iat":${now}}', true);
set session authorization authenticator;
set role authenticated;
do $$ begin
  if exists (select 1 from public.agents where tenant_id = current_setting('aidr.test.new_team')::uuid)
    or exists (select 1 from public.events where tenant_id = current_setting('aidr.test.new_team')::uuid)
    or exists (select 1 from public.incident_events where tenant_id = current_setting('aidr.test.new_team')::uuid)
    or exists (select 1 from public.team_policies where tenant_id = current_setting('aidr.test.new_team')::uuid)
    or exists (select 1 from public.audit_logs where tenant_id = current_setting('aidr.test.new_team')::uuid)
    or (select count(*) from public.agents where tenant_id = '${member}') <> 1
  then raise exception 'team MFA barrier or personal read failed'; end if;
end $$;
reset role;
reset session authorization;
select set_config('request.jwt.claim.role', '', true);
select set_config('request.jwt.claim.sub', '', true);
select set_config('request.jwt.claims', '{}', true);

delete from public.tenant_identity_policies
  where tenant_id = current_setting('aidr.test.new_team')::uuid;
delete from public.team_members
  where team_id = current_setting('aidr.test.new_team')::uuid and user_id = '${member}';
select set_config('request.jwt.claims', '{"sub":"${member}","role":"authenticated","aal":"aal2","iat":${now}}', true);
set session authorization authenticator;
set role authenticated;
do $$ begin
  if exists (select 1 from public.agents where tenant_id = current_setting('aidr.test.new_team')::uuid)
    or exists (select 1 from public.events where tenant_id = current_setting('aidr.test.new_team')::uuid)
    or exists (select 1 from public.incident_events where tenant_id = current_setting('aidr.test.new_team')::uuid)
    or exists (select 1 from public.team_policies where tenant_id = current_setting('aidr.test.new_team')::uuid)
    or exists (select 1 from public.audit_logs where tenant_id = current_setting('aidr.test.new_team')::uuid)
    or (select count(*) from public.agents where tenant_id = '${member}') <> 1
  then raise exception 'removed team member retained access or lost personal access'; end if;
end $$;
reset role;
reset session authorization;

insert into public.identity_user_session_state(user_id, revoked_before, reason)
values ('${user}', to_timestamp(${now + 60}), 'user_global_signout')
on conflict (user_id) do update
set revoked_before = excluded.revoked_before,
    reason = excluded.reason,
    global_revoke_pending_session_id = null,
    global_revoke_pending_at = null;
select set_config('request.jwt.claim.sub', '${user}', true);
select set_config('request.jwt.claims', '{"sub":"${user}","role":"authenticated","aal":"aal2","iat":${now}}', true);
set session authorization authenticator;
set role authenticated;
do $$ begin
  begin
    perform public.create_team_tenant('Revoked ${marker}', gen_random_uuid(), 'free');
    raise exception 'revoked JWT created a team through SECURITY DEFINER';
  exception when insufficient_privilege then null;
  end;
end $$;
reset role;
reset session authorization;

update public.identity_user_session_state
set revoked_before = to_timestamp(${now - 60}),
    global_revoke_pending_session_id = '${pendingSession}',
    global_revoke_pending_at = clock_timestamp()
where user_id = '${user}';
select set_config('request.jwt.claim.sub', '${user}', true);
select set_config('request.jwt.claims', '{"sub":"${user}","role":"authenticated","aal":"aal2","iat":${now + 60}}', true);
set session authorization authenticator;
set role authenticated;
do $$ begin
  begin
    perform public.create_team_tenant('Pending ${marker}', gen_random_uuid(), 'free');
    raise exception 'pending-revocation JWT created a team through SECURITY DEFINER';
  exception when insufficient_privilege then null;
  end;
end $$;
reset role;
reset session authorization;

do $$ begin
  if not exists (
    select 1 from public.teams t
    join public.team_members m on m.team_id = t.id and m.tenant_id = t.tenant_id
    where t.id = current_setting('aidr.test.new_team')::uuid
      and t.tenant_id = t.id and t.plan = 'free'
      and m.user_id = '${user}' and m.role = 'owner'
  ) then raise exception 'free team was not created with an owner and stable tenant identity'; end if;
  if exists (
    select 1 from public.tenants
    where name in ('Revoked ${marker}', 'Pending ${marker}')
  ) then raise exception 'identity barrier rejection left team rows behind'; end if;
end $$;

rollback;
select 'DATABASE_BOUNDARY_HARDENING_ROLLBACK';
`;

const result = spawnSync("docker", [
	"exec", "-i", "-e", "PGPASSWORD=postgres", container, "psql", "-X", "-v", "ON_ERROR_STOP=1",
	"-U", "supabase_admin", "-d", "postgres", "-q", "-At",
], { input: sql, encoding: "utf8", maxBuffer: 4 * 1024 * 1024, timeout: 120_000 });
if (result.error) throw result.error;
assert.equal(result.status, 0, `database boundary regression failed:\n${result.stdout}\n${result.stderr}`);
assert.match(result.stdout, /DATABASE_BOUNDARY_HARDENING_ROLLBACK/);
console.log("Database boundary regression passed: ACL, ordinary team JWT reads, nonmember isolation, MFA, revocation, plan, owner bootstrap, tenant identity, audit and export checks; transaction rolled back.");
