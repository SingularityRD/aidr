// Run after the local Supabase migration reset. Fixtures are rolled back.
// AIDR_RLS_TEST_DB_CONTAINER=supabase_db_aidr node scripts/team-member-email-projection-postgres.mjs
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";

const container = process.env.AIDR_RLS_TEST_DB_CONTAINER;
assert.ok(container, "AIDR_RLS_TEST_DB_CONTAINER must name the disposable Supabase db container");
assert.match(container, /^[A-Za-z0-9_.-]+$/, "invalid Docker container name");

const [ownerA, adminA, viewerA, ownerB, teamA, teamB] = Array.from({ length: 6 }, () => randomUUID());
const marker = randomUUID().replaceAll("-", "");
const now = Math.floor(Date.now() / 1000);
const context = (user, aal = "aal2") => `
select set_config('request.jwt.claim.sub', '${user}', true);
select set_config('request.jwt.claim.role', 'authenticated', true);
select set_config('request.jwt.claim.tenant_id', '', true);
select set_config('request.jwt.claims', '{"sub":"${user}","role":"authenticated","aal":"${aal}","iat":${now}}', true);
set role authenticated;
`;
const deny = (team, label) => `
do $$ begin
  begin
    perform public.list_team_members_with_email('${team}');
    raise exception '${label} unexpectedly read team member emails';
  exception when sqlstate '42501' then
    if sqlerrm <> 'team_member_email_access_denied' then raise; end if;
  end;
end $$;
`;

const sql = String.raw`
\set ON_ERROR_STOP on
begin;

do $$ begin
  if not has_function_privilege('authenticated', 'public.list_team_members_with_email(uuid)', 'EXECUTE')
     or has_function_privilege('anon', 'public.list_team_members_with_email(uuid)', 'EXECUTE')
     or has_function_privilege('service_role', 'public.list_team_members_with_email(uuid)', 'EXECUTE')
  then raise exception 'team member email RPC grants are not authenticated-only'; end if;
  if has_table_privilege('authenticated', 'auth.users', 'SELECT') then
    raise exception 'auth.users unexpectedly exposed to authenticated browser role';
  end if;
end $$;

insert into auth.users(id, email, aud, role, instance_id, raw_app_meta_data, raw_user_meta_data)
values
  ('${ownerA}', 'member-owner-a-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${adminA}', 'member-admin-a-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{"avatar_url":"https://avatar.example.invalid/admin.png"}'::jsonb),
  ('${viewerA}', 'member-viewer-a-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${ownerB}', 'member-owner-b-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb);
insert into public.tenants(id, name, kind, created_by)
values ('${teamA}', 'Projection A ${marker}', 'team', '${ownerA}'),
       ('${teamB}', 'Projection B ${marker}', 'team', '${ownerB}');
insert into public.teams(id, tenant_id, name)
values ('${teamA}', '${teamA}', 'Projection A ${marker}'),
       ('${teamB}', '${teamB}', 'Projection B ${marker}');
insert into public.team_members(team_id, tenant_id, user_id, role)
values ('${teamA}', '${teamA}', '${ownerA}', 'owner'),
       ('${teamA}', '${teamA}', '${adminA}', 'admin'),
       ('${teamA}', '${teamA}', '${viewerA}', 'viewer'),
       ('${teamB}', '${teamB}', '${ownerB}', 'owner');

${context(ownerA)}
do $$ begin
  if (select count(*) from public.list_team_members_with_email('${teamA}')) <> 3
     or not exists (
       select 1 from public.list_team_members_with_email('${teamA}')
       where user_id = '${adminA}'
         and email = 'member-admin-a-${marker}@example.invalid'
         and avatar_url = 'https://avatar.example.invalid/admin.png'
     )
  then raise exception 'owner did not see exact selected-team member contacts'; end if;
end $$;
${deny(teamB, "owner from another team")}
reset role;

${context(adminA)}
do $$ begin
  if (select count(*) from public.list_team_members_with_email('${teamA}')) <> 3 then
    raise exception 'team admin cannot read selected-team member contacts';
  end if;
end $$;
${deny(teamB, "admin from another team")}
reset role;

${context(viewerA)}
${deny(teamA, "viewer")}
reset role;

${context(ownerB)}
do $$ begin
  if (select count(*) from public.list_team_members_with_email('${teamB}')) <> 1 then
    raise exception 'other-team owner did not see only their own team';
  end if;
end $$;
${deny(teamA, "other-team owner")}
reset role;

-- Canonical tenant membership can expire independently of the legacy team row.
update public.tenant_members set expires_at = now() - interval '1 second'
where tenant_id = '${teamA}' and user_id = '${adminA}';
${context(adminA)}
${deny(teamA, "expired admin")}
reset role;
update public.tenant_members set expires_at = null
where tenant_id = '${teamA}' and user_id = '${adminA}';

-- Neither table's role alone may promote a viewer to member-email access.
update public.tenant_members set role = 'admin'
where tenant_id = '${teamA}' and user_id = '${viewerA}';
${context(viewerA)}
${deny(teamA, "mismatched viewer")}
reset role;
update public.tenant_members set role = 'viewer'
where tenant_id = '${teamA}' and user_id = '${viewerA}';

insert into public.tenant_identity_policies(tenant_id, require_mfa)
values ('${teamA}', true);
${context(adminA, "aal1")}
${deny(teamA, "pre-MFA admin")}
reset role;
${context(adminA)}
do $$ begin
  if (select count(*) from public.list_team_members_with_email('${teamA}')) <> 3 then
    raise exception 'MFA-complete admin lost access';
  end if;
end $$;
reset role;

update public.tenants set status = 'suspended' where id = '${teamA}';
${context(ownerA)}
${deny(teamA, "suspended tenant owner")}
reset role;

rollback;
select 'TEAM_MEMBER_EMAIL_PROJECTION_ROLLBACK';
`;

const result = spawnSync("docker", [
  "exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1",
  "-U", "postgres", "-d", "postgres", "-q", "-At",
], { input: sql, encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 120_000 });
if (result.error) throw result.error;
assert.equal(result.status, 0, `team member email projection regression failed:\n${result.stdout}\n${result.stderr}`);
assert.match(result.stdout, /TEAM_MEMBER_EMAIL_PROJECTION_ROLLBACK/);
console.log("Team member email PostgreSQL guard passed: selected-team owner/admin, viewer, cross-tenant, expiry, role mismatch, MFA, suspension; fixtures rolled back.");
