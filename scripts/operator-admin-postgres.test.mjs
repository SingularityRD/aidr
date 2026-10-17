// PostgreSQL regression for the platform-operator SQL wrappers
// (supabase/migrations/20260925000030_platform_operator_admin.sql).
//
// Run against a disposable Supabase PostgreSQL container with every migration
// through 20260925000030 applied:
//   AIDR_POSTGRES_DOCKER_CONTAINER=<name> node --test scripts/operator-admin-postgres.test.mjs
// Every case runs in one transaction that is rolled back, so the container's
// admission mode and legal-document configuration are left untouched.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";

const container = process.env.AIDR_POSTGRES_DOCKER_CONTAINER;
const dockerDesktop = process.env.LOCALAPPDATA
	? resolve(process.env.LOCALAPPDATA, "Programs/DockerDesktop/resources/bin/docker.exe")
	: null;
const docker = process.env.AIDR_DOCKER_BIN ?? (dockerDesktop && existsSync(dockerDesktop) ? dockerDesktop : "docker");
const dbUser = process.env.AIDR_POSTGRES_DB_USER ?? "postgres";
const marker = randomUUID().replaceAll("-", "");

function user(userId) {
	return `insert into auth.users(id,email,aud,role,instance_id,email_confirmed_at,raw_app_meta_data,raw_user_meta_data)
values ('${userId}','operator-${userId}@example.invalid','authenticated','authenticated',
  '00000000-0000-0000-0000-000000000000',clock_timestamp(),'{}'::jsonb,'{}'::jsonb);`;
}

function team(tenantId, ownerIds, kind = "team") {
	const members = ownerIds.map((ownerId) => `insert into public.tenant_members(tenant_id,user_id,role)
values ('${tenantId}','${ownerId}','owner');
insert into public.team_members(team_id,tenant_id,user_id,role)
values ('${tenantId}','${tenantId}','${ownerId}','owner');`).join("\n");
	return `insert into public.tenants(id,name,kind,created_by)
values ('${tenantId}','Operator ${marker}','${kind}','${ownerIds[0]}');
insert into public.teams(id,tenant_id,name,plan)
values ('${tenantId}','${tenantId}','Operator ${marker}','free');
${members}`;
}

const helpers = String.raw`
create function pg_temp.expect_error(statement text, expected text)
returns void language plpgsql as $fn$
declare actual_message text; actual_state text;
begin
  begin
    execute statement;
  exception when others then
    get stacked diagnostics actual_message = message_text, actual_state = returned_sqlstate;
    if actual_message = expected or actual_state = expected then return; end if;
    raise exception 'expected %, got % (%): %', expected, actual_message, actual_state, statement;
  end;
  raise exception 'expected %, statement succeeded: %', expected, statement;
end $fn$;
create function pg_temp.expect(actual jsonb, path text[], expected text, label text)
returns void language plpgsql as $fn$
begin
  if actual #>> path is distinct from expected then
    raise exception '%: expected % = %, got %', label, array_to_string(path, '.'), expected, actual;
  end if;
end $fn$;
create function pg_temp.expect_audit(action text, actor uuid, expected integer, label text)
returns void language plpgsql as $fn$
declare actual integer;
begin
  select count(*) into actual from public.admin_audit_logs l
   where l.action = expect_audit.action and l.actor_user_id = actor;
  if actual is distinct from expected then
    raise exception '%: expected % % receipts, got %', label, expected, action, actual;
  end if;
end $fn$;
-- Function EXECUTE is revoked from PUBLIC by default (security review
-- hardening), so the role-switched checks need the helpers granted.
grant execute on function pg_temp.expect_error(text,text) to anon, authenticated, service_role;
grant execute on function pg_temp.expect(jsonb,text[],text,text) to anon, authenticated, service_role;
`;

function run(label, fixture, body) {
	const sql = `\\set ON_ERROR_STOP on\nbegin;\n${fixture}\n${helpers}\n${body}\nrollback;\nselect 'OPERATOR_ADMIN_${label}_ROLLED_BACK';\n`;
	const result = spawnSync(docker, [
		"exec", "-i", container, "psql", "-X", "-w", "-v", "ON_ERROR_STOP=1",
		"-U", dbUser, "-d", "postgres", "-q", "-At",
	], { input: sql, encoding: "utf8", maxBuffer: 12 * 1024 * 1024, timeout: 120_000 });
	if (result.error) throw result.error;
	assert.equal(result.status, 0, `${label} operator-admin regression failed:\n${result.stdout}\n${result.stderr}`);
	assert.match(result.stdout, new RegExp(`OPERATOR_ADMIN_${label}_ROLLED_BACK`));
}

const skip = container ? false : "AIDR_POSTGRES_DOCKER_CONTAINER is not set";
if (container) {
	assert.match(container, /^[A-Za-z0-9_.-]+$/, "invalid Docker container name");
	assert.match(dbUser, /^[A-Za-z_][A-Za-z0-9_]*$/, "invalid PostgreSQL role");
}

test("only an active platform operator reaches the wrappers, and service_role cannot self-enroll", { skip }, () => {
	const operator = randomUUID();
	const expired = randomUUID();
	const outsider = randomUUID();
	run("GATE", `${user(operator)}\n${user(expired)}\n${user(outsider)}
insert into public.platform_operators(user_id,change_reference) values ('${operator}','CHG-${marker}');
insert into public.platform_operators(user_id,change_reference,expires_at)
values ('${expired}','CHG-${marker}',clock_timestamp()-interval '1 second');`, `
do $check$ begin
  if not exists(select 1 from public.platform_operators where user_id='${operator}'
    and expires_at > now() and expires_at <= now()+interval '31 days') then
    raise exception 'operator default was not finite and short-lived'; end if;
end $check$;
select pg_temp.expect_error($s$select public.operator_list_tenants('${outsider}',10)$s$,'platform_operator_forbidden');
select pg_temp.expect_error($s$select public.operator_list_tenants('${expired}',10)$s$,'platform_operator_forbidden');
select pg_temp.expect_error($s$select public.operator_list_tenants(null,10)$s$,'platform_operator_forbidden');
update public.platform_operators set revoked_at=clock_timestamp() where user_id='${operator}';
select pg_temp.expect_error($s$select public.operator_list_tenants('${operator}',10)$s$,'platform_operator_forbidden');
update public.platform_operators set revoked_at=null where user_id='${operator}';
select pg_temp.expect_error($s$select public.operator_list_tenants('${operator}',0)$s$,'invalid_page');
set local role service_role;
select pg_temp.expect_error($s$insert into public.platform_operators(user_id,change_reference) values ('${outsider}','self')$s$,'42501');
select pg_temp.expect_error($s$select app.require_platform_operator('${operator}')$s$,'42501');
select count(*) from public.platform_operators where user_id='${operator}';
reset role;
set local role authenticated;
select pg_temp.expect_error($s$select public.operator_list_tenants('${operator}',10)$s$,'42501');
reset role;
`);
});

test("mode, legal documents, license grant/revoke and reads are delegated and actor-audited", { skip }, () => {
	const operator = randomUUID();
	const owner = randomUUID();
	const secondOwner = randomUUID();
	const tenant = randomUUID();
	const twoOwners = randomUUID();
	run("LIFECYCLE", `${user(operator)}\n${user(owner)}\n${user(secondOwner)}
${team(tenant, [owner])}
${team(twoOwners, [owner, secondOwner])}
insert into public.platform_operators(user_id,change_reference) values ('${operator}','CHG-${marker}');
insert into public.admission_operators(tenant_id,user_id) values ('${tenant}','${operator}'),('${twoOwners}','${operator}');`, `
select pg_temp.expect_error($s$select public.operator_configure_admission_mode('${operator}','bogus')$s$,'invalid_admission_mode');
select pg_temp.expect(public.operator_configure_admission_mode('${operator}','cloud'),'{mode}','cloud','mode');
select pg_temp.expect(public.operator_configure_admission_mode('${operator}','cloud'),'{status}','already_configured','mode replay');
select pg_temp.expect_error($s$select public.operator_configure_admission_mode('${operator}','onprem')$s$,'admission_mode_immutable');
select pg_temp.expect_audit('operator.admission_mode_configured','${operator}',2,'mode receipts');

select pg_temp.expect(public.operator_configure_legal_documents('${operator}','v1',repeat('a',64),
  'https://aidr-test.invalid/terms','v1',repeat('b',64),'https://aidr-test.invalid/privacy','LEGAL-${marker}'),
  '{status}','configured','legal');
select pg_temp.expect_error($s$select public.operator_configure_legal_documents('${operator}','v1','nothex',
  'https://aidr-test.invalid/terms','v1',repeat('b',64),'https://aidr-test.invalid/privacy','LEGAL')$s$,'23514');
select pg_temp.expect_audit('operator.legal_documents_configured','${operator}',1,'legal receipts');

select pg_temp.expect_error($s$select public.operator_grant_license('${operator}','${tenant}','gold-tier-x',5,
  now()+interval '1 year','PO-${marker}')$s$,'invalid_plan');
select pg_temp.expect_error($s$select public.operator_grant_license('${operator}','${randomUUID()}','team',5,
  now()+interval '1 year','PO-${marker}')$s$,'tenant_not_found');
select pg_temp.expect_error($s$select public.operator_grant_license('${operator}','${twoOwners}','team',5,
  now()+interval '1 year','PO-${marker}')$s$,'owner_required');
select pg_temp.expect_error($s$select public.operator_grant_license('${operator}','${tenant}','team',0,
  now()+interval '1 year','PO-${marker}')$s$,'invalid_admission_grant');
select pg_temp.expect(public.operator_grant_license('${operator}','${tenant}','team',5,
  now()+interval '1 year',' PO-${marker} '),'{plan_id}','team','grant');
select pg_temp.expect(public.operator_grant_license('${operator}','${twoOwners}','team',3,
  now()+interval '1 year','PO2-${marker}','${secondOwner}'),'{owner_user_id}','${secondOwner}','explicit owner');
do $check$ begin
  if not exists(select 1 from public.tenant_admissions where tenant_id='${tenant}'
    and kind='licensed' and plan_id='team' and grant_reference='PO-${marker}') then
    raise exception 'licensed grant did not record the plan'; end if;
end $check$;
select pg_temp.expect_audit('operator.license_granted','${operator}',2,'grant receipts');
-- The plan resolvers read the billing-managed team label while the licence is
-- active; the grant must set it, not only label the admission row (a licensed
-- tenant used to stay on Free features and retention).
do $check$ begin
  if not exists(select 1 from public.teams where tenant_id='${tenant}' and plan='team') then
    raise exception 'licensed grant did not set the team plan'; end if;
end $check$;

select pg_temp.expect(public.operator_tenant_usage('${operator}','${tenant}'),'{admission,plan_id}','team','usage plan');
select pg_temp.expect(public.operator_tenant_usage('${operator}','${tenant}'),'{members}','1','usage members');
select pg_temp.expect_error($s$select public.operator_tenant_usage('${operator}','${randomUUID()}')$s$,'tenant_not_found');
do $check$
declare v_page jsonb := public.operator_list_tenants('${operator}',200,'${tenant}');
begin
  if exists (select 1 from jsonb_array_elements(v_page->'tenants') e
             where (e->>'id')::uuid <= '${tenant}'::uuid) then
    raise exception 'keyset page included the cursor: %', v_page; end if;
end $check$;
select pg_temp.expect_audit('operator.tenants_listed','${operator}',1,'list receipts');
select pg_temp.expect_audit('operator.tenant_usage_read','${operator}',2,'usage receipts');

select pg_temp.expect(public.operator_revoke_license('${operator}','${tenant}','contract ended'),'{status}','revoked','revoke');
select pg_temp.expect(public.operator_revoke_license('${operator}','${tenant}','contract ended'),'{status}','not_active','revoke replay');
select pg_temp.expect_audit('operator.license_revoked','${operator}',2,'revoke receipts');
`);
});
