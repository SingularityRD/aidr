// Run after `supabase start && supabase db reset --local --no-seed`.
// Every fixture is rolled back; never point this at a shared or hosted DB.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const container = process.env.AIDR_RLS_TEST_DB_CONTAINER;
assert.ok(container, "AIDR_RLS_TEST_DB_CONTAINER must name the disposable Supabase db container");
assert.match(container, /^[A-Za-z0-9_.-]+$/, "invalid Docker container name");

const [owner, passwordUser, samlUser, wrongSubjectUser, manualSamlUser, tenantA, tenantB, providerA, providerB, scimUser, manualScimUser, group, provisionalAuthUser, provisionalScimUser] =
	Array.from({ length: 14 }, () => randomUUID());
const marker = randomUUID().replaceAll("-", "");
const subject = `directory-${marker}`;
const manualSubject = `manual-${marker}`;
const email = `saml-${marker}@example.invalid`;
const provisionalEmail = `provisional-${marker}@example.invalid`;
const migration = process.argv.includes("--with-claim-recovery-migration")
	? readFileSync(new URL("../supabase/migrations/20260924000005_scim_auth_claim_recovery.sql", import.meta.url), "utf8")
	: "";
const now = Math.floor(Date.now() / 1000);
const claims = (method, provider = providerA, userId = samlUser) => JSON.stringify({
	sub: userId, role: "authenticated", aal: "aal2", iat: now,
	amr: [{ method, provider }],
}).replaceAll("'", "''");

const sql = String.raw`
\set ON_ERROR_STOP on
begin;
${migration}

do $$ begin
  if has_function_privilege('authenticated', 'public.scim_bind_saml_identity(uuid,uuid)', 'EXECUTE')
     or has_function_privilege('anon', 'public.scim_bind_saml_identity(uuid,uuid)', 'EXECUTE')
  then raise exception 'SAML binding RPC exposed to browser role'; end if;
  if not has_function_privilege('service_role', 'public.scim_bind_saml_identity(uuid,uuid)', 'EXECUTE')
  then raise exception 'SAML binding RPC unavailable to verified server route'; end if;
  if has_function_privilege('authenticated', 'public.scim_recover_unbound_auth_user(uuid,uuid,text)', 'EXECUTE')
     or has_function_privilege('anon', 'public.scim_recover_unbound_auth_user(uuid,uuid,text)', 'EXECUTE')
     or not has_function_privilege('service_role', 'public.scim_recover_unbound_auth_user(uuid,uuid,text)', 'EXECUTE')
  then raise exception 'SCIM provisional account recovery RPC role boundary changed'; end if;
end $$;

insert into auth.users(id, email, aud, role, instance_id, is_sso_user, raw_app_meta_data, raw_user_meta_data)
values
  ('${owner}', 'owner-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', false, '{}'::jsonb, '{}'::jsonb),
  ('${passwordUser}', '${email}', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', false, '{"provider":"email"}'::jsonb, '{}'::jsonb),
  ('${samlUser}', '${email}', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', true, '{"provider":"sso:${providerA}"}'::jsonb, '{}'::jsonb),
  ('${wrongSubjectUser}', 'wrong-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', true, '{"provider":"sso:${providerA}"}'::jsonb, '{}'::jsonb),
  ('${manualSamlUser}', 'manual-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', true, '{"provider":"sso:${providerA}"}'::jsonb, '{}'::jsonb),
  ('${provisionalAuthUser}', '${provisionalEmail}', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', false, '{"aidr_scim_provisioned":true,"aidr_scim_tenant_id":"${tenantB}","aidr_scim_user_id":"${provisionalScimUser}"}'::jsonb, '{}'::jsonb);

do $$ begin
  if exists (select 1 from public.tenant_members where user_id = '${samlUser}')
    or exists (select 1 from public.team_members where user_id = '${samlUser}')
  then raise exception 'SAML account received a personal workspace before SCIM authorization'; end if;
  if not exists (select 1 from public.tenant_members where user_id = '${passwordUser}')
  then raise exception 'non-SSO personal bootstrap changed'; end if;
end $$;

insert into auth.identities(provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
values
  ('${subject}', '${samlUser}', jsonb_build_object('sub', '${subject}', 'email', '${email}'), 'sso:${providerA}', now(), now(), now()),
  ('wrong-${marker}', '${wrongSubjectUser}', jsonb_build_object('sub', 'wrong-${marker}'), 'sso:${providerA}', now(), now(), now()),
  ('${manualSubject}', '${manualSamlUser}', jsonb_build_object('sub', '${manualSubject}'), 'sso:${providerA}', now(), now(), now());

insert into public.tenants(id, name, kind, created_by)
values ('${tenantA}', 'SAML regression A', 'team', '${owner}'),
       ('${tenantB}', 'SAML regression B', 'team', '${owner}');
insert into public.teams(id, tenant_id, name)
values ('${tenantA}', '${tenantA}', 'SAML regression A'),
       ('${tenantB}', '${tenantB}', 'SAML regression B');
insert into public.team_members(team_id, tenant_id, user_id, role)
values ('${tenantA}', '${tenantA}', '${owner}', 'owner'),
       ('${tenantB}', '${tenantB}', '${owner}', 'owner');
insert into public.tenant_identity_policies(tenant_id, required_saml_provider_id)
values ('${tenantA}', '${providerA}');

insert into public.scim_users(id, tenant_id, external_id, user_name, normalized_user_name, active)
values ('${scimUser}', '${tenantA}', '${subject}', '${email}', '${email}', true),
       ('${manualScimUser}', '${tenantA}', '${manualSubject}', 'manual-${marker}@example.invalid', 'manual-${marker}@example.invalid', true),
       ('${provisionalScimUser}', '${tenantB}', 'orphan-${marker}', '${provisionalEmail}', '${provisionalEmail}', true);
insert into public.scim_groups(id, tenant_id, external_id, display_name)
values ('${group}', '${tenantA}', 'members-${marker}', 'Members');
insert into public.scim_group_role_mappings(tenant_id, external_group_id, role, created_by)
values ('${tenantA}', 'members-${marker}', 'member', '${owner}');
insert into public.scim_group_memberships(tenant_id, group_id, user_id)
values ('${tenantA}', '${group}', '${scimUser}'), ('${tenantA}', '${group}', '${manualScimUser}');

do $$ begin
  if public.scim_recover_unbound_auth_user('${tenantB}', '${provisionalScimUser}', '${provisionalEmail}') <> '${provisionalAuthUser}'::uuid
     or public.scim_recover_unbound_auth_user('${tenantA}', '${provisionalScimUser}', '${provisionalEmail}') is not null
     or public.scim_recover_unbound_auth_user('${tenantB}', '${scimUser}', '${provisionalEmail}') is not null
     or public.scim_recover_unbound_auth_user('${tenantB}', '${provisionalScimUser}', 'other@example.invalid') is not null
     or public.scim_recover_unbound_auth_user('${tenantA}', '${scimUser}', '${email}') is not null
  then raise exception 'provisional SCIM Auth recovery was not tenant/resource/email bound'; end if;
  insert into public.tenant_members(tenant_id, user_id, role)
    values ('${tenantB}', '${provisionalAuthUser}', 'viewer');
  if public.scim_recover_unbound_auth_user('${tenantB}', '${provisionalScimUser}', '${provisionalEmail}') is not null
  then raise exception 'SCIM claimed an already-member provisional Auth account'; end if;
end $$;

do $$ begin
  if public.scim_bind_saml_identity('${passwordUser}', '${providerA}') is not null
     or public.scim_bind_saml_identity('${wrongSubjectUser}', '${providerA}') is not null
     or public.scim_bind_saml_identity('${samlUser}', '${providerB}') is not null
  then raise exception 'wrong Auth UUID, NameID or SAML provider was bound'; end if;
  if exists (select 1 from public.team_members where team_id = '${tenantA}' and user_id = '${passwordUser}')
  then raise exception 'same email inherited SCIM membership'; end if;
  if public.scim_bind_saml_identity('${samlUser}', '${providerA}') <> '${tenantA}'::uuid
  then raise exception 'exact SAML identity did not bind'; end if;
  if not exists (select 1 from public.scim_users where id = '${scimUser}' and auth_user_id = '${samlUser}')
     or not exists (select 1 from public.team_members where team_id = '${tenantA}' and user_id = '${samlUser}' and role = 'member')
  then raise exception 'bound SAML user did not receive the mapped group role'; end if;
  if public.scim_bind_saml_identity('${samlUser}', '${providerA}') <> '${tenantA}'::uuid
     or (select count(*) from public.admin_audit_logs where action = 'scim.user.bound' and target_user_id = '${samlUser}') <> 1
  then raise exception 'SAML binding replay was not idempotent'; end if;
end $$;

select set_config('request.jwt.claim.sub', '${samlUser}', true);
select set_config('request.jwt.claims', '${claims("magiclink")}', true);
set role authenticated;
do $$ begin
  if (select count(*) from public.teams where tenant_id = '${tenantA}') <> 0
  then raise exception 'email-link session bypassed tenant SSO'; end if;
end $$;
reset role;
select set_config('request.jwt.claim.sub', '${owner}', true);
select set_config('request.jwt.claims', '${claims("password", providerA, owner)}', true);
set role authenticated;
do $$ begin
  if (select count(*) from public.teams where tenant_id = '${tenantA}') <> 0
  then raise exception 'legacy password owner bypassed tenant SSO'; end if;
end $$;
reset role;
select set_config('request.jwt.claim.sub', '${samlUser}', true);
select set_config('request.jwt.claims', '${claims("sso/saml")}', true);
set role authenticated;
do $$ begin
  if (select count(*) from public.teams where tenant_id = '${tenantA}') <> 1
  then raise exception 'verified provider session could not read mapped team'; end if;
end $$;
reset role;

insert into public.tenant_members(tenant_id, user_id, role)
values ('${tenantA}', '${manualSamlUser}', 'viewer');
do $$ begin
  begin
    perform public.scim_bind_saml_identity('${manualSamlUser}', '${providerA}');
    raise exception 'manual same-tenant membership was taken over';
  exception when sqlstate '42501' then null;
  end;
  if exists (select 1 from public.scim_users where id = '${manualScimUser}' and auth_user_id is not null)
  then raise exception 'manual membership conflict left a partial binding'; end if;
  begin
    insert into public.tenant_identity_policies(tenant_id, required_saml_provider_id)
    values ('${tenantB}', '${providerA}');
    raise exception 'one provider was assigned to two tenants';
  exception when unique_violation then null;
  end;
end $$;

insert into public.scim_users(tenant_id, external_id, user_name, normalized_user_name, auth_user_id)
values ('${tenantB}', 'legacy-${marker}', 'legacy-${marker}@example.invalid', 'legacy-${marker}@example.invalid', '${passwordUser}');
do $$ begin
  begin
    insert into public.tenant_identity_policies(tenant_id, required_saml_provider_id)
    values ('${tenantB}', '${providerB}');
    raise exception 'provider activation accepted an email-bound SCIM account';
  exception when unique_violation then null;
  end;
  if exists (select 1 from public.tenant_identity_policies where tenant_id = '${tenantB}')
  then raise exception 'failed provider activation left a policy row'; end if;
end $$;

-- SCIM deprovisioning is a service-role Edge call, not the preceding user's JWT.
select set_config('request.jwt.claim.sub', '', true);
select set_config('request.jwt.claims', '{"role":"service_role"}', true);
set role service_role;
select public.scim_update_user('${tenantA}', '${scimUser}', null, false, null);
reset role;
do $$ begin
  if public.scim_bind_saml_identity('${samlUser}', '${providerA}') is not null
     or exists (select 1 from public.team_members where team_id = '${tenantA}' and user_id = '${samlUser}')
     or exists (select 1 from public.tenant_members where tenant_id = '${tenantA}' and user_id = '${samlUser}')
  then raise exception 'SCIM deactivation retained access'; end if;
end $$;
select set_config('request.jwt.claim.sub', '${samlUser}', true);
select set_config('request.jwt.claims', '${claims("sso/saml")}', true);
set role authenticated;
do $$ begin
  if (select count(*) from public.teams where tenant_id = '${tenantA}') <> 0
  then raise exception 'old SAML session retained deprovisioned team access'; end if;
end $$;
reset role;

rollback;
select 'SCIM_SAML_IDENTITY_ROLLBACK';
`;

const result = spawnSync("docker", [
	"exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1",
	"-U", "postgres", "-d", "postgres", "-q", "-At",
], { input: sql, encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 120_000 });
if (result.error) throw result.error;
assert.equal(result.status, 0, `SCIM/SAML PostgreSQL regression failed:\n${result.stdout}\n${result.stderr}`);
assert.match(result.stdout, /SCIM_SAML_IDENTITY_ROLLBACK/);
console.log("SCIM/SAML PostgreSQL passed: exact provider+subject binding, same-email isolation, manual conflicts, SSO-only RLS (including legacy owner), deprovision, rollback.");
