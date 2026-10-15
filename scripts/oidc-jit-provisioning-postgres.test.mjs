// Real PostgreSQL regression for just-in-time OIDC provisioning
// (supabase/migrations/20261014000110_oidc_jit_provisioning.sql).
//
// Default: starts an offline supabase/postgres container, applies every
// canonical migration and runs each scenario in a rolled-back transaction.
// Alternative for hosts without Docker: point AIDR_TEST_PG_HOST (a host name or
// unix socket directory), AIDR_TEST_PG_PORT and AIDR_TEST_PG_DATABASE at a
// DISPOSABLE database that already has every canonical migration applied. Every
// scenario still rolls back; never point this at a shared or hosted database.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { authIdentityFixtureSql } from "./lib/postgres-auth-fixture.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const external = process.env.AIDR_TEST_PG_HOST
	? {
			host: process.env.AIDR_TEST_PG_HOST,
			port: process.env.AIDR_TEST_PG_PORT ?? "5432",
			database: process.env.AIDR_TEST_PG_DATABASE ?? "postgres",
		}
	: null;
const container = `aidr-oidc-jit-${randomUUID().slice(0, 8)}`;
const psqlFlags = ["-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres"];
const psql = external
	? { bin: "psql", args: [...psqlFlags, "-h", external.host, "-p", external.port, "-d", external.database] }
	: { bin: "docker", args: ["exec", "-i", container, "psql", ...psqlFlags, "-d", "postgres"] };

function command(bin, args, input = "") {
	return new Promise((done, reject) => {
		const child = spawn(bin, args, {
			stdio: ["pipe", "pipe", "pipe"],
			timeout: 120_000,
			env: { ...process.env, PGOPTIONS: "-c statement_timeout=20000 -c lock_timeout=15000" },
		});
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk) => {
			stdout += chunk;
		});
		child.stderr.on("data", (chunk) => {
			stderr += chunk;
		});
		child.on("error", reject);
		child.on("close", (code) => done({ code, stdout: stdout.trim(), stderr }));
		child.stdin.on("error", () => {});
		child.stdin.end(input);
	});
}

async function sql(text) {
	const result = await command(psql.bin, psql.args, text);
	assert.equal(result.code, 0, result.stderr);
	return result.stdout;
}

const ids = () => ({
	tenant: randomUUID(),
	owner: randomUUID(),
	backup: randomUUID(),
	user: randomUUID(),
	provider: randomUUID(),
	other: randomUUID(),
});

/**
 * One rolled-back scenario: a tenant with two owners, an enabled provider, a
 * verified `corp.example` domain, a JIT policy (enabled, that domain, no
 * default role) with two group mappings, and one OIDC identity for `user`.
 * `body` runs inside a DO block with v_* variables bound; `rpc(...)` is the
 * provisioning call as the service role.
 */
function scenario(f, body, { defaultRole = "null" } = {}) {
	return `
begin;
insert into auth.users(id, email) values
  ('${f.owner}', 'owner-${f.owner}@test.invalid'), ('${f.backup}', 'backup-${f.backup}@test.invalid'),
  ('${f.other}', 'other-${f.other}@test.invalid');
-- Same app metadata as oidc-sso/store.ts createAuthUser: no personal workspace.
insert into auth.users(id, email, raw_app_meta_data) values ('${f.user}', 'oidc-${f.user}@sso.aidr.invalid',
  jsonb_build_object('aidr_scim_provisioned', true, 'aidr_oidc_provider_id', '${f.provider}', 'aidr_oidc_tenant_id', '${f.tenant}'));
insert into public.tenants(id, name, kind, created_by) values ('${f.tenant}', 'JIT fixture', 'enterprise', '${f.owner}');
insert into public.teams(id, name, tenant_id) values ('${f.tenant}', 'JIT fixture', '${f.tenant}');
insert into public.tenant_members(tenant_id, user_id, role) values ('${f.tenant}', '${f.owner}', 'owner'), ('${f.tenant}', '${f.backup}', 'owner');
insert into public.oidc_providers(id, tenant_id, kind, display_name, issuer, client_id, token_auth_method, enabled, discovery)
  values ('${f.provider}', '${f.tenant}', 'generic', 'Keycloak', 'https://sso.corp.example/realms/corp', 'aidr', 'none', true, '{}');
insert into public.oidc_tenant_domains(tenant_id, domain, verification_token, verified_at)
  values ('${f.tenant}', 'corp.example', '${"a".repeat(32)}', now()),
         ('${f.tenant}', 'pending.example', '${"b".repeat(32)}', null);
insert into public.oidc_identities(provider_id, subject, auth_user_id, tenant_id, email_claim)
  values ('${f.provider}', 'kc-subject-1', '${f.user}', '${f.tenant}', 'ayse@corp.example');
insert into public.oidc_jit_policies(provider_id, tenant_id, enabled, issuer, allowed_domains, default_role)
  values ('${f.provider}', '${f.tenant}', true, 'https://sso.corp.example/realms/corp', array['corp.example', 'pending.example'], ${defaultRole});
insert into public.oidc_jit_group_role_mappings(provider_id, tenant_id, group_value, role) values
  ('${f.provider}', '${f.tenant}', '/aidr/admins', 'admin'),
  ('${f.provider}', '${f.tenant}', '/aidr/users', 'member');
create temporary table jit_ids(tenant uuid, owner uuid, backup uuid, usr uuid, provider uuid, other uuid) on commit drop;
insert into jit_ids values ('${f.tenant}', '${f.owner}', '${f.backup}', '${f.user}', '${f.provider}', '${f.other}');
grant select on jit_ids to service_role, authenticated;
create function pg_temp.rpc(p_groups text[], p_domain text default 'corp.example', p_evaluable boolean default true,
                            p_subject text default 'kc-subject-1', p_user uuid default '${f.user}')
returns jsonb language plpgsql as $fn$
declare v jsonb;
begin
  set local role service_role;
  perform set_config('request.jwt.claims', '{"role":"service_role"}', true);
  v := public.oidc_jit_provision('${f.provider}', p_user, p_subject, p_domain, p_groups, p_evaluable, 'req-test');
  reset role;
  return v;
end $fn$;
create function pg_temp.member_role() returns text language sql as $fn$
  select role from public.tenant_members where tenant_id = '${f.tenant}' and user_id = '${f.user}' $fn$;
create function pg_temp.audits(p_action text) returns bigint language sql as $fn$
  select count(*) from public.admin_audit_logs where tenant_id = '${f.tenant}' and action = p_action $fn$;
do $body$
declare
  v_tenant uuid := '${f.tenant}'; v_owner uuid := '${f.owner}'; v_user uuid := '${f.user}';
  v_provider uuid := '${f.provider}'; v_other uuid := '${f.other}';
  v jsonb; v_text text;
begin
${body}
end
$body$;
rollback;
`;
}

test("JIT OIDC provisioning on full-chain PostgreSQL", { timeout: 900_000 }, async (t) => {
	if (!external) {
		const started = await command("docker", ["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
			"-e", "POSTGRES_PASSWORD=oidc-jit-fixture-only", "supabase/postgres:17.11.0.004"]);
		assert.equal(started.code, 0, started.stderr);
	}
	try {
		if (!external) {
			let ready = false;
			for (let i = 0; i < 150 && !ready; i++) {
				ready = (await command("docker", ["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])).code === 0;
				if (!ready) await delay(200);
			}
			assert.ok(ready, "isolated PostgreSQL must start");
			const storage = await command("docker", ["exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "supabase_admin", "-d", "postgres"],
				`grant create on schema storage to postgres;
				 ${authIdentityFixtureSql}
				 create function auth.jwt() returns jsonb language sql stable as $$
				   select coalesce(nullif(current_setting('request.jwt.claims',true),''),'{}')::jsonb $$;`);
			assert.equal(storage.code, 0, storage.stderr);
			await sql(`create table storage.buckets(id text primary key, name text, public boolean);
				create table storage.objects(id uuid primary key default gen_random_uuid(), bucket_id text, name text, metadata jsonb);
				create function storage.foldername(name text) returns text[] language sql immutable as $$ select string_to_array(name, '/') $$;`);
			const migrations = readdirSync(resolve(root, "supabase/migrations")).filter((name) => name.endsWith(".sql")).sort();
			for (const name of migrations) {
				const result = await command(psql.bin, psql.args, `begin;\n${readFileSync(resolve(root, "supabase/migrations", name), "utf8")}\ncommit;`);
				assert.equal(result.code, 0, `${name}: ${result.stderr}`);
			}
			t.diagnostic(`Applied all ${migrations.length} canonical migrations through ${migrations.at(-1)}`);
		}
		assert.equal(await sql("select to_regprocedure('public.oidc_jit_provision(uuid,uuid,text,text,text[],boolean,text)') is not null;"), "t",
			"the JIT migration must be applied");

		await t.test("only the service role can call the RPCs or read the JIT tables", async () => {
			const out = await sql(`select
				has_function_privilege('anon', 'public.oidc_jit_provision(uuid,uuid,text,text,text[],boolean,text)', 'execute'),
				has_function_privilege('authenticated', 'public.oidc_jit_provision(uuid,uuid,text,text,text[],boolean,text)', 'execute'),
				has_function_privilege('service_role', 'public.oidc_jit_provision(uuid,uuid,text,text,text[],boolean,text)', 'execute'),
				has_function_privilege('authenticated', 'public.oidc_save_jit_policy(uuid,uuid,uuid,boolean,text[],text,jsonb,text)', 'execute'),
				has_function_privilege('service_role', 'public.oidc_save_jit_policy(uuid,uuid,uuid,boolean,text[],text,jsonb,text)', 'execute'),
				has_function_privilege('authenticated', 'public.oidc_jit_readmit(uuid,uuid,uuid,text)', 'execute'),
				has_table_privilege('authenticated', 'public.oidc_jit_policies', 'select'),
				has_table_privilege('authenticated', 'public.oidc_jit_memberships', 'select'),
				has_table_privilege('anon', 'public.oidc_jit_group_role_mappings', 'select'),
				has_table_privilege('service_role', 'public.oidc_jit_memberships', 'select'),
				has_table_privilege('service_role', 'public.oidc_jit_memberships', 'insert'),
				has_table_privilege('service_role', 'public.oidc_jit_group_role_mappings', 'delete'),
				(select bool_and(relrowsecurity) from pg_class where oid in
				  ('public.oidc_jit_policies'::regclass, 'public.oidc_jit_group_role_mappings'::regclass, 'public.oidc_jit_memberships'::regclass));`);
			assert.equal(out, "f|f|t|f|t|f|f|f|f|t|f|f|t");
		});

		await t.test("a mapped group provisions, a higher group raises, no group revokes, all audited", async () => {
			await sql(scenario(ids(), `
  v := pg_temp.rpc(array['/aidr/users', 'unmapped']);
  if v ->> 'status' <> 'provisioned' or v ->> 'role' <> 'member' then raise exception 'FAIL provision: %', v; end if;
  if pg_temp.member_role() <> 'member' then raise exception 'FAIL tenant_members role'; end if;
  if not exists (select 1 from public.team_members where team_id = v_tenant and user_id = v_user and role = 'member') then
    raise exception 'FAIL team_members row'; end if;
  if pg_temp.audits('identity.oidc.jit_provisioned') <> 1 then raise exception 'FAIL provision audit'; end if;
  if not exists (select 1 from public.admin_audit_logs where tenant_id = v_tenant and action = 'identity.oidc.jit_provisioned'
      and detail -> 'matched_groups' = '["/aidr/users"]'::jsonb and detail ->> 'source' = 'group' and detail ->> 'request_id' = 'req-test') then
    raise exception 'FAIL provision audit detail'; end if;

  v := pg_temp.rpc(array['/aidr/users', '/aidr/admins']);
  if v ->> 'status' <> 'updated' or pg_temp.member_role() <> 'admin' then raise exception 'FAIL raise: %', v; end if;
  if pg_temp.audits('identity.oidc.jit_role_changed') <> 1 then raise exception 'FAIL role audit'; end if;
  v := pg_temp.rpc(array['/aidr/admins']);
  if v ->> 'status' <> 'unchanged' then raise exception 'FAIL unchanged: %', v; end if;

  v := pg_temp.rpc(array['/AIDR/ADMINS', ' /aidr/admins']);
  if v ->> 'status' <> 'revoked' then raise exception 'FAIL group values must match exactly: %', v; end if;
  if pg_temp.member_role() is not null or exists (select 1 from public.team_members where team_id = v_tenant and user_id = v_user) then
    raise exception 'FAIL revoke left a membership'; end if;
  if exists (select 1 from public.oidc_jit_memberships where tenant_id = v_tenant) then raise exception 'FAIL revoke left a JIT row'; end if;
  if pg_temp.audits('identity.oidc.jit_membership_revoked') <> 1 then raise exception 'FAIL revoke audit'; end if;
  v := pg_temp.rpc(array[]::text[]);
  if v ->> 'status' <> 'no_role' then raise exception 'FAIL no_role: %', v; end if;`));
		});

		await t.test("the default role applies without a mapped group and is never admin or owner", async () => {
			await sql(scenario(ids(), `
  v := pg_temp.rpc(null);
  if v ->> 'status' <> 'provisioned' or v ->> 'role' <> 'viewer' then raise exception 'FAIL default role: %', v; end if;
  if not exists (select 1 from public.admin_audit_logs where tenant_id = v_tenant and action = 'identity.oidc.jit_provisioned'
      and detail ->> 'source' = 'default') then raise exception 'FAIL default audit source'; end if;
  begin
    update public.oidc_jit_policies set default_role = 'admin' where provider_id = v_provider;
    raise exception 'FAIL admin default accepted';
  exception when check_violation then null; end;
  begin
    insert into public.oidc_jit_group_role_mappings(provider_id, tenant_id, group_value, role) values (v_provider, v_tenant, 'x', 'owner');
    raise exception 'FAIL owner mapping accepted';
  exception when check_violation then null; end;`, { defaultRole: "'viewer'" }));
		});

		await t.test("domain, issuer, enablement and identity preconditions fail closed", async () => {
			await sql(scenario(ids(), `
  v := pg_temp.rpc(array['/aidr/admins'], 'evil.example');
  if v ->> 'status' <> 'domain_not_allowed' then raise exception 'FAIL foreign domain: %', v; end if;
  v := pg_temp.rpc(array['/aidr/admins'], 'pending.example');
  if v ->> 'status' <> 'domain_not_allowed' then raise exception 'FAIL unverified domain: %', v; end if;
  if pg_temp.member_role() is not null then raise exception 'FAIL membership after refused domain'; end if;

  update public.oidc_jit_policies set issuer = 'https://sso.corp.example/realms/other' where provider_id = v_provider;
  v := pg_temp.rpc(array['/aidr/admins']);
  if v ->> 'status' <> 'disabled' then raise exception 'FAIL issuer pin: %', v; end if;
  update public.oidc_jit_policies set issuer = 'https://sso.corp.example/realms/corp', enabled = false where provider_id = v_provider;
  v := pg_temp.rpc(array['/aidr/admins']);
  if v ->> 'status' <> 'disabled' then raise exception 'FAIL disabled policy: %', v; end if;
  update public.oidc_jit_policies set enabled = true where provider_id = v_provider;
  update public.oidc_providers set enabled = false where id = v_provider;
  v := pg_temp.rpc(array['/aidr/admins']);
  if v ->> 'status' <> 'disabled' then raise exception 'FAIL disabled provider: %', v; end if;
  update public.oidc_providers set enabled = true where id = v_provider;

  begin
    v := pg_temp.rpc(array['/aidr/admins'], 'corp.example', true, 'kc-subject-1', v_other);
    raise exception 'FAIL identity mismatch accepted';
  exception when insufficient_privilege then
    if sqlerrm <> 'oidc_jit_identity_mismatch' then raise; end if;
  end;
  begin
    v := pg_temp.rpc(array['/aidr/admins'], 'corp.example', true, 'another-subject');
    raise exception 'FAIL subject mismatch accepted';
  exception when insufficient_privilege then null; end;

  v := pg_temp.rpc(array['/aidr/admins'], 'corp.example', false);
  if v ->> 'status' <> 'groups_unevaluable' or pg_temp.member_role() is not null then raise exception 'FAIL unevaluable: %', v; end if;

  insert into public.tenant_directory_authority(tenant_id, enabled, directory_id) values (v_tenant, true, 'corp-ad');
  v := pg_temp.rpc(array['/aidr/admins']);
  if v ->> 'status' <> 'directory_authoritative' then raise exception 'FAIL directory authority: %', v; end if;
  delete from public.tenant_directory_authority where tenant_id = v_tenant;

  update public.tenants set status = 'suspended' where id = v_tenant;
  v := pg_temp.rpc(array['/aidr/admins']);
  if v ->> 'status' <> 'tenant_inactive' then raise exception 'FAIL suspended tenant: %', v; end if;`));
		});

		await t.test("manual, owner-promoted and SCIM-provisioned members are never JIT-managed", async () => {
			await sql(scenario(ids(), `
  insert into public.tenant_members(tenant_id, user_id, role) values (v_tenant, v_user, 'viewer');
  v := pg_temp.rpc(array['/aidr/admins']);
  if v ->> 'status' <> 'manual_membership' or pg_temp.member_role() <> 'viewer' then raise exception 'FAIL manual: %', v; end if;
  if exists (select 1 from public.oidc_jit_memberships where tenant_id = v_tenant) then raise exception 'FAIL manual became JIT'; end if;`));

			await sql(scenario(ids(), `
  v := pg_temp.rpc(array['/aidr/users']);
  if v ->> 'status' <> 'provisioned' then raise exception 'FAIL setup: %', v; end if;
  update public.team_members set role = 'owner' where team_id = v_tenant and user_id = v_user;
  v := pg_temp.rpc(array[]::text[]);
  if v ->> 'status' <> 'manual_membership' or pg_temp.member_role() <> 'owner' then raise exception 'FAIL owner release: %', v; end if;
  if exists (select 1 from public.oidc_jit_memberships where tenant_id = v_tenant) then raise exception 'FAIL owner still JIT'; end if;
  if pg_temp.audits('identity.oidc.jit_membership_released') <> 1 then raise exception 'FAIL release audit'; end if;`));

			await sql(scenario(ids(), `
  insert into public.scim_users(tenant_id, external_id, user_name, normalized_user_name, active)
  values (v_tenant, 'kc-subject-1', 'ayse@corp.example', 'ayse@corp.example', false);
  v := pg_temp.rpc(array['/aidr/admins']);
  if v ->> 'status' <> 'scim_inactive' or pg_temp.member_role() is not null then raise exception 'FAIL inactive SCIM user: %', v; end if;
  update public.scim_users set active = true where tenant_id = v_tenant and external_id = 'kc-subject-1';
  v := pg_temp.rpc(array['/aidr/admins']);
  if v ->> 'status' <> 'scim_bound' then raise exception 'FAIL SCIM bind: %', v; end if;
  if not exists (select 1 from public.scim_users where tenant_id = v_tenant and external_id = 'kc-subject-1' and auth_user_id = v_user) then
    raise exception 'FAIL SCIM user not bound'; end if;
  -- SCIM groups decide the role: no SCIM group, no membership, whatever the token says.
  if pg_temp.member_role() is not null then raise exception 'FAIL JIT granted a role to a SCIM user'; end if;
  v := pg_temp.rpc(array['/aidr/admins']);
  if v ->> 'status' <> 'scim_managed' then raise exception 'FAIL SCIM managed: %', v; end if;`));

			await sql(scenario(ids(), `
  v := pg_temp.rpc(array['/aidr/users']);
  if v ->> 'status' <> 'provisioned' then raise exception 'FAIL setup: %', v; end if;
  insert into public.scim_users(tenant_id, external_id, user_name, normalized_user_name, active)
  values (v_tenant, 'kc-subject-1', 'ayse@corp.example', 'ayse@corp.example', true);
  v := pg_temp.rpc(array['/aidr/admins']);
  if v ->> 'status' <> 'scim_bound' then raise exception 'FAIL handover: %', v; end if;
  if exists (select 1 from public.oidc_jit_memberships where tenant_id = v_tenant) then raise exception 'FAIL JIT row survived handover'; end if;
  if pg_temp.audits('identity.oidc.jit_handed_to_scim') <> 1 then raise exception 'FAIL handover audit'; end if;`));
		});

		await t.test("an administrator's removal sticks until an owner re-admits the user", async () => {
			await sql(scenario(ids(), `
  v := pg_temp.rpc(array['/aidr/users']);
  if v ->> 'status' <> 'provisioned' then raise exception 'FAIL setup: %', v; end if;
  set local role service_role;
  perform set_config('request.jwt.claims', '{"role":"service_role"}', true);
  delete from public.team_members where team_id = v_tenant and user_id = v_user;
  reset role;
  if not exists (select 1 from public.oidc_jit_memberships where tenant_id = v_tenant and auth_user_id = v_user
      and removed_at is not null and role is null) then raise exception 'FAIL removal not recorded'; end if;
  v := pg_temp.rpc(array['/aidr/admins']);
  if v ->> 'status' <> 'removed_by_admin' or pg_temp.member_role() is not null then raise exception 'FAIL re-added: %', v; end if;

  set local role service_role;
  begin
    perform public.oidc_jit_readmit(v_other, v_tenant, v_user, 'req');
    raise exception 'FAIL non-owner readmit';
  exception when insufficient_privilege then null; end;
  perform public.oidc_jit_readmit(v_owner, v_tenant, v_user, 'req');
  reset role;
  if pg_temp.audits('identity.oidc.jit_readmitted') <> 1 then raise exception 'FAIL readmit audit'; end if;
  v := pg_temp.rpc(array['/aidr/admins']);
  if v ->> 'status' <> 'provisioned' or pg_temp.member_role() <> 'admin' then raise exception 'FAIL after readmit: %', v; end if;`));
		});

		await t.test("owner-only, audited policy saves validate domains and directory authority", async () => {
			await sql(scenario(ids(), `
  set local role service_role;
  begin
    perform public.oidc_save_jit_policy(v_other, v_tenant, v_provider, true, array['corp.example'], null, '[]', 'r');
    raise exception 'FAIL non-owner save';
  exception when insufficient_privilege then null; end;
  begin
    perform public.oidc_save_jit_policy(v_owner, v_tenant, v_provider, true, array['pending.example'], null, '[]', 'r');
    raise exception 'FAIL unverified domain saved';
  exception when invalid_parameter_value then
    if sqlerrm <> 'oidc_jit_domain_not_verified' then raise; end if;
  end;
  begin
    perform public.oidc_save_jit_policy(v_owner, v_tenant, v_provider, true, array['corp.example'], 'admin', '[]', 'r');
    raise exception 'FAIL admin default saved';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.oidc_save_jit_policy(v_owner, v_tenant, v_provider, true, array['corp.example'], null,
      '[{"group":"g","role":"owner"}]', 'r');
    raise exception 'FAIL owner mapping saved';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.oidc_save_jit_policy(v_owner, v_tenant, gen_random_uuid(), true, array['corp.example'], null, '[]', 'r');
    raise exception 'FAIL foreign provider saved';
  exception when insufficient_privilege then null; end;

  v := public.oidc_save_jit_policy(v_owner, v_tenant, v_provider, true, array['CORP.example ', 'corp.example'], 'member',
    '[{"group":"cn=aidr-admins,ou=groups,dc=corp,dc=example","role":"admin"}]', 'r');
  reset role;
  if (v ->> 'mapping_count')::int <> 1 then raise exception 'FAIL save result: %', v; end if;
  if (select allowed_domains from public.oidc_jit_policies where provider_id = v_provider) <> array['corp.example'] then
    raise exception 'FAIL domains not normalized'; end if;
  if (select count(*) from public.oidc_jit_group_role_mappings where provider_id = v_provider) <> 1 then
    raise exception 'FAIL mappings not replaced'; end if;
  if not exists (select 1 from public.admin_audit_logs where tenant_id = v_tenant and action = 'identity.oidc.jit_policy_updated'
      and actor_user_id = v_owner and detail ->> 'default_role' = 'member' and detail ->> 'issuer' = 'https://sso.corp.example/realms/corp') then
    raise exception 'FAIL policy audit'; end if;

  insert into public.tenant_directory_authority(tenant_id, enabled, directory_id) values (v_tenant, true, 'corp-ad');
  set local role service_role;
  begin
    perform public.oidc_save_jit_policy(v_owner, v_tenant, v_provider, true, array['corp.example'], null, '[]', 'r');
    raise exception 'FAIL JIT enabled under directory authority';
  exception when insufficient_privilege then
    if sqlerrm <> 'oidc_jit_directory_authoritative' then raise; end if;
  end;
  -- Disabling is always possible.
  perform public.oidc_save_jit_policy(v_owner, v_tenant, v_provider, false, array[]::text[], null, '[]', 'r');
  reset role;`));
		});

		await t.test("extra authorization scopes come from a fixed allow-list and are saved atomically", async () => {
			await sql(scenario(ids(), `
  begin
    update public.oidc_providers set extra_scopes = array['offline_access'] where id = v_provider;
    raise exception 'FAIL arbitrary scope accepted';
  exception when check_violation then null; end;
  set local role service_role;
  perform public.oidc_save_provider(v_owner, (select to_jsonb(p) - 'extra_scopes' || jsonb_build_object('extra_scopes', array['allatclaims'])
    from public.oidc_providers p where id = v_provider), 'identity.oidc.provider_updated', '{}');
  reset role;
  if (select extra_scopes from public.oidc_providers where id = v_provider) <> array['allatclaims'] then
    raise exception 'FAIL extra scopes not saved'; end if;
  set local role service_role;
  -- A save that omits the field (an older Edge function) clears it instead of failing.
  perform public.oidc_save_provider(v_owner, (select to_jsonb(p) - 'extra_scopes' from public.oidc_providers p where id = v_provider),
    'identity.oidc.provider_updated', '{}');
  reset role;
  if (select cardinality(extra_scopes) from public.oidc_providers where id = v_provider) <> 0 then
    raise exception 'FAIL omitted extra scopes not cleared'; end if;`));
		});

		await t.test("RLS: a JIT member reads its tenant through the normal policies, never the JIT tables", async () => {
			await sql(scenario(ids(), `
  v := pg_temp.rpc(array['/aidr/users']);
  if v ->> 'status' <> 'provisioned' then raise exception 'FAIL setup: %', v; end if;
  perform set_config('request.jwt.claims', json_build_object('sub', v_user, 'role', 'authenticated', 'aal', 'aal1')::text, true);
  set local role authenticated;
  if not exists (select 1 from public.tenant_members where tenant_id = v_tenant and user_id = v_user) then
    raise exception 'FAIL JIT member cannot read own tenant membership'; end if;
  begin
    perform 1 from public.oidc_jit_memberships;
    raise exception 'FAIL browser role read JIT memberships';
  exception when insufficient_privilege then null; end;
  begin
    perform public.oidc_jit_provision(v_provider, v_user, 'kc-subject-1', 'corp.example', array['/aidr/admins'], true, 'x');
    raise exception 'FAIL browser role called provisioning';
  exception when insufficient_privilege then null; end;
  reset role;`));
		});
	} finally {
		if (!external) await command("docker", ["rm", "-f", container]);
	}
});
