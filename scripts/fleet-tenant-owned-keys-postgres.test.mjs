// Real-PostgreSQL contract for
//   supabase/migrations/20261016000300_fleet_keys_tenant_owned.sql
// replayed on top of the COMPLETE canonical migration chain.
//
// Runs against AIDR_POSTGRES_TEST_URL=postgres://user@host:port/db (a
// disposable database is created next to it and dropped afterwards) and is
// skipped, visibly, when it is not set. The platform fixture is the same as
// incident-triage-postgres.test.mjs (roles, auth.*, storage.*, pgcrypto).
//
// It proves that device keys minted through a fleet enrollment key belong to
// the tenant:
//   * the key carries no person (user_id NULL) and names its fleet key;
//   * removing, downgrading or SCIM-deprovisioning the administrator who
//     created the fleet key revokes that person's own keys but none of the
//     fleet devices' keys, and the devices keep their machine paths (fleet
//     response delivery, approval requests, admission, policy receipt,
//     installer audit);
//   * a departed issuer's fleet key no longer admits NEW machines;
//   * revoking the fleet key revokes its devices' keys and every machine path
//     refuses them; suspending the tenant stops tenant-owned keys too;
//   * owner shape and fleet-key binding cannot be rewritten;
//   * the backfill converts keys minted before the migration, and leaves an
//     already revoked key revoked.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const admin = process.env.AIDR_POSTGRES_TEST_URL;
const MIGRATION = "20261016000300_fleet_keys_tenant_owned.sql";

const PLATFORM = `
do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role nologin bypassrls; end if;
  if not exists (select 1 from pg_roles where rolname = 'supabase_auth_admin') then create role supabase_auth_admin nologin; end if;
end $$;
create schema if not exists auth;
create schema if not exists extensions;
create schema if not exists storage;
create extension if not exists pgcrypto with schema extensions;
create table auth.users (id uuid primary key, email text, raw_user_meta_data jsonb default '{}'::jsonb,
  raw_app_meta_data jsonb default '{}'::jsonb, created_at timestamptz default now(), updated_at timestamptz default now(),
  email_confirmed_at timestamptz, last_sign_in_at timestamptz, is_sso_user boolean default false,
  deleted_at timestamptz, banned_until timestamptz, phone text, is_anonymous boolean default false);
create table auth.sessions (id uuid primary key default gen_random_uuid(), user_id uuid, created_at timestamptz default now(),
  updated_at timestamptz, aal text, not_after timestamptz);
create table auth.identities (id uuid primary key default gen_random_uuid(), user_id uuid, provider text, provider_id text,
  identity_data jsonb, created_at timestamptz default now());
create table auth.mfa_factors (id uuid primary key default gen_random_uuid(), user_id uuid, status text, factor_type text,
  created_at timestamptz default now());
create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
create function auth.role() returns text language sql stable as $$ select nullif(current_setting('request.jwt.claim.role', true), '') $$;
create function auth.jwt() returns jsonb language sql stable as $$ select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $$;
create table storage.buckets(id text primary key, name text, public boolean, file_size_limit bigint, allowed_mime_types text[]);
create table storage.objects(id uuid primary key default gen_random_uuid(), bucket_id text, name text, owner uuid,
  metadata jsonb, created_at timestamptz default now());
create function storage.foldername(name text) returns text[] language sql immutable as $$ select string_to_array(name, '/') $$;
alter table storage.objects enable row level security;
grant usage on schema auth, extensions, storage to anon, authenticated, service_role;
`;

function psql(url, sql) {
	const result = spawnSync("psql", [url, "-X", "-qAt", "-v", "ON_ERROR_STOP=1"], {
		input: sql, encoding: "utf8", timeout: 120_000,
	});
	return { code: result.status ?? 1, stdout: (result.stdout ?? "").trim(), stderr: result.stderr ?? "" };
}

const hash = () => randomBytes(32).toString("hex");
const sha = (value) => createHash("sha256").update(value).digest("hex");

test("fleet-minted device keys are tenant-owned on real PostgreSQL", {
	skip: admin ? false : "AIDR_POSTGRES_TEST_URL is not set",
}, async (t) => {
	const name = `aidr_fleet_owned_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
	assert.equal(psql(admin, `create database ${name}`).code, 0);
	const url = new URL(admin);
	url.pathname = `/${name}`;
	const db = url.toString();
	const sql = (text) => {
		const result = psql(db, text);
		assert.equal(result.code, 0, result.stderr);
		return result.stdout;
	};
	const fails = (text, pattern) => {
		const result = psql(db, text);
		assert.notEqual(result.code, 0, `must be refused: ${text.slice(0, 160)}`);
		assert.match(result.stderr, pattern);
	};
	const service = (text) => sql(`set role service_role; ${text}`);
	const json = (text) => JSON.parse(service(`select (${text})::text;`));
	const applyMigrations = (files) => {
		for (const file of files) {
			const result = psql(db, `begin;\n${readFileSync(resolve(root, "supabase/migrations", file), "utf8")}\ncommit;`);
			assert.equal(result.code, 0, `${file}: ${result.stderr}`);
		}
	};

	const [TENANT, OWNER, ISSUER, ISSUER2, MEMBER] = Array.from({ length: 5 }, () => randomUUID());
	const marker = randomUUID().slice(0, 8);
	const exchange = (fleetHash, iid, keyHash) =>
		json(`public.exchange_fleet_enrollment_key('${fleetHash}', '${iid}', 'claude-code', null, '${keyHash}')`);
	const keyRow = (keyHash) => sql(`select coalesce(user_id::text, '-') || '|' || coalesce(fleet_key_id::text, '-') || '|' || revoked
		from public.api_keys where key_hash = '${keyHash}';`);
	const agentOf = (keyHash) => sql(`select agent_id from public.api_keys where key_hash = '${keyHash}';`);
	const keyIdOf = (keyHash) => sql(`select id from public.api_keys where key_hash = '${keyHash}';`);
	const fleetIdOf = (fleetHash) => sql(`select id from public.fleet_enrollment_keys where key_hash = '${fleetHash}';`);
	const poll = (keyHash, iid) =>
		`select public.poll_bound_fleet_response_command('${keyHash}', '${TENANT}', '${agentOf(keyHash)}', '${iid}');`;
	const approval = (keyHash, iid, requester = null) => `public.create_approval_request('${TENANT}',
		${requester ? `'${requester}'` : "null"}, '${keyIdOf(keyHash)}', '${agentOf(keyHash)}', '${iid}', 'claude-code',
		'action-${randomUUID()}', 'sha256:${hash()}', 'Bash', array['T-1'], 'Run reviewed command', now() + interval '10 minutes')`;
	const admission = (keyHash) => json(`public.get_fleet_device_admission('${keyIdOf(keyHash)}')`);
	const receipt = (keyHash) => {
		const [version, digest] = sql(`select r.version || '|' || encode(extensions.digest(convert_to(
			app.policy_rollout_canonical_json(r.policy), 'UTF8'), 'sha256'), 'hex')
			from public.runtime_policy_revisions r where r.tenant_id = '${TENANT}' order by r.version desc limit 1;`).split("|");
		return service(`select public.record_policy_receipt('${keyHash}', ${version}, '${digest}');`);
	};

	const legacyFleet = hash();
	const legacyLive = sha(`legacy-live-${marker}`);
	const legacyRevoked = sha(`legacy-revoked-${marker}`);
	const personalIssuer = sha(`personal-issuer-${marker}`);
	const personalIssuer2 = sha(`personal-issuer2-${marker}`);
	const personalMember = sha(`personal-member-${marker}`);

	try {
		sql(PLATFORM);
		const all = readdirSync(resolve(root, "supabase/migrations")).filter((f) => f.endsWith(".sql")).sort();
		const split = all.indexOf(MIGRATION);
		assert.ok(split > 0, `${MIGRATION} is part of the canonical chain`);
		applyMigrations(all.slice(0, split));

		// Tenant in pilot mode with ten seats, an owner, two admin issuers and a member.
		sql(`
			update app.tenant_admission_config set mode = 'pilot', configured_at = now() where singleton;
			insert into auth.users(id, email) values
			  ('${OWNER}', 'owner-${marker}@example.invalid'), ('${ISSUER}', 'issuer-${marker}@example.invalid'),
			  ('${ISSUER2}', 'issuer2-${marker}@example.invalid'), ('${MEMBER}', 'member-${marker}@example.invalid');
			insert into public.tenants(id, name, kind, created_by) values ('${TENANT}', 'Fleet owned ${marker}', 'team', '${OWNER}');
			insert into public.teams(id, tenant_id, name, plan) values ('${TENANT}', '${TENANT}', 'Fleet owned ${marker}', 'free')
			  on conflict (id) do nothing;
			insert into public.tenant_members(tenant_id, user_id, role) values
			  ('${TENANT}', '${OWNER}', 'owner'), ('${TENANT}', '${ISSUER}', 'admin'),
			  ('${TENANT}', '${ISSUER2}', 'admin'), ('${TENANT}', '${MEMBER}', 'member')
			  on conflict (tenant_id, user_id) do update set role = excluded.role;
			insert into public.entitlements(user_id, tenant_id, included_agents, extra_agents) values ('${OWNER}', '${TENANT}', 10, 0)
			  on conflict do nothing;
			update public.entitlements set included_agents = 10 where tenant_id = '${TENANT}';
			insert into public.pilot_applications(user_id, tenant_id, status) values ('${OWNER}', '${TENANT}', 'approved');`);

		// Pre-migration enrollment: the legacy exchange binds keys to the issuer.
		assert.equal(json(`public.issue_fleet_enrollment_key_with_audit('${ISSUER}', '${TENANT}', 'legacy', 10, 90, '${legacyFleet}', 'lgcy')`).status, "issued");
		assert.equal(exchange(legacyFleet, "legacy-live", legacyLive).status, "enrolled");
		assert.equal(exchange(legacyFleet, "legacy-revoked", legacyRevoked).status, "enrolled");
		sql(`update public.api_keys set revoked = true where key_hash = '${legacyRevoked}';`);
		assert.equal(sql(`select user_id from public.api_keys where key_hash = '${legacyLive}';`), ISSUER);

		applyMigrations(all.slice(split));

		await t.test("the backfill converts fleet-minted keys and never revives a revoked one", () => {
			const legacyId = fleetIdOf(legacyFleet);
			assert.equal(keyRow(legacyLive), `-|${legacyId}|false`);
			assert.equal(keyRow(legacyRevoked), `-|${legacyId}|true`);
		});

		// Personal keys for both issuers and the member, plus fresh fleet enrollments.
		sql(`insert into public.api_keys(user_id, tenant_id, label, key_hash) values
			('${ISSUER}', '${TENANT}', 'issuer laptop', '${personalIssuer}'),
			('${ISSUER2}', '${TENANT}', 'issuer2 laptop', '${personalIssuer2}'),
			('${MEMBER}', '${TENANT}', 'member laptop', '${personalMember}');`);
		const fleetA = hash();
		const fleetB = hash();
		const fleetC = hash();
		assert.equal(json(`public.issue_fleet_enrollment_key_with_audit('${ISSUER}', '${TENANT}', 'laptops', 10, 90, '${fleetA}', 'aaaa')`).status, "issued");
		assert.equal(json(`public.issue_fleet_enrollment_key_with_audit('${ISSUER}', '${TENANT}', 'servers', 10, 90, '${fleetB}', 'bbbb')`).status, "issued");
		assert.equal(json(`public.issue_fleet_enrollment_key_with_audit('${ISSUER2}', '${TENANT}', 'kiosks', 10, 90, '${fleetC}', 'cccc')`).status, "issued");
		const devA = sha(`dev-a-${marker}`);
		const devB = sha(`dev-b-${marker}`);
		const devC = sha(`dev-c-${marker}`);

		await t.test("a fleet exchange mints a tenant-owned, agent-bound key", () => {
			const enrolled = exchange(fleetA, "host-a", devA);
			assert.equal(enrolled.status, "enrolled");
			assert.equal(enrolled.key_owner, "tenant");
			assert.equal(exchange(fleetB, "host-b", devB).status, "enrolled");
			assert.equal(exchange(fleetC, "host-c", devC).status, "enrolled");
			assert.equal(keyRow(devA), `-|${fleetIdOf(fleetA)}|false`);
			assert.notEqual(agentOf(devA), "");
			assert.equal(sql(`select detail ->> 'key_owner' from public.admin_audit_logs
				where action = 'fleet_key.enroll' and detail ->> 'iid' = 'host-a';`), "tenant");
		});

		await t.test("a tenant-owned key records its policy receipt", () => {
			service(`select public.publish_runtime_policy('${TENANT}', '${OWNER}', 0, '{}'::jsonb);`);
			assert.equal(receipt(devA), "t");
		});

		await t.test("owner shape and the fleet-key binding are fixed at mint time", () => {
			fails(`insert into public.api_keys(user_id, tenant_id, label, agent_id, key_hash, fleet_key_id)
				values ('${ISSUER}', '${TENANT}', 'x', '${agentOf(devA)}', '${hash()}', '${fleetIdOf(fleetA)}');`, /api_key_fleet_key_inactive/);
			// The check holds even with triggers bypassed.
			fails(`set session_replication_role = replica;
				insert into public.api_keys(tenant_id, label, key_hash) values ('${TENANT}', 'ownerless', '${hash()}');`, /api_keys_owner_shape/);
			fails(`update public.api_keys set fleet_key_id = '${fleetIdOf(fleetB)}' where key_hash = '${devA}';`, /api_key_owner_immutable/);
			fails(`update public.api_keys set user_id = '${ISSUER}' where key_hash = '${devA}';`, /api_keys_owner_shape/);
		});

		await t.test("removing the fleet key's creator keeps the fleet working and revokes only their keys", () => {
			sql(`delete from public.tenant_members where tenant_id = '${TENANT}' and user_id = '${ISSUER}';`);
			assert.equal(keyRow(personalIssuer).split("|")[2], "true", "the creator's personal key is revoked");
			assert.equal(keyRow(personalMember).split("|")[2], "false", "other members are untouched");
			for (const key of [devA, devB, legacyLive]) assert.equal(keyRow(key).split("|")[2], "false");
			// Machine paths keep working for the creator's fleet devices.
			service(poll(devA, "host-a"));
			service(poll(legacyLive, "legacy-live"));
			assert.equal(receipt(devA), "t");
			assert.equal(json(approval(devA, "host-a")).status, "pending");
			const adm = admission(devA);
			assert.equal(adm.status, "active");
			assert.equal(adm.trial_available, false);
			// A departed issuer's key cannot admit new machines.
			assert.equal(exchange(fleetA, "host-new", hash()).status, "tenant_not_authorized");
			// Re-enrolment of the removed member's personal key is still refused.
			fails(`update public.api_keys set key_hash = '${hash()}' where key_hash = '${personalIssuer}';`, /api_key_member_inactive/);
		});

		await t.test("SCIM-deprovisioning a fleet key's creator keeps their fleet devices", () => {
			const scim = randomUUID();
			sql(`insert into public.scim_users(id, tenant_id, external_id, user_name, normalized_user_name)
				values ('${scim}', '${TENANT}', 'issuer2-${marker}', 'issuer2@example.invalid', 'issuer2@example.invalid');
				set session_replication_role = replica;
				update public.scim_users set auth_user_id = '${ISSUER2}', active = true where id = '${scim}';
				set session_replication_role = origin;
				update public.scim_users set active = false where id = '${scim}';`);
			assert.equal(keyRow(personalIssuer2).split("|")[2], "true", "the deprovisioned person's key is revoked");
			assert.equal(keyRow(devC).split("|")[2], "false", "their fleet device keeps its key");
			service(poll(devC, "host-c"));
			assert.equal(sql(`select (detail ->> 'api_keys_revoked') from public.admin_audit_logs
				where action = 'scim.user.deprovisioned' and target_user_id = '${ISSUER2}';`), "1");
		});

		await t.test("revoking the fleet key stops its devices on every machine path", () => {
			const revoked = json(`public.revoke_fleet_enrollment_key_with_audit('${OWNER}', '${TENANT}', '${fleetIdOf(fleetB)}')`);
			assert.equal(revoked.status, "revoked");
			assert.equal(revoked.device_keys_revoked, 1);
			assert.equal(keyRow(devB).split("|")[2], "true");
			assert.equal(keyRow(devA).split("|")[2], "false", "another fleet key's devices are untouched");
			fails(`set role service_role; ${poll(devB, "host-b")}`, /fleet_agent_forbidden/);
			assert.equal(receipt(devB), "f");
			fails(`set role service_role; select ${approval(devB, "host-b")};`, /approval_requester_forbidden/);
			assert.equal(admission(devB).status, "forbidden");
			assert.equal(json(`public.record_fleet_device_installer_download('${keyIdOf(devB)}', '${TENANT}', '1.2.3',
				'linux-x64', 'aidr.deb', '${hash()}', 'deb')`).status, "forbidden");
			// Fail closed even if a device key were left unrevoked under a revoked fleet key.
			sql(`set session_replication_role = replica;
				update public.api_keys set revoked = false where key_hash = '${devB}';
				set session_replication_role = origin;`);
			fails(`set role service_role; ${poll(devB, "host-b")}`, /fleet_agent_forbidden/);
			assert.equal(receipt(devB), "f");
			assert.equal(admission(devB).status, "forbidden");
			sql(`update public.api_keys set revoked = true where key_hash = '${devB}';`);
		});

		await t.test("a tenant-owned key needs its own agent binding to file approvals", () => {
			fails(`set role service_role; select public.create_approval_request('${TENANT}', null, '${keyIdOf(devA)}',
				'${agentOf(devC)}', 'host-c', 'claude-code', 'a-${randomUUID()}', 'sha256:${hash()}', 'Bash', array['T-1'],
				'Run reviewed command', now() + interval '10 minutes');`, /approval_requester_forbidden/);
			assert.equal(json(`public.record_fleet_device_installer_download('${keyIdOf(devA)}', '${TENANT}', '1.2.3',
				'linux-x64', 'aidr.deb', '${hash()}', 'deb')`).status, "recorded");
			assert.equal(json(`public.record_fleet_device_installer_download('${keyIdOf(personalMember)}', '${TENANT}', '1.2.3',
				'linux-x64', 'aidr.deb', '${hash()}', 'deb')`).status, "forbidden", "personal keys keep the member-audited path");
		});

		await t.test("suspending the tenant stops tenant-owned keys", () => {
			sql(`update public.tenants set status = 'suspended' where id = '${TENANT}';`);
			fails(`set role service_role; ${poll(devA, "host-a")}`, /fleet_agent_forbidden/);
			assert.equal(admission(devA).status, "forbidden");
		});
	} finally {
		psql(admin, `drop database if exists ${name} with (force)`);
	}
});
