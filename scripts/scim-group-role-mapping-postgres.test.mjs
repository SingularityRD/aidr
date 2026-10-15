// Real SQL regression for T19: SCIM group -> tenant role mapping is driven
// only by server-verified immutable Group.externalId values and an owner-set
// allowlist. Covers forged metadata, look-alike display names, precedence,
// group removal/deletion, mapping removal, account deactivation, replay and
// pagination, and tenant mixing, plus the owner-only attribution read.
//
// Own random-name offline container only; complete ordered migration chain,
// no existing database or deployment. Requires a running Docker daemon and
// the pinned supabase/postgres image already pulled (`--pull never`).
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const container = `aidr-scim-role-mapping-${randomUUID()}`;
const pgArgs = ["exec", "-i", "-e", "PGOPTIONS=-c statement_timeout=10000 -c lock_timeout=5000",
	container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"];
const literal = value => `'${String(value).replaceAll("'", "''")}'`;
function docker(args, input = "") {
	return new Promise((done, reject) => {
		const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"], timeout: 120_000 });
		let stdout = "", stderr = "";
		child.stdout.on("data", chunk => { stdout += chunk; });
		child.stderr.on("data", chunk => { stderr += chunk; });
		child.once("error", reject);
		child.once("close", code => done({ code, stdout: stdout.trim(), stderr }));
		child.stdin.on("error", () => {});
		child.stdin.end(input);
	});
}
async function sql(text) {
	const result = await docker(pgArgs, text);
	assert.equal(result.code, 0, result.stderr);
	return result.stdout;
}
async function denied(text, pattern) {
	const result = await docker(pgArgs, text);
	assert.notEqual(result.code, 0, "statement must be refused");
	assert.match(result.stderr, pattern);
}
const service = text => `set role service_role; ${text}`;
const rpc = async expression => JSON.parse(await sql(service(`select coalesce(to_jsonb(${expression}), 'null'::jsonb);`)));
const uuidArray = ids => `array[${ids.map(literal).join(",")}]::uuid[]`;

test("SCIM group-role mapping is exact, deterministic, revocable and tenant-scoped", { timeout: 900_000 }, async t => {
	const started = await docker(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=scim-role-mapping-fixture-only",
		// Same pinned image as the other *-postgres tests; an operator may point
		// at the identical local image by digest/ID when the tag is not present.
		process.env.AIDR_SUPABASE_POSTGRES_IMAGE ?? "supabase/postgres:17.11.0.004"]);
	assert.equal(started.code, 0, started.stderr);
	try {
		let ready = false;
		for (let attempt = 0; attempt < 150 && !ready; attempt++) {
			ready = (await docker(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])).code === 0;
			if (!ready) await delay(100);
		}
		assert.ok(ready, "own isolated PostgreSQL must start");
		const bootstrap = await docker(["exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "supabase_admin", "-d", "postgres"],
			`grant create on schema storage to postgres;
             create table auth.identities(id uuid primary key default gen_random_uuid(), user_id uuid,
               provider text, provider_id text, identity_data jsonb);
             grant select, insert, update, delete on auth.identities to postgres;
             create function auth.jwt() returns jsonb language sql stable as $$
               select coalesce(nullif(current_setting('request.jwt.claims',true),''),'{}')::jsonb $$;`);
		assert.equal(bootstrap.code, 0, bootstrap.stderr);
		await sql(`create table storage.buckets(id text primary key, name text, public boolean);
          create table storage.objects(id uuid primary key default gen_random_uuid(), bucket_id text, name text, metadata jsonb);
          create function storage.foldername(name text) returns text[] language sql immutable as $$ select string_to_array(name, '/') $$;`);
		for (const name of readdirSync(resolve(root, "supabase/migrations")).filter(name => name.endsWith(".sql")).sort()) {
			const result = await docker(pgArgs, `begin;\n${readFileSync(resolve(root, "supabase/migrations", name), "utf8")}\ncommit;`);
			assert.equal(result.code, 0, `${name}: ${result.stderr}`);
		}
		await rpc("public.configure_tenant_admission_mode('pilot')");

		async function user(prefix, userMetadata = {}, appMetadata = { aidr_scim_provisioned: true }) {
			const id = randomUUID();
			await sql(`insert into auth.users(id,email,raw_app_meta_data,raw_user_meta_data)
              values (${literal(id)},${literal(`${prefix}-${id}@example.invalid`)},
                ${literal(JSON.stringify(appMetadata))}::jsonb,${literal(JSON.stringify(userMetadata))}::jsonb);`);
			return id;
		}
		async function tenant(name, owner) {
			const id = randomUUID();
			await sql(`insert into public.tenants(id,name,kind,created_by) values (${literal(id)},${literal(name)},'team',${literal(owner)});
              insert into public.teams(id,tenant_id,name) values (${literal(id)},${literal(id)},${literal(name)});
              insert into public.team_members(team_id,tenant_id,user_id,role) values (${literal(id)},${literal(id)},${literal(owner)},'owner');`);
			return id;
		}
		async function scimUser(tenantId, authUserId, subject) {
			const id = randomUUID();
			await sql(`insert into public.scim_users(id,tenant_id,external_id,user_name,normalized_user_name) values
                (${literal(id)},${literal(tenantId)},${literal(subject)},${literal(`${subject}@example.invalid`)},${literal(`${subject}@example.invalid`)});`);
			await sql(service(`select public.scim_bind_user(${literal(tenantId)},${literal(id)},${literal(authUserId)});`));
			return id;
		}
		// Groups go through the same SECURITY DEFINER RPCs the SCIM endpoint uses.
		const createGroup = async (tenantId, externalId, displayName, members) =>
			(await rpc(`(select g from public.scim_create_group(${literal(tenantId)},${literal(externalId)},${literal(displayName)},${uuidArray(members)}) g)`));
		const groupVersion = async groupId => Number(await sql(`select version from public.scim_groups where id=${literal(groupId)};`));
		const setMembers = (tenantId, groupId, displayName, members, version = null) =>
			sql(service(`select public.scim_update_group(${literal(tenantId)},${literal(groupId)},${literal(displayName)},${uuidArray(members)},${version === null ? "null" : version});`));
		const map = (tenantId, actor, externalId, role) =>
			rpc(`public.scim_admin_set_group_role_mapping(${literal(tenantId)},${literal(actor)},${literal(externalId)},${literal(role)})`);
		const unmap = (tenantId, actor, externalId) =>
			rpc(`public.scim_admin_remove_group_role_mapping(${literal(tenantId)},${literal(actor)},${literal(externalId)})`);
		const grants = (tenantId, actor, after = null, limit = 100) =>
			rpc(`public.scim_admin_list_role_grants(${literal(tenantId)},${literal(actor)},${after ? literal(after) : "null"}::uuid,${limit})`);
		const role = async (tenantId, who) => sql(`select coalesce((select role from public.tenant_members
          where tenant_id=${literal(tenantId)} and user_id=${literal(who)}),'none');`);
		const isMember = async (tenantId, who) => sql(`begin;
          set local request.jwt.claims = ${literal(JSON.stringify({ sub: who, role: "authenticated" }))};
          set local request.jwt.claim.sub = ${literal(who)};
          select app.is_tenant_member(${literal(tenantId)}); commit;`);

		const ownerA = await user("owner-a"), ownerB = await user("owner-b");
		const A = await tenant("Tenant A", ownerA);
		const B = await tenant("Tenant B", ownerB);
		// Every closing scenario below uses these mappings in tenant A.
		assert.equal(await map(A, ownerA, "grp-admins", "admin"), true);
		assert.equal(await map(A, ownerA, "grp-members", "member"), true);
		assert.equal(await map(A, ownerA, "grp-staff", "viewer"), true);

		await t.test("forged user/app metadata never grants a role", async () => {
			const forged = { groups: ["grp-admins", "Admins"], role: "owner", aidr_role: "admin", tenant_id: A };
			const mallory = await user("mallory", forged, { aidr_scim_provisioned: true, groups: ["grp-admins"], role: "admin" });
			const outsider = await user("outsider", forged);
			const malloryScim = await scimUser(A, mallory, "mallory-subject");
			// Reconciliation runs (directory update) but the user is in no group.
			await sql(service(`select public.scim_update_user(${literal(A)},${literal(malloryScim)},'Mallory',true,null);`));
			await sql(service(`select public.scim_reconcile_membership(${literal(A)},${literal(malloryScim)});`));
			assert.equal(await role(A, mallory), "none");
			assert.equal(await isMember(A, mallory), "f");
			assert.equal(await role(A, outsider), "none");
			assert.equal(await isMember(A, outsider), "f");
			// A user editing their own metadata after being granted changes nothing.
			const grp = await createGroup(A, "grp-staff", "Staff", [malloryScim]);
			assert.equal(await role(A, mallory), "viewer");
			await sql(`update auth.users set raw_user_meta_data = ${literal(JSON.stringify({ groups: ["grp-admins"], role: "admin" }))}::jsonb where id=${literal(mallory)};`);
			await sql(service(`select public.scim_reconcile_membership(${literal(A)},${literal(malloryScim)});`));
			assert.equal(await role(A, mallory), "viewer");
			await setMembers(A, grp.group_id, "Staff", []);
			assert.equal(await role(A, mallory), "none");
		});

		let alice, aliceScim, adminsGroup;
		await t.test("a look-alike display name or case/homoglyph id grants nothing", async () => {
			alice = await user("alice");
			aliceScim = await scimUser(A, alice, "alice-subject");
			const bob = await user("bob");
			const bobScim = await scimUser(A, bob, "bob-subject");
			adminsGroup = (await createGroup(A, "grp-admins", "Ops", [aliceScim])).group_id;
			assert.equal(await role(A, alice), "admin");
			// Displayed exactly as "Admins", but its immutable id is not mapped.
			await createGroup(A, "grp-admins-lookalike", "Admins", [bobScim]);
			await createGroup(A, "GRP-ADMINS", "Admins", [bobScim]);
			await createGroup(A, "grp-admіns", "Admins", [bobScim]); // Cyrillic і
			// A mapping created on the display-name string does not match either.
			assert.equal(await map(A, ownerA, "Admins", "admin"), true);
			assert.equal(await role(A, bob), "none");
			assert.equal(await isMember(A, bob), "f");
			// Renames move no authority: the real group keeps it, the fake gains none.
			await setMembers(A, adminsGroup, "Viewers", [aliceScim]);
			assert.equal(await role(A, alice), "admin");
			assert.equal(await unmap(A, ownerA, "Admins"), true);
			assert.equal(await role(A, bob), "none");
			// External ids are immutable once provisioned.
			await denied(`update public.scim_groups set external_id='grp-admins' where external_id='GRP-ADMINS' and tenant_id=${literal(A)};`,
				/scim|immutable|unique|duplicate/i);
		});

		await t.test("multi-group precedence is admin > member > viewer regardless of order", async () => {
			const carol = await user("carol");
			const carolScim = await scimUser(A, carol, "carol-subject");
			const staff = (await createGroup(A, "grp-staff-2", "Staff 2", [carolScim])).group_id;
			assert.equal(await map(A, ownerA, "grp-staff-2", "viewer"), true);
			assert.equal(await role(A, carol), "viewer");
			const members = (await createGroup(A, "grp-members", "Members", [carolScim, aliceScim])).group_id;
			assert.equal(await role(A, carol), "member", "member outranks viewer");
			assert.equal(await role(A, alice), "admin", "admin outranks member");
			await setMembers(A, adminsGroup, "Viewers", [aliceScim, carolScim]);
			assert.equal(await role(A, carol), "admin");
			// Attribution names the deciding group; a tie on role is broken by byte order.
			await createGroup(A, "grp-a-admins", "Zeta", [carolScim]);
			assert.equal(await map(A, ownerA, "grp-a-admins", "admin"), true);
			const page = await grants(A, ownerA);
			const carolGrant = page.grants.find(row => row.scim_user_id === carolScim);
			assert.equal(carolGrant.status, "granted");
			assert.equal(carolGrant.effective_role, "admin");
			assert.equal(carolGrant.granted_by_external_group_id, "grp-a-admins");
			assert.deepEqual(carolGrant.mapped_groups.map(group => `${group.role}:${group.external_group_id}`),
				["admin:grp-a-admins", "admin:grp-admins", "member:grp-members", "viewer:grp-staff-2"]);
			// Removing the deciding admin groups downgrades to the next mapping.
			assert.equal(await unmap(A, ownerA, "grp-a-admins"), true);
			await setMembers(A, adminsGroup, "Viewers", [aliceScim]);
			assert.equal(await role(A, carol), "member");
			assert.equal((await grants(A, ownerA)).grants.find(row => row.scim_user_id === carolScim).granted_by_external_group_id, "grp-members");
			// Changing a mapping's role re-reconciles immediately.
			assert.equal(await map(A, ownerA, "grp-members", "viewer"), true);
			assert.equal(await role(A, carol), "viewer");
			assert.equal(await map(A, ownerA, "grp-members", "member"), true);
			assert.equal(await role(A, carol), "member");
			// Removing the user from the group and deleting the last group revokes.
			await setMembers(A, members, "Members", [aliceScim]);
			assert.equal(await role(A, carol), "viewer");
			const version = await groupVersion(staff);
			assert.equal(await sql(service(`select public.scim_delete_group(${literal(A)},${literal(staff)},${version});`)), "t");
			assert.equal(await role(A, carol), "none");
			assert.equal(await isMember(A, carol), "f");
			assert.equal(await sql(`select count(*) from public.scim_managed_memberships where scim_user_id=${literal(carolScim)};`), "0");
		});

		await t.test("removing a mapping revokes; deactivation revokes until the directory reactivates", async () => {
			const dave = await user("dave");
			const daveScim = await scimUser(A, dave, "dave-subject");
			await createGroup(A, "grp-temp", "Temp", [daveScim]);
			assert.equal(await map(A, ownerA, "grp-temp", "member"), true);
			assert.equal(await role(A, dave), "member");
			// Commercial admission capacity is out of scope here; the membership
			// guard trigger on api_keys stays enabled.
			await sql(`alter table public.api_keys disable trigger api_keys_enrollment_admission;
              insert into public.api_keys(user_id, tenant_id, key_hash)
                values (${literal(dave)}, ${literal(A)}, encode(extensions.gen_random_bytes(32),'hex'));
              alter table public.api_keys enable trigger api_keys_enrollment_admission;`);
			assert.equal(await sql(`select count(*) from public.api_keys where user_id=${literal(dave)} and not revoked;`), "1");
			assert.equal(await unmap(A, ownerA, "grp-temp"), true);
			assert.equal(await role(A, dave), "none");
			// The cut also revokes the bearer keys issued under that membership.
			assert.equal(await sql(`select count(*) from public.api_keys where user_id=${literal(dave)} and not revoked;`), "0");
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(A)}
              and action='scim.mapping.deleted' and actor_user_id=${literal(ownerA)} and detail->>'external_group_id'='grp-temp';`), "1");

			assert.equal(await role(A, alice), "admin");
			assert.equal(await sql(service(`select public.scim_update_user(${literal(A)},${literal(aliceScim)},'Alice',false,null);`)), "t");
			assert.equal(await role(A, alice), "none");
			assert.equal(await isMember(A, alice), "f");
			const inactive = (await grants(A, ownerA)).grants.find(row => row.scim_user_id === aliceScim);
			assert.equal(inactive.status, "inactive");
			assert.equal(inactive.effective_role, null);
			assert.equal(inactive.granted_by_external_group_id, null);
			// Group membership changes while inactive cannot re-grant.
			await setMembers(A, adminsGroup, "Viewers", [aliceScim]);
			assert.equal(await role(A, alice), "none");
			assert.equal(await sql(service(`select public.scim_update_user(${literal(A)},${literal(aliceScim)},'Alice',true,null);`)), "t");
			assert.equal(await role(A, alice), "admin");
		});

		await t.test("replays are idempotent and a stale replay cannot restore removed access", async () => {
			const erin = await user("erin");
			const erinScim = await scimUser(A, erin, "erin-subject");
			const created = await createGroup(A, "grp-replay", "Replay", [erinScim]);
			assert.equal(created.created, true);
			assert.equal(await map(A, ownerA, "grp-replay", "member"), true);
			assert.equal(await role(A, erin), "member");
			const audits = await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(A)};`);
			// Identical POST replay: same resource, no new grant or audit row.
			const replay = await createGroup(A, "grp-replay", "Replay", [erinScim]);
			assert.deepEqual(replay, { group_id: created.group_id, created: false });
			assert.equal(await map(A, ownerA, "grp-replay", "member"), false, "re-setting an identical mapping is a no-op");
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(A)};`), audits);
			// A replay that differs is a conflict, not a silent overwrite.
			await denied(service(`select * from public.scim_create_group(${literal(A)},'grp-replay','Replay',array[]::uuid[]);`), /scim_replay_conflict/);
			// Remove Erin, then replay the earlier snapshot with its old version.
			const before = await groupVersion(created.group_id);
			await setMembers(A, created.group_id, "Replay", [], before);
			assert.equal(await role(A, erin), "none");
			await denied(service(`select public.scim_update_group(${literal(A)},${literal(created.group_id)},'Replay',${uuidArray([erinScim])},${before});`),
				/scim_version_mismatch/);
			assert.equal(await role(A, erin), "none");
			assert.equal(await isMember(A, erin), "f");
		});

		await t.test("attribution pages are keyset-stable, owner-only and service-role-only", async () => {
			const all = (await grants(A, ownerA)).grants.map(row => row.scim_user_id);
			assert.deepEqual(all, [...all].sort(), "rows are ordered by SCIM user id");
			assert.equal(new Set(all).size, all.length);
			const paged = [];
			let after = null;
			for (let i = 0; i < 50; i++) {
				const page = await grants(A, ownerA, after, 2);
				assert.ok(page.grants.length <= 2);
				paged.push(...page.grants.map(row => row.scim_user_id));
				after = page.next_after_scim_user_id;
				if (!after) break;
			}
			assert.deepEqual(paged, all, "pages neither skip nor repeat rows");
			await denied(service(`select public.scim_admin_list_role_grants(${literal(A)},${literal(ownerA)},null,0);`), /scim_admin_invalid_pagination/);
			await denied(service(`select public.scim_admin_list_role_grants(${literal(A)},${literal(ownerA)},null,101);`), /scim_admin_invalid_pagination/);
			await denied(service(`select public.scim_admin_list_role_grants(${literal(A)},${literal(alice)},null,10);`), /scim_admin_owner_required/);
			await denied(service(`select public.scim_admin_list_role_grants(${literal(A)},${literal(ownerB)},null,10);`), /scim_admin_owner_required/);
			for (const apiRole of ["anon", "authenticated"]) {
				assert.equal(await sql(`select has_function_privilege('${apiRole}', 'public.scim_admin_list_role_grants(uuid, uuid, uuid, integer)', 'execute');`), "f");
			}
			assert.equal(await sql(`select has_function_privilege('service_role', 'public.scim_admin_list_role_grants(uuid, uuid, uuid, integer)', 'execute');`), "t");
		});

		await t.test("a mapping or group in tenant B never affects tenant A", async () => {
			const frank = await user("frank");
			const frankScim = await scimUser(B, frank, "frank-subject");
			// Same immutable id in tenant B, mapped to a different role.
			assert.equal(await map(B, ownerB, "grp-admins", "viewer"), true);
			await createGroup(B, "grp-admins", "Ops", [frankScim]);
			assert.equal(await role(B, frank), "viewer");
			assert.equal(await role(A, alice), "admin");
			assert.equal(await role(A, frank), "none");
			assert.equal(await isMember(A, frank), "f");
			// A tenant-A SCIM user cannot be placed in a tenant-B group.
			await denied(service(`select * from public.scim_create_group(${literal(B)},'grp-cross','Cross',${uuidArray([aliceScim])});`),
				/scim_cross_tenant_or_unknown_user/);
			// Owners are tenant-scoped for mapping and attribution.
			await denied(service(`select public.scim_admin_set_group_role_mapping(${literal(A)},${literal(ownerB)},'grp-x','admin');`), /scim_admin_owner_required/);
			await denied(service(`select public.scim_admin_remove_group_role_mapping(${literal(A)},${literal(ownerB)},'grp-admins');`), /scim_admin_owner_required/);
			// Removing tenant B's mapping leaves tenant A untouched.
			assert.equal(await unmap(B, ownerB, "grp-admins"), true);
			assert.equal(await role(B, frank), "none");
			assert.equal(await role(A, alice), "admin");
			const bGrants = (await grants(B, ownerB)).grants;
			assert.ok(bGrants.every(row => row.scim_user_id !== aliceScim));
			// SCIM can never grant owner, in any tenant.
			await denied(service(`select public.scim_admin_set_group_role_mapping(${literal(A)},${literal(ownerA)},'grp-owners','owner');`), /scim_admin_invalid_mapping/);
			await denied(`insert into public.scim_group_role_mappings(tenant_id,external_group_id,role) values (${literal(A)},'grp-owners','owner');`, /check|violates/i);
		});
	} finally {
		await docker(["rm", "--force", container]);
	}
});
