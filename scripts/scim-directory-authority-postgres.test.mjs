// Real SQL regression for TEN-04 directory-authoritative tenant membership.
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
const container = `aidr-directory-authority-${randomUUID()}`;
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

test("directory-authoritative membership is enforced by the live database", { timeout: 600_000 }, async t => {
	const started = await docker(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=directory-authority-fixture-only", "supabase/postgres:17.6.1.136"]);
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

		async function user(prefix) {
			const id = randomUUID();
			await sql(`insert into auth.users(id,email,raw_app_meta_data)
              values (${literal(id)},${literal(`${prefix}-${id}@example.invalid`)},'{"aidr_scim_provisioned":true}');`);
			return id;
		}
		async function tenant(name, owners) {
			const id = randomUUID();
			await sql(`insert into public.tenants(id,name,kind,created_by) values (${literal(id)},${literal(name)},'team',${literal(owners[0])});
              insert into public.teams(id,tenant_id,name) values (${literal(id)},${literal(id)},${literal(name)});
              insert into public.team_members(team_id,tenant_id,user_id,role)
                select ${literal(id)},${literal(id)},u,'owner' from unnest(${uuidArray(owners)}) u;`);
			return id;
		}
		const token = (id, actor, directory, rotatedFrom = null) => rpc(`public.scim_admin_create_token(${literal(id)},${literal(actor)},
          encode(extensions.gen_random_bytes(32),'hex'),'Fixture credential',now()+interval '30 days',
          ${rotatedFrom ? literal(rotatedFrom) : "null"}::uuid,${directory ? literal(directory) : "null"}::text)`);
		const enable = (id, actor, breakGlass, adopt, remove, directory = "entra-prod") =>
			`select public.scim_admin_enable_directory_authority(${literal(id)},${literal(actor)},${literal(directory)},
              ${uuidArray(breakGlass)},${adopt},${remove});`;
		const member = async (id, who) => sql(`select coalesce((select role from public.tenant_members
          where tenant_id=${literal(id)} and user_id=${literal(who)}),'none');`);
		// The bare image's auth.uid() reads request.jwt.claim.sub; GoTrue's own
		// migrations later make it read request.jwt.claims too. Set both.
		const isMember = async (id, who) => sql(`begin;
          set local request.jwt.claims = ${literal(JSON.stringify({ sub: who, role: "authenticated" }))};
          set local request.jwt.claim.sub = ${literal(who)};
          select app.is_tenant_member(${literal(id)}); commit;`);

		const owner = await user("owner"), owner2 = await user("owner2");
		const managed = await user("managed"), manual = await user("manual"), late = await user("late");
		const id = await tenant("Directory authority", [owner, owner2]);
		const scimUser = randomUUID(), group = randomUUID();
		await sql(`insert into public.scim_users(id,tenant_id,external_id,user_name,normalized_user_name) values
            (${literal(scimUser)},${literal(id)},'managed-subject','managed@example.invalid','managed@example.invalid');
          insert into public.scim_groups(id,tenant_id,external_id,display_name) values (${literal(group)},${literal(id)},'operators','Operators');
          insert into public.scim_group_role_mappings(tenant_id,external_group_id,role,created_by) values (${literal(id)},'operators','admin',${literal(owner)});
          insert into public.scim_group_memberships(tenant_id,group_id,user_id) values (${literal(id)},${literal(group)},${literal(scimUser)});`);
		await sql(service(`select public.scim_bind_user(${literal(id)},${literal(scimUser)},${literal(managed)});`));

		await t.test("the mode is off by default and manual memberships keep working", async () => {
			assert.equal(await sql(`select count(*) from public.tenant_directory_authority where tenant_id=${literal(id)};`), "0");
			await sql(`insert into public.team_members(team_id,tenant_id,user_id,role) values (${literal(id)},${literal(id)},${literal(manual)},'viewer');`);
			assert.equal(await member(id, manual), "viewer");
			assert.equal(await isMember(id, manual), "t");
			assert.equal(await member(id, managed), "admin");
			assert.equal(await sql(`select directory_id is null from public.scim_managed_memberships where scim_user_id=${literal(scimUser)};`), "t");
		});

		let legacyToken;
		await t.test("credentials carry an immutable source directory", async () => {
			await denied(`insert into public.scim_tokens(tenant_id,token_hash,label) values (${literal(id)},repeat('a',64),'unbound');`,
				/scim_token_directory_required/);
			await denied(service(`select public.scim_admin_create_token(${literal(id)},${literal(owner)},repeat('b',64),'unbound',now()+interval '1 day',null,null);`),
				/scim_admin_directory_required/);
			await denied(service(`select public.scim_admin_create_token(${literal(id)},${literal(owner)},repeat('b',64),'bad',now()+interval '1 day',null,'bad directory');`),
				/scim_admin_invalid_token/);
			const entra = await token(id, owner, "entra-prod");
			await denied(`update public.scim_tokens set directory_id='okta' where id=${literal(entra)};`, /scim_token_directory_immutable/);
			await denied(service(`select public.scim_admin_create_token(${literal(id)},${literal(owner)},repeat('c',64),'rotation',now()+interval '1 day',${literal(entra)},'okta');`),
				/scim_admin_directory_mismatch/);
			const rotated = await token(id, owner, null, entra);
			assert.equal(await sql(`select directory_id from public.scim_tokens where id=${literal(rotated)};`), "entra-prod");
			assert.equal(await sql(`select detail->>'directory_id' from public.admin_audit_logs
              where tenant_id=${literal(id)} and action='scim.token.rotated' order by id desc limit 1;`), "entra-prod");
			// A credential from before this migration has no recorded directory.
			await sql(`alter table public.scim_tokens disable trigger scim_tokens_directory_guard;
              insert into public.scim_tokens(tenant_id,token_hash,label,expires_at) values (${literal(id)},repeat('d',64),'legacy',now()+interval '1 day');
              alter table public.scim_tokens enable trigger scim_tokens_directory_guard;`);
			legacyToken = await sql(`select id from public.scim_tokens where token_hash=repeat('d',64);`);
		});

		await t.test("enabling refuses while another directory's credential is live", async () => {
			await denied(service(enable(id, owner, [owner, owner2], true, true)), /directory_authority_foreign_token_active/);
			await sql(service(`select public.scim_admin_revoke_token(${literal(id)},${literal(owner)},${literal(legacyToken)});`));
			const okta = await token(id, owner, "okta-prod");
			await denied(service(enable(id, owner, [owner, owner2], true, true)), /directory_authority_foreign_token_active/);
			await sql(service(`select public.scim_admin_revoke_token(${literal(id)},${literal(owner)},${literal(okta)});`));
			// A revoked credential of another known directory still makes adoption ambiguous.
			await denied(service(enable(id, owner, [owner, owner2], true, true)), /directory_authority_adoption_ambiguous/);
			await denied(service(enable(id, owner, [owner, owner2], true, true, "workday")), /directory_authority_directory_token_required/);
		});

		await t.test("break-glass owners must be exactly the active owners and enabling is owner-only", async () => {
			await denied(service(enable(id, owner, [owner], false, true)), /directory_authority_break_glass_mismatch/);
			await denied(service(enable(id, managed, [owner, owner2], false, true)), /scim_admin_owner_required/);
			await denied(service(enable(id, owner, [owner, owner, owner2], false, true)), /directory_authority_break_glass_invalid/);
		});

		await t.test("enabling refuses to strand unmanaged members unless removal is explicit", async () => {
			const result = await docker(pgArgs, `\\set VERBOSITY verbose\n${service(enable(id, owner, [owner, owner2], false, false))}`);
			assert.notEqual(result.code, 0);
			assert.match(result.stderr, /directory_authority_unmanaged_members/);
			// The unstamped SCIM admin and the manual viewer.
			assert.match(result.stderr, /DETAIL:\s+2/);
			assert.equal(await sql(`select count(*) from public.tenant_directory_authority where tenant_id=${literal(id)};`), "0");
			assert.equal(await member(id, manual), "viewer");
		});

		await t.test("enabling with explicit removal is audited and keeps directory and break-glass access", async () => {
			const result = JSON.parse(await sql(service(enable(id, owner, [owner2, owner], false, true))));
			assert.equal(result.enabled, true);
			assert.equal(result.removed_count, 2);
			assert.equal(await member(id, manual), "none");
			assert.equal(await member(id, managed), "none", "an unstamped SCIM membership is not this directory's");
			assert.equal(await sql(`select count(*) from public.scim_managed_memberships where tenant_id=${literal(id)};`), "0");
			assert.equal(await member(id, owner), "owner");
			assert.equal(await member(id, owner2), "owner");
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(id)}
              and action='scim.directory_authority.enabled' and actor_user_id=${literal(owner)}
              and detail->>'directory_id'='entra-prod' and (detail->>'removed_count')::int=2;`), "1");
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(id)}
              and action='team.member.removed' and target_user_id in (${literal(manual)},${literal(managed)});`), "2");
			// The directory re-provisions its user: the new row is stamped and grants access.
			await sql(service(`select public.scim_update_user(${literal(id)},${literal(scimUser)},'Managed',true,null);`));
			assert.equal(await member(id, managed), "admin");
			assert.equal(await sql(`select directory_id from public.scim_managed_memberships where scim_user_id=${literal(scimUser)};`), "entra-prod");
			assert.equal(await isMember(id, managed), "t");
			assert.equal(await isMember(id, owner), "t");
		});

		await t.test("while on, nothing but the directory or break-glass can grant access", async () => {
			await denied(`insert into public.team_members(team_id,tenant_id,user_id,role) values (${literal(id)},${literal(id)},${literal(late)},'viewer');`,
				/directory_authority_membership_required/);
			await denied(`insert into public.tenant_members(tenant_id,user_id,role) values (${literal(id)},${literal(late)},'member');`,
				/directory_authority_membership_required/);
			await denied(`update public.team_members set role='owner' where team_id=${literal(id)} and user_id=${literal(managed)};`,
				/directory_authority_membership_required/);
			await denied(`update public.team_members set role='admin' where team_id=${literal(id)} and user_id=${literal(owner2)};`,
				/directory_authority_membership_required/);
			// Deactivating the directory user without reconciliation cannot leave access behind.
			await denied(`update public.scim_users set active=false where id=${literal(scimUser)};`, /directory_authority_membership_required/);
			await denied(service(`select public.scim_admin_create_token(${literal(id)},${literal(owner)},repeat('e',64),'okta',now()+interval '1 day',null,'okta-prod');`),
				/scim_admin_directory_not_authoritative/);
			await denied(service(enable(id, owner, [owner, owner2], true, true)), /directory_authority_already_enabled/);
			assert.equal(await member(id, late), "none");
		});

		await t.test("only the configured directory's credential resolves", async () => {
			await sql(`alter table public.scim_tokens disable trigger scim_tokens_directory_guard;
              insert into public.scim_tokens(tenant_id,token_hash,label,expires_at,directory_id)
                values (${literal(id)},repeat('f',64),'smuggled',now()+interval '1 day','okta-prod');
              alter table public.scim_tokens enable trigger scim_tokens_directory_guard;`);
			assert.equal(await sql(service(`select count(*) from public.scim_resolve_token(repeat('f',64));`)), "0");
			const entraHash = "9".repeat(64);
			await sql(service(`select public.scim_admin_create_token(${literal(id)},${literal(owner)},${literal(entraHash)},'entra',now()+interval '1 day',null,'entra-prod');`));
			assert.equal(await sql(service(`select tenant_id from public.scim_resolve_token(${literal(entraHash)});`)), id);
		});

		await t.test("directory deprovisioning still removes access", async () => {
			await sql(service(`select public.scim_update_user(${literal(id)},${literal(scimUser)},'Managed',false,null);`));
			assert.equal(await member(id, managed), "none");
			assert.equal(await isMember(id, managed), "f");
		});

		await t.test("the last break-glass owner cannot be removed while the mode is on", async () => {
			await sql(`delete from public.team_members where team_id=${literal(id)} and user_id=${literal(owner2)};`);
			// The remaining owner loses break-glass status, so commit refuses it.
			await denied(`delete from public.tenant_directory_break_glass_owners where tenant_id=${literal(id)} and user_id=${literal(owner)};`,
				/directory_authority_(membership|break_glass_owner)_required/);
			assert.equal(await isMember(id, owner), "t");
		});

		await t.test("disabling is audited and restores the default behaviour", async () => {
			await denied(service(`select public.scim_admin_disable_directory_authority(${literal(id)},${literal(managed)});`), /scim_admin_owner_required/);
			assert.equal(await sql(service(`select public.scim_admin_disable_directory_authority(${literal(id)},${literal(owner)});`)), "t");
			assert.equal(await sql(service(`select public.scim_admin_disable_directory_authority(${literal(id)},${literal(owner)});`)), "f");
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(id)}
              and action='scim.directory_authority.disabled' and actor_user_id=${literal(owner)};`), "1");
			assert.equal(await sql(`select count(*) from public.tenant_directory_break_glass_owners where tenant_id=${literal(id)};`), "0");
			await sql(`insert into public.team_members(team_id,tenant_id,user_id,role) values (${literal(id)},${literal(id)},${literal(late)},'viewer');`);
			assert.equal(await isMember(id, late), "t");
		});

		await t.test("adoption stamps existing SCIM memberships when no other directory is known", async () => {
			const adoptOwner = await user("adopt-owner"), adopted = await user("adopted");
			const adoptTenant = await tenant("Adopting tenant", [adoptOwner]);
			const adoptScim = randomUUID(), adoptGroup = randomUUID();
			await sql(`insert into public.scim_users(id,tenant_id,external_id,user_name,normalized_user_name) values
                (${literal(adoptScim)},${literal(adoptTenant)},'adopted-subject','adopted@example.invalid','adopted@example.invalid');
              insert into public.scim_groups(id,tenant_id,external_id,display_name) values (${literal(adoptGroup)},${literal(adoptTenant)},'staff','Staff');
              insert into public.scim_group_role_mappings(tenant_id,external_group_id,role,created_by) values (${literal(adoptTenant)},'staff','member',${literal(adoptOwner)});
              insert into public.scim_group_memberships(tenant_id,group_id,user_id) values (${literal(adoptTenant)},${literal(adoptGroup)},${literal(adoptScim)});`);
			await sql(service(`select public.scim_bind_user(${literal(adoptTenant)},${literal(adoptScim)},${literal(adopted)});`));
			await token(adoptTenant, adoptOwner, "entra-prod");
			const result = JSON.parse(await sql(service(enable(adoptTenant, adoptOwner, [adoptOwner], true, false))));
			assert.equal(result.adopted_memberships, 1);
			assert.equal(result.removed_count, 0);
			assert.equal(await member(adoptTenant, adopted), "member");
			assert.equal(await isMember(adoptTenant, adopted), "t");
		});

		await t.test("offboarding erases the setting and suspends the invariant", async () => {
			const closeOwner = await user("close-owner");
			const closing = await tenant("Closing tenant", [closeOwner]);
			await token(closing, closeOwner, "entra-prod");
			await sql(service(enable(closing, closeOwner, [closeOwner], false, false)));
			await sql(`update public.tenant_data_retention_policies set retention_days=0 where tenant_id=${literal(closing)};`);
			const run = (await rpc(`public.request_tenant_offboarding(${literal(closing)},${literal(closeOwner)})`)).run_id;
			assert.equal(await sql(`select phase_order||':'||data_class from public.tenant_offboarding_phase_receipts
              where run_id=${literal(run)} and phase='tenant_directory_authority';`), "57:identity_membership");
			let state;
			for (let attempt = 0; attempt < 200; attempt++) {
				state = await rpc(`public.run_tenant_offboarding_batch(${literal(run)},100)`);
				if (state.action === "invalidate_cache") await rpc(`public.ack_tenant_offboarding_cache(${literal(run)},array['fixture-cache'],0)`);
				if (state.status === "completed") break;
			}
			assert.equal(state.status, "completed");
			assert.equal(await sql(`select count(*) from public.tenant_directory_authority where tenant_id=${literal(closing)};`), "0");
			assert.equal(await sql(`select status from public.tenant_offboarding_phase_receipts
              where run_id=${literal(run)} and phase='tenant_directory_authority';`), "completed");
		});
	} finally {
		await docker(["rm", "--force", container]);
	}
});
