// Disposable PostgreSQL fixture: reproduce delegated recovery-code issuance,
// then verify the self-only migration and its invalidation of old codes.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";

const container = `aidr-recovery-p0-${randomUUID().slice(0, 8)}`;
const oldMigration = readFileSync(new URL("../supabase/migrations/20260912000013_identity_security.sql", import.meta.url), "utf8");
const newMigration = readFileSync(new URL("../supabase/migrations/20260924000001_recovery_code_self_only.sql", import.meta.url), "utf8");
const lockMigration = readFileSync(new URL("../supabase/migrations/20260924000012_identity_recovery_policy_lock_order.sql", import.meta.url), "utf8");
const start = oldMigration.indexOf("create or replace function public.issue_identity_recovery_codes(");
const end = oldMigration.indexOf("\n$$;", start);
assert.ok(start >= 0 && end > start, "original recovery-code function is missing");
const originalFunction = oldMigration.slice(start, end + 4);
const installed = process.argv.includes("--installed");
const [ownerA, target, tenantA, tenantB] = Array.from({ length: 4 }, () => randomUUID());
const hashes = (chars) => `array[${chars.map((char) => `'${char.repeat(64)}'`).join(",")}]::text[]`;
const issue = (tenant, actor, user, chars) => `public.issue_identity_recovery_codes('${tenant}','${actor}','${user}',${hashes(chars)},now()+interval '7 days')`;

function docker(args, input = "") {
	const result = spawnSync("docker", args, { input, encoding: "utf8", timeout: 60_000, maxBuffer: 4 * 1024 * 1024 });
	if (result.error) throw result.error;
	return result;
}

function sql(script) {
	const result = docker(["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres"], script);
	assert.equal(result.status, 0, `PostgreSQL test failed:\n${result.stdout}\n${result.stderr}`);
	return result.stdout.trim();
}

test("recovery codes cannot be issued across a shared user's tenant boundary", { timeout: 180_000 }, async () => {
	const started = docker(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=recovery-fixture-only", "postgres:17-alpine"]);
	assert.equal(started.status, 0, started.stderr);
	try {
		let ready = false;
		for (let i = 0; i < 100; i++) {
			if (docker(["exec", container, "pg_isready", "-U", "postgres"]).status === 0) { ready = true; break; }
			await delay(100);
		}
		assert.ok(ready, "isolated PostgreSQL did not start");
		sql(`create role anon; create role authenticated; create role service_role;
			create schema auth;
			create table auth.users(id uuid primary key);
			create table public.tenants(id uuid primary key, status text not null);
			create table public.tenant_members(tenant_id uuid, user_id uuid, role text, expires_at timestamptz);
			create table public.tenant_identity_policies(tenant_id uuid primary key, break_glass_enabled boolean not null);
			create table public.identity_recovery_codes(id uuid primary key default gen_random_uuid(),
				batch_id uuid, tenant_id uuid, user_id uuid, code_hash text unique, created_by uuid,
				created_at timestamptz default now(), expires_at timestamptz, used_at timestamptz, used_request_id text);
			create table public.admin_audit_logs(actor_user_id uuid, tenant_id uuid, target_user_id uuid,
				action text, detail jsonb);
			${originalFunction}`);
		if (installed) sql(`${newMigration}\n${lockMigration}`);

		const result = sql(`begin;
			insert into auth.users(id) values ('${ownerA}'), ('${target}');
			insert into public.tenants(id,status) values ('${tenantA}','active'), ('${tenantB}','active');
			insert into public.tenant_members(tenant_id,user_id,role) values
				('${tenantA}','${ownerA}','owner'), ('${tenantA}','${target}','viewer'),
				('${tenantB}','${target}','owner');
			insert into public.tenant_identity_policies values ('${tenantA}',true), ('${tenantB}',true);
			${installed ? "" : `select ${issue(tenantA, ownerA, target, ["a", "b", "c", "d"])};
				do $$ begin
					if (select count(*) from public.identity_recovery_codes where tenant_id='${tenantA}'
						and user_id='${target}' and used_at is null) <> 4 then
						raise exception 'old delegated issuance not reproduced'; end if;
				end $$;
				${newMigration}
				${lockMigration}
				do $$ begin
					if exists(select 1 from public.identity_recovery_codes where tenant_id='${tenantA}'
						and user_id='${target}' and used_at is null) then
						raise exception 'delegated recovery codes survived migration'; end if;
				end $$;`}
			do $$ begin
				if has_function_privilege('authenticated', 'public.issue_identity_recovery_codes(uuid,uuid,uuid,text[],timestamptz)', 'EXECUTE') then
					raise exception 'authenticated can execute recovery issuance'; end if;
				if not has_function_privilege('service_role', 'public.issue_identity_recovery_codes(uuid,uuid,uuid,text[],timestamptz)', 'EXECUTE') then
					raise exception 'service role cannot execute recovery issuance'; end if;
			end $$;
			create temp table audit_before as select count(*)::integer as n from public.admin_audit_logs;
			do $$ begin
				begin
					perform ${issue(tenantA, ownerA, target, ["6", "7", "8", "9"])};
					raise exception 'cross-tenant recovery issuance was accepted';
				exception when insufficient_privilege then null;
				end;
				if exists(select 1 from public.identity_recovery_codes where tenant_id='${tenantA}'
					and user_id='${target}' and used_at is null) then
					raise exception 'denied issuance wrote recovery codes'; end if;
				if (select count(*) from public.admin_audit_logs) <> (select n from audit_before) then
					raise exception 'denied issuance wrote success audit'; end if;
			end $$;
			select ${issue(tenantA, target, target, ["2", "3", "4", "5"])};
			do $$ begin
				if (select count(*) from public.identity_recovery_codes where tenant_id='${tenantA}'
					and user_id='${target}' and created_by='${target}' and used_at is null) <> 4 then
					raise exception 'active member self issuance failed'; end if;
			end $$;
			select ${issue(tenantB, target, target, ["e", "f", "0", "1"])};
			do $$ begin
				if (select count(*) from public.identity_recovery_codes where tenant_id='${tenantB}'
					and user_id='${target}' and created_by='${target}' and used_at is null) <> 4 then
					raise exception 'self issuance failed'; end if;
			end $$;
			select 'RECOVERY_CROSS_TENANT_ROLLBACK_OK';
			rollback;`);
		assert.match(result, /RECOVERY_CROSS_TENANT_ROLLBACK_OK/);
	} finally {
		docker(["rm", "--force", container]);
	}
});
