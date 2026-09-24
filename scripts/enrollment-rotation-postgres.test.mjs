import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const container = `aidr-t43-rotation-${randomUUID().slice(0, 8)}`;

function docker(args, input = "") {
	return new Promise((done, reject) => {
		const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"], timeout: 60_000 });
		let stdout = "", stderr = "";
		child.stdout.on("data", (chunk) => { stdout += chunk; });
		child.stderr.on("data", (chunk) => { stderr += chunk; });
		child.on("error", reject);
		child.on("close", (code) => done({ code, stdout: stdout.trim(), stderr }));
		child.stdin.on("error", () => {});
		child.stdin.end(input);
	});
}

async function sql(query) {
	const result = await docker(["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres"], query);
	assert.equal(result.code, 0, result.stderr);
	return result.stdout;
}

test("rotated enrollment hash resolves only during bounded overlap and never after consumption", { timeout: 180_000 }, async () => {
	const started = await docker(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=rotation-fixture-only", "postgres:17-alpine"]);
	assert.equal(started.code, 0, started.stderr);
	try {
		let ready = false;
		for (let i = 0; i < 100; i++) {
			if ((await docker(["exec", container, "psql", "-X", "-qAt", "-U", "postgres", "-c", "select 1"])).stdout === "1") { ready = true; break; }
			await new Promise((done) => setTimeout(done, 100));
		}
		assert.ok(ready, "isolated PostgreSQL must start");
		await sql(`create role anon; create role authenticated; create role service_role;
			create table public.tenants(id uuid primary key, status text not null);
			create table public.tenant_members(tenant_id uuid not null, user_id uuid not null, expires_at timestamptz);
			create table public.enrollment_tokens(token_hash text primary key, previous_hash text,
				previous_hash_expires_at timestamptz, consumed_at timestamptz, expires_at timestamptz not null,
				tenant_id uuid not null, user_id uuid not null);`);
		const oldMigration = readFileSync(resolve(root, "supabase/migrations/20260915000001_tenant_auth_isolation_hardening.sql"), "utf8");
		const start = oldMigration.indexOf("create or replace function public.resolve_enrollment_token(");
		const end = oldMigration.indexOf("$$;", start);
		assert.ok(start >= 0 && end > start, "existing resolver must be present");
		await sql(oldMigration.slice(start, end + 3));
		const tenant = randomUUID(), user = randomUUID();
		const oldHash = "a".repeat(64), currentHash = "b".repeat(64);
		await sql(`insert into public.tenants values ('${tenant}', 'active');
			insert into public.tenant_members values ('${tenant}', '${user}', null);
			insert into public.enrollment_tokens values ('${currentHash}', '${oldHash}',
				now() + interval '15 minutes', null, now() + interval '1 hour', '${tenant}', '${user}');`);
		const resolveHash = (hash) => `select coalesce(public.resolve_enrollment_token('${hash}')->>'tenant_id', 'null');`;
		assert.equal(await sql(resolveHash(oldHash)), "null", "old resolver reproduces the broken overlap");
		assert.equal(await sql(resolveHash(currentHash)), tenant);

		await sql(readFileSync(resolve(root, "supabase/migrations/20260923000050_enrollment_rotation_resolution.sql"), "utf8"));
		assert.equal(await sql(resolveHash(oldHash)), tenant);
		assert.equal(await sql(resolveHash(currentHash)), tenant);
		assert.equal(await sql(`select has_function_privilege('authenticated', 'public.resolve_enrollment_token(text)', 'EXECUTE');`), "f");
		assert.equal(await sql(`select has_function_privilege('service_role', 'public.resolve_enrollment_token(text)', 'EXECUTE');`), "t");
		await sql(`update public.enrollment_tokens set previous_hash_expires_at = now() - interval '1 second';`);
		assert.equal(await sql(resolveHash(oldHash)), "null");
		assert.equal(await sql(resolveHash(currentHash)), tenant);
		await sql(`update public.enrollment_tokens set previous_hash_expires_at = now() + interval '15 minutes';
			update public.tenants set status = 'suspended';`);
		assert.equal(await sql(resolveHash(oldHash)), "null");
		await sql(`update public.tenants set status = 'active';
			update public.tenant_members set expires_at = now() - interval '1 second';`);
		assert.equal(await sql(resolveHash(oldHash)), "null");
		await sql(`update public.tenant_members set expires_at = null;
			update public.enrollment_tokens set consumed_at = now();`);
		assert.equal(await sql(resolveHash(oldHash)), "null");
		assert.equal(await sql(resolveHash(currentHash)), "null");
		await sql(`update public.enrollment_tokens set consumed_at = null, expires_at = now() - interval '1 second';`);
		assert.equal(await sql(resolveHash(oldHash)), "null");
		assert.equal(await sql(resolveHash(currentHash)), "null");
	} finally {
		await docker(["rm", "--force", container]);
	}
});
