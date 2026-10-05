// Real PostgreSQL guard: applies the COMPLETE canonical migration chain inside its
// OWN offline container (cached supabase/postgres image, --pull never) and then
// asserts, from the live catalog, that
//   * every SECURITY DEFINER function in public/app pins search_path with pg_temp,
//   * the backfill migration is idempotent (re-running changes nothing),
//   * app.tenant_admission_config is deny-by-default (RLS on, no policy) while the
//     owner-run SECURITY DEFINER admission functions keep working.
// It never targets an existing deployment.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { SEARCH_PATH_HARDENING_VERSION } from "./lib/security-definer-scan.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const container = `aidr-secdef-${randomUUID().slice(0, 8)}`;

function docker(args, input = "") {
	return new Promise((done, reject) => {
		const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"], timeout: 120_000 });
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk) => { stdout += chunk; });
		child.stderr.on("data", (chunk) => { stderr += chunk; });
		child.on("error", reject);
		child.on("close", (code) => done({ code, stdout: stdout.trim(), stderr }));
		child.stdin.on("error", () => {});
		child.stdin.end(input);
	});
}
const psql = ["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"];
async function sql(text) {
	const result = await docker(psql, text);
	assert.equal(result.code, 0, result.stderr);
	return result.stdout;
}
async function denied(text, pattern) {
	const result = await docker(psql, text);
	assert.notEqual(result.code, 0, "statement must be refused");
	assert.match(result.stderr, pattern);
}

const UNPINNED = `
select n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where p.prosecdef and n.nspname in ('public', 'app')
  and not exists (select 1 from unnest(coalesce(p.proconfig, array[]::text[])) c where c ~* '^search_path=.*pg_temp')
order by 1;`;

test("every SECURITY DEFINER function pins search_path with pg_temp after the full chain", { timeout: 600_000 }, async () => {
	const started = await docker(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=secdef-fixture-only", "supabase/postgres:17.6.1.136"]);
	assert.equal(started.code, 0, started.stderr);
	try {
		let ready = false;
		for (let i = 0; i < 150 && !ready; i++) {
			ready = (await docker(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])).code === 0;
			if (!ready) await new Promise((done) => setTimeout(done, 200));
		}
		assert.ok(ready, "isolated PostgreSQL must start");
		const fixture = await docker(["exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "supabase_admin", "-d", "postgres"],
			`grant create on schema storage to postgres;
			 create function auth.jwt() returns jsonb language sql stable as $$
			   select coalesce(nullif(current_setting('request.jwt.claims',true),''),'{}')::jsonb $$;`);
		assert.equal(fixture.code, 0, fixture.stderr);
		await sql(`create table storage.buckets(id text primary key, name text, public boolean);
			create table storage.objects(id uuid primary key default gen_random_uuid(), bucket_id text, name text, metadata jsonb);
			create function storage.foldername(name text) returns text[] language sql immutable as $$ select string_to_array(name, '/') $$;`);

		const migrations = readdirSync(resolve(root, "supabase/migrations")).filter((name) => name.endsWith(".sql")).sort();
		let beforeBackfill = null;
		for (const name of migrations) {
			if (name.startsWith(SEARCH_PATH_HARDENING_VERSION)) beforeBackfill = await sql(UNPINNED);
			const result = await docker(psql, `begin;\n${readFileSync(resolve(root, "supabase/migrations", name), "utf8")}\ncommit;`);
			assert.equal(result.code, 0, `${name}: ${result.stderr}`);
		}
		assert.ok(beforeBackfill, "the backfill migration must be part of the chain");
		assert.ok(beforeBackfill.length > 0, "the fixture proves the gap existed before the backfill");

		assert.equal(await sql(UNPINNED), "", "SECURITY DEFINER functions without search_path ... pg_temp");

		// Original path entries are preserved; only pg_temp was appended.
		assert.equal(
			await sql(`select array_to_string(proconfig, ';') from pg_proc where oid = 'public.increment_rate_limit(text,bigint,integer)'::regprocedure;`),
			"search_path=public, pg_temp",
		);
		assert.match(
			await sql(`select array_to_string(proconfig, ';') from pg_proc where oid = 'app.visible_tenant_admission_capacity(uuid)'::regprocedure;`),
			/pg_catalog, pg_temp/,
		);

		// Idempotent: a second run changes no function configuration.
		const snapshot = `select md5(string_agg(p.oid::regprocedure::text || coalesce(array_to_string(p.proconfig, ';'), ''), '|' order by p.oid::regprocedure::text))
			from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname in ('public', 'app');`;
		const before = await sql(snapshot);
		const rerun = readFileSync(resolve(root, "supabase/migrations", `${SEARCH_PATH_HARDENING_VERSION}_security_definer_search_path_pg_temp.sql`), "utf8");
		await sql(`begin;\n${rerun}\ncommit;`);
		assert.equal(await sql(snapshot), before);

		// A new unpinned SECURITY DEFINER function is detected by the live query.
		await sql(`create function public.__unpinned_probe() returns int language sql security definer as $$ select 1 $$;`);
		assert.equal(await sql(UNPINNED), "public.__unpinned_probe()");
		await sql(`drop function public.__unpinned_probe();`);

		// app.tenant_admission_config: RLS on, zero policies, no non-owner access.
		assert.equal(await sql(`select relrowsecurity::text || '/' || relforcerowsecurity::text from pg_class where oid = 'app.tenant_admission_config'::regclass;`), "true/false");
		assert.equal(await sql(`select count(*) from pg_policies where schemaname = 'app' and tablename = 'tenant_admission_config';`), "0");
		for (const role of ["anon", "authenticated", "service_role"]) {
			await denied(`set role ${role}; select * from app.tenant_admission_config;`, /permission denied|row-level security/i);
			await denied(`set role ${role}; update app.tenant_admission_config set mode = 'cloud';`, /permission denied|row-level security/i);
			await denied(`set role ${role}; insert into app.tenant_admission_config(singleton, mode) values (false, 'cloud');`, /permission denied|row-level security|violates check/i);
		}
		// Even with table privileges granted, RLS with no policy returns nothing and refuses writes.
		await sql(`grant select, update on app.tenant_admission_config to authenticated;`);
		assert.equal(await sql(`set role authenticated; select count(*) from app.tenant_admission_config;`), "0");
		assert.equal(await sql(`set role authenticated; with u as (update app.tenant_admission_config set mode = 'cloud' returning 1) select count(*) from u;`), "0");
		await sql(`revoke all on app.tenant_admission_config from authenticated;`);
		assert.equal(await sql(`select mode from app.tenant_admission_config;`), "unconfigured");

		// The owner-run SECURITY DEFINER function still reads the row.
		const tenant = randomUUID();
		const user = randomUUID();
		await sql(`insert into auth.users(id, email) values ('${user}', 'secdef-${user}@example.invalid');
			insert into public.tenants(id, name, kind, created_by) values ('${tenant}', 'secdef fixture', 'enterprise', '${user}') on conflict do nothing;`);
		await sql(`select public.tenant_admission_capacity('${tenant}');`);
	} finally {
		await docker(["rm", "-f", container]);
	}
});
