import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";

const container = `aidr-pack-offboarding-${randomUUID().slice(0, 8)}`;
const migration = readFileSync(new URL("../supabase/migrations/20260924000014_pack_storage_offboarding_guard.sql", import.meta.url), "utf8");
const tenant = "11111111-1111-4111-8111-111111111111";
const other = "22222222-2222-4222-8222-222222222222";

function docker(args, input = "") {
	const result = spawnSync("docker", args, { input, encoding: "utf8", timeout: 60_000, maxBuffer: 4 * 1024 * 1024 });
	if (result.error) throw result.error;
	return result;
}

function sql(statement) {
	const result = docker(["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres"], statement);
	assert.equal(result.status, 0, `Pack offboarding fixture failed:\n${result.stderr}`);
	return result.stdout.trim();
}

function denied(statement, reason) {
	const result = docker(["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres"], statement);
	assert.notEqual(result.status, 0, `Expected pack lifecycle refusal: ${statement}`);
	assert.match(result.stderr, reason);
}

test("tenant pack bytes cannot outlive a completed offboarding or bypass legal hold", { timeout: 120_000 }, async () => {
	const started = docker(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container, "-e", "POSTGRES_PASSWORD=fixture-only", "supabase/postgres:17.6.1.136"]);
	assert.equal(started.status, 0, started.stderr);
	try {
		let ready = false;
		for (let attempt = 0; attempt < 100; attempt += 1) {
			if (docker(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"]).status === 0) { ready = true; break; }
			await delay(100);
		}
		assert.ok(ready, "isolated PostgreSQL did not start");
		const storageGrant = docker(["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "supabase_admin", "-d", "postgres"], "grant create on schema storage to postgres;");
		assert.equal(storageGrant.status, 0, storageGrant.stderr);
		sql(`create schema if not exists app; create schema if not exists storage;
			create table public.tenants(id uuid primary key, status text not null);
			create table public.tenant_legal_holds(tenant_id uuid not null, released_at timestamptz);
			create table public.pack_versions(tenant_id uuid, storage_path text not null);
			create table public.tenant_offboarding_runs(tenant_id uuid not null, status text not null);
			create table storage.objects(bucket_id text not null, name text not null);
			insert into public.tenants values ('${tenant}','active'),('${other}','active');
			${migration}`);
		denied(`insert into public.pack_versions values ('${tenant}','other/path.pack');`, /pack_versions_tenant_storage_path/);
		sql(`insert into public.pack_versions values ('${tenant}','${tenant}/pack.bin');
			insert into storage.objects values ('aidr-packs','${tenant}/pack.bin');
			insert into public.tenant_offboarding_runs values ('${tenant}','requested');`);
		denied(`delete from public.pack_versions where tenant_id='${tenant}';`, /tenant_pack_storage_object_present/);
		denied(`update public.tenants set status='closed' where id='${tenant}';`, /offboarding_pack_storage_residue/);
		denied(`update public.tenant_offboarding_runs set status='completed' where tenant_id='${tenant}';`, /offboarding_pack_storage_residue/);
		sql(`insert into public.tenant_legal_holds values ('${tenant}',null);`);
		denied(`delete from storage.objects where bucket_id='aidr-packs' and name='${tenant}/pack.bin';`, /tenant_pack_storage_legal_hold/);
		denied(`update storage.objects set name='shared/pack.bin' where name='${tenant}/pack.bin';`, /tenant_pack_storage_legal_hold/);
		sql(`update public.tenant_legal_holds set released_at=now() where tenant_id='${tenant}';
			delete from storage.objects where bucket_id='aidr-packs' and name='${tenant}/pack.bin';
			delete from public.pack_versions where tenant_id='${tenant}';
			update public.tenant_offboarding_runs set status='completed' where tenant_id='${tenant}';
			update public.tenants set status='closed' where id='${tenant}';`);
		denied(`insert into storage.objects values ('aidr-packs','${tenant}/late.bin');`, /tenant_pack_storage_tenant_inactive/);
		assert.equal(sql(`insert into storage.objects values ('aidr-packs','${other}/active.bin');
			select count(*) from storage.objects where name='${other}/active.bin';`), "1");
	} finally {
		docker(["rm", "-f", container]);
	}
});
