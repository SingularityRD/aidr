// Disposable PostgreSQL regression for trusted reputation provenance writes.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";

const container = `aidr-reputation-lockdown-${randomUUID().slice(0, 8)}`;
const migration = readFileSync(
	new URL("../supabase/migrations/20260924000002_reputation_provenance_write_lockdown.sql", import.meta.url),
	"utf8",
);

function docker(args, input = "") {
	const result = spawnSync("docker", args, {
		input,
		encoding: "utf8",
		timeout: 60_000,
		maxBuffer: 4 * 1024 * 1024,
	});
	if (result.error) throw result.error;
	return result;
}

function sql(script) {
	const result = docker(
		["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres"],
		script,
	);
	assert.equal(result.status, 0, `PostgreSQL test failed:\n${result.stdout}\n${result.stderr}`);
	return result.stdout.trim();
}

test("authenticated tenants cannot write reputation while service-role ingestion remains available", { timeout: 180_000 }, async () => {
	const started = docker([
		"run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=reputation-fixture-only", "postgres:17-alpine",
	]);
	assert.equal(started.status, 0, started.stderr);
	try {
		let ready = false;
		for (let i = 0; i < 100; i += 1) {
			if (docker(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"]).status === 0) {
				ready = true;
				break;
			}
			await delay(100);
		}
		assert.ok(ready, "isolated PostgreSQL did not start");
		sql(`create role anon;
			create role authenticated;
			create role service_role bypassrls;
			create schema auth;
			create table public.url_reputation(
				id bigint generated always as identity primary key,
				tenant_id uuid not null,
				user_id uuid not null,
				url text,
				domain text,
				is_malicious boolean not null default false,
				created_at timestamptz not null default now()
			);
			create table public.file_reputation(
				id bigint generated always as identity primary key,
				tenant_id uuid not null,
				user_id uuid not null,
				sha256 text not null,
				severity text not null default 'SEVERITY_UNKNOWN',
				created_at timestamptz not null default now()
			);
			insert into public.url_reputation(tenant_id,user_id,url,is_malicious)
			values ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','https://legacy-clean.example',false);
			insert into public.file_reputation(tenant_id,user_id,sha256,severity)
			values ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002',repeat('b',64),'SEVERITY_UNKNOWN');
			alter table public.url_reputation enable row level security;
			alter table public.file_reputation enable row level security;
			create policy tenant_url_reputation_insert on public.url_reputation for insert to authenticated with check (true);
			create policy tenant_url_reputation_update on public.url_reputation for update to authenticated using (true) with check (true);
			create policy tenant_url_reputation_delete on public.url_reputation for delete to authenticated using (true);
			create policy tenant_file_reputation_insert on public.file_reputation for insert to authenticated with check (true);
			create policy tenant_file_reputation_update on public.file_reputation for update to authenticated using (true) with check (true);
			create policy tenant_file_reputation_delete on public.file_reputation for delete to authenticated using (true);
			create policy tenant_url_reputation_select on public.url_reputation for select to authenticated using (true);
			grant select, insert, update, delete on public.url_reputation, public.file_reputation to authenticated;
			grant usage, select, update on sequence public.url_reputation_id_seq, public.file_reputation_id_seq to authenticated;
			grant usage on schema public to anon, authenticated, service_role;
			grant all on public.url_reputation, public.file_reputation to service_role;
			grant all on sequence public.url_reputation_id_seq, public.file_reputation_id_seq to service_role;
			${migration}`);

		const privileges = sql(`select
			has_table_privilege('authenticated','public.url_reputation','SELECT')
			and not has_table_privilege('authenticated','public.url_reputation','INSERT')
			and not has_table_privilege('authenticated','public.url_reputation','UPDATE')
			and not has_table_privilege('authenticated','public.url_reputation','DELETE')
			and not has_table_privilege('authenticated','public.file_reputation','INSERT')
			and not has_sequence_privilege('authenticated','public.url_reputation_id_seq','USAGE')
			and has_table_privilege('service_role','public.url_reputation','INSERT')
			and has_table_privilege('service_role','public.file_reputation','INSERT');`);
		assert.equal(privileges, "t", "migration must remove browser writes and preserve service ingestion grants");
		const legacyRowsUntrusted = sql(`select
			(select provenance_verified from public.url_reputation where url='https://legacy-clean.example') is false
			and (select provenance_verified from public.file_reputation where sha256=repeat('b',64)) is false;`);
		assert.equal(legacyRowsUntrusted, "t", "pre-migration reputation rows must default to untrusted");

		const result = sql(`begin;
			set local role authenticated;
			do $$ begin
				begin
					insert into public.url_reputation(tenant_id,user_id,url,is_malicious)
					values ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','https://clean.example',false);
					raise exception 'authenticated reputation insert unexpectedly succeeded';
				exception when insufficient_privilege then null;
				end;
			end $$;
			reset role;
			set local role service_role;
			insert into public.url_reputation(tenant_id,user_id,url,is_malicious,provenance_verified)
			values ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','https://known-bad.example',true,true);
			insert into public.file_reputation(tenant_id,user_id,sha256,severity,provenance_verified)
			values ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002',repeat('a',64),'SEVERITY_MALWARE',true);
			select (select count(*) from public.url_reputation where provenance_verified) = 1
			and (select count(*) from public.file_reputation where provenance_verified) = 1;
			select 'REPUTATION_WRITE_LOCKDOWN_OK';
			rollback;`);
		assert.match(result, /^t\s+REPUTATION_WRITE_LOCKDOWN_OK$/,
			"trusted service-role writes should be consumable while historical rows remain excluded");
	} finally {
		docker(["rm", "--force", container]);
	}
});
