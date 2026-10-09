// Force both serialization orders on a disposable, network-isolated PostgreSQL.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";

const container = `aidr-recovery-lock-${randomUUID().slice(0, 8)}`;
const baseMigration = readFileSync(new URL("../supabase/migrations/20260912000013_identity_security.sql", import.meta.url), "utf8");
const selfMigration = readFileSync(new URL("../supabase/migrations/20260924000001_recovery_code_self_only.sql", import.meta.url), "utf8");
const lockMigration = readFileSync(new URL("../supabase/migrations/20260924000012_identity_recovery_policy_lock_order.sql", import.meta.url), "utf8");

function extractFunction(source, name) {
	const start = source.indexOf(`create or replace function public.${name}(`);
	const end = source.indexOf("\n$$;", start);
	assert.ok(start >= 0 && end > start, `missing ${name} function`);
	return source.slice(start, end + 4);
}

function docker(args, input = "") {
	const result = spawnSync("docker", args, { input, encoding: "utf8", timeout: 60_000, maxBuffer: 4 * 1024 * 1024 });
	if (result.error) throw result.error;
	return result;
}

function sql(script) {
	const result = docker(["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres"], script);
	assert.equal(result.status, 0, `PostgreSQL fixture failed:\n${result.stdout}\n${result.stderr}`);
	return result.stdout.trim();
}

function startSql() {
	const child = spawn("docker", ["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres"], { stdio: ["pipe", "pipe", "pipe"] });
	const process = { child, stdout: "", stderr: "", closed: null };
	child.stdout.setEncoding("utf8").on("data", chunk => { process.stdout += chunk; });
	child.stderr.setEncoding("utf8").on("data", chunk => { process.stderr += chunk; });
	process.closed = new Promise(resolve => child.on("close", (code, signal) => resolve({ code, signal })));
	return process;
}

async function waitForText(process, text) {
	for (let attempt = 0; attempt < 200; attempt++) {
		if (process.stdout.includes(text)) return;
		if (process.child.exitCode !== null) break;
		await delay(25);
	}
	throw new Error(`did not observe PostgreSQL marker ${text}; output=${process.stdout}; error=${process.stderr}`);
}

async function waitForAdvisoryWait() {
	for (let attempt = 0; attempt < 120; attempt++) {
		const count = Number(sql("select count(*) from pg_stat_activity where wait_event_type='Lock' and wait_event='advisory'"));
		if (count > 0) return;
		await delay(25);
	}
	throw new Error("second transaction did not block on the shared tenant advisory lock");
}

async function finish(process) {
	return await process.closed;
}

test("recovery-code issue and policy-disable races serialize in either order", { timeout: 60_000 }, async () => {
	const owner = randomUUID();
	const tenant = randomUUID();
	const issue = (digits) => `public.issue_identity_recovery_codes('${tenant}','${owner}','${owner}',array[${digits.map(d => `'${d.repeat(64)}'`).join(",")}]::text[],now()+interval '7 days')`;
	const setPolicy = enabled => `public.set_tenant_identity_policy('${tenant}','${owner}',false,${enabled})`;
	const processes = new Set();
	const beginSql = docker(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=recovery-lock-fixture-only", "postgres:17-alpine"]);
	assert.equal(beginSql.status, 0, beginSql.stderr);
	try {
		let ready = false;
		for (let i = 0; i < 100; i++) {
			if (docker(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"]).status === 0) { ready = true; break; }
			await delay(100);
		}
		assert.ok(ready, "isolated PostgreSQL did not start");
		const setFunction = extractFunction(baseMigration, "set_tenant_identity_policy");
		sql(`create role anon; create role authenticated; create role service_role;
			create schema auth;
			create table auth.users(id uuid primary key);
			create table public.tenants(id uuid primary key, status text not null);
			create table public.tenant_members(tenant_id uuid, user_id uuid, role text, expires_at timestamptz);
			create table public.tenant_identity_policies(tenant_id uuid primary key, require_mfa boolean not null default false,
				break_glass_enabled boolean not null, updated_by uuid);
			create table public.identity_recovery_codes(id uuid primary key default gen_random_uuid(), batch_id uuid not null,
				tenant_id uuid not null, user_id uuid not null, code_hash text not null unique, created_by uuid not null,
				created_at timestamptz not null default now(), expires_at timestamptz not null,
				used_at timestamptz, used_request_id text);
			create table public.admin_audit_logs(actor_user_id uuid, tenant_id uuid, target_user_id uuid, action text, detail jsonb);
			${setFunction}
			${selfMigration}
			${lockMigration}
			insert into auth.users values ('${owner}');
			insert into public.tenants values ('${tenant}','active');
			insert into public.tenant_members values ('${tenant}','${owner}','owner',null);
			insert into public.tenant_identity_policies values ('${tenant}',false,true,'${owner}');`);

		// Disable holds the tenant barrier before a concurrent issuer can read
		// the old policy snapshot. Once disable commits, issuance must reject.
		sql(`insert into public.identity_recovery_codes(batch_id,tenant_id,user_id,code_hash,created_by,expires_at)
			values(gen_random_uuid(),'${tenant}','${owner}','${"a".repeat(64)}','${owner}',now()+interval '7 days');`);
		const disableFirst = startSql();
		processes.add(disableFirst);
		disableFirst.child.stdin.write(`begin; select ${setPolicy(false)}; select 'DISABLE_LOCK_HELD';\n`);
		await waitForText(disableFirst, "DISABLE_LOCK_HELD");
		const issueAfterDisable = startSql();
		processes.add(issueAfterDisable);
		issueAfterDisable.child.stdin.end(`begin; select ${issue(["b", "c", "d", "e"])}; commit;\n`);
		await waitForAdvisoryWait();
		disableFirst.child.stdin.end("commit;\n");
		const [disableResult, blockedIssueResult] = await Promise.all([finish(disableFirst), finish(issueAfterDisable)]);
		assert.equal(disableResult.code, 0, disableFirst.stderr);
		assert.notEqual(blockedIssueResult.code, 0, "issuance unexpectedly succeeded after policy disable");
		assert.match(issueAfterDisable.stderr, /break_glass_disabled/);
		assert.equal(sql(`select count(*) from public.identity_recovery_codes where tenant_id='${tenant}' and used_at is null`), "0");
		sql(`select ${setPolicy(true)};`);
		assert.equal(sql(`select count(*) from public.identity_recovery_codes where tenant_id='${tenant}' and used_at is null`), "0",
			"reopening policy must not resurrect a pre-disable code");

		// Issuance holds the same tenant barrier first. Disable waits; after issue
		// commits, disable deletes that batch before it commits.
		const issueFirst = startSql();
		processes.add(issueFirst);
		issueFirst.child.stdin.write(`begin; select ${issue(["6", "7", "8", "9"])}; select 'ISSUE_LOCK_HELD';\n`);
		await waitForText(issueFirst, "ISSUE_LOCK_HELD");
		const disableAfterIssue = startSql();
		processes.add(disableAfterIssue);
		disableAfterIssue.child.stdin.end(`begin; select ${setPolicy(false)}; commit;\n`);
		await waitForAdvisoryWait();
		issueFirst.child.stdin.end("commit;\n");
		const [issueResult, disableResult2] = await Promise.all([finish(issueFirst), finish(disableAfterIssue)]);
		assert.equal(issueResult.code, 0, issueFirst.stderr);
		assert.equal(disableResult2.code, 0, disableAfterIssue.stderr);
		assert.equal(sql(`select count(*) from public.identity_recovery_codes where tenant_id='${tenant}' and used_at is null`), "0",
			"disable must remove the batch issued immediately before it");
		sql(`select ${setPolicy(true)};`);
		assert.equal(sql(`select count(*) from public.identity_recovery_codes where tenant_id='${tenant}' and used_at is null`), "0",
			"reopening policy must not resurrect a code issued before disable");
	} finally {
		for (const process of processes) process.child.kill();
		docker(["rm", "--force", container]);
	}
});
