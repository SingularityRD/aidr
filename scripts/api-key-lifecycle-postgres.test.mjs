// Transaction, tenant/owner, and audit regression for API-key lifecycle RPCs.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";

const container = `aidr-api-key-lifecycle-${randomUUID().slice(0, 8)}`;
const migrations = [
	readFileSync(new URL("../supabase/migrations/20260923000008_atomic_credential_lifecycle.sql", import.meta.url), "utf8"),
	readFileSync(new URL("../supabase/migrations/20260923000047_membership_api_key_revocation.sql", import.meta.url), "utf8"),
];

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
	const result = docker(["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres"], script);
	assert.equal(result.status, 0, `Isolated API-key PostgreSQL test failed:\n${result.stdout}\n${result.stderr}`);
	return result.stdout.trim();
}

test("API-key issue, rotation, revocation, membership invalidation, and audit are atomic and tenant-bound", { timeout: 180_000 }, async () => {
	const started = docker([
		"run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=api-key-fixture-only", "postgres:17-alpine",
	]);
	assert.equal(started.status, 0, started.stderr);
	try {
		let ready = false;
		for (let i = 0; i < 100; i += 1) {
			if (docker(["exec", container, "pg_isready", "-U", "postgres"]).status === 0) {
				ready = true;
				break;
			}
			await delay(100);
		}
		assert.ok(ready, "isolated PostgreSQL did not start");

		const owner = "00000000-0000-4000-8000-000000000001";
		const member = "00000000-0000-4000-8000-000000000002";
		const secondMember = "00000000-0000-4000-8000-000000000003";
		const otherOwner = "00000000-0000-4000-8000-000000000004";
		const tenant = "00000000-0000-4000-8000-000000000101";
		const otherTenant = "00000000-0000-4000-8000-000000000102";
		const ownerHash = "a".repeat(64);
		const rotatedHash = "b".repeat(64);
		const memberHash = "c".repeat(64);
		const auditFailureHash = "d".repeat(64);

		sql(`create role anon;
			create role authenticated;
			create role service_role bypassrls;
			create schema auth;
			create function auth.uid() returns uuid language sql stable as $$ select null::uuid $$;
			create schema app;
			create table public.tenants(id uuid primary key, status text not null);
			create table public.tenant_members(
				tenant_id uuid not null, user_id uuid not null, role text not null, expires_at timestamptz,
				primary key (tenant_id, user_id));
			create table public.api_keys(
				id uuid primary key default gen_random_uuid(), user_id uuid not null, tenant_id uuid not null,
				label text, key_hash text not null unique, revoked boolean not null default false,
				previous_hash text, previous_hash_expires_at timestamptz, rotated_at timestamptz,
				created_at timestamptz not null default now());
			create table public.enrollment_tokens(
				id uuid primary key default gen_random_uuid(), user_id uuid not null, tenant_id uuid not null,
				label text, token_hash text not null unique, expires_at timestamptz not null,
				consumed_at timestamptz, previous_hash text, previous_hash_expires_at timestamptz, rotated_at timestamptz);
			create table public.admin_audit_logs(
				id bigint generated always as identity primary key, actor_user_id uuid, tenant_id uuid,
				target_user_id uuid, action text not null, detail jsonb not null default '{}'::jsonb);
			insert into public.tenants values ('${tenant}', 'active'), ('${otherTenant}', 'active');
			insert into public.tenant_members values
				('${tenant}', '${owner}', 'owner', null),
				('${tenant}', '${member}', 'member', null),
				('${tenant}', '${secondMember}', 'member', null),
				('${otherTenant}', '${otherOwner}', 'owner', null);
			${migrations[0]}
			${migrations[1]}`);

		assert.equal(sql(`select has_function_privilege('service_role','public.issue_api_key_with_audit(uuid,uuid,text,text)','EXECUTE')
			and not has_function_privilege('authenticated','public.issue_api_key_with_audit(uuid,uuid,text,text)','EXECUTE');`), "t");

		const ownerIssue = JSON.parse(sql(`set role service_role;
			select public.issue_api_key_with_audit('${owner}', '${tenant}', 'owner-key', '${ownerHash}');`));
		assert.equal(ownerIssue.status, "issued");
		const keyId = ownerIssue.id;
		assert.equal(sql(`select count(*) from public.admin_audit_logs where action='api_key.create' and detail->>'id'='${keyId}';`), "1");

		const memberIssue = JSON.parse(sql(`select public.issue_api_key_with_audit('${member}', '${tenant}', 'member-key', '${memberHash}');`));
		assert.equal(memberIssue.status, "issued");
		assert.equal(sql(`select public.renew_api_key_with_audit('${secondMember}', '${tenant}', '${memberIssue.id}', '${memberHash}', '${rotatedHash}', 24)->>'status';`), "not_found");
		assert.equal(sql(`select public.revoke_api_key_with_audit('${secondMember}', '${tenant}', '${memberIssue.id}')->>'status';`), "not_found");

		const renewed = JSON.parse(sql(`select public.renew_api_key_with_audit('${owner}', '${tenant}', '${keyId}', '${ownerHash}', '${rotatedHash}', 24);`));
		assert.equal(renewed.status, "rotated");
		assert.ok(Date.parse(renewed.previous_secret_valid_until) > Date.now());
		assert.equal(sql(`select key_hash='${rotatedHash}' and previous_hash='${ownerHash}' and not revoked from public.api_keys where id='${keyId}';`), "t");
		assert.equal(sql(`select public.renew_api_key_with_audit('${owner}', '${tenant}', '${keyId}', '${ownerHash}', '${rotatedHash}', 24)->>'status';`), "rotated");
		assert.equal(sql(`select count(*) from public.admin_audit_logs where action='api_key.renew' and detail->>'id'='${keyId}';`), "1", "lost-response retry must not duplicate rotation audit");
		assert.equal(sql(`select public.renew_api_key_with_audit('${otherOwner}', '${otherTenant}', '${keyId}', '${rotatedHash}', '${ownerHash}', 24)->>'status';`), "not_found");

		assert.equal(sql(`select public.revoke_api_key_with_audit('${owner}', '${tenant}', '${keyId}')->>'status';`), "revoked");
		assert.equal(sql(`select public.revoke_api_key_with_audit('${owner}', '${tenant}', '${keyId}')->>'status';`), "revoked");
		assert.equal(sql(`select count(*) from public.admin_audit_logs where action='api_key.revoke' and detail->>'id'='${keyId}';`), "1", "revoke retry must not duplicate audit");
		assert.equal(sql(`select public.renew_api_key_with_audit('${owner}', '${tenant}', '${keyId}', '${rotatedHash}', '${ownerHash}', 24)->>'status';`), "revoked");

		sql(`create function public.fail_selected_key_audit() returns trigger language plpgsql as $$
			begin
				if new.action='api_key.create' and new.detail->>'label'='audit-failure' then raise exception 'injected audit failure'; end if;
				return new;
			end $$;
			create trigger fail_selected_key_audit before insert on public.admin_audit_logs
			for each row execute function public.fail_selected_key_audit();
			do $$ begin
				begin
					perform public.issue_api_key_with_audit('${owner}', '${tenant}', 'audit-failure', '${auditFailureHash}');
					raise exception 'injected audit failure did not abort key issuance';
				exception when others then
					if sqlerrm = 'injected audit failure did not abort key issuance' then raise; end if;
				end;
				if exists (select 1 from public.api_keys where key_hash='${auditFailureHash}') then
					raise exception 'API key persisted without its audit row';
				end if;
			end $$;`);

		const memberRotatedHash = "e".repeat(64);
		const memberRenewed = JSON.parse(sql(`select public.renew_api_key_with_audit('${member}', '${tenant}', '${memberIssue.id}', '${memberHash}', '${memberRotatedHash}', 24);`));
		assert.equal(memberRenewed.status, "rotated");
		sql(`update public.tenant_members set role='viewer' where tenant_id='${tenant}' and user_id='${member}';`);
		assert.equal(sql(`select revoked and previous_hash is null and previous_hash_expires_at is null from public.api_keys where id='${memberIssue.id}';`), "t");
		sql(`update public.tenant_members set role='member' where tenant_id='${tenant}' and user_id='${member}';`);
		assert.equal(sql(`select revoked from public.api_keys where id='${memberIssue.id}';`), "t", "membership restoration must not revive old credentials");
		assert.equal(sql(`select count(*) from public.admin_audit_logs where action='api_key.membership_revoked' and target_user_id='${member}';`), "1");

		console.log("API-key lifecycle passed in isolated PostgreSQL: tenant/owner scoping, one-time hash issue, bounded rotation, idempotent revoke, audit atomicity, and membership revocation.");
	} finally {
		docker(["rm", "--force", container]);
	}
});
