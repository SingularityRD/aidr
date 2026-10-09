// Real PostgreSQL regression: full canonical migrations in our own offline
// container. Two-session races wait for observed locks, never timing guesses.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { authIdentityFixtureSql } from "./lib/postgres-auth-fixture.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const container = `aidr-oidc-admin-${randomUUID().slice(0, 8)}`;
const psql = ["exec", "-i", "-e", "PGOPTIONS=-c statement_timeout=20000 -c lock_timeout=15000", container,
	"psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"];
const sessions = new Set();

function command(args, input = "") {
	return new Promise((done, reject) => {
		const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"], timeout: 120_000 });
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", chunk => { stdout += chunk; });
		child.stderr.on("data", chunk => { stderr += chunk; });
		child.on("error", reject);
		child.on("close", code => done({ code, stdout: stdout.trim(), stderr }));
		child.stdin.on("error", () => {});
		child.stdin.end(input);
	});
}

async function sql(text) {
	const result = await command(psql, text);
	assert.equal(result.code, 0, result.stderr);
	return result.stdout;
}

async function denied(text, pattern) {
	const result = await command(psql, text);
	assert.notEqual(result.code, 0, "statement must be refused");
	assert.match(result.stderr, pattern);
	return result;
}

function session(name) {
	const child = spawn("docker", psql, { stdio: ["pipe", "pipe", "pipe"], timeout: 30_000 });
	const state = { child, stdout: "", stderr: "", closed: null };
	child.stdout.setEncoding("utf8").on("data", chunk => { state.stdout += chunk; });
	child.stderr.setEncoding("utf8").on("data", chunk => { state.stderr += chunk; });
	child.stdin.on("error", () => {});
	state.closed = new Promise((done, reject) => {
		child.on("error", reject);
		child.on("close", code => done({ code, stdout: state.stdout, stderr: state.stderr }));
	});
	sessions.add(state);
	child.stdin.write(`set application_name='${name}'; begin;\n`);
	return state;
}

async function marker(state, text) {
	for (let i = 0; i < 200; i++) {
		if (state.stdout.includes(text)) return;
		if (state.child.exitCode !== null) break;
		await delay(25);
	}
	assert.fail(`missing ${text}: ${state.stdout}\n${state.stderr}`);
}

async function advisoryWait(name) {
	for (let i = 0; i < 100; i++) {
		if (await sql(`select exists(select 1 from pg_stat_activity where application_name='${name}'
			and wait_event_type='Lock' and wait_event='advisory');`) === "t") return;
		await delay(25);
	}
	assert.fail(`${name} did not wait for the advisory lock`);
}

async function fixture({ domains = 1, linked = true, enforced = false } = {}) {
	const tenant = randomUUID();
	const owner = randomUUID();
	const backup = randomUUID();
	const provider = randomUUID();
	const authSession = randomUUID();
	const email = `oidc-${owner}@example.invalid`;
	await sql(`insert into auth.users(id,email) values ('${owner}','${email}'),('${backup}','oidc-${backup}@example.invalid');
		insert into public.tenants(id,name,kind,created_by) values ('${tenant}','OIDC fixture','enterprise','${owner}');
		insert into public.tenant_members(tenant_id,user_id,role) values
			('${tenant}','${owner}','owner'),('${tenant}','${backup}','owner');
		insert into public.oidc_providers(id,tenant_id,kind,display_name,issuer,client_id,token_auth_method,enabled,discovery)
			values ('${provider}','${tenant}','generic','Fixture IdP','https://idp.example.invalid','fixture-client','none',true,'{}');
		insert into public.oidc_sso_sessions(session_id,user_id,provider_id,tenant_id,expires_at)
			values ('${authSession}','${owner}','${provider}','${tenant}',now()+interval '1 hour');`);
	if (linked) await sql(`insert into public.oidc_identities(provider_id,subject,auth_user_id,tenant_id) values
		('${provider}','owner-subject','${owner}','${tenant}'),('${provider}','backup-subject','${backup}','${tenant}');`);
	const verifiedDomains = Array.from({ length: domains }, (_, index) => `d${index}-${tenant}.example.invalid`);
	for (const domain of verifiedDomains) await sql(`insert into public.oidc_tenant_domains(tenant_id,domain,verification_token,verified_at)
		values ('${tenant}','${domain}','${"a".repeat(32)}',now());`);
	const enable = `select public.oidc_set_enforcement('${tenant}','${owner}','${authSession}','${provider}',
		'Activate reviewed tenant identity policy','fixture-change');`;
	if (enforced) await sql(`set role service_role; ${enable}`);
	return { tenant, owner, backup, provider, authSession, email, verifiedDomains, enable };
}

test("OIDC administration, recovery and retention guards on full-chain PostgreSQL", { timeout: 900_000 }, async t => {
	const started = await command(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=oidc-admin-fixture-only", "supabase/postgres:17.6.1.136"]);
	assert.equal(started.code, 0, started.stderr);
	try {
		let ready = false;
		for (let i = 0; i < 150 && !ready; i++) {
			ready = (await command(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])).code === 0;
			if (!ready) await delay(200);
		}
		assert.ok(ready, "isolated PostgreSQL must start");
		const storage = await command(["exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "supabase_admin", "-d", "postgres"],
			`grant create on schema storage to postgres;
			 ${authIdentityFixtureSql}
			 create function auth.jwt() returns jsonb language sql stable as $$
			   select coalesce(nullif(current_setting('request.jwt.claims',true),''),'{}')::jsonb $$;`);
		assert.equal(storage.code, 0, storage.stderr);
		await sql(`create table storage.buckets(id text primary key, name text, public boolean);
			create table storage.objects(id uuid primary key default gen_random_uuid(), bucket_id text, name text, metadata jsonb);
			create function storage.foldername(name text) returns text[] language sql immutable as $$ select string_to_array(name, '/') $$;`);
		const migrations = readdirSync(resolve(root, "supabase/migrations")).filter(name => name.endsWith(".sql")).sort();
		for (const name of migrations) {
			const result = await command(psql, `begin;\n${readFileSync(resolve(root, "supabase/migrations", name), "utf8")}\ncommit;`);
			assert.equal(result.code, 0, `${name}: ${result.stderr}`);
		}
		assert.ok(migrations.includes("20261005220000_oidc_administration_hardening.sql"));
		assert.ok(migrations.includes("20261005221000_oidc_scim_offboarding.sql"));
		assert.ok(migrations.includes("20261005223000_fleet_response_key_overlap.sql"));
		assert.ok(migrations.includes("20261005224000_oidc_identity_namespace_cas.sql"));
		assert.ok(migrations.includes("20261005225000_scim_saml_binding_lock_order.sql"));
		t.diagnostic(`Applied all ${migrations.length} canonical migrations through ${migrations.at(-1)}`);

		await t.test("reviewed endpoint rate-limit scopes work and unreviewed scopes stay denied", async () => {
			const window = 987654321;
			const scopes = ["device_poll", "scim", "oidc-start", "oidc-callback", "oidc-break-glass"];
			for (const scope of scopes) {
				await sql(`set role service_role; select public.increment_rate_limit('${scope}:fixture',${window},1);
					select public.increment_rate_limit('${scope}:fixture',${window},1);`);
				assert.equal(await sql(`select count from public.rate_limits where key='${scope}:fixture' and window_start=${window};`), "2");
			}
			await denied(`set role service_role; select public.increment_rate_limit('bogus-scope:fixture',${window},1);`, /invalid_rate_limit_scope/);
			assert.equal(await sql("select count(*) from public.rate_limits where key='bogus-scope:fixture';"), "0");
			for (const role of ["anon", "authenticated"]) await denied(`set role ${role};
				select public.increment_rate_limit('oidc-start:fixture',${window},1);`, /permission denied/);
		});

		await t.test("linked subjects keep their identity namespace and an enforced IdP stays enabled", async () => {
			const f = await fixture();
			for (const edit of ["issuer='https://replacement.example.invalid'", "client_id='replacement-client'", "subject_claim='oid'"]) {
				await denied(`set role service_role; update public.oidc_providers set ${edit} where id='${f.provider}';`, /oidc_provider_identity_namespace_locked/);
			}
			assert.equal(await sql(`select issuer || '/' || client_id || '/' || subject_claim from public.oidc_providers where id='${f.provider}';`),
				"https://idp.example.invalid/fixture-client/sub");
			await sql(`set role service_role; ${f.enable}`);
			await denied(`set role service_role; update public.oidc_providers set enabled=false where id='${f.provider}';`, /oidc_provider_locked_by_enforcement/);
			await sql(`set role service_role; update public.oidc_providers set last_login_at=now(),discovery='{"issuer":"unchanged"}' where id='${f.provider}';`);
			assert.equal(await sql(`select enabled from public.oidc_providers where id='${f.provider}';`), "t");
		});

		await t.test("activation requires a verified domain inside the database transaction", async () => {
			const f = await fixture({ domains: 0 });
			await denied(`set role service_role; ${f.enable}`, /oidc_verified_domain_required/);
			assert.equal(await sql(`select count(*) from public.tenant_identity_policies where tenant_id='${f.tenant}' and required_oidc_provider_id is not null;`), "0");
		});

		await t.test("first identity insertion compares the verified provider namespace with its current configuration", async () => {
			const f = await fixture({ linked: false });
			await sql(`set role service_role; update public.oidc_providers set issuer='https://replacement.example.invalid' where id='${f.provider}';`);
			const insert = issuer => `select public.oidc_insert_identity('${f.provider}','${f.tenant}','new-subject','${f.owner}',
				'${f.email}','${issuer}','fixture-client','sub');`;
			await denied(`set role service_role; ${insert("https://idp.example.invalid")}`, /oidc_provider_identity_namespace_changed/);
			assert.equal(await sql(`select count(*) from public.oidc_identities where provider_id='${f.provider}';`), "0");
			await sql(`set role service_role; ${insert("https://replacement.example.invalid")}`);
			assert.equal(await sql(`select auth_user_id from public.oidc_identities where provider_id='${f.provider}' and subject='new-subject';`), f.owner);
			await denied(`set role service_role; update public.oidc_providers set issuer='https://third.example.invalid' where id='${f.provider}';`,
				/oidc_provider_identity_namespace_locked/);
		});

		await t.test("concurrent verified-domain removals preserve one domain without deadlocking", async () => {
			const f = await fixture({ domains: 2, enforced: true });
			const first = session("oidc-domain-first");
			first.child.stdin.write(`set local role service_role; delete from public.oidc_tenant_domains
				where tenant_id='${f.tenant}' and domain='${f.verifiedDomains[0]}'; select 'DOMAIN_REMOVED';\n`);
			await marker(first, "DOMAIN_REMOVED");
			const second = session("oidc-domain-second");
			second.child.stdin.end(`set local role service_role; delete from public.oidc_tenant_domains
				where tenant_id='${f.tenant}' and domain='${f.verifiedDomains[1]}'; commit;\n`);
			await advisoryWait("oidc-domain-second");
			first.child.stdin.end("commit;\n");
			const [a, b] = await Promise.all([first.closed, second.closed]);
			assert.equal(a.code, 0, a.stderr);
			assert.notEqual(b.code, 0, "second deletion removed the last domain");
			assert.match(b.stderr, /oidc_last_verified_domain_locked_by_enforcement/);
			assert.doesNotMatch(b.stderr, /deadlock|lock timeout/);
			assert.equal(await sql(`select count(*) from public.oidc_tenant_domains where tenant_id='${f.tenant}' and verified_at is not null;`), "1");
		});

		for (const operation of ["rotate", "disable"]) await t.test(`break-glass rechecks its code after waiting for ${operation}`, async () => {
			const f = await fixture({ enforced: true });
			const oldHash = "f".repeat(64);
			// Each fixture owns its code hash; avoid collisions with prior subtests.
			const codeHash = await sql(`select encode(extensions.digest('${f.tenant}:${oldHash}','sha256'),'hex');`);
			const issue = hashes => `select public.issue_identity_recovery_codes('${f.tenant}','${f.owner}','${f.owner}',
				array[${hashes.map(hash => `'${hash}'`).join(",")}],now()+interval '7 days');`;
			await sql(`set role service_role; select public.set_tenant_identity_policy('${f.tenant}','${f.owner}',false,true);
				${issue([codeHash, ...["a", "b", "c"].map(d => d + f.tenant.replaceAll("-", "").repeat(2).slice(0, 63))])}`);
			const holder = session(`oidc-recovery-${operation}-holder`);
			holder.child.stdin.write(`select pg_advisory_xact_lock(hashtextextended('${f.tenant}',2607)); select 'POLICY_LOCK_HELD';\n`);
			await marker(holder, "POLICY_LOCK_HELD");
			const waiter = session(`oidc-recovery-${operation}-waiter`);
			waiter.child.stdin.end(`set local role service_role; select coalesce(public.oidc_break_glass_suspend(
				'${f.email}','${codeHash}','fixture-${operation}')::text,'NO_SUSPEND'); commit;\n`);
			await advisoryWait(`oidc-recovery-${operation}-waiter`);
			const change = operation === "rotate"
				? issue(["1", "2", "3", "4"].map(d => d + f.tenant.replaceAll("-", "").repeat(2).slice(0, 63)))
				: `select public.set_tenant_identity_policy('${f.tenant}','${f.owner}',false,false);`;
			holder.child.stdin.end(`set local role service_role; ${change} commit;\n`);
			const [a, b] = await Promise.all([holder.closed, waiter.closed]);
			assert.equal(a.code, 0, a.stderr);
			assert.equal(b.code, 0, b.stderr);
			assert.match(b.stdout, /NO_SUSPEND/);
			assert.equal(await sql(`select required_oidc_provider_id='${f.provider}'::uuid from public.tenant_identity_policies where tenant_id='${f.tenant}';`), "t");
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id='${f.tenant}' and action='identity.oidc.break_glass_enforcement_suspended';`), "0");
		});

		for (const mutation of ["release_hold", "set_retention"]) await t.test(`retention owner recheck prevents ${mutation} after demotion while waiting`, async () => {
			const f = await fixture();
			const hold = await sql(`set role service_role; select public.admin_place_tenant_legal_hold('${f.tenant}','${f.owner}',
				'FIXTURE-CASE','Fixture owner','Preserve investigation evidence','fixture-hold');`);
			const before = await sql(`select retention_days from public.tenant_data_retention_policies where tenant_id='${f.tenant}' and data_class='telemetry';`);
			const holder = session(`retention-${mutation}-holder`);
			holder.child.stdin.write(`select pg_advisory_xact_lock(hashtextextended('${f.tenant}',2606)); select 'RETENTION_LOCK_HELD';\n`);
			await marker(holder, "RETENTION_LOCK_HELD");
			const waiter = session(`retention-${mutation}-waiter`);
			const mutate = mutation === "release_hold"
				? `select public.admin_release_tenant_legal_hold('${f.tenant}','${f.owner}','${hold}','Investigation complete');`
				: `select public.admin_set_tenant_retention('${f.tenant}','${f.owner}','telemetry',7,'Change after review');`;
			waiter.child.stdin.end(`set local role service_role; ${mutate} commit;\n`);
			await advisoryWait(`retention-${mutation}-waiter`);
			holder.child.stdin.end(`update public.tenant_members set role='admin' where tenant_id='${f.tenant}' and user_id='${f.owner}'; commit;\n`);
			const [a, b] = await Promise.all([holder.closed, waiter.closed]);
			assert.equal(a.code, 0, a.stderr);
			assert.notEqual(b.code, 0, "demoted owner changed retention state");
			assert.match(b.stderr, /retention_admin_owner_required/);
			assert.equal(await sql(`select released_at is null from public.tenant_legal_holds where id='${hold}';`), "t");
			assert.equal(await sql(`select retention_days from public.tenant_data_retention_policies where tenant_id='${f.tenant}' and data_class='telemetry';`), before);
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id='${f.tenant}' and action in ('legal_hold.released','retention.policy.changed');`), "0");
		});

		await t.test("documented privileged release clears a closing tenant's hold atomically without reopening or faking receipts", async () => {
			const document = readFileSync(resolve(root, "docs/production-readiness/retention-holds.md"), "utf8");
			const fences = [...document.matchAll(/^```sql\r?\n([\s\S]*?)^```/gm)]
				.map(match => match[1]).filter(text => text.includes("do $release_offboarding_hold$"));
			assert.equal(fences.length, 1, "the operator runbook must contain one exact release transaction");
			const f = await fixture();
			const hold = await sql(`set role service_role; select public.admin_place_tenant_legal_hold('${f.tenant}','${f.owner}',
				'OPERATOR-CASE','Fixture hold owner','Preserve evidence until approved release','operator-hold');`);
			const run = JSON.parse(await sql(`set role service_role; select public.request_tenant_offboarding('${f.tenant}','${f.owner}');`));
			assert.equal(run.status, "blocked_legal_hold");
			const lifecycle = () => sql(`select jsonb_build_object('tenant',t.status,'run',r.status,
				'receipts',(select jsonb_agg(to_jsonb(p) order by p.phase_order) from public.tenant_offboarding_phase_receipts p where p.run_id=r.id))
				from public.tenants t join public.tenant_offboarding_runs r on r.tenant_id=t.id
				where t.id='${f.tenant}' and r.id='${run.run_id}';`);
			const auditCount = () => sql(`select count(*) from public.admin_audit_logs where tenant_id='${f.tenant}' and action='legal_hold.released';`);
			const before = await lifecycle();
			const reason = "Release approved after operator's review";
			const change = "CHANGE-OPERATOR-123";
			const approval = "APPROVAL-LEGAL-456";
			const operator = "Named legal/database operator";
			const releaseSql = ({ owner = f.owner, holdId = hold } = {}) => {
				const replacements = new Map([
					["<tenant UUID>", f.tenant], ["<hold UUID>", holdId], ["<current owner Auth UUID>", owner],
					["<approved release reason>", reason], ["<change reference>", change],
					["<written approval reference>", approval], ["<named legal/database operator>", operator],
				]);
				let text = fences[0];
				for (const [placeholder, value] of replacements) {
					const quoted = `'${placeholder}'`;
					assert.equal(text.split(quoted).length, 2, `runbook placeholder ${placeholder} must occur once`);
					text = text.replace(quoted, `'${value.replaceAll("'", "''")}'`);
				}
				assert.doesNotMatch(text, /<[^>]+>/, "every runbook placeholder must be substituted");
				return text;
			};
			await denied(`set role service_role; select public.admin_release_tenant_legal_hold('${f.tenant}','${f.owner}','${hold}',
				'Ordinary tenant API must remain closed');`, /retention_admin_owner_required/);
			for (const [input, error] of [[{ owner: randomUUID() }, /closing tenant and current owner required/],
				[{ holdId: randomUUID() }, /active hold not found/]]) {
				await denied(releaseSql(input), error);
				assert.equal(await sql(`select released_at is null from public.tenant_legal_holds where id='${hold}';`), "t");
				assert.equal(await auditCount(), "0");
				assert.equal(await lifecycle(), before);
			}
			await sql(releaseSql());
			const released = JSON.parse(await sql(`select jsonb_build_object('released',released_at is not null,
				'owner',released_by,'reason',release_reason,'case',case_id,'hold_owner',hold_owner)
				from public.tenant_legal_holds where id='${hold}';`));
			assert.deepEqual(released, { released: true, owner: f.owner, reason, case: "OPERATOR-CASE", hold_owner: "Fixture hold owner" });
			assert.equal(await auditCount(), "1");
			const audit = JSON.parse(await sql(`select jsonb_build_object('actor',actor_user_id,'detail',detail)
				from public.admin_audit_logs where tenant_id='${f.tenant}' and action='legal_hold.released';`));
			assert.equal(audit.actor, f.owner);
			assert.equal(audit.detail.hold_id, hold);
			assert.equal(audit.detail.case_id, "OPERATOR-CASE");
			assert.equal(audit.detail.hold_owner, "Fixture hold owner");
			assert.equal(audit.detail.release_reason, reason);
			assert.equal(audit.detail.change_reference, change);
			assert.equal(audit.detail.approval_reference, approval);
			assert.equal(audit.detail.operator, operator);
			assert.equal(audit.detail.method, "trusted_operator_offboarding");
			assert.equal(await lifecycle(), before, "release cannot reopen a tenant, finish a run or modify erasure receipts");
			await denied(releaseSql(), /active hold not found/);
			assert.equal(await auditCount(), "1", "a replay cannot release again or invent another audit event");
		});

		await t.test("fleet command credentials honour renewed-key overlap and preserve state on rejected credentials", async () => {
			const f = await fixture();
			const agent = randomUUID();
			const otherTenant = randomUUID();
			const otherAgent = randomUUID();
			const oldHash = await sql(`select encode(extensions.digest('${f.tenant}:old-key','sha256'),'hex');`);
			const newHash = await sql(`select encode(extensions.digest('${f.tenant}:new-key','sha256'),'hex');`);
			await sql(`set role service_role; select public.configure_tenant_admission_mode('pilot');`);
			await sql(`insert into public.pilot_applications(user_id,tenant_id,status,cohort)
				values ('${f.owner}','${f.tenant}','approved','oidc_admin') on conflict (user_id,tenant_id) do nothing;
				insert into public.agents(id,tenant_id,user_id,iid) values ('${agent}','${f.tenant}','${f.owner}','fleet-${agent}');
				insert into public.api_keys(user_id,tenant_id,agent_id,key_hash) values ('${f.owner}','${f.tenant}','${agent}','${oldHash}');`);
			const key = await sql(`select id from public.api_keys where key_hash='${oldHash}';`);
			await sql(`set role service_role; select public.renew_api_key_with_audit('${f.owner}','${f.tenant}','${key}','${oldHash}','${newHash}',1);`);
			const queue = () => sql(`set role service_role; select (public.queue_bounded_fleet_response_command('${f.tenant}','${f.owner}','${agent}',
				'agent_pause','Contain suspicious agent activity','fixture-${randomUUID()}',300,null)).id;`);
			const poll = (hash, tenant = f.tenant, target = agent) => `select (public.poll_fleet_response_command('${hash}','${tenant}','${target}')).state;`;
			const record = (hash, id, tenant = f.tenant, target = agent) => `select (public.record_fleet_response_command('${hash}','${tenant}','${target}','${id}','ack','accepted',null)).state;`;
			const first = await queue();
			assert.equal(await sql(`set role service_role; ${poll(oldHash)}`), "delivered");
			assert.equal(await sql(`set role service_role; ${record(oldHash, first)}`), "acknowledged");
			const pending = await queue();
			const unchanged = () => sql(`select state || '/' || attempts from public.fleet_response_commands where id='${pending}';`);
			for (const [tenant, target] of [[otherTenant, agent], [f.tenant, otherAgent]]) {
				await denied(`set role service_role; ${poll(oldHash, tenant, target)}`, /fleet_agent_forbidden/);
				await denied(`set role service_role; ${record(oldHash, pending, tenant, target)}`, /fleet_agent_forbidden/);
				assert.equal(await unchanged(), "pending/0");
			}
			await sql(`update public.api_keys set rotated_at=now()-interval '2 hours',previous_hash_expires_at=now()-interval '1 hour' where id='${key}';`);
			await denied(`set role service_role; ${poll(oldHash)}`, /fleet_agent_forbidden/);
			await denied(`set role service_role; ${record(oldHash, pending)}`, /fleet_agent_forbidden/);
			assert.equal(await unchanged(), "pending/0");
			assert.equal(await sql(`set role service_role; ${poll(newHash)}`), "delivered");
			await sql(`update public.api_keys set revoked=true where id='${key}';`);
			await denied(`set role service_role; ${poll(newHash)}`, /fleet_agent_forbidden/);
			await denied(`set role service_role; ${record(newHash, pending)}`, /fleet_agent_forbidden/);
			assert.equal(await unchanged(), "delivered/1");
		});
	} finally {
		for (const state of sessions) if (state.child.exitCode === null) state.child.kill();
		await command(["rm", "-f", container]);
	}
});
