// Full canonical SQL chain in our own cached, network-isolated PostgreSQL.
// This exercises transport and audit authority, not device/OS execution.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const container = `aidr-fleet-signed-${randomUUID().slice(0, 8)}`;
const psql = ["exec", "-i", "-e", "PGOPTIONS=-c statement_timeout=20000 -c lock_timeout=15000", container,
	"psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"];
const sessions = new Set();
const literal = value => value === null ? "null" : `'${String(value).replaceAll("'", "''")}'`;
const digest = value => createHash("sha256").update(value).digest("hex");

function command(args, input = "") {
	return new Promise((done, reject) => {
		const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"], timeout: 120_000 });
		let stdout = "", stderr = "";
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
const rpc = async expression => JSON.parse(await sql(`set role service_role; select ${expression};`));

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
	child.stdin.write(`set application_name=${literal(name)}; begin;\n`);
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
async function observedWait(name, kind) {
	for (let i = 0; i < 100; i++) {
		if (await sql(`select exists(select 1 from pg_stat_activity where application_name=${literal(name)}
			and wait_event_type='Lock' and ${kind === "advisory" ? "wait_event='advisory'" : "wait_event in ('transactionid','tuple')"});`) === "t") return;
		await delay(25);
	}
	assert.fail(`${name} did not wait for the expected ${kind} lock`);
}
async function passDeadline(deadline) {
	const ms = Number(await sql(`select greatest(0,ceil(extract(epoch from (${literal(deadline)}::timestamptz-clock_timestamp()))*1000))::integer;`));
	assert.ok(ms <= 3000, "fixture deadline must remain a short real-clock wait");
	await delay(ms + 50);
	assert.equal(await sql(`select clock_timestamp()>${literal(deadline)}::timestamptz;`), "t");
}

async function fixture() {
	const tenant = randomUUID(), owner = randomUUID(), backup = randomUUID(), agent = randomUUID(), iid = randomUUID();
	const keyHash = digest(`${tenant}:current`), key = randomUUID();
	await sql(`insert into auth.users(id,email,raw_app_meta_data) values
		(${literal(owner)},${literal(`signed-${owner}@example.invalid`)},'{"aidr_scim_provisioned":true}'),
		(${literal(backup)},${literal(`signed-${backup}@example.invalid`)},'{"aidr_scim_provisioned":true}');
		insert into public.tenants(id,name,kind,created_by) values (${literal(tenant)},'Signed fleet fixture','enterprise',${literal(owner)});
		insert into public.tenant_members(tenant_id,user_id,role) values
		(${literal(tenant)},${literal(owner)},'owner'),(${literal(tenant)},${literal(backup)},'owner');
		insert into public.pilot_applications(user_id,tenant_id,status,cohort)
		values (${literal(owner)},${literal(tenant)},'approved','signed_fleet');
		insert into public.agents(id,tenant_id,user_id,iid) values (${literal(agent)},${literal(tenant)},${literal(owner)},${literal(iid)});
		insert into public.api_keys(id,user_id,tenant_id,agent_id,key_hash)
		values (${literal(key)},${literal(owner)},${literal(tenant)},${literal(agent)},${literal(keyHash)});`);
	return { tenant, owner, backup, agent, iid, key, keyHash, incident: randomUUID(), triggerKey: `trigger-${randomUUID()}` };
}
const queueSql = (f, key = `command-${randomUUID()}`) =>
	`public.queue_bounded_fleet_response_command(${literal(f.tenant)},${literal(f.owner)},${literal(f.agent)},
	'agent_pause','Contain reviewed suspicious agent activity',${literal(key)},300,null)`;
const pollSql = (f, { hash = f.keyHash, tenant = f.tenant, agent = f.agent, iid = f.iid } = {}) =>
	`public.poll_bound_fleet_response_command(${literal(hash)},${literal(tenant)},${literal(agent)},${literal(iid)})`;
const recordSql = (f, id, stage = "ack", outcome = "accepted", hash = f.keyHash) =>
	`public.record_fleet_response_command(${literal(hash)},${literal(f.tenant)},${literal(f.agent)},${literal(id)},${literal(stage)},${literal(outcome)},null)`;
const triggerSql = (f, { actor = f.owner, incident = f.incident, reason = "Contain reviewed suspicious agent activity", key = f.triggerKey, source = "alarm" } = {}) =>
	`public.trigger_fleet_response_playbook(${literal(f.tenant)},${literal(actor)},${literal(f.agent)},${literal(incident)},
	'agent_containment_v1',${literal(reason)},${literal(key)},300,${literal(source)})`;
const startSql = (f, key) =>
	`public.start_fleet_response_playbook(${literal(f.tenant)},${literal(f.owner)},${literal(f.agent)},${literal(f.incident)},
	'agent_containment_v1','Contain reviewed suspicious agent activity',${literal(key)},300)`;
const counts = f => sql(`select jsonb_build_object('commands',(select count(*) from public.fleet_response_commands where tenant_id=${literal(f.tenant)}),
	'runs',(select count(*) from public.fleet_response_playbook_runs where tenant_id=${literal(f.tenant)}),
	'steps',(select count(*) from public.fleet_response_playbook_steps where tenant_id=${literal(f.tenant)}),
	'audits',(select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)}));`);
const commandState = id => sql(`select state||'/'||attempts from public.fleet_response_commands where id=${literal(id)};`);
const grantSql = (f, hash, issuedAt, { actor = f.owner, source = "alarm", maxTtl = 300, lifetime = 86400,
	reason = "Authorize reviewed unattended incident containment", agent = f.agent } = {}) =>
	`public.create_response_automation_grant(${literal(f.tenant)},${literal(actor)},${literal(agent)},${literal(source)},${literal(reason)},
	${maxTtl},${lifetime},${literal(hash)},${literal(issuedAt)}::timestamptz)`;
async function automation(f, options = {}) {
	// Fixture server output represents the Edge-verified issuance time; this
	// native database regression does not claim a real MFA ceremony.
	const hash = digest(randomBytes(32).toString("base64url"));
	const issuedAt = await sql("select clock_timestamp()-interval '5 seconds';");
	return { ...(await rpc(grantSql(f, hash, issuedAt, options))), hash, issuedAt };
}
const machineSql = (f, grant, { tenant = f.tenant, id = grant.grant_id, hash = grant.hash, incident = f.incident,
	reason = "Contain reviewed suspicious agent activity", ttl = 300 } = {}) =>
	`public.trigger_response_automation_playbook(${literal(tenant)},${literal(id)},${literal(hash)},${literal(incident)},${literal(reason)},${ttl})`;
const revokeSql = (f, grant, { actor = f.owner, issuedAt = grant.issuedAt } = {}) =>
	`public.revoke_response_automation_grant(${literal(f.tenant)},${literal(actor)},${literal(grant.grant_id)},
	'Revoke the reviewed unattended containment grant',${literal(issuedAt)}::timestamptz)`;
const grantCount = f => sql(`select count(*) from public.delegated_credential_grants where tenant_id=${literal(f.tenant)};`);
async function separateTarget(f) {
	const target = randomUUID();
	await sql(`insert into auth.users(id,email,raw_app_meta_data)
		values (${literal(target)},${literal(`automation-${target}@example.invalid`)},'{"aidr_scim_provisioned":true}');
		insert into public.tenant_members(tenant_id,user_id,role) values (${literal(f.tenant)},${literal(target)},'member');
		update public.agents set user_id=${literal(target)} where id=${literal(f.agent)};
		update public.api_keys set user_id=${literal(target)} where id=${literal(f.key)};`);
	return target;
}
async function expiringGrant(f, original) {
	const id = randomUUID(), hash = digest(randomBytes(32).toString("base64url"));
	// Trusted isolated fixture clone changes expiry at INSERT. API minting still
	// enforces its 60-second minimum; no production proof/TTL is UPDATEd.
	await sql(`insert into public.delegated_credential_grants(id,tenant_id,subject_user_id,agent_id,tool_server_id,tool_name,
		resource_type,resource_id,audience,scopes,max_ttl_seconds,max_delegation_depth,expires_at,created_by,created_at,
		automation_secret_hash,automation_session_issued_at,automation_target_identity)
		select ${literal(id)},tenant_id,subject_user_id,agent_id,tool_server_id,tool_name,resource_type,resource_id,audience,
		scopes,max_ttl_seconds,max_delegation_depth,clock_timestamp()+interval '3 seconds',created_by,clock_timestamp(),
		${literal(hash)},automation_session_issued_at,automation_target_identity
		from public.delegated_credential_grants where id=${literal(original.grant_id)};`);
	return { ...original, grant_id: id, hash, expires_at: await sql(`select expires_at from public.delegated_credential_grants where id=${literal(id)};`) };
}
async function withAutomationAuditFailure(f, action, work) {
	await sql(`create function public.__response_automation_test_failure() returns trigger language plpgsql as $$ begin
		if new.tenant_id=${literal(f.tenant)}::uuid and new.action=${literal(action)} then
			raise exception 'fixture_automation_audit_failure'; end if; return new; end $$;
		create trigger response_automation_test_failure before insert on public.admin_audit_logs
		for each row execute function public.__response_automation_test_failure();`);
	try { return await work(); }
	finally { await sql("drop trigger response_automation_test_failure on public.admin_audit_logs; drop function public.__response_automation_test_failure();"); }
}

test("signed fleet delivery keeps live bindings, immutable command bytes and atomic trigger provenance", { timeout: 900_000 }, async t => {
	const started = await command(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=fleet-signed-fixture-only", "supabase/postgres:17.11.0.004"]);
	assert.equal(started.code, 0, started.stderr);
	try {
		let ready = false;
		for (let i = 0; i < 150 && !ready; i++) {
			ready = (await command(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])).code === 0;
			if (!ready) await delay(200);
		}
		assert.ok(ready, "isolated PostgreSQL must start");
		const auth = await command(["exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "supabase_admin", "-d", "postgres"],
			`grant create on schema storage to postgres;
			 create table if not exists auth.sso_providers(id uuid primary key,disabled boolean);
			 create table if not exists auth.saml_providers(id uuid primary key,sso_provider_id uuid references auth.sso_providers(id));
			 create table if not exists auth.sessions(id uuid primary key,user_id uuid references auth.users(id) on delete cascade,aal text,not_after timestamptz,created_at timestamptz default now());
			 create table if not exists auth.identities(id uuid primary key,user_id uuid references auth.users(id) on delete cascade,provider text,provider_id text,identity_data jsonb);
			 grant select,insert,update,delete on auth.sso_providers,auth.saml_providers,auth.sessions,auth.identities to postgres;
			 create function auth.jwt() returns jsonb language sql stable as $$
			   select coalesce(nullif(current_setting('request.jwt.claims',true),''),'{}')::jsonb $$;`);
		assert.equal(auth.code, 0, auth.stderr);
		await sql(`create table storage.buckets(id text primary key,name text,public boolean);
			create table storage.objects(id uuid primary key default gen_random_uuid(),bucket_id text,name text,metadata jsonb);
			create function storage.foldername(name text) returns text[] language sql immutable as $$ select string_to_array(name,'/') $$;`);
		const migrations = readdirSync(resolve(root, "supabase/migrations")).filter(name => name.endsWith(".sql")).sort();
		assert.ok(migrations.includes("20261006001000_fleet_response_signed_delivery.sql"));
		for (const name of migrations) {
			const result = await command(psql, `begin;\n${readFileSync(resolve(root, "supabase/migrations", name), "utf8")}\ncommit;`);
			assert.equal(result.code, 0, `${name}: ${result.stderr}`);
		}
		t.diagnostic(`Applied all ${migrations.length} canonical migrations through ${migrations.at(-1)}`);
		await sql("set role service_role; select public.configure_tenant_admission_mode('pilot');");

		await t.test("bound poll returns the presented credential and one immutable targeted command", async () => {
			const f = await fixture(), queued = await rpc(`to_jsonb(${queueSql(f)})`);
			const snapshot = await rpc(pollSql(f));
			assert.deepEqual(Object.keys(snapshot).sort(), ["command", "tenant_id", "agent_id", "installation_id", "key_hash"].sort());
			assert.equal(snapshot.tenant_id, f.tenant);
			assert.equal(snapshot.agent_id, f.agent);
			assert.equal(snapshot.installation_id, f.iid);
			assert.equal(snapshot.key_hash, f.keyHash);
			assert.equal(snapshot.command.id, queued.id);
			assert.equal(snapshot.command.state, "delivered");
			assert.equal(snapshot.command.attempts, 1);
			assert.equal((await rpc(pollSql(f))).command, null, "a retry inside the lease cannot re-deliver");
			assert.equal(await commandState(queued.id), "delivered/1");
			await rpc(`to_jsonb(${recordSql(f, queued.id)})`);
			await rpc(`to_jsonb(${recordSql(f, queued.id, "result", "succeeded")})`);
			await rpc(`to_jsonb(${recordSql(f, queued.id, "result", "succeeded")})`);
			assert.equal(await commandState(queued.id), "succeeded/1");
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)} and action='fleet.response.result';`), "1");
		});

		await t.test("ordinary roles cannot poll, trigger or alter any signed command binding", async () => {
			const f = await fixture(), queued = await rpc(`to_jsonb(${queueSql(f)})`);
			for (const role of ["anon", "authenticated"]) {
				await denied(`set role ${role}; select ${pollSql(f)};`, /permission denied/);
				await denied(`set role ${role}; select ${triggerSql(f)};`, /permission denied/);
				await denied(`set role ${role}; update public.fleet_response_commands set state='cancelled' where id=${literal(queued.id)};`, /permission denied/);
			}
			const before = await sql(`select to_jsonb(c) from public.fleet_response_commands c where id=${literal(queued.id)};`);
			const edits = {
				id: literal(randomUUID()), tenant_id: literal(randomUUID()), agent_id: literal(randomUUID()), actor_user_id: literal(randomUUID()),
				command_type: "'network_isolate'", reason: "'Alter the signed containment justification'", idempotency_key: "'changed-signed-command'",
				request_fingerprint: "repeat('f',64)", rollback_of: literal(randomUUID()), created_at: "created_at-interval '1 second'", expires_at: "expires_at+interval '1 day'",
			};
			for (const [field, value] of Object.entries(edits)) {
				await denied(`set role service_role; update public.fleet_response_commands set ${field}=${value} where id=${literal(queued.id)};`, /fleet_command_binding_immutable/);
				assert.equal(await sql(`select to_jsonb(c) from public.fleet_response_commands c where id=${literal(queued.id)};`), before);
			}
		});

		await t.test("wrong credentials, tenant, agent and installation leave queued commands unchanged", async () => {
			const f = await fixture(), queued = await rpc(`to_jsonb(${queueSql(f)})`);
			for (const inputs of [{ hash: digest("wrong") }, { tenant: randomUUID() }, { agent: randomUUID() },
				{ iid: randomUUID() }, { iid: null }, { iid: "" }, { iid: " " }, { iid: "a".repeat(129) }, { iid: "bad\niid" }]) {
				await denied(`set role service_role; select ${pollSql(f, inputs)};`, /fleet_agent_forbidden/);
				assert.equal(await commandState(queued.id), "pending/0");
			}
			await sql(`update public.tenant_members set role='viewer' where tenant_id=${literal(f.tenant)} and user_id=${literal(f.owner)};`);
			await denied(`set role service_role; select ${pollSql(f)};`, /fleet_agent_forbidden/);
			assert.equal(await commandState(queued.id), "pending/0");
		});

		await t.test("rotation overlap uses the presented retired hash without substituting the current hash", async () => {
			const f = await fixture(), next = digest(`${f.tenant}:renewed`);
			await rpc(`public.renew_api_key_with_audit(${literal(f.owner)},${literal(f.tenant)},${literal(f.key)},${literal(f.keyHash)},${literal(next)},1)`);
			const first = await rpc(`to_jsonb(${queueSql(f)})`), snapshot = await rpc(pollSql(f));
			assert.equal(snapshot.command.id, first.id);
			assert.equal(snapshot.key_hash, f.keyHash);
			assert.equal(await sql(`select key_hash from public.api_keys where id=${literal(f.key)};`), next);
			await rpc(`to_jsonb(${recordSql(f, first.id)})`);
			const pending = await rpc(`to_jsonb(${queueSql(f)})`);
			await sql(`update public.api_keys set rotated_at=clock_timestamp()-interval '2 hours',previous_hash_expires_at=clock_timestamp()-interval '1 hour' where id=${literal(f.key)};`);
			await denied(`set role service_role; select ${pollSql(f)};`, /fleet_agent_forbidden/);
			assert.equal(await commandState(pending.id), "pending/0");
			assert.equal((await rpc(pollSql(f, { hash: next }))).command.id, pending.id);
			await sql(`update public.api_keys set revoked=true where id=${literal(f.key)};`);
			await denied(`set role service_role; select ${pollSql(f, { hash: next })};`, /fleet_agent_forbidden/);
			assert.equal(await commandState(pending.id), "delivered/1");
		});

		for (const race of ["previous_expiry", "previous_removed", "membership_expiry", "viewer_demotion", "binding_change", "revocation", "command_ttl", "result_ttl"]) {
			await t.test(`live ${race} is rechecked after an observed row-lock wait`, async () => {
				const f = await fixture();
				let queued, deadline, poll = pollSql(f);
				if (race === "command_ttl" || race === "result_ttl") {
					// Fixture-only short deadline is set at INSERT, never by changing
					// frozen bytes. Poll/result still use the actual transport RPCs.
					const id = randomUUID();
					await sql(`insert into public.fleet_response_commands(id,tenant_id,agent_id,actor_user_id,command_type,reason,
						idempotency_key,request_fingerprint,expires_at) values (${literal(id)},${literal(f.tenant)},${literal(f.agent)},${literal(f.owner)},
						'agent_pause','Fixture bounded short transport deadline',${literal(`ttl-${id}`)},${literal(digest(id))},clock_timestamp()+interval '3 seconds');`);
					queued = { id };
					deadline = await sql(`select expires_at from public.fleet_response_commands where id=${literal(id)};`);
					if (race === "result_ttl") {
						assert.equal((await rpc(pollSql(f))).command.id, id);
						poll = `to_jsonb(${recordSql(f, id)})`;
					}
				} else queued = await rpc(`to_jsonb(${queueSql(f)})`);
				if (race.startsWith("previous_")) {
					await sql(`update public.api_keys set key_hash=${literal(digest(`${f.tenant}:new`))},previous_hash=${literal(f.keyHash)},
						rotated_at=clock_timestamp(),previous_hash_expires_at=clock_timestamp()+interval '3 seconds' where id=${literal(f.key)};`);
					deadline = await sql(`select previous_hash_expires_at from public.api_keys where id=${literal(f.key)};`);
				}
				if (race === "membership_expiry") {
					await sql(`update public.tenant_members set expires_at=clock_timestamp()+interval '3 seconds'
						where tenant_id=${literal(f.tenant)} and user_id=${literal(f.owner)};`);
					deadline = await sql(`select expires_at from public.tenant_members where tenant_id=${literal(f.tenant)} and user_id=${literal(f.owner)};`);
				}
				const holder = session(`fleet-${race}-holder`), waiter = session(`fleet-${race}-waiter`);
				const lockedRow = ["membership_expiry", "viewer_demotion"].includes(race)
					? `select user_id from public.tenant_members where tenant_id=${literal(f.tenant)} and user_id=${literal(f.owner)} for update;`
					: race === "binding_change" ? `select id from public.agents where id=${literal(f.agent)} for update;`
						: `select id from public.api_keys where id=${literal(f.key)} for update;`;
				holder.child.stdin.write(`${lockedRow} select 'FLEET_AUTH_ROW_HELD';\n`);
				await marker(holder, "FLEET_AUTH_ROW_HELD");
				waiter.child.stdin.end(`set local role service_role; select ${poll}; commit;\n`);
				let results;
				try {
					await observedWait(`fleet-${race}-waiter`, "row");
					if (["previous_expiry", "membership_expiry", "command_ttl", "result_ttl"].includes(race)) await passDeadline(deadline);
				} finally {
					const mutation = race === "previous_removed" ? `update public.api_keys set previous_hash=null,previous_hash_expires_at=null where id=${literal(f.key)};`
						: race === "binding_change" ? `update public.agents set iid=${literal(randomUUID())} where id=${literal(f.agent)};`
							: race === "revocation" ? `update public.api_keys set revoked=true where id=${literal(f.key)};`
								: race === "viewer_demotion" ? `update public.tenant_members set role='viewer' where tenant_id=${literal(f.tenant)} and user_id=${literal(f.owner)};` : "";
					holder.child.stdin.end(`${mutation} commit;\n`);
					results = await Promise.all([holder.closed, waiter.closed]);
				}
				assert.equal(results[0].code, 0, results[0].stderr);
				assert.doesNotMatch(results[1].stderr, /deadlock|lock timeout/);
				if (race === "command_ttl") {
					assert.equal(results[1].code, 0, results[1].stderr);
					assert.equal(JSON.parse(results[1].stdout.trim()).command, null);
					assert.equal(await commandState(queued.id), "expired/0");
				} else if (race === "result_ttl") {
					assert.equal(results[1].code, 0, results[1].stderr);
					assert.equal(JSON.parse(results[1].stdout.trim()).state, "outcome_unknown");
					assert.equal(await commandState(queued.id), "outcome_unknown/1");
				} else {
					assert.notEqual(results[1].code, 0, "stale authentication accepted after a real lock wait");
					assert.match(results[1].stderr, /fleet_agent_forbidden/);
					assert.equal(await commandState(queued.id), "pending/0");
				}
			});
		}

		for (const boundary of ["poll_retired_hash", "receipt_retired_hash", "poll_membership"]) {
			await t.test(`${boundary} expiry during a command-row wait rolls transport writes back`, async () => {
				const f = await fixture(), queued = await rpc(`to_jsonb(${queueSql(f)})`);
				if (boundary === "receipt_retired_hash") assert.equal((await rpc(pollSql(f))).command.id, queued.id);
				let deadline;
				if (boundary === "poll_membership") {
					await sql(`update public.tenant_members set expires_at=clock_timestamp()+interval '3 seconds'
						where tenant_id=${literal(f.tenant)} and user_id=${literal(f.owner)};`);
					deadline = await sql(`select expires_at from public.tenant_members where tenant_id=${literal(f.tenant)} and user_id=${literal(f.owner)};`);
				} else {
					await sql(`update public.api_keys set key_hash=${literal(digest(`${f.tenant}:new`))},previous_hash=${literal(f.keyHash)},
						rotated_at=clock_timestamp(),previous_hash_expires_at=clock_timestamp()+interval '3 seconds' where id=${literal(f.key)};`);
					deadline = await sql(`select previous_hash_expires_at from public.api_keys where id=${literal(f.key)};`);
				}
				let blocked = queued.id;
				if (boundary !== "receipt_retired_hash") {
					blocked = randomUUID();
					// An already-expired fixture row forces poll's expiry sweep to
					// wait AFTER credential validation, before the live command.
					await sql(`insert into public.fleet_response_commands(id,tenant_id,agent_id,actor_user_id,command_type,reason,
						idempotency_key,request_fingerprint,expires_at) values (${literal(blocked)},${literal(f.tenant)},${literal(f.agent)},${literal(f.owner)},
						'agent_pause','Fixture expired sweep contention boundary',${literal(`sweep-${blocked}`)},${literal(digest(blocked))},clock_timestamp()-interval '1 second');`);
				}
				const before = await counts(f), holder = session(`fleet-${boundary}-holder`), waiter = session(`fleet-${boundary}-waiter`);
				holder.child.stdin.write(`select id from public.fleet_response_commands where id=${literal(blocked)} for update; select 'COMMAND_ROW_HELD';\n`);
				await marker(holder, "COMMAND_ROW_HELD");
				const expression = boundary === "receipt_retired_hash" ? `to_jsonb(${recordSql(f, queued.id)})` : pollSql(f);
				waiter.child.stdin.end(`set local role service_role; select ${expression}; commit;\n`);
				let results;
				try { await observedWait(`fleet-${boundary}-waiter`, "row"); await passDeadline(deadline); }
				finally { holder.child.stdin.end("commit;\n"); results = await Promise.all([holder.closed, waiter.closed]); }
				assert.equal(results[0].code, 0, results[0].stderr);
				assert.notEqual(results[1].code, 0, "authority expired while transport waited on its command row");
				assert.match(results[1].stderr, /fleet_agent_forbidden/);
				assert.doesNotMatch(results[1].stderr, /deadlock|lock timeout/);
				assert.equal(await commandState(queued.id), boundary === "receipt_retired_hash" ? "delivered/1" : "pending/0");
				if (blocked !== queued.id) assert.equal(await commandState(blocked), "pending/0", "unauthorized expiry sweep must also roll back");
				assert.equal(await counts(f), before);
			});
		}

		await t.test("alarm and SOAR triggers are stable, provenance-bound and audited once", async () => {
			const f = await fixture(), first = await rpc(triggerSql(f));
			assert.equal(first.state, "running");
			assert.equal((await rpc(triggerSql(f))).id, first.id);
			for (const changed of [{ reason: "Different reviewed incident containment" }, { incident: randomUUID() }, { actor: f.backup }]) {
				await denied(`set role service_role; select ${triggerSql(f, changed)};`, /response_playbook_idempotency_conflict/);
			}
			assert.deepEqual(JSON.parse(await counts(f)), { commands: 1, runs: 1, steps: 1, audits: 3 });
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)} and action='fleet.response.playbook_started';`), "1");
			const provenance = JSON.parse(await sql(`select detail from public.admin_audit_logs where tenant_id=${literal(f.tenant)} and action='fleet.response.playbook_triggered';`));
			assert.equal(provenance.run_id, first.id);
			assert.equal(provenance.trigger_source, "alarm");
			assert.equal(provenance.incident_reference, f.incident);
			assert.equal(provenance.agent_id, f.agent);
			assert.notEqual((await rpc(triggerSql(f, { source: "soar" }))).id, first.id);
			await denied(`set role service_role; select ${triggerSql(f, { source: "cron" })};`, /invalid_response_playbook_trigger/);
			await denied(`set role service_role; select ${triggerSql(f, { actor: randomUUID(), key: `trigger-unauthorized-${randomUUID()}` })};`, /response_playbook_operator_forbidden/);
		});

		await t.test("an ordinary start cannot be relabeled as an alarm by guessing the trigger namespace", async () => {
			const f = await fixture(), key = `trigger-guessed-${randomUUID()}`, internal = `trigger:alarm:${digest(key)}`;
			const ordinary = await rpc(startSql(f, internal)), before = await counts(f);
			await denied(`set role service_role; select ${triggerSql(f, { key })};`, /response_playbook_trigger_provenance_conflict/);
			assert.equal(await counts(f), before);
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)} and action='fleet.response.playbook_triggered';`), "0");
			assert.equal(await sql(`select count(*) from public.fleet_response_playbook_runs where id=${literal(ordinary.id)};`), "1");
		});

		await t.test("a trigger audit failure atomically rolls back the run, step, command and prior start audits", async () => {
			const f = await fixture();
			await sql(`create function public.__fleet_trigger_test_failure() returns trigger language plpgsql as $$ begin
				if new.tenant_id=${literal(f.tenant)}::uuid and new.action='fleet.response.playbook_triggered' then
					raise exception 'fixture_trigger_audit_failure'; end if; return new; end $$;
				create trigger fleet_trigger_test_failure before insert on public.admin_audit_logs
				for each row execute function public.__fleet_trigger_test_failure();`);
			try {
				await denied(`set role service_role; select ${triggerSql(f)};`, /fixture_trigger_audit_failure/);
				assert.deepEqual(JSON.parse(await counts(f)), { commands: 0, runs: 0, steps: 0, audits: 0 });
			} finally { await sql("drop trigger fleet_trigger_test_failure on public.admin_audit_logs; drop function public.__fleet_trigger_test_failure();"); }
			await rpc(triggerSql(f));
			assert.deepEqual(JSON.parse(await counts(f)), { commands: 1, runs: 1, steps: 1, audits: 3 });
		});

		await t.test("simultaneous exact trigger retries produce one run and one provenance audit", async () => {
			const f = await fixture(), key = `trigger-concurrent-${randomUUID()}`, internal = `trigger:alarm:${digest(key)}`;
			const fence = session("fleet-trigger-fence");
			fence.child.stdin.write(`select pg_advisory_xact_lock(hashtextextended(${literal(`${f.tenant}:response-playbook:${internal}`)},73923)); select 'TRIGGER_FENCE_HELD';\n`);
			await marker(fence, "TRIGGER_FENCE_HELD");
			const a = session("fleet-trigger-a"), b = session("fleet-trigger-b");
			a.child.stdin.end(`set local role service_role; select ${triggerSql(f, { key })}; commit;\n`);
			b.child.stdin.end(`set local role service_role; select ${triggerSql(f, { key })}; commit;\n`);
			let results;
			try { await observedWait("fleet-trigger-a", "advisory"); await observedWait("fleet-trigger-b", "advisory"); }
			finally { fence.child.stdin.end("commit;\n"); results = await Promise.all([fence.closed, a.closed, b.closed]); }
			for (const result of results) assert.equal(result.code, 0, result.stderr);
			assert.equal(JSON.parse(results[1].stdout.trim()).id, JSON.parse(results[2].stdout.trim()).id);
			assert.deepEqual(JSON.parse(await counts(f)), { commands: 1, runs: 1, steps: 1, audits: 3 });
		});

		await t.test("trigger authority expiry is rechecked after an observed idempotency-lock wait", async () => {
			const f = await fixture(), key = `trigger-expiry-${randomUUID()}`, internal = `trigger:alarm:${digest(key)}`;
			await sql(`update public.tenant_members set expires_at=clock_timestamp()+interval '3 seconds' where tenant_id=${literal(f.tenant)} and user_id=${literal(f.owner)};`);
			const deadline = await sql(`select expires_at from public.tenant_members where tenant_id=${literal(f.tenant)} and user_id=${literal(f.owner)};`);
			const fence = session("fleet-trigger-expiry-fence"), waiter = session("fleet-trigger-expiry-waiter");
			fence.child.stdin.write(`select pg_advisory_xact_lock(hashtextextended(${literal(`${f.tenant}:response-playbook:${internal}`)},73923)); select 'TRIGGER_EXPIRY_FENCE_HELD';\n`);
			await marker(fence, "TRIGGER_EXPIRY_FENCE_HELD");
			waiter.child.stdin.end(`set local role service_role; select ${triggerSql(f, { key })}; commit;\n`);
			let results;
			try { await observedWait("fleet-trigger-expiry-waiter", "advisory"); await passDeadline(deadline); }
			finally { fence.child.stdin.end("commit;\n"); results = await Promise.all([fence.closed, waiter.closed]); }
			assert.equal(results[0].code, 0, results[0].stderr);
			assert.notEqual(results[1].code, 0);
			assert.match(results[1].stderr, /response_playbook_operator_forbidden|fleet_operator_forbidden/);
			assert.deepEqual(JSON.parse(await counts(f)), { commands: 0, runs: 0, steps: 0, audits: 0 });
		});

		await t.test("explicit machine grants pin safe metadata, source, target and event idempotency", async () => {
			const f = await fixture(), grant = await automation(f);
			const { hash, issuedAt, ...metadata } = grant;
			assert.deepEqual(Object.keys(metadata).sort(), ["grant_id", "tenant_id", "agent_id", "playbook_id", "trigger_source",
				"created_by", "max_ttl_seconds", "created_at", "expires_at", "revoked_at"].sort());
			assert.equal(grant.tenant_id, f.tenant);
			assert.equal(grant.agent_id, f.agent);
			assert.equal(grant.playbook_id, "agent_containment_v1");
			assert.equal(grant.trigger_source, "alarm");
			assert.equal(grant.created_by, f.owner);
			assert.equal(grant.revoked_at, null);
			const proof = JSON.parse(await sql(`select automation_target_identity from public.delegated_credential_grants where id=${literal(grant.grant_id)};`));
			assert.deepEqual(proof, { user_id: f.owner, iid: f.iid });
			const first = await rpc(machineSql(f, grant));
			assert.equal(first.agent_id, f.agent);
			assert.equal(first.actor_user_id, f.owner);
			assert.equal((await rpc(machineSql(f, grant))).id, first.id);
			for (const changed of [{ reason: "A different reviewed containment justification" }, { ttl: 60 }]) {
				await denied(`set role service_role; select ${machineSql(f, grant, changed)};`, /response_playbook_idempotency_conflict/);
			}
			assert.deepEqual(JSON.parse(await counts(f)), { commands: 1, runs: 1, steps: 1, audits: 4 });
			const provenance = JSON.parse(await sql(`select detail from public.admin_audit_logs where tenant_id=${literal(f.tenant)} and action='fleet.response.playbook_triggered';`));
			assert.equal(provenance.grant_id, grant.grant_id);
			assert.equal(provenance.trigger_source, "alarm");
			assert.equal(provenance.incident_reference, f.incident);
			assert.ok(!JSON.stringify(provenance).includes(hash));
			const audit = JSON.parse(await sql(`select detail from public.admin_audit_logs where tenant_id=${literal(f.tenant)} and action='fleet.response.automation_grant_created';`));
			assert.ok(!JSON.stringify(audit).includes(hash));
			assert.ok(!Object.keys(audit).some(field => /hash|session|identity/.test(field)));
			assert.notEqual((await rpc(machineSql(f, grant, { incident: randomUUID() }))).id, first.id);
			const revoked = await rpc(revokeSql(f, grant));
			assert.ok(revoked.revoked_at);
			assert.deepEqual(await rpc(revokeSql(f, grant)), revoked);
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)} and action='fleet.response.automation_grant_revoked';`), "1");
			const before = await counts(f);
			await denied(`set role service_role; select ${machineSql(f, grant, { incident: randomUUID() })};`, /response_automation_grant_inactive/);
			await denied(`update public.delegated_credential_grants set revoked_at=null where id=${literal(grant.grant_id)};`, /response_automation_binding_immutable/);
			assert.equal(await counts(f), before);
		});

		await t.test("only the grant RPC mints fixed machine proof and its immutable authority cannot be edited", async () => {
			const f = await fixture(), grant = await automation(f);
			for (const role of ["anon", "authenticated"]) {
				await denied(`set role ${role}; select ${grantSql(f, grant.hash, grant.issuedAt)};`, /permission denied/);
				await denied(`set role ${role}; select ${machineSql(f, grant)};`, /permission denied/);
				await denied(`set role ${role}; select ${revokeSql(f, grant)};`, /permission denied/);
			}
			for (const statement of ["insert into public.delegated_credential_grants select * from public.delegated_credential_grants",
				"update public.delegated_credential_grants set revoked_at=clock_timestamp()", "delete from public.delegated_credential_grants",
				"truncate public.delegated_credential_grants"]) await denied(`set role service_role; ${statement};`, /permission denied/);
			const before = await sql(`select to_jsonb(g) from public.delegated_credential_grants g where id=${literal(grant.grant_id)};`);
			for (const [field, value] of Object.entries({ automation_secret_hash: literal(digest(randomBytes(32).toString("base64url"))),
				automation_session_issued_at: "automation_session_issued_at-interval '1 second'",
				automation_target_identity: `jsonb_build_object('user_id',${literal(f.owner)},'iid',${literal(randomUUID())})`,
				agent_id: literal(randomUUID()), created_by: literal(f.backup), subject_user_id: literal(f.backup),
				tool_name: "'soar'", max_ttl_seconds: "60", expires_at: "expires_at+interval '1 day'" })) {
				await denied(`update public.delegated_credential_grants set ${field}=${value} where id=${literal(grant.grant_id)};`, /response_automation_binding_immutable/);
				assert.equal(await sql(`select to_jsonb(g) from public.delegated_credential_grants g where id=${literal(grant.grant_id)};`), before);
			}
			const hash = digest(randomBytes(32).toString("base64url"));
			for (const options of [{ source: "cron" }, { maxTtl: 29 }, { maxTtl: 901 }, { lifetime: 59 }, { lifetime: 7776001 },
				{ actor: randomUUID() }, { agent: randomUUID() }]) {
				await denied(`set role service_role; select ${grantSql(f, hash, grant.issuedAt, options)};`, /invalid_response_automation_grant|response_automation_forbidden|response_automation_target_changed/);
			}
			await denied(`set role service_role; select ${grantSql(f, hash, null)};`, /response_automation_forbidden/);
			const future = await sql("select clock_timestamp()+interval '2 minutes';");
			await denied(`set role service_role; select ${grantSql(f, hash, future)};`, /response_automation_forbidden/);
			assert.equal(await grantCount(f), "1");
			assert.deepEqual(JSON.parse(await counts(f)), { commands: 0, runs: 0, steps: 0, audits: 1 });
		});

		await t.test("ordinary delegated grants and broker claims cannot mint or relabel machine authority", async () => {
			const f = await fixture(), grant = await automation(f);
			const request = { tenant_id: f.tenant, subject_user_id: f.owner, agent_id: f.agent, tool_server_id: "aidr-response",
				tool_name: "alarm", resource_type: "response_playbook", resource_id: "agent_containment_v1",
				audience: "aidr-response-playbooks", scopes: ["fleet:containment"], max_ttl_seconds: 300,
				max_delegation_depth: 0, grant_expires_in_seconds: 86400, automation_secret_hash: grant.hash,
				automation_session_issued_at: grant.issuedAt, automation_target_identity: { user_id: f.owner, iid: f.iid } };
			const ordinary = await rpc(`public.create_delegated_credential_grant(${literal(f.owner)},${literal(JSON.stringify(request))}::jsonb)`);
			assert.equal(await sql(`select automation_secret_hash is null and automation_session_issued_at is null and automation_target_identity is null
				from public.delegated_credential_grants where id=${literal(ordinary.grant_id)};`), "t");
			const brokerRequest = { tenant_id: f.tenant, grant_id: ordinary.grant_id, scopes: ["fleet:containment"], ttl_seconds: 60,
				validated_session_issued_at: grant.issuedAt };
			const reserved = await rpc(`public.reserve_delegated_credential(${literal(f.owner)},'fixture-issuer',${literal(JSON.stringify(brokerRequest))}::jsonb)`);
			assert.ok(reserved.claims.tokenId);
			await denied(`set role service_role; select ${machineSql(f, grant, { id: ordinary.grant_id, hash: digest(JSON.stringify(reserved.claims)) })};`, /response_automation_grant_inactive/);
			await denied(`update public.delegated_credential_grants set automation_secret_hash=${literal(grant.hash)},
				automation_session_issued_at=${literal(grant.issuedAt)},automation_target_identity=jsonb_build_object('user_id',${literal(f.owner)},'iid',${literal(f.iid)})
				where id=${literal(ordinary.grant_id)};`, /response_automation_binding_immutable/);
			await denied(`set role service_role; select public.reserve_delegated_credential(${literal(f.owner)},'fixture-issuer',
				${literal(JSON.stringify({ ...brokerRequest, grant_id: grant.grant_id }))}::jsonb);`, /delegation_grant_inactive/);
			assert.equal(JSON.parse(await counts(f)).runs, 0);
		});

		await t.test("machine secrets are independent of endpoint rotation and cannot exceed either TTL bound", async () => {
			const f = await fixture(), grant = await automation(f, { maxTtl: 60 }), next = digest(randomBytes(32).toString("base64url"));
			await rpc(`public.renew_api_key_with_audit(${literal(f.owner)},${literal(f.tenant)},${literal(f.key)},${literal(f.keyHash)},${literal(next)},1)`);
			const before = await counts(f);
			for (const hash of [f.keyHash, next, digest(randomBytes(32).toString("base64url"))]) {
				await denied(`set role service_role; select ${machineSql(f, grant, { hash, ttl: 60 })};`, /response_automation_grant_inactive/);
			}
			await denied(`set role service_role; select ${machineSql(f, grant, { ttl: 61 })};`, /response_automation_ttl_exceeded/);
			await denied(`set role service_role; select ${machineSql(f, grant, { ttl: 29 })};`, /response_automation_invalid_trigger/);
			await denied(`set role service_role; select ${machineSql(f, grant, { tenant: randomUUID(), ttl: 60 })};`, /response_automation_grant_inactive/);
			assert.equal(await counts(f), before);
			await rpc(machineSql(f, grant, { ttl: 60 }));
			assert.equal(await sql(`select automation_secret_hash from public.delegated_credential_grants where id=${literal(grant.grant_id)};`), grant.hash);
			const short = await fixture(), bounded = await automation(short, { lifetime: 60 });
			await denied(`set role service_role; select ${machineSql(short, bounded)};`, /response_automation_ttl_exceeded/);
			const run = await rpc(machineSql(short, bounded, { ttl: 30 }));
			assert.equal(await sql(`select r.expires_at <= g.expires_at from public.fleet_response_playbook_runs r
				join public.delegated_credential_grants g on g.id=${literal(bounded.grant_id)} where r.id=${literal(run.id)};`), "t");
		});

		await t.test("an ordinary operator start cannot be relabeled with a machine grant", async () => {
			const f = await fixture(), grant = await automation(f), internal = `automation:${grant.grant_id}:${f.incident}`;
			await rpc(startSql(f, internal));
			const before = await counts(f);
			await denied(`set role service_role; select ${machineSql(f, grant)};`, /response_playbook_trigger_provenance_conflict/);
			assert.equal(await counts(f), before);
		});

		await t.test("grant creation, machine triggering and revocation are atomic with their audit", async () => {
			const f = await fixture(), hash = digest(randomBytes(32).toString("base64url"));
			const issuedAt = await sql("select clock_timestamp()-interval '5 seconds';");
			await withAutomationAuditFailure(f, "fleet.response.automation_grant_created", async () => {
				await denied(`set role service_role; select ${grantSql(f, hash, issuedAt)};`, /fixture_automation_audit_failure/);
				assert.equal(await grantCount(f), "0");
				assert.deepEqual(JSON.parse(await counts(f)), { commands: 0, runs: 0, steps: 0, audits: 0 });
			});
			const grant = await automation(f), before = await counts(f);
			await withAutomationAuditFailure(f, "fleet.response.playbook_triggered", async () => {
				await denied(`set role service_role; select ${machineSql(f, grant)};`, /fixture_automation_audit_failure/);
				assert.equal(await counts(f), before);
			});
			await withAutomationAuditFailure(f, "fleet.response.automation_grant_revoked", async () => {
				await denied(`set role service_role; select ${revokeSql(f, grant)};`, /fixture_automation_audit_failure/);
				assert.equal(await sql(`select revoked_at is null from public.delegated_credential_grants where id=${literal(grant.grant_id)};`), "t");
				assert.equal(await counts(f), before);
			});
			await rpc(machineSql(f, grant));
			await rpc(revokeSql(f, grant));
			assert.deepEqual(JSON.parse(await counts(f)), { commands: 1, runs: 1, steps: 1, audits: 5 });
		});

		for (const race of ["mint_revocation", "creator_demotion", "creator_revocation", "grant_revoke", "grant_expiry",
			"target_iid", "target_user", "target_member_demotion", "target_member_expiry"]) {
			await t.test(`machine ${race} authority is rechecked after an observed lock wait`, async () => {
				const f = await fixture(), target = await separateTarget(f);
				let grant, expression, deadline;
				if (race === "mint_revocation") {
					grant = { hash: digest(randomBytes(32).toString("base64url")), issuedAt: await sql("select clock_timestamp()-interval '5 seconds';") };
					expression = grantSql(f, grant.hash, grant.issuedAt);
				} else {
					grant = await automation(f);
					if (race === "grant_expiry") { grant = await expiringGrant(f, grant); deadline = grant.expires_at; }
					expression = machineSql(f, grant);
				}
				if (race === "target_member_expiry") {
					await sql(`update public.tenant_members set expires_at=clock_timestamp()+interval '3 seconds'
						where tenant_id=${literal(f.tenant)} and user_id=${literal(target)};`);
					deadline = await sql(`select expires_at from public.tenant_members where tenant_id=${literal(f.tenant)} and user_id=${literal(target)};`);
				}
				const holder = session(`automation-${race}-holder`), waiter = session(`automation-${race}-waiter`);
				let lock, kind = "row";
				if (["mint_revocation", "creator_revocation"].includes(race)) {
					lock = `select pg_advisory_xact_lock(hashtextextended(${literal(f.owner)},2611));`; kind = "advisory";
				} else if (race === "grant_revoke") {
					lock = `select pg_advisory_xact_lock(hashtextextended(${literal(f.tenant)},2606));`; kind = "advisory";
				} else if (race === "grant_expiry") lock = `select id from public.delegated_credential_grants where id=${literal(grant.grant_id)} for update;`;
				else if (["target_iid", "target_user"].includes(race)) lock = `select id from public.agents where id=${literal(f.agent)} for update;`;
				else lock = `select user_id from public.tenant_members where tenant_id=${literal(f.tenant)}
					and user_id=${literal(race === "creator_demotion" ? f.owner : target)} for update;`;
				holder.child.stdin.write(`${lock} select 'AUTOMATION_AUTHORITY_HELD';\n`);
				await marker(holder, "AUTOMATION_AUTHORITY_HELD");
				waiter.child.stdin.end(`set local role service_role; select ${expression}; commit;\n`);
				let results;
				try {
					await observedWait(`automation-${race}-waiter`, kind);
					if (deadline) await passDeadline(deadline);
				} finally {
					let mutation = "";
					if (["mint_revocation", "creator_revocation"].includes(race)) mutation = `insert into public.identity_user_session_state(user_id,revoked_before,reason)
						values (${literal(f.owner)},clock_timestamp(),'user_global_signout') on conflict(user_id) do update set revoked_before=excluded.revoked_before;`;
					if (race === "creator_demotion") mutation = `update public.tenant_members set role='member' where tenant_id=${literal(f.tenant)} and user_id=${literal(f.owner)};`;
					if (race === "grant_revoke") mutation = `set local role service_role; select ${revokeSql(f, grant)}; reset role;`;
					if (race === "target_iid") mutation = `update public.agents set iid=${literal(randomUUID())} where id=${literal(f.agent)};`;
					if (race === "target_user") mutation = `update public.agents set user_id=${literal(f.backup)} where id=${literal(f.agent)};
						update public.api_keys set user_id=${literal(f.backup)} where id=${literal(f.key)};`;
					if (race === "target_member_demotion") mutation = `update public.tenant_members set role='viewer' where tenant_id=${literal(f.tenant)} and user_id=${literal(target)};`;
					holder.child.stdin.end(`${mutation} commit;\n`);
					results = await Promise.all([holder.closed, waiter.closed]);
				}
				assert.equal(results[0].code, 0, results[0].stderr);
				assert.notEqual(results[1].code, 0, "machine authority crossed a changed or expired boundary");
				const expected = ["mint_revocation", "creator_revocation"].includes(race) ? /response_automation_session_revoked/
					: ["grant_revoke", "grant_expiry"].includes(race) ? /response_automation_grant_inactive/
						: ["target_iid", "target_user"].includes(race) ? /response_automation_target_changed/ : /response_automation_forbidden/;
				assert.match(results[1].stderr, expected);
				assert.doesNotMatch(results[1].stderr, /deadlock|lock timeout/);
				const state = JSON.parse(await counts(f));
				assert.equal(state.commands, 0); assert.equal(state.runs, 0); assert.equal(state.steps, 0);
				assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)} and action='fleet.response.playbook_triggered';`), "0");
				if (race === "mint_revocation") assert.equal(await grantCount(f), "0");
				if (race === "grant_revoke") assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)} and action='fleet.response.automation_grant_revoked';`), "1");
			});
		}

		await t.test("legal hold blocks closing-tenant delivery and preserves immutable records until actual offboarding", async () => {
			const f = await fixture(), neighbor = await fixture();
			await rpc(`to_jsonb(${queueSql(f)})`); await rpc(triggerSql(f));
			const neighborCommand = await rpc(`to_jsonb(${queueSql(neighbor)})`);
			const grant = await automation(f), neighborGrant = await automation(neighbor);
			await rpc(machineSql(f, grant, { incident: randomUUID() }));
			const before = await counts(f);
			await sql(`update public.tenant_data_retention_policies set retention_days=0 where tenant_id=${literal(f.tenant)};`);
			const hold = await sql(`set role service_role; select public.admin_place_tenant_legal_hold(${literal(f.tenant)},${literal(f.owner)},
				'SIGNED-FLEET-HOLD','Fixture legal owner','Preserve signed response provenance','signed-fleet-hold');`);
			const run = await rpc(`public.request_tenant_offboarding(${literal(f.tenant)},${literal(f.owner)})`);
			assert.equal((await rpc(`public.run_tenant_offboarding_batch(${literal(run.run_id)},100)`)).status, "blocked_legal_hold");
			await denied(`set role service_role; select ${pollSql(f)};`, /fleet_agent_forbidden/);
			await denied(`set role service_role; select ${triggerSql(f, { key: `trigger-closing-${randomUUID()}` })};`, /response_playbook_operator_forbidden/);
			await denied(`set role service_role; select ${machineSql(f, grant)};`, /response_automation_forbidden|response_automation_grant_inactive/);
			assert.equal(JSON.parse(await counts(f)).commands, JSON.parse(before).commands);
			assert.equal(JSON.parse(await counts(f)).runs, JSON.parse(before).runs);
			assert.equal(await grantCount(f), "1");
			// Fixture legal approval; the exact operator runbook has a separate
			// native regression, so this test exercises transport erasure only.
			await sql(`update public.tenant_legal_holds set released_at=clock_timestamp(),released_by=${literal(f.owner)},
				release_reason='Fixture legal approval after checking response hold' where id=${literal(hold)};`);
			let state;
			for (let i = 0; i < 100; i++) {
				state = await rpc(`public.run_tenant_offboarding_batch(${literal(run.run_id)},100)`);
				if (state.action === "invalidate_cache") await rpc(`public.ack_tenant_offboarding_cache(${literal(run.run_id)},array['fixture-cache'],0)`);
				if (state.status === "completed") break;
			}
			assert.equal(state.status, "completed");
			assert.deepEqual(JSON.parse(await counts(f)), { commands: 0, runs: 0, steps: 0, audits: 0 });
			assert.equal(await grantCount(f), "0");
			assert.equal(await sql(`select count(*) from public.delegated_credential_grants where id=${literal(neighborGrant.grant_id)} and revoked_at is null;`), "1");
			assert.equal(await commandState(neighborCommand.id), "pending/0");
		});
	} finally {
		for (const state of sessions) if (state.child.exitCode === null) state.child.kill();
		await command(["rm", "-f", container]);
	}
});
