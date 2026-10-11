// Full canonical SQL chain in our own cached, network-isolated PostgreSQL.
// Session proofs below are fixture server output; no live Auth/IdP is claimed.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const container = `aidr-saml-admin-${randomUUID().slice(0, 8)}`;
const psql = ["exec", "-i", "-e", "PGOPTIONS=-c statement_timeout=20000 -c lock_timeout=15000", container,
	"psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"];
const sessions = new Set();
const literal = value => value === null ? "null" : `'${String(value).replaceAll("'", "''")}'`;
const proofLiteral = value => `${literal(JSON.stringify(value))}::jsonb`;

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
async function advisoryWait(name) {
	for (let i = 0; i < 100; i++) {
		if (await sql(`select exists(select 1 from pg_stat_activity where application_name=${literal(name)}
			and wait_event_type='Lock' and wait_event='advisory');`) === "t") return;
		await delay(25);
	}
	assert.fail(`${name} did not wait for the expected advisory lock`);
}
async function rowWait(name) {
	for (let i = 0; i < 100; i++) {
		if (await sql(`select exists(select 1 from pg_stat_activity where application_name=${literal(name)}
			and wait_event_type='Lock' and wait_event in ('transactionid','tuple'));`) === "t") return;
		await delay(25);
	}
	assert.fail(`${name} did not wait for the expected row lock`);
}

async function provider({ disabled = null } = {}) {
	const id = randomUUID();
	await sql(`insert into auth.sso_providers(id,disabled) values (${literal(id)},${disabled === null ? "null" : disabled});
		insert into auth.saml_providers(id,sso_provider_id) values (${literal(randomUUID())},${literal(id)});`);
	return id;
}
async function identity(user, providerId, subject = `directory-${user}`) {
	await sql(`insert into auth.identities(id,user_id,provider,provider_id,identity_data)
		values (${literal(randomUUID())},${literal(user)},${literal(`sso:${providerId}`)},${literal(subject)},jsonb_build_object('sub',${literal(subject)}));`);
}
async function proof(user, providerId, { seconds = 600, aal = "aal2", sessionAal = "aal2", notAfter = "now()+interval '1 hour'" } = {}) {
	const id = randomUUID();
	await sql(`insert into auth.sessions(id,user_id,aal,not_after,created_at)
		values (${literal(id)},${literal(user)},${literal(sessionAal)},${notAfter},now()-interval '1 minute');`);
	return JSON.parse(await sql(`select jsonb_build_object('session_id',${literal(id)},
		'issued_at',clock_timestamp()-interval '5 seconds','expires_at',clock_timestamp()+make_interval(secs=>${seconds}),
		'aal',${literal(aal)},'saml_provider_id',${literal(providerId)});`));
}
async function fixture() {
	const tenant = randomUUID(), owner = randomUUID(), backup = randomUUID();
	const target = await provider();
	await sql(`insert into auth.users(id,email,raw_app_meta_data) values
		(${literal(owner)},${literal(`saml-${owner}@example.invalid`)},'{"aidr_scim_provisioned":true}'),
		(${literal(backup)},${literal(`saml-${backup}@example.invalid`)},'{"aidr_scim_provisioned":true}');
		insert into public.tenants(id,name,kind,created_by) values (${literal(tenant)},'SAML administration fixture','enterprise',${literal(owner)});
		insert into public.tenant_members(tenant_id,user_id,role) values
		(${literal(tenant)},${literal(owner)},'owner'),(${literal(tenant)},${literal(backup)},'owner');`);
	await identity(owner, target);
	await identity(backup, target);
	return { tenant, owner, backup, target, ownerProof: await proof(owner, target), backupProof: await proof(backup, target) };
}

const requestSql = (f, { actor = f.owner, target = f.target, validated = f.ownerProof, reason = "Activate the reviewed tenant SAML provider", changeRef = "CHANGE-SAML-123" } = {}) =>
	`public.request_tenant_saml_policy_change(${literal(f.tenant)},${literal(actor)},${literal(target)},${literal(reason)},${literal(changeRef)},${proofLiteral(validated)})`;
const approveSql = (f, id, { actor = f.backup, validated = f.backupProof } = {}) =>
	`public.approve_tenant_saml_policy_change(${literal(f.tenant)},${literal(actor)},${literal(id)},${proofLiteral(validated)})`;
const getSql = (f, id, actor = f.owner) =>
	`public.get_tenant_saml_policy_change(${literal(f.tenant)},${literal(actor)},${literal(id)})`;

test("SAML policy cutover uses current verified owners and atomic dual approval", { timeout: 900_000 }, async t => {
	const started = await command(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=saml-admin-fixture-only", "supabase/postgres:17.11.0.004"]);
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
		assert.ok(migrations.includes("20261005230000_saml_policy_administration.sql"), "SAML administration migration must exist before this real-SQL run");
		for (const name of migrations) {
			const result = await command(psql, `begin;\n${readFileSync(resolve(root, "supabase/migrations", name), "utf8")}\ncommit;`);
			assert.equal(result.code, 0, `${name}: ${result.stderr}`);
		}
		t.diagnostic(`Applied all ${migrations.length} canonical migrations through ${migrations.at(-1)}`);

		await t.test("two distinct current owners enable and disable SAML with bounded metadata-only requests", async () => {
			const f = await fixture();
			f.ownerProof = await proof(f.owner, f.target, { notAfter: "null" });
			const requested = await rpc(requestSql(f));
			assert.match(requested.request_id, /^[0-9a-f-]{36}$/);
			assert.equal(requested.tenant_id, f.tenant);
			assert.equal(requested.requested_by, f.owner);
			assert.equal(requested.old_provider_id, null);
			assert.equal(requested.new_provider_id, f.target);
			assert.equal(requested.approved_by, null);
			assert.equal(requested.approved_at, null);
			assert.deepEqual(Object.keys(requested).sort(), ["request_id", "tenant_id", "requested_by", "old_provider_id",
				"new_provider_id", "reason", "change_ref", "created_at", "expires_at", "approved_by", "approved_at"].sort());
			assert.equal(await sql(`select expires_at <= created_at+interval '5 minutes' and expires_at > created_at+interval '4 minutes'
				from public.tenant_saml_policy_change_requests where id=${literal(requested.request_id)};`), "t");
			assert.deepEqual(await rpc(getSql(f, requested.request_id)), requested);
			const approved = await rpc(approveSql(f, requested.request_id));
			assert.equal(approved.approved_by, f.backup);
			assert.ok(approved.approved_at);
			assert.equal(await sql(`select required_saml_provider_id from public.tenant_identity_policies where tenant_id=${literal(f.tenant)};`), f.target);
			const disabled = await rpc(requestSql(f, { target: null, reason: "Disable the reviewed tenant SAML provider", changeRef: "CHANGE-SAML-456" }));
			assert.equal(disabled.old_provider_id, f.target);
			assert.equal(disabled.new_provider_id, null);
			await rpc(approveSql(f, disabled.request_id));
			assert.equal(await sql(`select required_saml_provider_id is null from public.tenant_identity_policies where tenant_id=${literal(f.tenant)};`), "t");
		});

		await t.test("ordinary API roles cannot bypass SAML policy service boundaries", async () => {
			const f = await fixture();
			for (const role of ["anon", "authenticated"]) {
				await denied(`set role ${role}; select ${requestSql(f)};`, /permission denied/);
				await denied(`set role ${role}; select * from public.tenant_saml_policy_change_requests;`, /permission denied/);
			}
			const requested = await rpc(requestSql(f));
			await denied(`set role service_role; delete from public.tenant_saml_policy_change_requests where id=${literal(requested.request_id)};`, /permission denied|saml_/);
			await denied(`set role service_role; update public.tenant_saml_policy_change_requests set approved_by=${literal(f.owner)}
				where id=${literal(requested.request_id)};`, /permission denied|saml_/);
		});

		await t.test("AAL, exact Auth sessions, expiry and opaque owner identities are rechecked", async () => {
			const f = await fixture();
			const candidates = [
				{ ...f.ownerProof, aal: "aal1" },
				{ ...f.ownerProof, session_id: f.backupProof.session_id },
				{ ...f.ownerProof, session_id: randomUUID() },
				await proof(f.owner, f.target, { sessionAal: "aal1" }),
				await proof(f.owner, f.target, { seconds: -1 }),
				await proof(f.owner, f.target, { notAfter: "now()-interval '1 second'" }),
			];
			for (const validated of candidates) await denied(`set role service_role; select ${requestSql(f, { validated })};`, /saml_|invalid_session/);
			assert.equal(await sql(`select count(*) from public.tenant_saml_policy_change_requests where tenant_id=${literal(f.tenant)};`), "0");
			await sql(`update auth.identities set provider_id='owner@example.invalid',identity_data='{"sub":"owner@example.invalid"}'
				where user_id=${literal(f.backup)} and provider=${literal(`sso:${f.target}`)};`);
			await denied(`set role service_role; select ${requestSql(f)};`, /saml_/);
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)};`), "0");
		});

		await t.test("self approval, replay and stale policy cannot change tenant authority", async () => {
			const f = await fixture();
			const first = await rpc(requestSql(f));
			await denied(`set role service_role; select ${approveSql(f, first.request_id, { actor: f.owner, validated: f.ownerProof })};`, /saml_policy_distinct_owner_required/);
			const stale = await rpc(requestSql(f, { changeRef: "CHANGE-SAML-STALE" }));
			await rpc(approveSql(f, first.request_id));
			await denied(`set role service_role; select ${approveSql(f, first.request_id)};`, /saml_policy_request_consumed/);
			await denied(`set role service_role; select ${approveSql(f, stale.request_id)};`, /saml_policy_policy_conflict/);
			assert.equal(await sql(`select approved_at is null from public.tenant_saml_policy_change_requests where id=${literal(stale.request_id)};`), "t");
			assert.equal(await sql(`select required_saml_provider_id from public.tenant_identity_policies where tenant_id=${literal(f.tenant)};`), f.target);
		});

		await t.test("missing, disabled and conflicting provider configurations are refused", async () => {
			const missing = await fixture();
			await sql(`delete from auth.saml_providers where sso_provider_id=${literal(missing.target)};
				delete from auth.sso_providers where id=${literal(missing.target)};`);
			await denied(`set role service_role; select ${requestSql(missing)};`, /saml_policy_provider_unavailable/);
			const disabled = await fixture();
			await sql(`update auth.sso_providers set disabled=true where id=${literal(disabled.target)};`);
			await denied(`set role service_role; select ${requestSql(disabled)};`, /saml_policy_provider_unavailable/);
			const scim = await fixture();
			await sql(`insert into public.scim_users(tenant_id,external_id,user_name,normalized_user_name,auth_user_id)
				values (${literal(scim.tenant)},'different-directory-subject','legacy@example.invalid','legacy@example.invalid',${literal(scim.owner)});`);
			await denied(`set role service_role; select ${requestSql(scim)};`, /saml_policy_scim_identity_conflict/);
			const oidc = await fixture();
			const oidcProvider = randomUUID();
			await sql(`insert into public.oidc_providers(id,tenant_id,kind,display_name,issuer,client_id,token_auth_method,enabled,discovery)
				values (${literal(oidcProvider)},${literal(oidc.tenant)},'generic','Conflicting OIDC provider','https://idp.example.invalid','fixture','none',true,'{}');
				insert into public.oidc_tenant_domains(tenant_id,domain,verification_token,verified_at)
				values (${literal(oidc.tenant)},${literal(`d${oidc.tenant}.example.invalid`)},repeat('v',32),now());
				insert into public.tenant_identity_policies(tenant_id,required_oidc_provider_id) values (${literal(oidc.tenant)},${literal(oidcProvider)});`);
			await denied(`set role service_role; select ${requestSql(oidc)};`, /saml_policy_policy_conflict/);
		});

		await t.test("parent-first Auth deletion and SAML requests complete without a membership/identity deadlock", async () => {
			const f = await fixture(), departing = randomUUID();
			await sql(`insert into auth.users(id,email,raw_app_meta_data) values
				(${literal(departing)},${literal(`saml-${departing}@example.invalid`)},'{"aidr_scim_provisioned":true}');
				insert into public.tenant_members(tenant_id,user_id,role) values (${literal(f.tenant)},${literal(departing)},'owner');`);
			await identity(departing, f.target);
			const deletion = session("saml-auth-delete-holder");
			deletion.child.stdin.write(`select id from auth.users where id=${literal(departing)} for update;
				select id from auth.identities where user_id=${literal(departing)} for update;
				select 'AUTH_PARENT_AND_IDENTITY_HELD';\n`);
			await marker(deletion, "AUTH_PARENT_AND_IDENTITY_HELD");
			const request = session("saml-auth-delete-request");
			request.child.stdin.end(`set local role service_role;
				select 'REQUEST:'||(${requestSql(f)}->>'request_id'); commit;\n`);
			await rowWait("saml-auth-delete-request");
			deletion.child.stdin.end(`delete from auth.users where id=${literal(departing)}; commit;\n`);
			const [a, b] = await Promise.all([deletion.closed, request.closed]);
			assert.equal(a.code, 0, `real Auth parent deletion failed: ${a.stderr}\n${b.stderr}`);
			assert.equal(b.code, 0, `SAML request failed during real Auth parent deletion: ${b.stderr}`);
			assert.doesNotMatch(`${a.stderr}\n${b.stderr}`, /deadlock|lock timeout/);
			const id = b.stdout.match(/REQUEST:([0-9a-f-]{36})/)?.[1];
			assert.ok(id, "remaining qualified owners must be able to request SAML");
			assert.equal(await sql(`select count(*) from auth.users where id=${literal(departing)};`), "0");
			assert.equal(await sql(`select count(*) from public.tenant_members where tenant_id=${literal(f.tenant)} and role='owner';`), "2");
			assert.equal(await sql(`select count(*) from public.tenant_saml_policy_change_requests where id=${literal(id)} and tenant_id=${literal(f.tenant)};`), "1");
		});

		await t.test("owner writes cannot add an unverified owner during or after SAML cutover", async () => {
			const f = await fixture(), unqualified = randomUUID(), qualified = randomUUID(), newOwner = randomUUID();
			await sql(`insert into auth.users(id,email,raw_app_meta_data) values
				(${literal(unqualified)},${literal(`saml-${unqualified}@example.invalid`)},'{"aidr_scim_provisioned":true}'),
				(${literal(qualified)},${literal(`saml-${qualified}@example.invalid`)},'{"aidr_scim_provisioned":true}'),
				(${literal(newOwner)},${literal(`saml-${newOwner}@example.invalid`)},'{"aidr_scim_provisioned":true}');
				insert into public.tenant_members(tenant_id,user_id,role) values
				(${literal(f.tenant)},${literal(unqualified)},'member'),(${literal(f.tenant)},${literal(qualified)},'member');`);
			await identity(qualified, f.target);
			const requested = await rpc(requestSql(f));
			const fence = session("saml-owner-write-fence");
			fence.child.stdin.write(`select pg_advisory_xact_lock(hashtextextended(${literal(f.owner)},2611)); select 'OWNER_WRITE_FENCE_HELD';\n`);
			await marker(fence, "OWNER_WRITE_FENCE_HELD");
			const approval = session("saml-owner-write-approval");
			approval.child.stdin.end(`set local role service_role; select ${approveSql(f, requested.request_id)}; commit;\n`);
			let completed;
			try {
				await advisoryWait("saml-owner-write-approval");
				assert.equal(await sql(`select pg_try_advisory_xact_lock(hashtextextended(${literal(f.tenant)},2607));`), "f",
					"real approval must own the tenant cutover lock before owner-write checks");
				const bounded = "set statement_timeout='1000ms'; set lock_timeout='500ms';";
				await denied(`${bounded} update public.tenant_members set role='owner'
					where tenant_id=${literal(f.tenant)} and user_id=${literal(unqualified)};`, /saml_policy_policy_conflict/);
				await denied(`${bounded} insert into public.tenant_members(tenant_id,user_id,role)
					values (${literal(f.tenant)},${literal(newOwner)},'owner');`, /saml_policy_policy_conflict/);
				await denied(`${bounded} insert into public.tenant_members(tenant_id,user_id,role)
					values (${literal(f.tenant)},${literal(f.backup)},'owner')
					on conflict(tenant_id,user_id) do update set role=excluded.role;`, /saml_policy_policy_conflict/);
				assert.equal(await sql(`select count(*) from public.tenant_members where tenant_id=${literal(f.tenant)} and role='owner';`), "2");
			} finally {
				fence.child.stdin.end("commit;\n");
				completed = await Promise.all([fence.closed, approval.closed]);
			}
			assert.equal(completed[0].code, 0, completed[0].stderr);
			assert.equal(completed[1].code, 0, completed[1].stderr);
			assert.equal(await sql(`select required_saml_provider_id from public.tenant_identity_policies where tenant_id=${literal(f.tenant)};`), f.target);
			await denied(`update public.tenant_members set role='owner'
				where tenant_id=${literal(f.tenant)} and user_id=${literal(unqualified)};`, /saml_policy_owners_not_verified/);
			await denied(`insert into public.tenant_members(tenant_id,user_id,role)
				values (${literal(f.tenant)},${literal(newOwner)},'owner');`, /saml_policy_owners_not_verified/);
			await sql(`update public.tenant_members set role='owner'
				where tenant_id=${literal(f.tenant)} and user_id=${literal(qualified)};`);
			assert.equal(await sql(`select role from public.tenant_members where tenant_id=${literal(f.tenant)} and user_id=${literal(qualified)};`), "owner");
			assert.equal(await sql(`select role from public.tenant_members where tenant_id=${literal(f.tenant)} and user_id=${literal(unqualified)};`), "member");
			assert.equal(await sql(`select count(*) from public.tenant_members where tenant_id=${literal(f.tenant)} and role='owner';`), "3");
		});

		for (const race of ["demotion", "revocation", "expiry"]) await t.test(`approval rechecks ${race} after an observed lock wait`, async () => {
			const f = await fixture();
			if (race === "expiry") f.ownerProof = await proof(f.owner, f.target, { seconds: 3 });
			const requested = await rpc(requestSql(f));
			const lock = race === "revocation" ? `hashtextextended(${literal(f.backup)},2611)` : `hashtextextended(${literal(f.tenant)},2607)`;
			const holder = session(`saml-${race}-holder`);
			holder.child.stdin.write(`select pg_advisory_xact_lock(${lock}); select 'CUTOVER_LOCK_HELD';\n`);
			await marker(holder, "CUTOVER_LOCK_HELD");
			const waiter = session(`saml-${race}-waiter`);
			waiter.child.stdin.end(`set local role service_role; select ${approveSql(f, requested.request_id)}; commit;\n`);
			await advisoryWait(`saml-${race}-waiter`);
			let mutation = "";
			if (race === "demotion") mutation = `update public.tenant_members set role='admin'
				where tenant_id=${literal(f.tenant)} and user_id=${literal(f.backup)};`;
			if (race === "revocation") mutation = `insert into public.identity_user_session_state(user_id,revoked_before,reason)
				values (${literal(f.backup)},clock_timestamp(),'user_global_signout') on conflict (user_id) do update set revoked_before=excluded.revoked_before;`;
			if (race === "expiry") {
				const remaining = Number(await sql(`select greatest(0,ceil(extract(epoch from (${literal(requested.expires_at)}::timestamptz-clock_timestamp()))*1000))::integer;`));
				assert.ok(remaining <= 3000, "fixture expiry must be a short real deadline");
				await delay(remaining + 50);
				assert.equal(await sql(`select clock_timestamp()>${literal(requested.expires_at)}::timestamptz;`), "t");
			}
			holder.child.stdin.end(`${mutation} commit;\n`);
			const [a, b] = await Promise.all([holder.closed, waiter.closed]);
			assert.equal(a.code, 0, a.stderr);
			assert.notEqual(b.code, 0, "approval passed a stale authorization boundary");
			assert.match(b.stderr, /saml_/);
			assert.doesNotMatch(b.stderr, /deadlock|lock timeout/);
			assert.equal(await sql(`select approved_at is null from public.tenant_saml_policy_change_requests where id=${literal(requested.request_id)};`), "t");
			assert.equal(await sql(`select count(*) from public.tenant_identity_policies where tenant_id=${literal(f.tenant)} and required_saml_provider_id is not null;`), "0");
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)};`), "1");
		});

		await t.test("an audit insertion failure rolls back policy publication and request consumption", async () => {
			const f = await fixture();
			const requested = await rpc(requestSql(f));
			await sql(`create function public.__saml_test_audit_failure() returns trigger language plpgsql as $$ begin
				if new.tenant_id=${literal(f.tenant)}::uuid then raise exception 'fixture_saml_audit_failure'; end if; return new; end $$;
				create trigger saml_test_audit_failure before insert on public.admin_audit_logs
				for each row execute function public.__saml_test_audit_failure();`);
			try {
				await denied(`set role service_role; select ${approveSql(f, requested.request_id)};`, /fixture_saml_audit_failure/);
				assert.equal(await sql(`select approved_at is null from public.tenant_saml_policy_change_requests where id=${literal(requested.request_id)};`), "t");
				assert.equal(await sql(`select count(*) from public.tenant_identity_policies where tenant_id=${literal(f.tenant)} and required_saml_provider_id is not null;`), "0");
				assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)};`), "1");
			} finally { await sql("drop trigger saml_test_audit_failure on public.admin_audit_logs; drop function public.__saml_test_audit_failure();"); }
			await rpc(approveSql(f, requested.request_id));
		});

		await t.test("a held tenant retains linked requests until the real offboarding audit phase, without affecting a neighbor", async () => {
			const f = await fixture(), neighbor = await fixture();
			const requested = await rpc(requestSql(f)), neighborRequest = await rpc(requestSql(neighbor));
			// Fixture-only zero retention makes every existing phase immediately eligible.
			await sql(`update public.tenant_data_retention_policies set retention_days=0 where tenant_id=${literal(f.tenant)};`);
			const hold = await sql(`set role service_role; select public.admin_place_tenant_legal_hold(${literal(f.tenant)},${literal(f.owner)},
				'SAML-HOLD','Fixture legal owner','Preserve SAML cutover evidence','saml-hold-reference');`);
			const run = await rpc(`public.request_tenant_offboarding(${literal(f.tenant)},${literal(f.owner)})`);
			assert.equal((await rpc(`public.run_tenant_offboarding_batch(${literal(run.run_id)},100)`)).status, "blocked_legal_hold");
			assert.equal(await sql(`select count(*) from public.tenant_saml_policy_change_requests where id=${literal(requested.request_id)};`), "1");
			const auditCount = await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)};`);
			await denied(`delete from public.tenant_saml_policy_change_requests where id=${literal(requested.request_id)};`, /saml_policy_request_immutable/);
			await denied("truncate public.tenant_saml_policy_change_requests;", /audit.*truncate|truncate.*audit/);
			assert.equal(await sql(`select count(*) from public.tenant_saml_policy_change_requests where id=${literal(requested.request_id)};`), "1");
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)};`), auditCount);
			await sql(`update public.tenant_legal_holds set released_at=clock_timestamp(),released_by=${literal(f.owner)},
				release_reason='Fixture legal approval after testing the held phase' where id=${literal(hold)};`);
			let state;
			for (let i = 0; i < 100; i++) {
				state = await rpc(`public.run_tenant_offboarding_batch(${literal(run.run_id)},100)`);
				if (state.action === "invalidate_cache") await rpc(`public.ack_tenant_offboarding_cache(${literal(run.run_id)},array['fixture-cache'],0)`);
				if (state.status === "completed") break;
			}
			assert.equal(state.status, "completed");
			assert.equal(await sql(`select count(*) from public.tenant_saml_policy_change_requests where tenant_id=${literal(f.tenant)};`), "0");
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)};`), "0");
			assert.equal(await sql(`select status from public.tenant_offboarding_phase_receipts where run_id=${literal(run.run_id)} and phase='admin_audit_logs';`), "completed");
			assert.equal(await sql(`select count(*) from public.tenant_saml_policy_change_requests where id=${literal(neighborRequest.request_id)};`), "1");
			assert.deepEqual(await rpc(getSql(neighbor, neighborRequest.request_id)), neighborRequest);
		});
	} finally {
		for (const state of sessions) if (state.child.exitCode === null) state.child.kill();
		await command(["rm", "-f", container]);
	}
});
