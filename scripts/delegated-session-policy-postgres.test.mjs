// Canonical SQL regression in a disposable offline database. Session evidence
// represents the Edge-verified JWT; this does not perform a live MFA ceremony.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const container = `aidr-delegate-policy-${randomUUID().slice(0, 8)}`;
const psql = ["exec", "-i", "-e", "PGOPTIONS=-c statement_timeout=20000 -c lock_timeout=15000", container,
	"psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"];
const sessions = new Set();
const literal = value => value === null ? "null" : `'${String(value).replaceAll("'", "''")}'`;
const json = value => `${literal(JSON.stringify(value))}::jsonb`;
const digest = value => createHash("sha256").update(JSON.stringify(value)).digest("hex");
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
async function denied(text, pattern = /delegation_(?:session|grant|subject)_inactive|parent_delegation_inactive/) {
	const result = await command(psql, text);
	assert.notEqual(result.code, 0, "statement must be refused");
	assert.match(result.stderr, pattern);
}
const rpc = async expression => JSON.parse(await sql(`set role service_role; select to_jsonb(${expression});`));
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
	assert.fail(`${name} did not wait for ${kind}`);
}
async function liveSession(user, { aal = "aal1", saml = null, seconds = 3600 } = {}) {
	const id = randomUUID();
	const dates = JSON.parse(await sql(`select jsonb_build_object('issued',date_trunc('second',clock_timestamp()-interval '5 seconds'),
		'expires',date_trunc('second',clock_timestamp())+make_interval(secs=>${seconds}));`));
	await sql(`insert into auth.sessions(id,user_id,aal,not_after) values
		(${literal(id)},${literal(user)},${literal(aal)},${literal(dates.expires)});`);
	return { session_id: id, issued_at: dates.issued, expires_at: dates.expires, aal, saml_provider_id: saml };
}
async function fixture({ managed = false } = {}) {
	const f = { tenant: randomUUID(), owner: randomUUID(), backup: randomUUID(), subject: randomUUID(), agent: randomUUID() };
	await sql(`insert into auth.users(id,email,raw_app_meta_data) values
		${[f.owner, f.backup, f.subject].map(id => `(${literal(id)},${literal(`delegate-${id}@example.invalid`)},'{"aidr_scim_provisioned":true}')`).join(",")};
		insert into public.tenants(id,name,kind,created_by) values (${literal(f.tenant)},'Delegate session fixture','enterprise',${literal(f.owner)});
		insert into public.teams(id,tenant_id,name) values (${literal(f.tenant)},${literal(f.tenant)},'Delegate session fixture');
		insert into public.tenant_members(tenant_id,user_id,role) values
		(${literal(f.tenant)},${literal(f.owner)},'owner'),(${literal(f.tenant)},${literal(f.backup)},'owner');
		${managed ? "" : `insert into public.tenant_members(tenant_id,user_id,role) values (${literal(f.tenant)},${literal(f.subject)},'member');`}
		insert into public.pilot_applications(user_id,tenant_id,status,cohort) values (${literal(f.owner)},${literal(f.tenant)},'approved','delegate_session');
		insert into public.agents(id,tenant_id,user_id,iid) values (${literal(f.agent)},${literal(f.tenant)},${literal(f.owner)},${literal(randomUUID())});`);
	f.proof = await liveSession(f.subject);
	f.ownerProof = await liveSession(f.owner, { aal: "aal2" });
	return f;
}
const grantRequest = f => ({ tenant_id: f.tenant, subject_user_id: f.subject, agent_id: f.agent,
	tool_server_id: "review-tool", tool_name: "read", resource_type: "directory", resource_id: "reviewed-resource",
	audience: "review-consumer", scopes: ["read:resource"], max_ttl_seconds: 300, max_delegation_depth: 1, grant_expires_in_seconds: 3600 });
const createSql = (f, proof = f.ownerProof) => `public.create_delegated_credential_grant(${literal(f.owner)},${json({
	...grantRequest(f), ...(proof === null ? {} : { validated_session_issued_at: proof.issued_at, validated_session: proof }),
})})`;
const issueSql = (f, grant, proof = f.proof, issuedAt = proof.issued_at) => `public.reserve_delegated_credential(${literal(f.subject)},'review-issuer',${json({
	tenant_id: f.tenant, grant_id: grant.grant_id, scopes: ["read:resource"], ttl_seconds: 300,
	validated_session_issued_at: issuedAt, validated_session: proof,
})})`;
const validateSql = receipt => `public.validate_delegated_credential(${json(receipt.claims)},${literal(receipt.hash)})`;
const finalizeSql = receipt => `public.finalize_delegated_credential(${json(receipt.claims)},${literal(receipt.hash)})`;
const childSql = receipt => `public.reserve_child_delegated_credential('review-issuer',${json(receipt.claims)},${literal(receipt.hash)},${json({ scopes: ["read:resource"], ttl_seconds: 30 })})`;
async function reserve(f, grant, proof = f.proof) {
	const receipt = await rpc(issueSql(f, grant, proof));
	return { ...receipt, hash: digest(receipt.claims) };
}
async function issued(f, grant = null, proof = f.proof) {
	const actualGrant = grant ?? await rpc(createSql(f));
	const receipt = await reserve(f, actualGrant, proof);
	assert.equal(await rpc(finalizeSql(receipt)), true);
	assert.equal((await rpc(validateSql(receipt))).active, true);
	return { grant: actualGrant, receipt };
}
async function historicClone(receipt) {
	const claims = { ...receipt.claims, tokenId: randomUUID() }, hash = digest(claims);
	await sql(`insert into public.delegated_credential_receipts(token_id,grant_id,tenant_id,subject_user_id,agent_id,
		delegation_depth,claims,claims_sha256,state,issued_at,not_before,expires_at)
		select ${literal(claims.tokenId)},grant_id,tenant_id,subject_user_id,agent_id,delegation_depth,${json(claims)},${literal(hash)},
		'active',issued_at,not_before,expires_at from public.delegated_credential_receipts where token_id=${literal(receipt.claims.tokenId)};`);
	return { claims, hash };
}
async function oidc(f, { activate = true, bindSubject = false } = {}) {
	const provider = randomUUID(), ownerSession = f.ownerProof.session_id;
	await sql(`insert into public.oidc_providers(id,tenant_id,kind,display_name,issuer,client_id,token_auth_method,enabled,discovery)
		values (${literal(provider)},${literal(f.tenant)},'generic','Required IdP','https://idp.example.invalid','review-client','none',true,'{}');
		insert into public.oidc_identities(provider_id,subject,auth_user_id,tenant_id) values
		(${literal(provider)},'owner-subject',${literal(f.owner)},${literal(f.tenant)}),
		(${literal(provider)},'backup-subject',${literal(f.backup)},${literal(f.tenant)});
		insert into public.oidc_sso_sessions(session_id,user_id,provider_id,tenant_id,expires_at)
		values (${literal(ownerSession)},${literal(f.owner)},${literal(provider)},${literal(f.tenant)},clock_timestamp()+interval '1 hour');
		insert into public.oidc_tenant_domains(tenant_id,domain,verification_token,verified_at)
		values (${literal(f.tenant)},${literal(`${f.tenant}.example.invalid`)},${literal(randomUUID())},clock_timestamp());`);
	if (bindSubject) await sql(`insert into public.oidc_identities(provider_id,subject,auth_user_id,tenant_id)
		values (${literal(provider)},'subject-opaque',${literal(f.subject)},${literal(f.tenant)});`);
	if (activate) assert.equal((await rpc(`public.oidc_set_enforcement(${literal(f.tenant)},${literal(f.owner)},${literal(ownerSession)},${literal(provider)},
		'Activate reviewed tenant identity policy','native-delegate-cutover')`)).required_oidc_provider_id, provider);
	return provider;
}
async function oidcSession(f, provider) {
	const proof = await liveSession(f.subject);
	await sql(`insert into public.oidc_sso_sessions(session_id,user_id,provider_id,tenant_id,expires_at)
		values (${literal(proof.session_id)},${literal(f.subject)},${literal(provider)},${literal(f.tenant)},${literal(proof.expires_at)});`);
	return proof;
}
async function managedSubject(f, provider) {
	f.scim = randomUUID(); f.group = randomUUID();
	await sql(`insert into public.scim_users(id,tenant_id,external_id,user_name,normalized_user_name)
		values (${literal(f.scim)},${literal(f.tenant)},'subject-opaque',${literal(`scim-${f.subject}@example.invalid`)},${literal(`scim-${f.subject}@example.invalid`)});
		insert into public.scim_groups(id,tenant_id,external_id,display_name) values (${literal(f.group)},${literal(f.tenant)},'exact-selected-group','Selected group');
		insert into public.scim_group_role_mappings(tenant_id,external_group_id,role,created_by)
		values (${literal(f.tenant)},'exact-selected-group','member',${literal(f.owner)});
		insert into public.scim_group_memberships(tenant_id,group_id,user_id) values (${literal(f.tenant)},${literal(f.group)},${literal(f.scim)});`);
	await rpc(`public.scim_bind_user(${literal(f.tenant)},${literal(f.scim)},${literal(f.subject)})`);
	f.proof = await oidcSession(f, provider);
}
async function withAuditFailure(f, action, work) {
	await sql(`create function public.__delegate_audit_failure() returns trigger language plpgsql as $$ begin
		if new.tenant_id=${literal(f.tenant)}::uuid and new.action=${literal(action)} then raise exception 'fixture_delegate_audit_failure'; end if;
		return new; end $$; create trigger delegate_audit_failure before insert on public.admin_audit_logs
		for each row execute function public.__delegate_audit_failure();`);
	try { await work(); }
	finally { await sql("drop trigger delegate_audit_failure on public.admin_audit_logs; drop function public.__delegate_audit_failure();"); }
}

test("delegated sessions obey current identity policy and irreversible membership removal", { timeout: 900_000 }, async t => {
	const started = await command(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", `POSTGRES_PASSWORD=${randomUUID()}`, "supabase/postgres:17.11.0.004"]);
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
			 create function auth.jwt() returns jsonb language sql stable as $$ select coalesce(nullif(current_setting('request.jwt.claims',true),''),'{}')::jsonb $$;`);
		assert.equal(auth.code, 0, auth.stderr);
		await sql(`create table storage.buckets(id text primary key,name text,public boolean);
			create table storage.objects(id uuid primary key default gen_random_uuid(),bucket_id text,name text,metadata jsonb);
			create function storage.foldername(name text) returns text[] language sql immutable as $$ select string_to_array(name,'/') $$;`);
		const migrations = readdirSync(resolve(root, "supabase/migrations")).filter(name => name.endsWith(".sql")).sort();
		assert.ok(migrations.includes("20261006007000_delegated_session_policy_binding.sql"));
		for (const name of migrations) {
			const result = await command(psql, `begin;\n${readFileSync(resolve(root, "supabase/migrations", name), "utf8")}\ncommit;`);
			assert.equal(result.code, 0, `${name}: ${result.stderr}`);
		}
		t.diagnostic(`Applied all ${migrations.length} canonical migrations through ${migrations.at(-1)}`);
		await rpc("public.configure_tenant_admission_mode('pilot')");

		await t.test("actual OIDC cutover denies password and historical receipts while neighboring authority remains live", async () => {
			const f = await fixture(), neighbor = await fixture();
			const before = await issued(f), untouched = await issued(neighbor);
			const historical = await historicClone(before.receipt);
			assert.equal((await rpc(validateSql(historical))).active, true);
			await oidc(f, { bindSubject: true });
			for (const receipt of [before.receipt, historical]) {
				assert.equal((await rpc(validateSql(receipt))).active, false);
				await denied(`set role service_role; select ${childSql(receipt)};`, /parent_delegation_inactive/);
			}
			await denied(`set role service_role; select ${issueSql(f, before.grant)};`, /delegation_session_inactive/);
			assert.equal((await rpc(validateSql(untouched.receipt))).active, true);
			assert.equal(await sql(`select count(*) from public.delegated_credential_receipts where grant_id=${literal(before.grant.grant_id)};`), "2");
		});

		await t.test("grant creation rechecks its issuer session after actual OIDC cutover commits", async () => {
			const f = await fixture(), oldProof = await liveSession(f.owner);
			const provider = await oidc(f, { activate: false });
			const humanCheck = `set role authenticated; set request.jwt.claim.sub=${literal(f.owner)};
				set request.jwt.claims=${literal(JSON.stringify({ sub: f.owner, session_id: oldProof.session_id,
					iat: Math.floor(Date.parse(oldProof.issued_at) / 1000), aal: oldProof.aal }))};
				select public.tenant_identity_access_allowed(${literal(f.tenant)});`;
			assert.equal(await sql(humanCheck), "t", "the old issuer session passes before cutover");
			const holder = session("delegate-cutover-holder"), writer = session("delegate-cutover-writer");
			holder.child.stdin.write(`select pg_advisory_xact_lock(hashtextextended(${literal(f.tenant)},2606));
				select pg_advisory_xact_lock(hashtextextended(${literal(f.tenant)},2607)); select 'HELD';\n`);
			await marker(holder, "HELD");
			writer.child.stdin.write(`set role service_role; select ${createSql(f, oldProof)}; commit;\n`);
			await observedWait("delegate-cutover-writer", "advisory");
			holder.child.stdin.end(`set role service_role; select public.oidc_set_enforcement(${literal(f.tenant)},
				${literal(f.owner)},${literal(f.ownerProof.session_id)},${literal(provider)},
				'Activate reviewed tenant identity policy','native-delegate-grant-cutover'); commit;\n`);
			const cutover = await holder.closed;
			assert.equal(cutover.code, 0, cutover.stderr);
			assert.equal(await sql(`select required_oidc_provider_id from public.tenant_identity_policies where tenant_id=${literal(f.tenant)};`), provider);
			writer.child.stdin.end(); const outcome = await writer.closed;
			assert.notEqual(outcome.code, 0); assert.match(outcome.stderr, /delegation_grant_forbidden/);
			assert.equal(await sql(humanCheck), "f", "the old issuer session fails the current policy");
			assert.equal(await sql(`select count(*) from public.delegated_credential_grants where tenant_id=${literal(f.tenant)};`), "0");
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)} and action='delegated_credential.grant_created';`), "0");
			for (const proof of [oldProof, null, { ...f.ownerProof, session_id: randomUUID() }, await liveSession(f.subject, { aal: "aal2" })])
				await denied(`set role service_role; select ${createSql(f, proof)};`, /delegation_grant_forbidden/);
			const current = await rpc(createSql(f));
			assert.ok(current.grant_id);
			assert.equal(await sql(`select count(*) from public.delegated_credential_grants where tenant_id=${literal(f.tenant)} and revoked_at is null;`), "1");
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)} and action='delegated_credential.grant_created';`), "1");
			assert.equal(await sql(`select coalesce(bool_or(detail::text like '%validated_session%'),false) from public.admin_audit_logs where tenant_id=${literal(f.tenant)};`), "f");
			const unenforced = await fixture();
			assert.ok((await rpc(createSql(unenforced, null))).grant_id, "historical trusted service callers only retain unenforced compatibility");
		});

		await t.test("grant audit wait cannot outlive its issuer proof or leave authority behind", async () => {
			const f = await fixture(), fence = randomUUID();
			f.ownerProof = await liveSession(f.owner, { aal: "aal2", seconds: 3 });
			await sql(`create function public.__delegate_grant_audit_fence() returns trigger language plpgsql as $$ begin
				if new.tenant_id=${literal(f.tenant)}::uuid and new.action='delegated_credential.grant_created' then
					perform pg_advisory_xact_lock(hashtextextended(${literal(fence)},9020)); end if;
				return new; end $$; create trigger delegate_grant_audit_fence before insert on public.admin_audit_logs
				for each row execute function public.__delegate_grant_audit_fence();`);
			const holder = session("delegate-grant-expiry-holder"), writer = session("delegate-grant-expiry-writer");
			try {
				holder.child.stdin.write(`select pg_advisory_xact_lock(hashtextextended(${literal(fence)},9020)); select 'HELD';\n`);
				await marker(holder, "HELD");
				writer.child.stdin.write(`set role service_role; select ${createSql(f)}; commit;\n`);
				await observedWait("delegate-grant-expiry-writer", "advisory");
				const ms = Number(await sql(`select greatest(0,ceil(extract(epoch from (${literal(f.ownerProof.expires_at)}::timestamptz-clock_timestamp()))*1000))::integer;`));
				assert.ok(ms <= 3000); await delay(ms + 50);
				holder.child.stdin.end("commit;\n"); assert.equal((await holder.closed).code, 0);
				writer.child.stdin.end(); const outcome = await writer.closed;
				assert.notEqual(outcome.code, 0); assert.match(outcome.stderr, /delegation_grant_forbidden/);
				assert.equal(await sql(`select count(*) from public.delegated_credential_grants where tenant_id=${literal(f.tenant)};`), "0");
				assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)} and action='delegated_credential.grant_created';`), "0");
			} finally { await sql("drop trigger delegate_grant_audit_fence on public.admin_audit_logs; drop function public.__delegate_grant_audit_fence();"); }
		});

		await t.test("current OIDC session proof is private and inherited exactly by children", async () => {
			const f = await fixture(), provider = await oidc(f, { bindSubject: true });
			f.proof = await oidcSession(f, provider);
			const { grant, receipt } = await issued(f);
			assert.deepEqual(JSON.parse(await sql(`select validated_session from public.delegated_credential_receipts where token_id=${literal(receipt.claims.tokenId)};`)), f.proof);
			assert.equal(Object.hasOwn(receipt.claims, "validated_session"), false);
			assert.equal(Object.hasOwn(receipt.claims, "sessionId"), false);
			const child = await rpc(childSql(receipt)); child.hash = digest(child.claims);
			assert.equal(await rpc(finalizeSql(child)), true);
			assert.equal((await rpc(validateSql(child))).active, true);
			assert.deepEqual(JSON.parse(await sql(`select validated_session from public.delegated_credential_receipts where token_id=${literal(child.claims.tokenId)};`)), f.proof);
			await sql(`update public.oidc_sso_sessions set revoked_at=clock_timestamp() where session_id=${literal(f.proof.session_id)};`);
			assert.equal((await rpc(validateSql(receipt))).active, false);
			assert.equal((await rpc(validateSql(child))).active, false);
			await denied(`set role service_role; select ${issueSql(f, grant)};`, /delegation_session_inactive/);
		});

		await t.test("receipt proof cannot be promoted, mutated or written around the broker", async () => {
			const f = await fixture(), { receipt } = await issued(f), historical = await historicClone(receipt);
			for (const token of [receipt.claims.tokenId, historical.claims.tokenId]) await denied(`update public.delegated_credential_receipts
				set validated_session=${json({ ...f.proof, session_id: randomUUID() })} where token_id=${literal(token)};`, /delegation_session_proof_immutable/);
			for (const statement of ["insert into public.delegated_credential_receipts select * from public.delegated_credential_receipts",
				"update public.delegated_credential_receipts set state='revoked'", "delete from public.delegated_credential_receipts", "truncate public.delegated_credential_receipts"])
				await denied(`set role service_role; ${statement};`, /permission denied/);
			for (const role of ["anon", "authenticated"]) {
				await denied(`set role ${role}; select ${validateSql(receipt)};`, /permission denied/);
				await denied(`set role ${role}; select app.validate_delegated_credential_inner(${json(receipt.claims)},${literal(receipt.hash)});`, /permission denied/);
			}
			assert.equal((await rpc(validateSql(receipt))).active, true);
		});

		await t.test("current MFA policy and actual Auth session ownership and expiry govern delegated authority", async () => {
			const f = await fixture(), { grant, receipt } = await issued(f);
			await sql(`insert into public.tenant_identity_policies(tenant_id,require_mfa,updated_by) values (${literal(f.tenant)},true,${literal(f.owner)});`);
			assert.equal((await rpc(validateSql(receipt))).active, false);
			await denied(`set role service_role; select ${issueSql(f, grant)};`, /delegation_session_inactive/);
			const strong = await liveSession(f.subject, { aal: "aal2" });
			const current = await issued(f, grant, strong);
			for (const proof of [{ ...strong, session_id: randomUUID() }, await liveSession(f.backup, { aal: "aal2" }),
				{ ...strong, aal: "aal1" }, { ...strong, issued_at: new Date(Date.parse(strong.issued_at) + 1000).toISOString() },
				{ ...strong, expires_at: "2000-01-01T00:00:00Z" }]) {
				const expression = issueSql(f, grant, proof, strong.issued_at);
				await denied(`set role service_role; select ${expression};`, /delegation_session_inactive/);
			}
			await sql(`update auth.sessions set not_after=clock_timestamp()-interval '1 second' where id=${literal(strong.session_id)};`);
			assert.equal((await rpc(validateSql(current.receipt))).active, false);
			await denied(`set role service_role; select ${childSql(current.receipt)};`, /parent_delegation_inactive/);
		});

		await t.test("actual dual-owner SAML cutover requires the issuing session's exact current provider", async () => {
			const f = await fixture(), old = await issued(f), provider = randomUUID();
			await sql(`insert into auth.sso_providers(id,disabled) values (${literal(provider)},null);
				insert into auth.saml_providers(id,sso_provider_id) values (${literal(randomUUID())},${literal(provider)});
				insert into auth.identities(id,user_id,provider,provider_id,identity_data) values
				${[f.owner, f.backup, f.subject].map(user => `(${literal(randomUUID())},${literal(user)},${literal(`sso:${provider}`)},${literal(`opaque-${user}`)},jsonb_build_object('sub',${literal(`opaque-${user}`)}))`).join(",")};`);
			const ownerProof = await liveSession(f.owner, { aal: "aal2", saml: provider });
			const backupProof = await liveSession(f.backup, { aal: "aal2", saml: provider });
			const request = await rpc(`public.request_tenant_saml_policy_change(${literal(f.tenant)},${literal(f.owner)},${literal(provider)},
				'Activate reviewed SAML identity policy','native-delegate-saml',${json(ownerProof)})`);
			await rpc(`public.approve_tenant_saml_policy_change(${literal(f.tenant)},${literal(f.backup)},${literal(request.request_id)},${json(backupProof)})`);
			assert.equal((await rpc(validateSql(old.receipt))).active, false, "linked account identity cannot promote its old password session");
			await denied(`set role service_role; select ${issueSql(f, old.grant)};`, /delegation_session_inactive/);
			const proof = await liveSession(f.subject, { saml: provider });
			const current = await issued(f, old.grant, proof);
			await denied(`set role service_role; select ${issueSql(f, old.grant, { ...proof, saml_provider_id: randomUUID() })};`, /delegation_session_inactive/);
			await sql(`update auth.sso_providers set disabled=true where id=${literal(provider)};`);
			assert.equal((await rpc(validateSql(current.receipt))).active, false);
		});

		await t.test("Auth session deletion and current global revocation invalidate ordinary receipts", async () => {
			const f = await fixture(), old = await issued(f), reserved = await reserve(f, old.grant);
			await sql(`delete from auth.sessions where id=${literal(f.proof.session_id)};`);
			assert.equal((await rpc(validateSql(old.receipt))).active, false);
			assert.equal(await rpc(finalizeSql(reserved)), false);
			f.proof = await liveSession(f.subject);
			const fresh = await issued(f, old.grant);
			await sql(`insert into public.identity_user_session_state(user_id,revoked_before,reason)
				values (${literal(f.subject)},clock_timestamp(),'user_global_signout');`);
			assert.equal((await rpc(validateSql(fresh.receipt))).active, false);
			await denied(`set role service_role; select ${childSql(fresh.receipt)};`, /parent_delegation_inactive/);
		});

		for (const removal of ["deactivate", "group_remove"]) await t.test(`SCIM ${removal} permanently revokes old grants and receipts across restoration`, async () => {
			const f = await fixture({ managed: true }), neighbor = await fixture();
			const provider = await oidc(f, { bindSubject: true });
			await managedSubject(f, provider);
			const old = await issued(f), untouched = await issued(neighbor);
			if (removal === "deactivate") await rpc(`public.scim_update_user(${literal(f.tenant)},${literal(f.scim)},null,false,null)`);
			else await rpc(`public.scim_replace_group_members(${literal(f.tenant)},${literal(f.group)},array[]::uuid[],null)`);
			assert.equal(await sql(`select count(*) from public.tenant_members where tenant_id=${literal(f.tenant)} and user_id=${literal(f.subject)};`), "0");
			assert.equal((await rpc(validateSql(old.receipt))).active, false);
			assert.equal(await sql(`select revoked_at is not null from public.delegated_credential_grants where id=${literal(old.grant.grant_id)};`), "t");
			if (removal === "deactivate") await rpc(`public.scim_update_user(${literal(f.tenant)},${literal(f.scim)},null,true,null)`);
			else await rpc(`public.scim_replace_group_members(${literal(f.tenant)},${literal(f.group)},array[${literal(f.scim)}::uuid],null)`);
			f.proof = await oidcSession(f, provider);
			await denied(`set role service_role; select ${issueSql(f, old.grant)};`);
			assert.equal((await rpc(validateSql(old.receipt))).active, false);
			await denied(`set role service_role; select ${childSql(old.receipt)};`, /parent_delegation_inactive/);
			assert.equal((await issued(f)).receipt.claims.subjectUserId, f.subject);
			assert.equal((await rpc(validateSql(untouched.receipt))).active, true);
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)} and action='delegated_credential.membership_revoked';`), "1");
		});

		await t.test("membership revocation and receipt finalization roll back with their audit", async () => {
			const f = await fixture(), old = await issued(f);
			await withAuditFailure(f, "delegated_credential.membership_revoked", async () => {
				await denied(`delete from public.tenant_members where tenant_id=${literal(f.tenant)} and user_id=${literal(f.subject)};`, /fixture_delegate_audit_failure/);
				assert.equal((await rpc(validateSql(old.receipt))).active, true);
				assert.equal(await sql(`select revoked_at is null from public.delegated_credential_grants where id=${literal(old.grant.grant_id)};`), "t");
			});
			const reserved = await reserve(f, old.grant);
			await withAuditFailure(f, "delegated_credential.issued", async () => {
				await denied(`set role service_role; select ${finalizeSql(reserved)};`, /fixture_delegate_audit_failure/);
				assert.equal(await sql(`select state from public.delegated_credential_receipts where token_id=${literal(reserved.claims.tokenId)};`), "reserved");
			});
			assert.equal(await rpc(finalizeSql(reserved)), true);
		});

		await t.test("grant creation linearizes before removal and its newly created authority is swept", async () => {
			const f = await fixture(), fence = randomUUID();
			await sql(`create function public.__delegate_insert_fence() returns trigger language plpgsql as $$ begin
				if new.tenant_id=${literal(f.tenant)}::uuid then perform pg_advisory_xact_lock(hashtextextended(${literal(fence)},9019)); end if;
				return new; end $$; create trigger delegate_insert_fence before insert on public.delegated_credential_grants
				for each row execute function public.__delegate_insert_fence();`);
			const holder = session("delegate-create-holder"), writer = session("delegate-create-writer"), remover = session("delegate-create-remover");
			try {
				holder.child.stdin.write(`select pg_advisory_xact_lock(hashtextextended(${literal(fence)},9019)); select 'HELD';\n`);
				await marker(holder, "HELD");
				writer.child.stdin.write(`set role service_role; select ${createSql(f)}; select 'CREATED'; commit;\n`);
				await observedWait("delegate-create-writer", "advisory");
				remover.child.stdin.write(`delete from public.tenant_members where tenant_id=${literal(f.tenant)} and user_id=${literal(f.subject)}; select 'REMOVED'; commit;\n`);
				await observedWait("delegate-create-remover", "row");
				holder.child.stdin.end("commit;\n");
				assert.equal((await holder.closed).code, 0);
				await marker(writer, "CREATED"); writer.child.stdin.end(); assert.equal((await writer.closed).code, 0, writer.stderr);
				await marker(remover, "REMOVED"); remover.child.stdin.end(); assert.equal((await remover.closed).code, 0, remover.stderr);
				assert.equal(await sql(`select count(*) from public.delegated_credential_grants where tenant_id=${literal(f.tenant)} and revoked_at is not null;`), "1");
				await sql(`insert into public.tenant_members(tenant_id,user_id,role) values (${literal(f.tenant)},${literal(f.subject)},'member');`);
				const grant = { grant_id: await sql(`select id from public.delegated_credential_grants where tenant_id=${literal(f.tenant)};`) };
				await denied(`set role service_role; select ${issueSql(f, grant)};`);
			} finally { await sql("drop trigger delegate_insert_fence on public.delegated_credential_grants; drop function public.__delegate_insert_fence();"); }
		});

		await t.test("session expiry is rechecked after a real grant-row wait without leaving a reserved receipt", async () => {
			const f = await fixture(), grant = await rpc(createSql(f));
			f.proof = await liveSession(f.subject, { seconds: 3 });
			const holder = session("delegate-expiry-holder"), writer = session("delegate-expiry-writer");
			holder.child.stdin.write(`select 1 from public.delegated_credential_grants where id=${literal(grant.grant_id)} for update; select 'HELD';\n`);
			await marker(holder, "HELD");
			writer.child.stdin.write(`set role service_role; select ${issueSql(f, grant)}; commit;\n`);
			await observedWait("delegate-expiry-writer", "row");
			const ms = Number(await sql(`select greatest(0,ceil(extract(epoch from (${literal(f.proof.expires_at)}::timestamptz-clock_timestamp()))*1000))::integer;`));
			assert.ok(ms <= 3000); await delay(ms + 50);
			holder.child.stdin.end("commit;\n"); assert.equal((await holder.closed).code, 0);
			writer.child.stdin.end(); const outcome = await writer.closed;
			assert.notEqual(outcome.code, 0); assert.match(outcome.stderr, /delegation_session_inactive/);
			assert.equal(await sql(`select count(*) from public.delegated_credential_receipts where grant_id=${literal(grant.grant_id)};`), "0");
		});
	} finally {
		for (const state of sessions) if (state.child.exitCode === null) state.child.kill();
		await command(["rm", "-f", container]);
	}
});
