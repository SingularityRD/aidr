// Real SQL/concurrency regression. Own random-name offline container only;
// complete ordered migration chain, no existing database or deployment.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const container = `aidr-oidc-lifecycle-${randomUUID()}`;
const pgArgs = ["exec", "-i", "-e", "PGOPTIONS=-c statement_timeout=10000 -c lock_timeout=5000",
	container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"];
const literal = value => `'${String(value).replaceAll("'", "''")}'`;
const tables = ["oidc_auth_requests", "oidc_login_tickets", "oidc_sso_sessions",
	"oidc_identities", "oidc_tenant_domains", "oidc_providers"];
function docker(args, input = "") {
	return new Promise((done, reject) => {
		const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"], timeout: 120_000 });
		let stdout = "", stderr = "";
		child.stdout.on("data", chunk => { stdout += chunk; });
		child.stderr.on("data", chunk => { stderr += chunk; });
		child.once("error", reject);
		child.once("close", code => done({ code, stdout: stdout.trim(), stderr }));
		child.stdin.on("error", () => {});
		child.stdin.end(input);
	});
}
async function sql(text) {
	const result = await docker(pgArgs, text);
	assert.equal(result.code, 0, result.stderr);
	return result.stdout;
}
async function denied(text, pattern) {
	const result = await docker(pgArgs, text);
	assert.notEqual(result.code, 0, "statement must be refused");
	assert.match(result.stderr, pattern);
}
const rpc = async expression => JSON.parse(await sql(`set role service_role; select coalesce(${expression}, 'null'::jsonb);`));
function session() {
	const child = spawn("docker", pgArgs, { stdio: ["pipe", "pipe", "pipe"] });
	let output = "", errors = "", pending;
	child.stdout.on("data", chunk => {
		output += chunk;
		if (!pending) return;
		const index = output.indexOf(`${pending.marker}\n`);
		if (index < 0) return;
		const value = output.slice(0, index).trim();
		output = output.slice(index + pending.marker.length + 1);
		const done = pending.done;
		pending = undefined;
		done(value);
	});
	child.stderr.on("data", chunk => { errors += chunk; });
	child.once("error", error => pending?.reject(error));
	child.once("close", code => pending?.reject(new Error(`psql exited ${code}: ${errors}`)));
	return {
		query(text) {
			assert.equal(pending, undefined);
			return new Promise((done, reject) => {
				const marker = randomUUID();
				pending = { marker, done, reject };
				child.stdin.write(`${text}\n\\echo ${marker}\n`);
			});
		},
		close() { child.stdin.end("rollback;\n\\q\n"); },
	};
}
async function waitForLock(application) {
	for (let attempt = 0; attempt < 100; attempt++) {
		if (await sql(`select exists(select 1 from pg_stat_activity
          where application_name=${literal(application)} and wait_event='advisory');`) === "t") return;
		await delay(20);
	}
	assert.fail("fixture writer did not reach the expected advisory lock");
}

test("OIDC SCIM binding and complete tenant erasure enforce the live database boundary", { timeout: 600_000 }, async t => {
	const started = await docker(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=oidc-lifecycle-fixture-only", "supabase/postgres:17.11.0.004"]);
	assert.equal(started.code, 0, started.stderr);
	try {
		let ready = false;
		for (let attempt = 0; attempt < 150 && !ready; attempt++) {
			ready = (await docker(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])).code === 0;
			if (!ready) await delay(100);
		}
		assert.ok(ready, "own isolated PostgreSQL must start");
		const bootstrap = await docker(["exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "supabase_admin", "-d", "postgres"],
			`grant create on schema storage to postgres;
             -- GoTrue supplies this table in a complete deployment. The offline
             -- Postgres image needs only the fields read by the binding guard.
             create table auth.identities(id uuid primary key default gen_random_uuid(), user_id uuid,
               provider text, provider_id text, identity_data jsonb);
             grant select, insert, update, delete on auth.identities to postgres;
             create function auth.jwt() returns jsonb language sql stable as $$
               select coalesce(nullif(current_setting('request.jwt.claims',true),''),'{}')::jsonb $$;`);
		assert.equal(bootstrap.code, 0, bootstrap.stderr);
		await sql(`create table storage.buckets(id text primary key, name text, public boolean);
          create table storage.objects(id uuid primary key default gen_random_uuid(), bucket_id text, name text, metadata jsonb);
          create function storage.foldername(name text) returns text[] language sql immutable as $$ select string_to_array(name, '/') $$;`);
		const owner = randomUUID(), owner2 = randomUUID(), legacyTenant = randomUUID();
		let legacyRun;
		for (const name of readdirSync(resolve(root, "supabase/migrations")).filter(name => name.endsWith(".sql")).sort()) {
			if (name === "20261005221000_oidc_scim_offboarding.sql") {
				await sql(`insert into auth.users(id,email,raw_app_meta_data) values
                (${literal(owner)},${literal(`oidc-owner-${owner}@example.invalid`)},'{"aidr_scim_provisioned":true}'),
                (${literal(owner2)},${literal(`oidc-owner-${owner2}@example.invalid`)},'{"aidr_scim_provisioned":true}');
              insert into public.tenants(id,name,kind,created_by) values (${literal(legacyTenant)},'Legacy OIDC run','enterprise',${literal(owner)});`);
				legacyRun = (await rpc(`public.request_tenant_offboarding(${literal(legacyTenant)},${literal(owner)})`)).run_id;
			}
			const result = await docker(pgArgs, `begin;\n${readFileSync(resolve(root, "supabase/migrations", name), "utf8")}\ncommit;`);
			assert.equal(result.code, 0, `${name}: ${result.stderr}`);
		}
		assert.equal(await sql(`select count(*) from public.tenant_offboarding_phase_receipts
          where run_id=${literal(legacyRun)} and phase like 'oidc_%' and status='pending';`), "6", "in-flight runs receive all new phases");
		await rpc("public.configure_tenant_admission_mode('pilot')");
		async function tenant(name) {
			const id = randomUUID();
			await sql(`insert into public.tenants(id,name,kind,created_by) values (${literal(id)},${literal(name)},'team',${literal(owner)});
              insert into public.teams(id,tenant_id,name) values (${literal(id)},${literal(id)},${literal(name)});
              insert into public.team_members(team_id,tenant_id,user_id,role) values
                (${literal(id)},${literal(id)},${literal(owner)},'owner'), (${literal(id)},${literal(id)},${literal(owner2)},'owner');
              update public.tenant_data_retention_policies set retention_days=0 where tenant_id=${literal(id)};`);
			return id;
		}
		async function provider(id) {
			const providerId = randomUUID();
			await sql(`insert into public.oidc_providers(id,tenant_id,kind,display_name,issuer,client_id,token_auth_method,enabled,discovery)
              values (${literal(providerId)},${literal(id)},'generic','Fixture','https://idp.example.invalid','fixture','none',true,'{}');
              insert into public.oidc_tenant_domains(tenant_id,domain,verification_token,verified_at)
              values (${literal(id)},${literal(`d${id.replaceAll("-", "")}.example.invalid`)},repeat('v',43),now());`);
			return providerId;
		}
		async function identity(id, providerId, user, subject) {
			await sql(`insert into public.oidc_identities(provider_id,subject,auth_user_id,tenant_id)
              values (${literal(providerId)},${literal(subject)},${literal(user)},${literal(id)});`);
		}
		const target = await tenant("OIDC binding target"), providerId = await provider(target);
		await identity(target, providerId, owner, "owner-one");
		await identity(target, providerId, owner2, "owner-two");
		const actorSession = randomUUID();
		await sql(`insert into public.oidc_sso_sessions(session_id,user_id,provider_id,tenant_id,expires_at)
          values (${literal(actorSession)},${literal(owner)},${literal(providerId)},${literal(target)},now()+interval '1 hour');`);
		const rawUser = randomUUID(), managedUser = randomUUID(), manualUser = randomUUID();
		const rawScim = randomUUID(), managedScim = randomUUID(), manualScim = randomUUID(), group = randomUUID();
		await sql(`insert into auth.users(id,email,raw_app_meta_data) values
          (${literal(rawUser)},${literal(`raw-${rawUser}@example.invalid`)},'{"aidr_scim_provisioned":true}'),
          (${literal(managedUser)},${literal(`managed-${managedUser}@example.invalid`)},'{"aidr_scim_provisioned":true}'),
          (${literal(manualUser)},${literal(`manual-${manualUser}@example.invalid`)},'{"aidr_scim_provisioned":true}');
          insert into public.scim_users(id,tenant_id,external_id,user_name,normalized_user_name) values
          (${literal(rawScim)},${literal(target)},'raw-subject','raw@example.invalid','raw@example.invalid'),
          (${literal(managedScim)},${literal(target)},'managed-subject','managed@example.invalid','managed@example.invalid'),
          (${literal(manualScim)},${literal(target)},'manual-subject','manual@example.invalid','manual@example.invalid');
          insert into public.scim_groups(id,tenant_id,external_id,display_name) values (${literal(group)},${literal(target)},'operators','Operators');
          insert into public.scim_group_role_mappings(tenant_id,external_group_id,role,created_by)
            values (${literal(target)},'operators','member',${literal(owner)});
          insert into public.scim_group_memberships(tenant_id,group_id,user_id) values
            (${literal(target)},${literal(group)},${literal(rawScim)}), (${literal(target)},${literal(group)},${literal(managedScim)}),
            (${literal(target)},${literal(group)},${literal(manualScim)});`);
		await t.test("a claim waiting behind OIDC activation cannot bind an email-only Auth user", async () => {
			const admin = session();
			try {
				await admin.query(`begin; select public.oidc_set_enforcement(${literal(target)},${literal(owner)},${literal(actorSession)},
                  ${literal(providerId)},'Exercise activation race','CHANGE-123');`);
				const application = `oidc-scim-${randomUUID()}`;
				const writer = docker(pgArgs, `set application_name=${literal(application)}; set role service_role;
                  select public.scim_bind_user(${literal(target)},${literal(rawScim)},${literal(rawUser)});`);
				await waitForLock(application);
				await admin.query("commit;");
				const result = await writer;
				assert.notEqual(result.code, 0);
				assert.match(result.stderr, /scim_oidc_identity_mismatch/);
				assert.equal(await sql(`select auth_user_id is null from public.scim_users where id=${literal(rawScim)};`), "t");
			} finally { admin.close(); }
		});
		await t.test("exact OIDC subjects bind and manual memberships keep their authority", async () => {
			await identity(target, providerId, managedUser, "managed-subject");
			await sql(`set role service_role; select public.scim_bind_user(${literal(target)},${literal(managedScim)},${literal(managedUser)});`);
			assert.equal(await sql(`select role from public.tenant_members where tenant_id=${literal(target)} and user_id=${literal(managedUser)};`), "member");
			await identity(target, providerId, manualUser, "manual-subject");
			await sql(`insert into public.tenant_members(tenant_id,user_id,role) values (${literal(target)},${literal(manualUser)},'viewer');`);
			await denied(`set role service_role; select public.scim_bind_user(${literal(target)},${literal(manualScim)},${literal(manualUser)});`, /scim_cannot_take_over_manual_membership/);
			assert.equal(await sql(`select role from public.tenant_members where tenant_id=${literal(target)} and user_id=${literal(manualUser)};`), "viewer");
		});
		await t.test("SAML and direct SCIM binding take the tenant lock before the same user row", async () => {
			const id = await tenant("SAML bind lock order"), samlProvider = randomUUID(), user = randomUUID(), scimUser = randomUUID();
			const samlGroup = randomUUID(), subject = `directory-${user}`;
			await sql(`insert into auth.users(id,email,raw_app_meta_data)
              values (${literal(user)},${literal(`saml-${user}@example.invalid`)},'{"aidr_scim_provisioned":true}');
              insert into auth.identities(user_id,provider,provider_id,identity_data) values
                (${literal(user)},${literal(`sso:${samlProvider}`)},${literal(subject)},jsonb_build_object('sub',${literal(subject)}));
              insert into public.scim_users(id,tenant_id,external_id,user_name,normalized_user_name)
                values (${literal(scimUser)},${literal(id)},${literal(subject)},'saml@example.invalid','saml@example.invalid');
              insert into public.scim_groups(id,tenant_id,external_id,display_name)
                values (${literal(samlGroup)},${literal(id)},'saml-operators','SAML operators');
              insert into public.scim_group_role_mappings(tenant_id,external_group_id,role,created_by)
                values (${literal(id)},'saml-operators','member',${literal(owner)});
              insert into public.scim_group_memberships(tenant_id,group_id,user_id)
                values (${literal(id)},${literal(samlGroup)},${literal(scimUser)});
              insert into public.tenant_identity_policies(tenant_id,required_saml_provider_id)
                values (${literal(id)},${literal(samlProvider)});`);
			const direct = session();
			try {
				// Pause the direct entry point immediately after its tenant lock.
				// The SAML entry point must wait here without taking the user row.
				await direct.query(`begin; select pg_advisory_xact_lock(hashtextextended(${literal(id)},2607));`);
				const application = `saml-bind-${randomUUID()}`;
				const saml = docker(pgArgs, `set application_name=${literal(application)}; set role service_role;
                  select public.scim_bind_saml_identity(${literal(user)},${literal(samlProvider)});`);
				await waitForLock(application);
				await direct.query(`select public.scim_bind_user(${literal(id)},${literal(scimUser)},${literal(user)}); commit;`);
				const result = await saml;
				assert.equal(result.code, 0, result.stderr);
				assert.equal(result.stdout, id);
				assert.equal(await sql(`select auth_user_id from public.scim_users where id=${literal(scimUser)};`), user);
				assert.equal(await sql(`select role from public.tenant_members where tenant_id=${literal(id)} and user_id=${literal(user)};`), "member");
			} finally { direct.close(); }
		});
		await t.test("applied playbook results survive a forbidden or full next-step queue", async playbookTest => {
			async function responseFixture(name, stage = "acknowledged") {
				const id = await tenant(name), agent = randomUUID(), hash = randomUUID().replaceAll("-", "").repeat(2);
				await sql(`insert into public.pilot_applications(user_id,tenant_id,status,cohort)
                  values (${literal(owner)},${literal(id)},'approved','response-regression');
                  insert into public.entitlements(user_id,tenant_id,included_agents) values (${literal(owner)},${literal(id)},1)
                    on conflict(tenant_id) do update set included_agents=1;
                  insert into public.agents(id,user_id,tenant_id,iid)
                    values (${literal(agent)},${literal(owner)},${literal(id)},${literal(`response-${agent}`)});
                  insert into public.api_keys(user_id,tenant_id,agent_id,key_hash)
                    values (${literal(owner)},${literal(id)},${literal(agent)},${literal(hash)});`);
				const run = await rpc(`public.start_fleet_response_playbook(${literal(id)},${literal(owner)},${literal(agent)},
                  gen_random_uuid(),'agent_containment_v1','Exercise actual host receipt preservation',${literal(`fixture-${randomUUID()}`)},300)`);
				const command = run.steps[0].command_id;
				if (stage !== "pending") {
					assert.equal(await sql(`set role service_role; select (public.poll_fleet_response_command(${literal(hash)},${literal(id)},${literal(agent)})).state;`), "delivered");
				}
				if (stage === "acknowledged") {
					assert.equal(await sql(`set role service_role; select (public.record_fleet_response_command(${literal(hash)},${literal(id)},${literal(agent)},${literal(command)},'ack','accepted',null)).state;`), "acknowledged");
				}
				return { id, agent, hash, run: run.id, command };
			}
			const demoted = await responseFixture("Playbook actor demoted after acknowledgement");
			await sql(`update public.team_members set role='member' where team_id=${literal(demoted.id)} and user_id=${literal(owner)};`);
			const full = await responseFixture("Playbook next-step queue at capacity");
			await sql(`insert into public.fleet_response_commands(tenant_id,agent_id,actor_user_id,command_type,reason,idempotency_key,request_fingerprint,expires_at)
              select ${literal(full.id)},${literal(full.agent)},${literal(owner)},'agent_pause','Outstanding fixture commands',
                'fixture-quota-'||i,repeat('a',64),now()+interval '1 hour' from generate_series(1,200) i;`);
			const late = await responseFixture("Step-two receipt insertion fails after command queue");
			await sql(`create function public.__fixture_reject_response_step() returns trigger language plpgsql as $$
              begin
                if new.run_id=${literal(late.run)} and new.ordinal=2 then
                  raise exception 'fixture_step_receipt_refused' using errcode='23514';
                end if;
                return new;
              end $$;
              create trigger fixture_reject_response_step before insert on public.fleet_response_playbook_steps
                for each row execute function public.__fixture_reject_response_step();`);
			for (const [fixture, errorCode] of [[demoted, "42501"], [full, "54000"], [late, "23514"]]) {
				const result = await sql(`set role service_role; select (public.record_fleet_response_command(
                  ${literal(fixture.hash)},${literal(fixture.id)},${literal(fixture.agent)},${literal(fixture.command)},'result','succeeded','agent_paused')).state;`);
				assert.equal(result, "succeeded", "actual first host action must retain its authenticated result");
				const saved = await rpc(`public.get_fleet_response_playbook(${literal(fixture.id)},${literal(fixture.run)})`);
				assert.equal(saved.state, "partial");
				assert.equal(saved.current_step, 1);
				assert.equal(saved.result_code, `next_step_queue_failed_${errorCode}`);
				assert.equal(saved.steps.length, 1, "isolation was never queued or reported successful");
				assert.equal(saved.steps[0].state, "succeeded");
				assert.equal(saved.steps[0].result_code, "agent_paused");
				assert.ok(saved.completed_at);
				assert.equal(await sql(`select count(*) from public.fleet_response_commands where tenant_id=${literal(fixture.id)} and command_type='network_isolate';`), "0");
				assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(fixture.id)}
                  and detail->>'command_type'='network_isolate';`), "0", "a failed next-step receipt also rolls back its queued audit");
				assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(fixture.id)}
                  and action='fleet.response.result' and detail->>'command_id'=${literal(fixture.command)};`), "1", "result and audit commit together");
				assert.equal(await sql(`set role service_role; select (public.record_fleet_response_command(
                  ${literal(fixture.hash)},${literal(fixture.id)},${literal(fixture.agent)},${literal(fixture.command)},'result','succeeded','agent_paused')).state;`), "succeeded", "receipt retry stays idempotent");
			}
			await sql("drop trigger fixture_reject_response_step on public.fleet_response_playbook_steps; drop function public.__fixture_reject_response_step();");
			const happy = await responseFixture("Successful first step still queues isolation");
			await denied(`set role service_role; select public.record_fleet_response_command(repeat('f',64),${literal(happy.id)},
              ${literal(happy.agent)},${literal(happy.command)},'result','succeeded','agent_paused');`, /fleet_agent_forbidden/);
			await sql(`set role service_role; select public.record_fleet_response_command(${literal(happy.hash)},${literal(happy.id)},
              ${literal(happy.agent)},${literal(happy.command)},'result','succeeded','agent_paused');`);
			const running = await rpc(`public.get_fleet_response_playbook(${literal(happy.id)},${literal(happy.run)})`);
			assert.equal(running.state, "running");
			assert.equal(running.current_step, 2);
			assert.equal(running.steps.length, 2);
			assert.equal(running.steps[1].state, "pending");
			await playbookTest.test("status derives elapsed command deadlines without changing recorded evidence", async () => {
				const read = fixture => rpc(`public.get_fleet_response_playbook(${literal(fixture.id)},${literal(fixture.run)})`);
				// Historical projection fixtures are inserted with elapsed timestamps.
				// Their sources retain the real start/poll/ACK/result coverage above;
				// no signed command identity or deadline is changed after insertion.
				async function pastProjection(source) {
					const snapshot = await read(source), run = randomUUID();
					const commands = snapshot.steps.map(step => [step.command_id, randomUUID()]);
					await sql(`begin;
                      insert into public.fleet_response_playbook_runs(id,tenant_id,actor_user_id,agent_id,incident_id,
                        playbook_id,reason,idempotency_key,request_fingerprint,expires_at,state,current_step,result_code,created_at,completed_at)
                      select ${literal(run)},tenant_id,actor_user_id,agent_id,incident_id,playbook_id,reason,
                        ${literal(`fixture-status-${run}`)},request_fingerprint,expires_at-interval '10 minutes',
                        state,current_step,result_code,created_at-interval '10 minutes',completed_at
                      from public.fleet_response_playbook_runs where id=${literal(source.run)};
                      ${commands.map(([original, command], index) => `
                        insert into public.fleet_response_commands(id,tenant_id,agent_id,actor_user_id,command_type,reason,
                          idempotency_key,request_fingerprint,rollback_of,state,attempts,created_at,expires_at,
                          delivered_at,delivery_lease_until,acknowledged_at,completed_at,result_code)
                        select ${literal(command)},tenant_id,agent_id,actor_user_id,command_type,reason,
                          ${literal(`pb:${run}:${snapshot.steps[index].ordinal}`)},request_fingerprint,rollback_of,state,attempts,
                          created_at-interval '10 minutes',expires_at-interval '10 minutes',
                          delivered_at-interval '10 minutes',delivery_lease_until-interval '10 minutes',acknowledged_at-interval '10 minutes',
                          completed_at,result_code
                        from public.fleet_response_commands where id=${literal(original)};
                        insert into public.fleet_response_playbook_steps(run_id,tenant_id,actor_user_id,agent_id,incident_id,
                          step_id,ordinal,command_type,command_id,state,result_code,created_at,completed_at)
                        select ${literal(run)},tenant_id,actor_user_id,agent_id,incident_id,step_id,ordinal,command_type,
                          ${literal(command)},state,result_code,created_at-interval '10 minutes',completed_at
                        from public.fleet_response_playbook_steps where run_id=${literal(source.run)} and command_id=${literal(original)};
                      `).join("\n")}
                      commit;`);
					return { ...source, run, command: commands[0][1] };
				}
				for (const stage of ["pending", "delivered", "acknowledged"]) {
					const source = await responseFixture(`Playbook status deadline ${stage}`, stage);
					assert.equal((await read(source)).steps[0].state, stage, "status reflects the actual command delivery/ack stage");
					const fixture = await pastProjection(source);
					const expired = await read(fixture);
					const expected = stage === "pending" ? "expired" : "outcome_unknown";
					assert.equal(expired.state, expected, "offline commands cannot remain operationally running after TTL");
					assert.equal(expired.result_code, "ttl_elapsed");
					assert.equal(expired.steps[0].state, expected);
					assert.equal(expired.steps[0].result_code, "ttl_elapsed");
					assert.equal(expired.completed_at, null, "a derived timeout must not invent a recorded host completion");
					assert.deepEqual(await read(fixture), expired, "repeated status reads are idempotent");
					assert.equal(await sql(`select r.state||':'||c.state from public.fleet_response_playbook_runs r
                      join public.fleet_response_commands c on c.id=${literal(fixture.command)} where r.id=${literal(fixture.run)};`), `running:${stage}`, "the getter writes no command or run evidence");
					assert.equal(await rpc(`public.get_fleet_response_playbook(${literal(happy.id)},${literal(fixture.run)})`), null, "status stays tenant-scoped");
					assert.equal(await sql(`set role service_role; select (public.record_fleet_response_command(
                      ${literal(fixture.hash)},${literal(fixture.id)},${literal(fixture.agent)},${literal(fixture.command)},'result','succeeded','agent_paused')).state;`), expected, "late result retains the consumer's existing timeout semantics");
					const persisted = await read(fixture);
					assert.equal(persisted.state, expected);
					assert.equal(persisted.steps[0].state, expected);
					assert.ok(persisted.completed_at, "only the existing authenticated transition records completion");
				}
				const partialFixture = await pastProjection(happy);
				const partial = await read(partialFixture);
				assert.equal(partial.state, "partial");
				assert.equal(partial.result_code, "ttl_elapsed");
				assert.equal(partial.current_step, 2);
				assert.equal(partial.steps[0].state, "succeeded");
				assert.equal(partial.steps[0].result_code, "agent_paused");
				assert.equal(partial.steps[1].state, "expired");
				assert.equal(partial.completed_at, null, "an elapsed second step must not invent a recorded completion");
				assert.deepEqual(await read(partialFixture), partial);
				assert.equal(await sql(`select r.state||':'||r.current_step||':'||string_agg(c.state,',' order by s.ordinal)
                      from public.fleet_response_playbook_runs r join public.fleet_response_playbook_steps s on s.run_id=r.id
                      join public.fleet_response_commands c on c.id=s.command_id
                      where r.id=${literal(partialFixture.run)} group by r.id;`), "running:2:succeeded,pending", "the partial projection writes no host receipt");
				const recordedPartial = await read(demoted);
				const terminalFixture = await pastProjection(demoted), terminal = await read(terminalFixture);
				assert.deepEqual(terminal, { ...recordedPartial, id: terminalFixture.run,
					expires_at: terminal.expires_at, created_at: terminal.created_at,
					steps: [{ ...recordedPartial.steps[0], command_id: terminalFixture.command, expires_at: terminal.steps[0].expires_at }] }, "stored terminal receipts, reason and completion survive later TTL");
				assert.deepEqual(await read(terminalFixture), terminal);
				assert.equal(await sql(`select has_function_privilege('service_role','public.get_fleet_response_playbook(uuid,uuid)','execute')
                  and not has_function_privilege('authenticated','public.get_fleet_response_playbook(uuid,uuid)','execute')
                  and not has_function_privilege('anon','public.get_fleet_response_playbook(uuid,uuid)','execute');`), "t", "status RPC retains its service-only privilege boundary");
			});
		});
		await t.test("hold, retention, neighbor isolation and all six receipts govern erasure", async () => {
			const neighbor = await tenant("OIDC neighbor"), neighborProvider = await provider(neighbor);
			await sql(`insert into public.scim_group_role_mappings(tenant_id,external_group_id,role,created_by)
              values (${literal(neighbor)},'temporary-fixture-mapping','viewer',${literal(owner)});
              delete from public.scim_group_role_mappings where tenant_id=${literal(neighbor)} and external_group_id='temporary-fixture-mapping';`);
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(neighbor)}
              and action in ('scim.mapping.created','scim.mapping.deleted');`), "2", "active-tenant mapping lifecycle still retains both audit receipts");
			const ticketHash = "a".repeat(64), requestHash = "b".repeat(64);
			await sql(`insert into public.oidc_auth_requests(state_hash,provider_id,tenant_id,nonce_hash,code_verifier,binding_hash,redirect_uri,expires_at)
              values (${literal(requestHash)},${literal(providerId)},${literal(target)},repeat('c',64),repeat('p',43),repeat('d',64),'https://app.example.invalid',now()+interval '5 minutes');
              insert into public.oidc_login_tickets(ticket_hash,provider_id,tenant_id,auth_user_id,expires_at)
              values (${literal(ticketHash)},${literal(providerId)},${literal(target)},${literal(owner)},now()+interval '5 minutes');
              update public.tenant_data_retention_policies set retention_days=2
                where tenant_id=${literal(target)} and data_class='identity_membership';`);
			const boundSession = randomUUID();
			assert.equal((await rpc(`public.oidc_record_sso_session(${literal(ticketHash)},${literal(owner)},${literal(boundSession)})`)).tenant_id, target);
			assert.equal(await rpc(`public.oidc_record_sso_session(${literal(ticketHash)},${literal(owner)},${literal(randomUUID())})`), null, "login tickets remain single-use");
			await sql(`insert into public.oidc_auth_requests(state_hash,provider_id,tenant_id,nonce_hash,code_verifier,binding_hash,redirect_uri,created_at,expires_at)
              values (repeat('e',64),${literal(providerId)},${literal(target)},repeat('f',64),repeat('p',43),repeat('d',64),
                'https://app.example.invalid',now()-interval '3 hours',now()-interval '2 hours'),
                (repeat('f',64),${literal(neighborProvider)},${literal(neighbor)},repeat('f',64),repeat('p',43),repeat('d',64),
                'https://app.example.invalid',now()-interval '3 hours',now()-interval '2 hours');`);
			const hold = await sql(`select public.admin_place_tenant_legal_hold(${literal(target)},${literal(owner)},'CASE-123','Fixture owner','Preserve evidence for the lifecycle regression');`);
			assert.equal(await sql("set role service_role; select public.oidc_prune_transient_rows();"), "1", "routine expiry skips held tenants but still cleans neighbors");
			const run = (await rpc(`public.request_tenant_offboarding(${literal(target)},${literal(owner)})`)).run_id;
			assert.equal((await rpc(`public.run_tenant_offboarding_batch(${literal(run)},100)`)).status, "blocked_legal_hold");
			assert.equal(await sql(`select count(*) from public.oidc_auth_requests where tenant_id=${literal(target)};`), "2");
			await denied(`insert into public.oidc_login_tickets(ticket_hash,provider_id,tenant_id,auth_user_id,expires_at)
              values (repeat('e',64),${literal(providerId)},${literal(target)},${literal(owner)},now()+interval '5 minutes');`, /oidc_tenant_inactive/);
			await denied(`update public.oidc_auth_requests set consumed_at=now() where state_hash=${literal(requestHash)};`, /oidc_tenant_inactive/);
			await sql(`update public.tenant_legal_holds set released_at=now(),released_by=${literal(owner)},
              release_reason='Fixture release after hold assertion' where id=${literal(hold)};`);
			assert.equal(await sql(`select retention_days from public.tenant_offboarding_phase_receipts
              where run_id=${literal(run)} and phase='oidc_providers';`), "2", "provider cascade cannot shorten identity retention");
			let state;
			for (let attempt = 0; attempt < 100; attempt++) {
				state = await rpc(`public.run_tenant_offboarding_batch(${literal(run)},100)`);
				if (state.action === "invalidate_cache") await rpc(`public.ack_tenant_offboarding_cache(${literal(run)},array['fixture-cache'],0)`);
				if (state.status === "waiting_retention") break;
			}
			assert.equal(state.status, "waiting_retention");
			assert.equal(await sql(`select count(*) from public.oidc_providers where tenant_id=${literal(target)};`), "1");
			assert.equal(await sql(`select count(*) from public.oidc_identities where tenant_id=${literal(target)};`), "4");
			await sql(`update public.tenant_offboarding_phase_receipts set eligible_at=now()
              where run_id=${literal(run)} and status <> 'completed';`);
			for (let attempt = 0; attempt < 100; attempt++) {
				state = await rpc(`public.run_tenant_offboarding_batch(${literal(run)},100)`);
				if (state.action === "invalidate_cache") await rpc(`public.ack_tenant_offboarding_cache(${literal(run)},array['fixture-cache'],0)`);
				if (state.status === "completed") break;
			}
			assert.equal(state.status, "completed");
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(target)};`), "0",
				"SCIM mapping cleanup must not recreate administrative logs after their completed purge");
			for (const table of tables) assert.equal(await sql(`select count(*) from public.${table} where tenant_id=${literal(target)};`), "0", table);
			assert.equal(await sql(`select count(*) from public.tenant_offboarding_phase_receipts where run_id=${literal(run)} and phase like 'oidc_%' and status='completed';`), "6");
			assert.equal(await sql(`select count(*) from public.oidc_providers where id=${literal(neighborProvider)};`), "1");
			await denied(`insert into public.oidc_providers(tenant_id,kind,display_name,issuer,client_id,token_auth_method)
              values (${literal(target)},'generic','Late provider','https://idp.example.invalid','late','none');`, /oidc_tenant_inactive/);
		});
	} finally { await docker(["rm", "-f", container]); }
});
