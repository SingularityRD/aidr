// Run only against a fully migrated, disposable local Supabase DB.
// The committed race fixture remains until that DB is reset/stopped: retained
// customer audit records intentionally prevent direct tenant hard-deletion.
// AIDR_TEST_DISPOSABLE_DB=1 AIDR_RLS_TEST_DB_CONTAINER=supabase_db_aidr node scripts/events-seat-admission-postgres.mjs
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

const container = process.env.AIDR_RLS_TEST_DB_CONTAINER;
assert.equal(process.env.AIDR_TEST_DISPOSABLE_DB, "1", "confirm a disposable database");
assert.match(container ?? "", /^supabase_db_[A-Za-z0-9_.-]+$/, "name a disposable Supabase database container");
const args = ["exec", "-i", "-e", "PGOPTIONS=-c statement_timeout=15000 -c lock_timeout=12000",
	container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"];
const quote = (value) => `'${String(value).replaceAll("'", "''")}'`;
const user = randomUUID();
const marker = randomUUID().replaceAll("-", "");
let created = false;

function sql(statement) {
	const result = spawnSync("docker", args, { input: statement, encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024 });
	if (result.error) throw result.error;
	assert.equal(result.status, 0, result.stderr);
	return result.stdout.trim();
}

const admissionMode = sql("select mode from app.tenant_admission_config where singleton;");
sql("update app.tenant_admission_config set mode='pilot' where singleton;");

function sqlAsync(statement) {
	return new Promise((resolve, reject) => {
		const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"] });
		let stdout = "", stderr = "";
		const timer = setTimeout(() => child.kill(), 20_000);
		child.stdout.on("data", (chunk) => { stdout += chunk; });
		child.stderr.on("data", (chunk) => { stderr += chunk; });
		child.stdin.on("error", () => {});
		child.once("error", (error) => { clearTimeout(timer); reject(error); });
		child.once("close", (code) => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
		child.stdin.end(statement);
	});
}

function session() {
	const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"] });
	let output = "", errors = "", pending;
	child.stdout.on("data", (chunk) => {
		output += chunk;
		if (!pending) return;
		const end = output.indexOf(`${pending.marker}\n`);
		if (end < 0) return;
		const value = output.slice(0, end).trim();
		output = output.slice(end + pending.marker.length + 1);
		clearTimeout(pending.timer);
		pending.resolve(value);
		pending = undefined;
	});
	child.stderr.on("data", (chunk) => { errors += chunk; });
	child.stdin.on("error", () => {});
	const closed = new Promise((resolve) => child.once("close", resolve));
	return {
		query(statement) {
			assert.equal(pending, undefined, "session query already pending");
			return new Promise((resolve, reject) => {
				const marker = `aidr_end_${randomUUID().replaceAll("-", "")}`;
				const timer = setTimeout(() => {
					pending = undefined;
					child.kill();
					reject(new Error(`psql query timed out: ${errors}`));
				}, 20_000);
				pending = { marker, timer, resolve, reject };
				child.stdin.write(`${statement}\n\\echo ${marker}\n`);
			});
		},
		async close() { if (!child.killed) child.stdin.end("\\q\n"); await closed; },
	};
}

async function waitForLock(application) {
	for (let attempt = 0; attempt < 160; attempt++) {
		if (sql(`select exists(select 1 from pg_stat_activity
		  where application_name=${quote(application)} and state='active' and wait_event_type='Lock');`) === "t") return;
		await delay(25);
	}
	throw new Error("event writer did not wait for the entitlement reduction");
}

let gate;
let writer;
try {
	sql(`begin;
	  insert into auth.users(id,email,aud,role,instance_id,raw_app_meta_data,raw_user_meta_data)
	  values (${quote(user)},${quote(`event-seat-${marker}@example.invalid`)},'authenticated','authenticated',
	    '00000000-0000-0000-0000-000000000000','{}'::jsonb,'{}'::jsonb);
	  insert into public.pilot_applications(user_id,tenant_id,status) values (${quote(user)},${quote(user)},'approved');
	  update public.entitlements set included_agents=1,extra_agents=0 where tenant_id=${quote(user)};
	  commit;`);
	created = true;
	const agent = sql(`select agent_id from public.register_agent_for_ingest(${quote(user)},'iid-${marker}',null,null,${quote(user)});`);
	assert.match(agent, /^[0-9a-f-]{36}$/i, "agent registration failed");
	sql(`insert into public.events(user_id,tenant_id,agent_id,event_id,type,payload)
	  values (${quote(user)},${quote(user)},${quote(agent)},${quote(`before-${marker}`)},'runtime_verdict','{}'::jsonb);`);
	gate = session();
	await gate.query(`begin; update public.entitlements set included_agents=0 where tenant_id=${quote(user)};`);
	const application = `aidr_event_seat_${marker}`;
	writer = sqlAsync(`set application_name=${quote(application)};
	  insert into public.events(user_id,tenant_id,agent_id,event_id,type,payload)
	  values (${quote(user)},${quote(user)},${quote(agent)},${quote(`after-${marker}`)},'runtime_verdict','{}'::jsonb);`);
	void writer.catch(() => undefined);
	await waitForLock(application);
	await gate.query("commit;");
	const result = await writer;
	assert.notEqual(result.code, 0, "new event inserted after the seat reduction");
	assert.match(result.stderr, /agent_seat_not_authorized/, "wrong event rejection");
	assert.equal(sql(`select count(*) from public.events where tenant_id=${quote(user)};`), "1");
	sql(`do $$ begin
	  begin
	    insert into public.events(user_id,tenant_id,agent_id,event_id,type,payload)
	    values (${quote(user)},${quote(user)},${quote(agent)},${quote(`before-${marker}`)},'runtime_verdict','{}'::jsonb)
	    on conflict (tenant_id,event_id) do nothing;
	  exception when sqlstate '42501' then
	    if sqlerrm = 'agent_seat_not_authorized' then return; end if;
	    raise;
	  end;
	  raise exception 'duplicate_event_was_allowed_after_seat_reduction';
	end $$;`);
	assert.equal(sql(`select count(*) from public.events where tenant_id=${quote(user)};`), "1");
	console.log("PASS event insert waits for committed seat reduction and denies new or duplicate telemetry");
} finally {
	try {
		if (gate) {
			await gate.query("rollback;").catch(() => undefined);
			await gate.close();
		}
		if (writer) await writer.catch(() => undefined);
		if (created) {
			assert.equal(sql(`begin;
			  do $$ begin
			    begin
			      delete from public.tenants where created_by=${quote(user)} and kind='team';
			    exception when sqlstate '23503' then
			      return;
			    end;
			    raise exception 'tenant_hard_delete_was_allowed';
			  end $$;
			  rollback;
			  select exists(select 1 from public.tenants
			    where created_by=${quote(user)} and kind='team');`), "t",
			"retained audit did not block direct tenant hard-delete");
			console.log("PASS disposable race fixture retained until database reset");
		}
	} finally {
		sql(`update app.tenant_admission_config set mode=${quote(admissionMode)} where singleton;`);
	}
}
