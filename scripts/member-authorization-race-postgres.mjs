// Run only against a fully migrated, named disposable local Supabase DB:
//   AIDR_TEST_DISPOSABLE_DB=1 AIDR_RLS_TEST_DB_CONTAINER=supabase_db_aidr node scripts/member-authorization-race-postgres.mjs
// Separate transactions need committed synthetic fixtures. They are retained
// in this disposable DB until its planned reset/stop; never run on a live DB.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

const container = process.env.AIDR_RLS_TEST_DB_CONTAINER;
assert.equal(process.env.AIDR_TEST_DISPOSABLE_DB, "1", "confirm a disposable database");
assert.match(container ?? "", /^supabase_db_[A-Za-z0-9_.-]+$/, "name a disposable Supabase DB container");
const args = ["exec", "-i", "-e", "PGPASSWORD=postgres", "-e", "PGOPTIONS=-c statement_timeout=15000 -c lock_timeout=12000",
  container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "supabase_admin", "-d", "postgres"];
const [owner, admin, member, tenant] = Array.from({ length: 4 }, () => randomUUID());
const marker = randomUUID().replaceAll("-", "");
const issuedAt = Math.floor(Date.now() / 1000);
const quote = value => `'${String(value).replaceAll("'", "''")}'`;
assert(!process.env.DOCKER_HOST || /^(unix:|npipe:)/.test(process.env.DOCKER_HOST), "refusing a remote Docker host");
const context = spawnSync("docker", ["context", "inspect"], { encoding: "utf8", timeout: 10_000 });
if (context.error) throw context.error;
assert.equal(context.status, 0, context.stderr);
assert.match(JSON.parse(context.stdout)[0]?.Endpoints?.docker?.Host ?? "", /^(unix:|npipe:)/,
  "refusing a remote Docker context");

function sql(statement) {
  const result = spawnSync("docker", args, { input: statement, encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024 });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `PostgreSQL regression failed:\n${result.stdout}\n${result.stderr}`);
  return result.stdout.trim();
}

function session() {
  const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"] });
  let output = "", errors = "", pending, exited = false;
  child.stdout.on("data", chunk => {
    output += chunk;
    if (!pending) return;
    const at = output.indexOf(`${pending.marker}\n`);
    if (at < 0) return;
    const value = output.slice(0, at).trim();
    output = output.slice(at + pending.marker.length + 1);
    clearTimeout(pending.timer);
    pending.resolve(value);
    pending = undefined;
  });
  child.stderr.on("data", chunk => { errors += chunk; });
  child.stdin.on("error", () => {});
  const closed = new Promise(resolve => child.once("close", code => {
    exited = true;
    if (pending) {
      clearTimeout(pending.timer);
      pending.reject(new Error(`psql exited ${code}: ${errors}`));
      pending = undefined;
    }
    resolve();
  }));
  child.once("error", error => {
    if (pending) {
      clearTimeout(pending.timer);
      pending.reject(error);
      pending = undefined;
    }
  });
  return {
    query(statement) {
      assert.equal(exited, false, "psql session already exited");
      assert.equal(pending, undefined, "session query already pending");
      return new Promise((resolve, reject) => {
        const end = `aidr_end_${randomUUID().replaceAll("-", "")}`;
        const timer = setTimeout(() => {
          pending = undefined;
          child.kill();
          reject(new Error(`psql query timed out: ${errors}`));
        }, 20_000);
        pending = { marker: end, timer, resolve, reject };
        child.stdin.write(`${statement}\n\\echo ${end}\n`);
      });
    },
    async close() { if (!exited && !child.killed) child.stdin.end("rollback;\n\\q\n"); await closed; },
  };
}

const identity = (user, aal) => `
select set_config('request.jwt.claim.sub', '${user}', false);
select set_config('request.jwt.claims', '{"sub":"${user}","role":"authenticated","aal":"${aal}","iat":${issuedAt}}', false);
set session authorization authenticator;
set role authenticated;`;

async function waitForBlockedActor(application, blockerPid) {
  let last;
  for (let attempt = 0; attempt < 160; attempt++) {
    last = JSON.parse(sql(`select coalesce((select json_build_object(
      'state', state, 'wait_type', wait_event_type,
      'blockers', pg_blocking_pids(pid)) from pg_stat_activity
      where application_name=${quote(application)}), '{}');`));
    if (last.state === "active" && last.wait_type === "Lock" && last.blockers?.includes(blockerPid)) return;
    await delay(25);
  }
  assert.fail(`member mutation never waited on revocation row lock: ${JSON.stringify(last)}`);
}

function assertMemberUntouched() {
  assert.equal(sql(`select (select role from public.team_members where tenant_id='${tenant}' and user_id='${member}') = 'member'
    and (select role from public.tenant_members where tenant_id='${tenant}' and user_id='${member}') = 'member'
    and not exists (select 1 from public.admin_audit_logs where tenant_id='${tenant}' and target_user_id='${member}'
      and action in ('team.member.role_changed','team.member.removed'))
    and not exists (select 1 from public.audit_logs where tenant_id='${tenant}'
      and action in ('team.member.role_changed','team.member.removed')
      and verdict->>'target_user_id'='${member}');`), "t", "revoked admin changed member or wrote audit");
}

async function race(revoke, attempted, label) {
  const ownerSession = session(), adminSession = session();
  let blocked;
  try {
    await ownerSession.query(`${identity(owner, "aal2")} set application_name=${quote(`aidr_owner_${marker}_${label}`)}; begin;`);
    const ownerPid = Number(await ownerSession.query("select pg_backend_pid();"));
    assert.ok(Number.isInteger(ownerPid) && ownerPid > 0);
    assert.equal(await ownerSession.query(revoke), "1", `${label}: owner revocation changed wrong row count`);

    // PostgreSQL truncates application_name at 63 bytes.
    const application = `aidr_m_${marker}_${label.slice(0, 12)}`;
    await adminSession.query(`${identity(admin, "aal1")} set application_name=${quote(application)}; begin;`);
    blocked = adminSession.query(`do $$ declare v_rows integer; begin
      begin
        ${attempted}
        get diagnostics v_rows = row_count;
        if v_rows <> 0 then raise exception 'revoked admin mutated % member rows', v_rows; end if;
      exception when insufficient_privilege then null;
      end;
    end $$;
    select 'REVOKED_ACTOR_DENIED';`);
    void blocked.catch(() => undefined);
    await waitForBlockedActor(application, ownerPid);
    await ownerSession.query("commit;");
    assert.match(await blocked, /REVOKED_ACTOR_DENIED/);
    await adminSession.query("rollback;");
    assertMemberUntouched();
    console.log(`PASS ${label}: revocation held a row lock, concurrent member action waited, then denied`);
  } finally {
    if (blocked) await blocked.catch(() => undefined);
    await Promise.all([ownerSession.close(), adminSession.close()]);
  }
}

assert.equal(sql(`select count(*) from pg_trigger where tgrelid='public.team_members'::regclass
  and not tgisinternal and tgname in ('team_members_owner_transition_audit',
    'team_members_member_role_audit', 'team_members_member_removal_audit',
    'team_members_identity_immutable');`), "4", "membership hardening migrations 33/38/39/43 are required");

sql(`begin;
  insert into auth.users(id,email,aud,role,instance_id,raw_app_meta_data,raw_user_meta_data)
  values ('${owner}','race-owner-${marker}@example.invalid','authenticated','authenticated','00000000-0000-0000-0000-000000000000','{}','{}'),
         ('${admin}','race-admin-${marker}@example.invalid','authenticated','authenticated','00000000-0000-0000-0000-000000000000','{}','{}'),
         ('${member}','race-member-${marker}@example.invalid','authenticated','authenticated','00000000-0000-0000-0000-000000000000','{}','{}');
  insert into public.tenants(id,name,kind,created_by) values ('${tenant}','Race ${marker}','team','${owner}');
  insert into public.teams(id,tenant_id,name,plan) values ('${tenant}','${tenant}','Race ${marker}','free');
  insert into public.team_members(team_id,tenant_id,user_id,role) values
    ('${tenant}','${tenant}','${owner}','owner'),
    ('${tenant}','${tenant}','${admin}','admin'),
    ('${tenant}','${tenant}','${member}','member');
  commit;`);

// Prove the AAL1 admin action succeeds without revocation; both probes roll
// back the member mutation and its paired audit before the actual races.
for (const attempt of [
  `update public.team_members set role='viewer' where tenant_id='${tenant}' and user_id='${member}';`,
  `delete from public.team_members where tenant_id='${tenant}' and user_id='${member}';`,
]) sql(`begin; ${identity(admin, "aal1")}
  do $$ declare v_rows integer; begin
    ${attempt} get diagnostics v_rows = row_count;
    if v_rows <> 1 then raise exception 'baseline admin action changed % rows', v_rows; end if;
  end $$;
  rollback;`);
assertMemberUntouched();

await race(`update public.team_members set role='member' where tenant_id='${tenant}' and user_id='${admin}' returning 1;`,
  `update public.team_members set role='viewer' where tenant_id='${tenant}' and user_id='${member}';`,
  "demotion_vs_role_update");
assert.equal(sql(`select role from public.tenant_members where tenant_id='${tenant}' and user_id='${admin}';`), "member");

// Restore the synthetic admin solely to exercise the second race ordering.
sql(`begin; update public.team_members set role='admin' where tenant_id='${tenant}' and user_id='${admin}'; commit;`);
await race(`delete from public.team_members where tenant_id='${tenant}' and user_id='${admin}' returning 1;`,
  `delete from public.team_members where tenant_id='${tenant}' and user_id='${member}';`,
  "removal_vs_member_delete");
assert.equal(sql(`select count(*) from public.tenant_members where tenant_id='${tenant}' and user_id='${admin}';`), "0");
console.log(`Member authorization races passed on disposable DB; synthetic tenant ${tenant} remains only until reset/stop.`);
