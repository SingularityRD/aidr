#!/usr/bin/env node
// Destructive synthetic Auth lifecycle probe. Only the isolated t18 development
// project may be targeted; tear its Compose volumes down after the run.
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const dir = resolve(process.argv[2] ?? "");
const manifest = JSON.parse(readFileSync(join(dir, "deployment.json"), "utf8"));
const base = new URL(manifest.supabase_url);
if (!manifest.development || !/^aidr-t18-auth-[a-z0-9-]+$/.test(manifest.project_name)
  || !["localhost", "127.0.0.1"].includes(base.hostname) || base.protocol !== "http:") {
  throw new Error("Auth deletion probe requires its own isolated loopback t18 project");
}
const env = Object.fromEntries(readFileSync(join(dir, ".env"), "utf8").split(/\r?\n/)
  .filter(line => /^[A-Z][A-Z0-9_]*=/.test(line))
  .map(line => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]));
assert.ok(env.SERVICE_ROLE_KEY);
const suffix = randomBytes(8).toString("hex");
const email = `t18-auth-${suffix}@example.invalid`;
const id = () => randomUUID();
const term = { version: "t18-test", sha256: "a".repeat(64) };
const privacy = { version: "t18-test", sha256: "b".repeat(64) };
const legal = { p_terms: term, p_privacy: privacy };

function query(statement) {
  const result = spawnSync("docker", ["compose", "--project-directory", dir,
    "-f", join(dir, "compose.yml"), "exec", "-T", "db", "psql", "-X", "-w",
    "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres", "-q", "-At", "-c", statement],
  { encoding: "utf8", timeout: 30_000 });
  if (result.error || result.status !== 0) throw new Error(`isolated database query failed (${result.status ?? "spawn"})`);
  return result.stdout.trim();
}

async function call(path, method = "GET", body) {
  const response = await fetch(new URL(path, base), {
    method, headers: { apikey: env.SERVICE_ROLE_KEY,
      Authorization: `Bearer ${env.SERVICE_ROLE_KEY}`, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(30_000),
  });
  const data = await response.json().catch(() => null);
  return { status: response.status, data };
}
async function createUser(address) {
  const response = await call("/auth/v1/admin/users", "POST", {
    email: address, password: randomBytes(32).toString("hex"), email_confirm: true,
  });
  assert.equal(response.status, 200, `Auth Admin create returned ${response.status}`);
  assert.match(response.data?.id ?? "", /^[0-9a-f-]{36}$/i);
  return response.data.id;
}
function createTeam(userId, teamId) {
  query(`insert into public.tenants(id,name,kind,created_by)
    values ('${teamId}','T18 synthetic','team','${userId}');
    insert into public.teams(id,tenant_id,name,plan)
    values ('${teamId}','${teamId}','T18 synthetic','free');
    insert into public.tenant_members(tenant_id,user_id,role)
    values ('${teamId}','${userId}','owner');
    insert into public.team_members(team_id,tenant_id,user_id,role)
    values ('${teamId}','${teamId}','${userId}','owner');`);
}
async function trial(userId, teamId) {
  return call("/rest/v1/rpc/start_verified_trial", "POST", {
    p_user_id: userId, p_tenant_id: teamId, ...legal,
  });
}
async function main() {
  assert.equal(query("select mode from app.tenant_admission_config where singleton"), "unconfigured");
  query("select public.configure_tenant_admission_mode('cloud')");
  query(`select public.configure_ga_legal_documents('t18-test','${term.sha256}',
    'https://example.invalid/terms','t18-test','${privacy.sha256}',
    'https://example.invalid/privacy','isolated-http-probe')`);
  const original = await createUser(email), originalTeam = id();
  createTeam(original, originalTeam);
  let response = await trial(original, originalTeam);
  assert.equal(response.status, 200, `first trial HTTP ${response.status}`);
  assert.equal(response.data?.status, "started");
  response = await call(`/auth/v1/admin/users/${original}`, "DELETE", { should_soft_delete: true });
  assert.equal(response.status, 200, `GoTrue soft-delete HTTP ${response.status}`);
  assert.equal(query(`select deleted_at is not null from auth.users where id='${original}'`), "t");
  assert.equal(query(`select raw_app_meta_data ? 'aidr_trial' from auth.users where id='${original}'`), "f");
  console.log("PASS GoTrue Auth Admin soft-delete HTTP 200; account tombstoned");

  // GoTrue may retain the tombstone, but it must permit a new account for the
  // former email without granting another active trial.
  const replacement = await createUser(email), replacementTeam = id();
  createTeam(replacement, replacementTeam);
  response = await trial(replacement, replacementTeam);
  assert.equal(response.status, 200, `repeat trial HTTP ${response.status}`);
  assert.equal(response.data?.status, "ineligible");
  console.log("PASS same-email new account denied a second active trial");

  // The owner guard requires all synthetic owner tenants to be closing before
  // GoTrue can hard-delete the tombstoned user. Revoke its trial admission
  // first: a closing tenant must not retain an active admission grant.
  query(`update public.tenant_admissions
    set revoked_at=greatest(starts_at,clock_timestamp()), updated_at=clock_timestamp()
    where owner_user_id='${original}' and revoked_at is null`);
  query(`update public.tenants set status='closing'
    where id in (select tenant_id from public.tenant_members where user_id='${original}')`);
  response = await call(`/auth/v1/admin/users/${original}`, "DELETE", { should_soft_delete: false });
  assert.equal(response.status, 200, `GoTrue hard-delete HTTP ${response.status}`);
  assert.equal(query(`select count(*) from auth.users where id='${original}'`), "0");
  response = await trial(replacement, replacementTeam);
  assert.equal(response.data?.status, "ineligible");
  console.log("PASS GoTrue hard-delete HTTP 200; repeat trial still denied");

  const digestCount = query("select count(*) from app.ga_trial_subjects");
  assert.equal(digestCount, "1");
  query("update app.ga_trial_subjects set expires_at=clock_timestamp()-interval '1 second'");
  response = await call("/rest/v1/rpc/purge_expired_ga_trial_subjects", "POST", {
    p_limit: 10, p_apply: false,
  });
  assert.equal(response.status, 200);
  assert.equal(response.data?.eligible, 1);
  assert.equal(response.data?.deleted, 0);
  response = await call("/rest/v1/rpc/purge_expired_ga_trial_subjects", "POST", {
    p_limit: 10, p_apply: true,
  });
  assert.equal(response.status, 200);
  assert.equal(response.data?.deleted, 1);
  assert.equal(response.data?.remaining, 0);
  response = await trial(replacement, replacementTeam);
  assert.equal(response.status, 200);
  assert.equal(response.data?.status, "started");
  console.log("PASS service-only bounded purge; after expiry, new 14-day term can start");

  query("delete from app.ga_trial_subject_key");
  const third = await createUser(`t18-third-${suffix}@example.invalid`), thirdTeam = id();
  createTeam(third, thirdTeam);
  response = await trial(third, thirdTeam);
  assert.ok(response.status >= 400, `missing-key trial unexpectedly HTTP ${response.status}`);
  assert.equal(query(`select count(*) from public.tenant_admissions where tenant_id='${thirdTeam}'`), "0");
  console.log("PASS missing HMAC key rejects trial without an admission");
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
