// Verify API-key lifecycle rejection using only a new loopback fixture.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { randomBytes } from "node:crypto";
const dir = resolve(process.argv[2]);
const manifest = JSON.parse(readFileSync(join(dir, "deployment.json"), "utf8"));
const base = new URL(manifest.supabase_url);
assert.ok(manifest.development && ["localhost", "127.0.0.1"].includes(base.hostname));
const env = Object.fromEntries(readFileSync(join(dir, ".env"), "utf8").split(/\r?\n/).filter(s => s.includes("=")).map(s => [s.slice(0, s.indexOf("=")), s.slice(s.indexOf("=") + 1)]));
async function request(path, body, token = env.SERVICE_ROLE_KEY, method = body === undefined ? "GET" : "POST", headers = {}) {
  const response = await fetch(new URL(path, base), { method, headers: { apikey: env.ANON_KEY, Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...headers }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(15000) });
  return { status: response.status, data: await response.json().catch(() => ({})) };
}
const email = `reputation-audit-${randomBytes(8).toString("hex")}@example.test`, password = randomBytes(32).toString("hex");
const user = await request("/auth/v1/admin/users", { email, password, email_confirm: true }); assert.equal(user.status, 200);
const login = await request("/auth/v1/token?grant_type=password", { email, password }, env.ANON_KEY); assert.equal(login.status, 200);
const jwt = login.data.access_token;
const created = await request("/rest/v1/rpc/create_team_tenant", { p_name: "Reputation lifecycle audit fixture", p_plan: "free" }, jwt); assert.equal(created.status, 200);
const tenant = created.data.id, headers = { "X-AIDR-Tenant-ID": tenant };
const issued = await request("/functions/v1/api-keys", { action: "create", label: "lifecycle-audit" }, jwt, "POST", headers); assert.equal(issued.status, 200);
const key = issued.data.api_key, observations = [];
async function observe(state) {
  for (const [endpoint, body] of [["url-check", { queries: [{ key: { "url-like": "https://reputation-audit.example.test/" } }] }], ["file-check", { requests: [{ key: { sha256: "a".repeat(64) } }] }]]) {
    const response = await request(`/functions/v1/${endpoint}`, body, key);
    observations.push({ state, endpoint, status: response.status, expected: state === "active" ? 200 : 403 });
  }
}
try {
  await observe("active");
  assert.equal((await request(`/rest/v1/tenants?id=eq.${tenant}`, { status: "suspended" }, undefined, "PATCH")).status, 204);
  await observe("tenant suspended");
  assert.equal((await request(`/rest/v1/tenants?id=eq.${tenant}`, { status: "active" }, undefined, "PATCH")).status, 204);
  assert.equal((await request(`/rest/v1/tenant_members?tenant_id=eq.${tenant}&user_id=eq.${user.data.id}`, { expires_at: new Date(Date.now() - 60000).toISOString() }, undefined, "PATCH")).status, 204);
  await observe("membership expired");
} finally {
  assert.equal((await request(`/rest/v1/api_keys?tenant_id=eq.${tenant}`, { revoked: true }, undefined, "PATCH")).status, 204);
  assert.equal((await request(`/rest/v1/tenants?id=eq.${tenant}`, { status: "closed" }, undefined, "PATCH")).status, 204);
}
assert.ok(observations.filter(row => row.state === "active").every(row => row.status === 200));
const findings = observations.filter(row => row.state !== "active" && row.status === 200);
const passed = observations.every(row => row.status === row.expected);
const evidence = { checked_at: new Date().toISOString(), passed, finding_reproduced: findings.length > 0, observations, scope: "New isolated local fixture only; issued key revoked and fixture tenant closed. No cross-tenant read demonstrated." };
writeFileSync("docs/production-readiness/evidence/2026-09-12-reputation-lifecycle-fix.json", JSON.stringify(evidence, null, 2) + "\n");
console.log(JSON.stringify({ passed, accepted_after_lifecycle_change: findings.length }));
if (!passed) process.exitCode = 1;
