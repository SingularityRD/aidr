#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";

const dir = resolve(process.argv[2] || ".aidr-deploy");
const manifest = JSON.parse(readFileSync(join(dir, "deployment.json"), "utf8"));
const base = new URL(manifest.supabase_url);
assert.ok(manifest.development && ["localhost", "127.0.0.1"].includes(base.hostname));
const credentials = JSON.parse(readFileSync(join(dir, "private-ui-fixture/login.json"), "utf8"));
const env = Object.fromEntries(readFileSync(join(dir, ".env"), "utf8").split(/\r?\n/).filter((s) => s.includes("=")).map((s) => [s.slice(0, s.indexOf("=")), s.slice(s.indexOf("=") + 1)]));
const checks = [];
async function request(path, token, body, method = body === undefined ? "GET" : "POST", headers = {}) {
  const response = await fetch(new URL(path, base), { method, headers: { apikey: env.ANON_KEY, Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...headers }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(30000) });
  const text = await response.text(); let data; try { data = JSON.parse(text); } catch { data = {}; } return { status: response.status, data };
}
const login = await request("/auth/v1/token?grant_type=password", env.ANON_KEY, { email: credentials.email, password: credentials.password }); assert.equal(login.status,200);
const jwt = login.data.access_token; const tenant = credentials.tenant_id;
const manage = (body) => request("/functions/v1/policy-management", jwt, { tenant_id: tenant, ...body });
const baseline = (await manage({ action: "read" })).data;
assert.ok(baseline.version > 0);
const latestRevision = (await manage({ action: "history" })).data.revisions[0]?.version;
assert.ok(Number.isSafeInteger(latestRevision) && latestRevision >= baseline.version);
async function agent() {
  const iid = `rollout-${randomBytes(8).toString("hex")}`;
  const device = (await request("/functions/v1/device-start", env.ANON_KEY, {})).data;
  const lookup = await request("/functions/v1/device-verify", jwt, { action: "lookup", user_code: device.user_code }); assert.equal(lookup.status,200);
  assert.equal((await request("/functions/v1/device-verify", jwt, { action: "authorize", user_code: device.user_code, device_session_id: lookup.data.device.device_session_id, confirmed: true })).status,200);
  await new Promise((done) => setTimeout(done,(device.interval_seconds+1)*1000));
  const exchange = (await request("/functions/v1/device-poll", jwt,{device_code:device.device_code})).data;
  const enrolled = await request("/functions/v1/enroll",exchange.enrollment_token,{iid,agent_runtime:"claude-code"}); assert.equal(enrolled.status,200);
  const rows = await request(`/rest/v1/agents?tenant_id=eq.${tenant}&iid=eq.${iid}&select=id`,jwt); assert.equal(rows.data.length,1);
  return {id:rows.data[0].id,iid,key:enrolled.data.api_key};
}
const a=await agent(),b=await agent();
checks.push("two agents enrolled with individual server-bound keys");
const stage=await manage({action:"stage",expected_version:baseline.version,expected_revision_version:latestRevision,policy:{command_default:"deny",mcp_unknown:"deny"},agent_ids:[a.id]}); assert.equal(stage.status,200); assert.ok(stage.data.staged);
assert.equal((await manage({action:"stage",expected_version:baseline.version,expected_revision_version:latestRevision,policy:{command_default:"allow"},agent_ids:[a.id]})).status,409);
checks.push("stale targeted stage cannot silently replace another operator's assignment");
const pa=(await request("/functions/v1/policy",a.key)).data,pb=(await request("/functions/v1/policy",b.key)).data;
assert.equal(Number(pa.policy_version),stage.data.version); assert.equal(Number(pb.policy_version),baseline.version);
assert.equal(pa.runtime_policy.command_default,"deny"); assert.deepEqual(pb.runtime_policy,baseline.policy);
checks.push("targeted stage reaches only selected agent; baseline stays active for others");
const endpoint=join(dir,`rollout-hook-${randomBytes(6).toString("hex")}`);mkdirSync(join(endpoint,".singularity-aidr"),{recursive:true,mode:0o700});
writeFileSync(join(endpoint,".singularity-aidr/config.json"),JSON.stringify({mode:"local",auth:{api_key:a.key},control_plane:{enabled:true,endpoint:`${base.origin}/functions/v1`,allow_insecure_loopback:true,remote_policy_required:true,timeout_seconds:2},logging:{enabled:false}}),{mode:0o600});
writeFileSync(join(endpoint,".singularity-aidr/installation-id"),a.iid,{mode:0o600});
const hook=spawnSync(process.execPath,[resolve("packages/claude-code/dist/pre-tool-use.cjs")],{input:JSON.stringify({hook_event_name:"PreToolUse",session_id:"rollout-proof",cwd:endpoint,tool_name:"mcp__unknown__read",tool_input:{}}),encoding:"utf8",timeout:20000,env:{...process.env,HOME:endpoint,USERPROFILE:endpoint}});
assert.equal(hook.status,0);assert.equal(JSON.parse(hook.stdout).hookSpecificOutput?.permissionDecision,"deny");
const loaded=(await manage({action:"adoption"})).data.agents.find(row=>row.id===a.id);assert.equal(loaded.loaded_version,stage.data.version);assert.equal(loaded.state,"current");
checks.push("built Claude hook enforces targeted policy and reports its loaded revision");
assert.equal((await request("/functions/v1/policy-ack",a.key,{version:stage.data.version,policy_sha256:pa.policy_sha256})).status,200);
assert.equal((await request("/functions/v1/policy-ack",a.key,{version:stage.data.version,policy_sha256:"0".repeat(64)})).status,409);
assert.equal((await request("/functions/v1/policy-ack",b.key,{version:stage.data.version,policy_sha256:pa.policy_sha256})).status,409);
checks.push("policy loading receipt requires exact revision hash and assigned version");
const adoption=(await manage({action:"adoption"})).data.agents;
assert.equal(adoption.find(row=>row.id===a.id).state,"current");assert.equal(adoption.find(row=>row.id===b.id).state,"unknown");
checks.push("fleet view distinguishes reported current policy from missing receipt");
assert.equal((await request("/functions/v1/ingest",a.key,{iid:b.iid,events:[],aidr_version:"test"})).status,403);
const keyHash=createHash("sha256").update(a.key).digest("hex");
assert.equal((await request(`/rest/v1/api_keys?key_hash=eq.${keyHash}`,jwt,{agent_id:b.id},"PATCH")).status,403);
checks.push("bound key cannot impersonate another agent or change its binding");
const malformedStage=await manage({action:"stage",expected_version:baseline.version,expected_revision_version:stage.data.version,policy:{command_default:"deny"},agent_ids:[crypto.randomUUID()]});assert.equal(malformedStage.status,400);
checks.push("unknown or foreign rollout targets refused atomically");
assert.equal((await manage({action:"stage",expected_version:baseline.version,policy:{command_default:"deny"},agent_ids:[a.id]})).status,400);
const nextStage=await manage({action:"stage",expected_version:baseline.version,expected_revision_version:stage.data.version,policy:{command_default:"deny",mcp_unknown:"deny"},agent_ids:[a.id]});
assert.equal(nextStage.status,200);assert.ok(nextStage.data.version>stage.data.version);
assert.equal(Number((await request("/functions/v1/policy",a.key)).data.policy_version),nextStage.data.version);
assert.equal(Number((await request("/functions/v1/policy",b.key)).data.policy_version),baseline.version);
checks.push("missing revision precondition is refused and a refreshed canary stage advances only its target");
const rollback=await manage({action:"restore",expected_version:baseline.version,target_version:baseline.version});assert.equal(rollback.status,200);assert.ok(rollback.data.version>stage.data.version);
for(const item of[a,b]){const policy=(await request("/functions/v1/policy",item.key)).data;assert.equal(Number(policy.policy_version),rollback.data.version);assert.deepEqual(policy.runtime_policy,baseline.policy);}
checks.push("rollback republishes baseline as a newer version and clears targeted assignments");
const promote=await manage({action:"restore",expected_version:rollback.data.version,target_version:stage.data.version});assert.equal(promote.status,200);
const all=(await request("/functions/v1/policy",b.key)).data;assert.equal(Number(all.policy_version),promote.data.version);assert.equal(all.runtime_policy.command_default,"deny");
checks.push("reviewed staged version can be promoted to all agents");
assert.equal((await manage({action:"restore",expected_version:rollback.data.version,target_version:baseline.version})).status,409);
checks.push("stale operator restore conflicts instead of overwriting newer publication");
const history=(await manage({action:"history"})).data.revisions;assert.ok(history.some(row=>row.version===stage.data.version));assert.ok(history.some(row=>row.version===baseline.version));
checks.push("immutable revision history retains baseline and staged policy");
// Return the fixture tenant to its original behavior using the supported rollback.
assert.equal((await manage({action:"restore",expected_version:promote.data.version,target_version:baseline.version})).status,200);
writeFileSync(join(dir,"policy-rollout-evidence.json"),JSON.stringify({passed:true,checked_at:new Date().toISOString(),checks,scope:"Isolated HTTP/database integration; receipts are agent-reported, not platform attestation."},null,2));
console.log(`${checks.length} policy rollout checks passed.`);
