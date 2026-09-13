#!/usr/bin/env node
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const deployment = resolve(process.argv[2] || ".aidr-deploy");
const manifest = JSON.parse(readFileSync(join(deployment, "deployment.json"), "utf8"));
const base = new URL(manifest.supabase_url);
assert.ok(manifest.development && ["localhost", "127.0.0.1"].includes(base.hostname), "Only isolated loopback development installations may receive fixtures");
const dir = mkdtempSync(join(deployment, "customer-test-"));
for (const file of ["deployment.json", ".env"]) copyFileSync(join(deployment, file), join(dir, file));
const env = Object.fromEntries(readFileSync(join(dir, ".env"), "utf8").split(/\r?\n/).filter((s) => s.includes("=")).map((s) => [s.slice(0, s.indexOf("=")), s.slice(s.indexOf("=") + 1)]));
const ingressEnv = Object.fromEntries(readFileSync(join(deployment, ".env.ingress"), "utf8").split(/\r?\n/).filter((s) => s.includes("=")).map((s) => [s.slice(0, s.indexOf("=")), s.slice(s.indexOf("=") + 1)]));
const email = `customer-${randomBytes(8).toString("hex")}@example.test`;
const password = randomBytes(32).toString("base64url");
const args = [resolve("scripts/deployment-bootstrap.mjs"), "--deployment", dir, "--email", email, "--name", "Customer acceptance fixture", "--seats", "5"];
const checks = [];
function bootstrap(extra = [], expected = 0) {
  const run = spawnSync(process.execPath, [...args, ...extra], { input: password, encoding: "utf8", timeout: 60000 });
  assert.equal(run.status, expected, run.stderr); assert.ok(!`${run.stdout}${run.stderr}`.includes(password));
}
async function request(path, token = env.SERVICE_ROLE_KEY, body) {
  const response = await fetch(new URL(path, base), { method: body === undefined ? "GET" : "POST", headers: { apikey: env.ANON_KEY, Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(30000) });
  return { status: response.status, data: await response.json() };
}
async function signedDeviceStart() {
	const { createDeviceStartIngress } = await import(pathToFileURL(join(deployment, "ingress/device-start.mjs")).href);
	const server = createDeviceStartIngress({
		signingSecret: ingressEnv.AIDR_DEVICE_START_INGRESS_SECRET,
		proxyToken: ingressEnv.AIDR_DEVICE_START_PROXY_TOKEN,
		upstreamUrl: ingressEnv.AIDR_DEVICE_START_UPSTREAM_URL,
		trustedPeers: "127.0.0.1",
		anonKey: ingressEnv.AIDR_DEVICE_START_ANON_KEY,
	});
	await new Promise((resolveListen, rejectListen) => {
		server.once("error", rejectListen);
		server.listen(0, "127.0.0.1", resolveListen);
	});
	try {
		const response = await fetch(`http://127.0.0.1:${server.address().port}/functions/v1/device-start`, {
			method: "POST",
			headers: { "Content-Type": "application/json", "X-AIDR-Proxy-Token": ingressEnv.AIDR_DEVICE_START_PROXY_TOKEN, "X-AIDR-Proxy-Client-IP": "127.0.0.1" },
			body: "{}",
			signal: AbortSignal.timeout(10000),
		});
		return { status: response.status, data: await response.json() };
	} finally {
		await new Promise((done) => server.close(done));
	}
}
bootstrap();
const receipt = JSON.parse(readFileSync(join(dir, "bootstrap-receipt.json"), "utf8"));
assert.equal(receipt.state, "complete"); assert.notEqual(receipt.tenant_id, receipt.user_id);
checks.push("first owner provisioned with a separate enterprise tenant");
bootstrap(["--resume"]); bootstrap([], 1); bootstrap(["--resume", "--seats", "6"], 1);
checks.push("resume is idempotent; duplicate and changed configuration refused");
const login = await request("/auth/v1/token?grant_type=password", env.ANON_KEY, { email, password });
assert.equal(login.status, 200); const token = login.data.access_token;
checks.push("provisioned owner signs in without SMTP or OAuth");
const status = await request("/functions/v1/pilot-status", token);
assert.equal(status.status, 200); assert.equal(status.data.status, "approved"); assert.equal(status.data.tenant_id, receipt.tenant_id);
checks.push("browser onboarding sees the enterprise enrollment approval");
const forbidden = await request("/rest/v1/rpc/bootstrap_customer", token, { p_user_id: receipt.user_id, p_bootstrap_id: receipt.bootstrap_id, p_name: receipt.name, p_seats: 100 });
assert.equal(forbidden.status, 403); checks.push("ordinary authenticated session cannot provision or increase seats");
const pilot = await request(`/rest/v1/pilot_applications?user_id=eq.${receipt.user_id}&select=tenant_id,status`);
assert.equal(pilot.data[0].tenant_id, receipt.tenant_id);
const ent = await request(`/rest/v1/entitlements?tenant_id=eq.${receipt.tenant_id}&select=included_agents`);
assert.equal(ent.data[0].included_agents, 5); checks.push("approval and seat allocation bound to enterprise tenant");
const started = await signedDeviceStart();
assert.equal(started.status, 200, "signed ingress must bootstrap the customer's device");
const device = started.data;
assert.equal((await request("/functions/v1/device-verify", token, { user_code: device.user_code })).status, 200);
await new Promise((done) => setTimeout(done, (device.interval_seconds + 1) * 1000));
const exchange = (await request("/functions/v1/device-poll", token, { device_code: device.device_code })).data;
const enrolled = await request("/functions/v1/enroll", exchange.enrollment_token, { iid: `customer-${randomBytes(8).toString("hex")}`, agent_runtime: "claude-code" });
assert.equal(enrolled.status, 200); assert.ok(enrolled.data.entitlement_signed);
const agent = await request(`/rest/v1/agents?user_id=eq.${receipt.user_id}&select=tenant_id`);
assert.equal(agent.data.length, 1); assert.equal(agent.data[0].tenant_id, receipt.tenant_id);
checks.push("device flow enrolls agent in the customer's enterprise tenant");
const initial = await request("/functions/v1/policy-management", token, { tenant_id: receipt.tenant_id, action: "read" });
assert.equal(initial.data.version, 1);
checks.push("new customer has a published central policy before its first tool call");
const publish = await request("/functions/v1/policy-management", token, { tenant_id: receipt.tenant_id, action: "publish", expected_version: 1, policy: { mcp_deny_tools: ["customer.exfiltrate"] } });
assert.equal(publish.status, 200);
const policy = await request("/functions/v1/policy", enrolled.data.api_key);
assert.equal(policy.status, 200); assert.deepEqual(policy.data.runtime_policy, { mcp_deny_tools: ["customer.exfiltrate"] });
checks.push("enrolled API key receives the enterprise team's published policy");
mkdirSync(join(deployment, "private-ui-fixture"), { recursive: true, mode: 0o700 });
writeFileSync(join(deployment, "private-ui-fixture/login.json"), JSON.stringify({ email, password, tenant_id: receipt.tenant_id }), { mode: 0o600 });
writeFileSync(join(deployment, "customer-onboarding-evidence.json"), JSON.stringify({ passed: true, checked_at: new Date().toISOString(), checks, scope: "Isolated local rehearsal; not customer field acceptance" }, null, 2));
console.log(`${checks.length} customer onboarding checks passed; credentials remain in the private rehearsal directory.`);
