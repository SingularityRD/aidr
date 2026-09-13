#!/usr/bin/env node
// Run only against an isolated development installation. Never prints tokens.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve, join } from "node:path";
import { createHash, randomBytes, verify as verifySignature } from "node:crypto";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const dir = resolve(process.argv[2] || ".aidr-deploy");
const manifest = JSON.parse(readFileSync(join(dir, "deployment.json"), "utf8"));
const base = new URL(manifest.supabase_url);
if (!manifest.development || !["localhost", "127.0.0.1"].includes(base.hostname)) throw new Error("Smoke fixtures require an isolated loopback development installation");
const env = Object.fromEntries(readFileSync(join(dir, ".env"), "utf8").split(/\r?\n/).filter((s) => s.includes("=")).map((s) => [s.slice(0, s.indexOf("=")), s.slice(s.indexOf("=") + 1)]));
const ingressEnv = Object.fromEntries(readFileSync(join(dir, ".env.ingress"), "utf8").split(/\r?\n/).filter((s) => s.includes("=")).map((s) => [s.slice(0, s.indexOf("=")), s.slice(s.indexOf("=") + 1)]));
const suffix = randomBytes(6).toString("hex");
const checks = [];
async function request(path, { token = env.SERVICE_ROLE_KEY, method = "GET", body, headers = {} } = {}) {
	const response = await fetch(new URL(path, base), { method, headers: { apikey: env.ANON_KEY, Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...headers }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(45000) });
	const text = await response.text();
	let data; try { data = JSON.parse(text); } catch { data = {}; }
	return { status: response.status, data };
}
function expect(result, status, label) {
	assert.equal(result.status, status, `${label}: HTTP ${result.status}; error=${result.data.error || result.data.code || "none"}`);
	checks.push(label); console.log(`PASS ${label}`); return result.data;
}
async function user(label) {
	const email = `aidr-smoke-${label}-${suffix}@example.test`;
	const password = randomBytes(32).toString("hex");
	const created = expect(await request("/auth/v1/admin/users", { method: "POST", body: { email, password, email_confirm: true } }), 200, `create ${label} fixture`);
	const login = expect(await request("/auth/v1/token?grant_type=password", { token: env.ANON_KEY, method: "POST", body: { email, password } }), 200, `login ${label}`);
	return { id: created.id, email, token: login.access_token };
}
const edge = (name, token, body) => request(`/functions/v1/${name}`, { token, method: "POST", body });
let deviceStartSigner;
async function signedDeviceStart() {
	if (!deviceStartSigner) {
		const { createDeviceStartIngress } = await import(pathToFileURL(join(dir, "ingress/device-start.mjs")).href);
		deviceStartSigner = createDeviceStartIngress({
			signingSecret: ingressEnv.AIDR_DEVICE_START_INGRESS_SECRET,
			proxyToken: ingressEnv.AIDR_DEVICE_START_PROXY_TOKEN,
			upstreamUrl: ingressEnv.AIDR_DEVICE_START_UPSTREAM_URL,
			trustedPeers: "127.0.0.1",
			anonKey: ingressEnv.AIDR_DEVICE_START_ANON_KEY,
		});
		await new Promise((resolveListen, rejectListen) => {
			deviceStartSigner.once("error", rejectListen);
			deviceStartSigner.listen(0, "127.0.0.1", resolveListen);
		});
	}
	const response = await fetch(`http://127.0.0.1:${deviceStartSigner.address().port}/functions/v1/device-start`, {
		method: "POST",
		headers: { "Content-Type": "application/json", "X-AIDR-Proxy-Token": ingressEnv.AIDR_DEVICE_START_PROXY_TOKEN, "X-AIDR-Proxy-Client-IP": "127.0.0.1" },
		body: "{}",
		signal: AbortSignal.timeout(10000),
	});
	return { status: response.status, data: await response.json() };
}
try {
	assert.equal((await fetch(manifest.dashboard_url)).status, 200); checks.push("dashboard root served");
	expect(await request("/auth/v1/health"), 200, "auth health");
	const alice = await user("owner");
	const bob = await user("outsider");
	const team = expect(await request("/rest/v1/rpc/create_team_tenant", { token: alice.token, method: "POST", body: { p_name: `Smoke ${suffix}`, p_plan: "free" } }), 200, "atomic team creation through user RLS");
	const tenant = team.id;
	assert.ok(tenant, "team id required");
	const published = expect(await edge("policy-management", alice.token, { tenant_id: tenant, action: "publish", expected_version: 0, policy: { mcp_deny_tools: ["smoke.exfiltrate"] } }), 200, "publish runtime policy");
	assert.equal(published.version, 1);
	expect(await edge("policy-management", alice.token, { tenant_id: tenant, action: "publish", expected_version: 0, policy: { command_default: "deny" } }), 409, "stale policy publication rejected");
	expect(await edge("policy-management", bob.token, { tenant_id: tenant, action: "read" }), 403, "cross-tenant policy rejected");
	const keys = expect(await request("/functions/v1/api-keys", { token: alice.token, method: "POST", headers: { "X-AIDR-Tenant-ID": tenant }, body: { label: `smoke-${suffix}` } }), 200, "native API key issuance");
	const policy = expect(await request("/functions/v1/policy", { token: keys.api_key }), 200, "native policy fetch");
	assert.deepEqual(policy.runtime_policy, { mcp_deny_tools: ["smoke.exfiltrate"] });
	const endpointHome = join(dir, `policy-smoke-${suffix}`);
	mkdirSync(join(endpointHome, ".singularity-aidr"), { recursive: true, mode: 0o700 });
	writeFileSync(join(endpointHome, ".singularity-aidr/config.json"), JSON.stringify({ mode: "local", auth: { api_key: keys.api_key }, control_plane: { enabled: true, endpoint: `${base.origin}/functions/v1` } }), { mode: 0o600 });
	const hook = spawnSync(process.execPath, [resolve("packages/claude-code/dist/pre-tool-use.cjs")], { input: JSON.stringify({ hook_event_name: "PreToolUse", session_id: "policy-smoke", cwd: endpointHome, tool_name: "mcp__smoke__exfiltrate", tool_input: {} }), encoding: "utf8", timeout: 20000, cwd: endpointHome, env: { ...process.env, HOME: endpointHome, USERPROFILE: endpointHome } });
	assert.equal(hook.status, 0, "built hook completes");
	assert.equal(JSON.parse(hook.stdout).hookSpecificOutput?.permissionDecision, "deny", "published policy reaches built hook and denies MCP tool");
	checks.push("published policy enforced by built Claude hook");
	const invite = expect(await edge("team-invite", alice.token, { team_id: tenant, email: bob.email, role: "viewer" }), 200, "create manually shared invitation");
	const inviteToken = new URL(invite.invite_url).searchParams.get("invite");
	expect(await edge("oauth-callback", alice.token, { invite_token: inviteToken }), 403, "invitation email mismatch rejected");
	expect(await edge("oauth-callback", bob.token, { invite_token: inviteToken }), 200, "accept invitation");
	expect(await edge("oauth-callback", bob.token, { invite_token: inviteToken }), 403, "invitation replay rejected");
	expect(await edge("policy-management", bob.token, { tenant_id: tenant, action: "publish", expected_version: 1, policy: { command_default: "allow" } }), 403, "viewer cannot publish policy");
	const exported = expect(await edge("audit-export", alice.token, { team_id: tenant, format: "csv" }), 200, "audit export");
	assert.equal(new URL(exported.url).origin, base.origin);
	const download = await fetch(exported.url); assert.equal(download.status, 200, "private signed audit download");
	assert.match(await download.text(), /member.invitation_accepted/); checks.push("audit download contains invitation event");
	expect(await edge("device-start", env.ANON_KEY, {}), 403, "unsigned direct device bootstrap rejected");
	const device = expect(await signedDeviceStart(), 200, "signed ingress device bootstrap");
	const pending = expect(await edge("device-poll", alice.token, { device_code: device.device_code }), 200, "browser JWT does not replace device code");
	assert.equal(pending.status, "pending");
	expect(await request("/rest/v1/pilot_applications", { method: "POST", body: { user_id: alice.id, tenant_id: alice.id, status: "approved" } }), 201, "provision isolated enrollment fixture");
	expect(await edge("device-verify", alice.token, { user_code: device.user_code }), 200, "authorize device");
	await new Promise((done) => setTimeout(done, (device.interval_seconds + 1) * 1000));
	const exchange = expect(await edge("device-poll", alice.token, { device_code: device.device_code }), 200, "exchange authorized device");
	assert.equal(exchange.status, "approved");
	const enrolled = expect(await edge("enroll", exchange.enrollment_token, { iid: `smoke-${suffix}`, agent_runtime: "claude-code" }), 200, "enroll agent with signed entitlement");
	assert.equal(enrolled.entitlement_signed?.alg, "ed25519", "signed entitlement must not silently become null");
	const canonical = (value) => value === null || typeof value !== "object" ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
	const publicKey = JSON.parse(readFileSync(join(dir, "agent-config.json"), "utf8")).licensing.public_keys_pem[0];
	assert.ok(verifySignature(null, Buffer.from(canonical(enrolled.entitlement_signed.snapshot)), publicKey, Buffer.from(enrolled.entitlement_signed.sig_b64, "base64")), "entitlement signature verifies against distributed agent key");
	checks.push("entitlement signature matches distributed public key");
	expect(await edge("enroll", exchange.enrollment_token, { iid: `replay-${suffix}` }), 401, "enrollment token replay rejected");
	expect(await edge("billing-checkout", alice.token, { seats: 1, plan: "monthly", request_id: crypto.randomUUID() }), 410, "invoice deployment rejects disabled self-service");
	const evidence = { schema_version: 1, passed: true, checked_at: new Date().toISOString(), deployment_mode: manifest.mode, checks, fixture_namespace: suffix, scope: "isolated loopback; not field acceptance", migrations: manifest.migrations,
		hook_sha256: createHash("sha256").update(readFileSync(resolve("packages/claude-code/dist/pre-tool-use.cjs"))).digest("hex"),
		function_sha256: Object.fromEntries(["policy", "policy-management", "api-keys", "team-invite", "oauth-callback", "audit-export", "device-start", "device-poll", "device-verify", "enroll", "billing-checkout"].map((name) => [name, createHash("sha256").update(readFileSync(join(dir, "volumes/functions", name, "index.ts"))).digest("hex")])) };
	writeFileSync(join(dir, "smoke-evidence.json"), JSON.stringify(evidence, null, 2));
	console.log(`${checks.length} checks passed. Isolated fixtures retained for inspection; evidence contains no credentials.`);
} catch (error) {
	writeFileSync(join(dir, "smoke-evidence.json"), JSON.stringify({ schema_version: 1, passed: false, checked_at: new Date().toISOString(), checks, failure: error.message }, null, 2));
	console.error(error.message); process.exitCode = 1;
} finally {
	if (deviceStartSigner) await new Promise((done) => deviceStartSigner.close(done));
}
