#!/usr/bin/env node
// Run only against an isolated development installation. Never prints tokens.
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, relative, resolve, join } from "node:path";
import { createHash, randomBytes, randomUUID, verify as verifySignature } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertReleaseSourceClean } from "./lib/release-source-clean.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dir = resolve(process.argv[2] || ".aidr-deploy");
const manifest = JSON.parse(readFileSync(join(dir, "deployment.json"), "utf8"));
const base = new URL(manifest.supabase_url);
if (!manifest.development || !["localhost", "127.0.0.1"].includes(base.hostname)) throw new Error("Smoke fixtures require an isolated loopback development installation");
if (process.argv.length > 3 && (process.argv.length !== 5 || process.argv[3] !== "--candidate-inventory")) {
	throw new Error("Usage: node scripts/deployment-smoke.mjs <deployment> [--candidate-inventory <release-inventory.json>]");
}
const sha256File = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
let candidate = null;
if (process.argv[3] === "--candidate-inventory") {
	const inventoryPath = resolve(process.argv[4]);
	const inventory = JSON.parse(readFileSync(inventoryPath, "utf8"));
	const metadataPath = join(dirname(inventoryPath), "release-metadata.json");
	const metadata = JSON.parse(readFileSync(metadataPath, "utf8"));
	const head = spawnSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" });
	if (head.status !== 0 || !/^[a-f0-9]{40}$/.test(head.stdout.trim())) throw new Error("Cannot bind smoke runner to a source commit");
	if (metadata.schema_version !== 1 || metadata.worktree_dirty !== false || manifest.source_has_changes !== false ||
		metadata.git_sha !== manifest.source_commit || head.stdout.trim() !== metadata.git_sha) {
		throw new Error("Candidate, deployed installation and smoke runner must share one clean source commit");
	}
	if (inventory.schema_version !== 1 || !Array.isArray(inventory.artifacts) || inventory.artifacts.length === 0 ||
		!Array.isArray(metadata.artifacts) || inventory.artifacts.length !== metadata.artifacts.length ||
		inventory.artifacts.some((item, index) => item.staged_path !== metadata.artifacts[index]?.path || item.sha256 !== metadata.artifacts[index]?.sha256)) {
		throw new Error("Candidate inventory differs from release metadata");
	}
	const inventorySha = sha256File(inventoryPath);
	const metadataSha = sha256File(metadataPath);
	const digest = createHash("sha256").update(`${metadataSha}  release-output/release-metadata.json\n${inventorySha}  release-output/release-inventory.json\n`).digest("hex");
	if (process.env.AIDR_E2E_RC_DIGEST && process.env.AIDR_E2E_RC_DIGEST !== digest) throw new Error("Candidate digest differs from the RC workflow binding");
	assertReleaseSourceClean(root, { outputRelative: relative(root, dirname(inventoryPath)).replaceAll("\\", "/") });
	const requiredFunctions = new Set(["invoice-entitlement", "discovery", "url-check", "file-check", "packs-download"].map((name) => `volumes/functions/${name}/index.ts`));
	for (const artifact of manifest.artifacts ?? []) {
		if (!artifact.path?.startsWith("volumes/functions/")) continue;
		if (!/^volumes\/functions\/[A-Za-z0-9._/-]+$/.test(artifact.path) || artifact.path.split("/").includes("..") ||
			!/^[a-f0-9]{64}$/.test(artifact.sha256) || artifact.sha256 !== sha256File(join(dir, artifact.path)) ||
			artifact.sha256 !== sha256File(resolve(root, artifact.path.replace(/^volumes\//, "supabase/")))) {
			throw new Error(`Deployed Edge bytes differ from the candidate source: ${artifact.path}`);
		}
		requiredFunctions.delete(artifact.path);
	}
	if (requiredFunctions.size) throw new Error(`Candidate deployment is missing Edge functions: ${[...requiredFunctions].join(", ")}`);
	candidate = { digest, inventory_sha256: inventorySha, metadata_sha256: metadataSha, source_commit: metadata.git_sha };
}
const evidencePath = join(dir, candidate ? `smoke-evidence-${candidate.digest}.json` : "smoke-evidence.json");
if (existsSync(evidencePath)) throw new Error("Smoke receipt already exists; use a fresh isolated installation");
const env = Object.fromEntries(readFileSync(join(dir, ".env"), "utf8").split(/\r?\n/).filter((s) => s.includes("=")).map((s) => [s.slice(0, s.indexOf("=")), s.slice(s.indexOf("=") + 1)]));
const ingressEnv = Object.fromEntries(readFileSync(join(dir, ".env.ingress"), "utf8").split(/\r?\n/).filter((s) => s.includes("=")).map((s) => [s.slice(0, s.indexOf("=")), s.slice(s.indexOf("=") + 1)]));
const suffix = randomBytes(6).toString("hex");
const checks = [];
let issuedKeyHash = "";
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
async function user(label, bootstrapId = null) {
	const email = `aidr-smoke-${label}-${suffix}@example.test`;
	const password = randomBytes(32).toString("hex");
	const created = expect(await request("/auth/v1/admin/users", { method: "POST", body: { email, password, email_confirm: true, ...(bootstrapId ? { app_metadata: { aidr_bootstrap_id: bootstrapId } } : {}) } }), 200, `create ${label} fixture`);
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
		headers: { "Content-Type": "application/json", "X-AIDR-Proxy-Token": ingressEnv.AIDR_DEVICE_START_PROXY_TOKEN, "X-AIDR-Proxy-Client-IP": "127.0.0.1", "X-AIDR-Proxy-Request-ID": randomBytes(16).toString("hex") },
		body: "{}",
		signal: AbortSignal.timeout(10000),
	});
	return { status: response.status, data: await response.json() };
}
try {
	assert.equal((await fetch(manifest.dashboard_url)).status, 200); checks.push("dashboard root served");
	expect(await request("/auth/v1/health"), 200, "auth health");
	const bootstrapId = randomUUID();
	const alice = await user("owner", bootstrapId);
	const bob = await user("outsider");
	const ownerTeams = expect(await request(`/rest/v1/tenants?select=id&created_by=eq.${alice.id}&kind=eq.team&status=eq.active`), 200, "owner signup created one team");
	assert.equal(ownerTeams.length, 1, "customer bootstrap requires one active owner-created team");
	const tenant = ownerTeams[0].id;
	const outsiderTeam = expect(await request("/rest/v1/rpc/create_team_tenant", { token: bob.token, method: "POST", body: { p_name: `Outsider ${suffix}`, p_request_id: randomUUID(), p_plan: "free" } }), 200, "atomic team creation through user RLS");
	assert.ok(outsiderTeam.id && outsiderTeam.id !== tenant, "separate team id required");
	const billingHeaders = { "X-AIDR-Tenant-ID": tenant };
	const invoice = (body) => request("/functions/v1/invoice-entitlement", { token: alice.token, method: body === undefined ? "GET" : "POST", headers: billingHeaders, body });
	assert.deepEqual(expect(await invoice(), 200, "invoice ledger readable").orders, []);
	const orderRequest = { request_id: `smoke${randomBytes(12).toString("hex")}`, requested_agents: 7, quote_reference: `local-${suffix}` };
	const order = expect(await invoice(orderRequest), 200, "invoice request remains pending finance").order;
	assert.equal(order.status, "pending_finance");
	assert.equal(expect(await invoice(orderRequest), 200, "invoice retry is idempotent").order.id, order.id);
	expect(await invoice({ ...orderRequest, requested_agents: 8 }), 409, "changed invoice retry rejected");
	expect(await invoice({ ...orderRequest, paid: true }), 400, "customer cannot assert paid state");
	assert.ok(expect(await invoice(), 200, "pending invoice listed").orders.some((row) => row.id === order.id));
	const collector = `smoke-${suffix}`;
	expect(await edge("discovery", alice.token, { action: "issue_credential", tenant_id: tenant, collector_id: collector }), 403, "collector issuance requires MFA");
	const machineToken = `aidr_dc_${randomBytes(32).toString("base64url")}`;
	expect(await request("/rest/v1/rpc/issue_tenant_discovery_credential", { method: "POST", body: { p_tenant_id: tenant, p_actor_user_id: alice.id, p_collector_id: collector, p_token_hash: createHash("sha256").update(machineToken).digest("hex"), p_expires_in_days: 1 } }), 200, "isolated collector credential fixture issued");
	const cursorRequest = { action: "cursor", tenant_id: tenant, collector_id: collector };
	assert.equal(expect(await edge("discovery", machineToken, cursorRequest), 200, "machine collector cursor").next_sequence, 1);
	const cycle = { action: "ingest", tenant_id: tenant, collector_id: collector, cycle_id: randomUUID(), sequence: 1, stale_after_ms: 60_000, complete: true, expected_targets: 1, items: [{ target: "https://example.test/", reachable: true, attempts: 1, error_code: null }] };
	expect(await edge("discovery", machineToken, cycle), 201, "machine collector ingest");
	expect(await edge("discovery", machineToken, cycle), 409, "machine collector replay rejected");
	assert.equal(expect(await edge("discovery", machineToken, cursorRequest), 200, "machine cursor advances").next_sequence, 2);
	expect(await edge("discovery", alice.token, { action: "read", tenant_id: tenant, collector_id: collector }), 200, "operator reads collector inventory");
	expect(await request("/rest/v1/rpc/revoke_tenant_discovery_credential", { method: "POST", body: { p_tenant_id: tenant, p_actor_user_id: alice.id, p_collector_id: collector } }), 200, "isolated collector credential revoked");
	expect(await edge("discovery", machineToken, cursorRequest), 401, "revoked collector credential rejected");
	const published = expect(await edge("policy-management", alice.token, { tenant_id: tenant, action: "publish", expected_version: 0, policy: { mcp_deny_tools: ["smoke.exfiltrate"] } }), 200, "publish runtime policy");
	assert.equal(published.version, 1);
	expect(await edge("policy-management", alice.token, { tenant_id: tenant, action: "publish", expected_version: 0, policy: { command_default: "deny" } }), 409, "stale policy publication rejected");
	expect(await edge("policy-management", bob.token, { tenant_id: tenant, action: "read" }), 403, "cross-tenant policy rejected");
	expect(await request("/functions/v1/api-keys", { token: alice.token, method: "POST", headers: billingHeaders, body: { label: `unlicensed-${suffix}` } }), 403, "free team cannot issue a managed API key");
	expect(await request("/functions/v1/enrollment-tokens", { token: alice.token, method: "POST", headers: billingHeaders, body: { label: `unlicensed-${suffix}` } }), 403, "free team cannot issue an enrollment token");
	expect(await request("/rest/v1/rpc/configure_tenant_admission_mode", { method: "POST", body: { p_mode: "onprem" } }), 200, "operator selects on-prem admission mode");
	const licenseExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
	const provisioned = expect(await request("/rest/v1/rpc/bootstrap_customer", { method: "POST", body: { p_user_id: alice.id, p_bootstrap_id: bootstrapId, p_name: `Smoke ${suffix}`, p_seats: 5, p_license_expires_at: licenseExpiresAt, p_license_reference: `synthetic-smoke-${suffix}` } }), 200, "operator bootstraps a licensed customer tenant");
	assert.equal(provisioned.tenant_id, tenant, "bootstrap must license the selected tenant");
	const enrollmentAccess = expect(await request("/functions/v1/pilot-status", { token: alice.token, headers: billingHeaders }), 200, "licensed tenant enrollment access is visible");
	assert.equal(enrollmentAccess.admission?.status, "active", "customer bootstrap must grant tenant admission");
	assert.equal(enrollmentAccess.admission?.access_kind, "licensed", "on-prem bootstrap must not claim pilot approval");
	assert.equal(enrollmentAccess.admission?.allowed_agents, 5, "licensed admission must preserve contracted seats");
	const keys = expect(await request("/functions/v1/api-keys", { token: alice.token, method: "POST", headers: { "X-AIDR-Tenant-ID": tenant }, body: { label: `smoke-${suffix}` } }), 200, "native API key issuance");
	issuedKeyHash = createHash("sha256").update(keys.api_key).digest("hex");
	const policy = expect(await request("/functions/v1/policy", { token: keys.api_key }), 200, "native policy fetch");
	assert.deepEqual(policy.runtime_policy, { mcp_deny_tools: ["smoke.exfiltrate"] });
	const endpointHome = join(dir, `policy-smoke-${suffix}`);
	mkdirSync(join(endpointHome, ".singularity-aidr"), { recursive: true, mode: 0o700 });
	const mcpInventoryPath = join(endpointHome, "mcp.json");
	writeFileSync(mcpInventoryPath, JSON.stringify({ mcpServers: { smoke: { command: "node", args: ["synthetic-no-exec-server.js"] } } }), { mode: 0o600 });
	writeFileSync(join(endpointHome, ".singularity-aidr/config.json"), JSON.stringify({ mode: "local", auth: { api_key: keys.api_key }, control_plane: { enabled: true, endpoint: `${base.origin}/functions/v1`, allow_insecure_loopback: true, remote_policy_required: true, remote_policy_cache_enabled: false }, policy: { mcp: { inventory_paths: [mcpInventoryPath] } } }), { mode: 0o600 });
	const hookDecision = () => {
		const hook = spawnSync(process.execPath, [resolve("packages/claude-code/dist/pre-tool-use.cjs")], { input: JSON.stringify({ hook_event_name: "PreToolUse", session_id: "policy-smoke", cwd: endpointHome, tool_name: "mcp__smoke__exfiltrate", tool_input: {} }), encoding: "utf8", timeout: 20000, cwd: endpointHome, env: { ...process.env, HOME: endpointHome, USERPROFILE: endpointHome } });
		assert.equal(hook.status, 0, "built hook completes");
		const response = JSON.parse(hook.stdout);
		return {
			decision: response.hookSpecificOutput?.permissionDecision ?? "allow",
			policyDenial: typeof response.systemMessage === "string" && response.systemMessage.includes("MCP tool denied by policy"),
		};
	};
	assert.deepEqual(hookDecision(), { decision: "deny", policyDenial: true }, "published policy reaches built hook and denies MCP tool");
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
	const relaxedPolicy = { mcp_allow_tools: ["smoke.exfiltrate"], mcp_deny_tools: [] };
	const relaxed = expect(await edge("policy-management", alice.token, { tenant_id: tenant, action: "publish", expected_version: 1, policy: relaxedPolicy }), 200, "publish replacement runtime policy");
	assert.equal(relaxed.version, 2);
	assert.deepEqual(expect(await request("/functions/v1/policy", { token: keys.api_key }), 200, "endpoint fetches replacement policy").runtime_policy, relaxedPolicy);
	assert.equal(hookDecision().decision, "allow", "replacement policy permits the same tool through the built hook");
	checks.push("replacement policy enforced by built Claude hook");
	const restored = expect(await edge("policy-management", alice.token, { tenant_id: tenant, action: "restore", expected_version: 2, target_version: 1 }), 200, "restore prior runtime policy");
	assert.equal(restored.version, 3);
	assert.deepEqual(expect(await request("/functions/v1/policy", { token: keys.api_key }), 200, "endpoint fetches restored policy").runtime_policy, { mcp_deny_tools: ["smoke.exfiltrate"] });
	assert.deepEqual(hookDecision(), { decision: "deny", policyDenial: true }, "restored policy blocks the same tool through the built hook");
	checks.push("restored policy enforced by built Claude hook");
	expect(await edge("device-start", env.ANON_KEY, {}), 403, "unsigned direct device bootstrap rejected");
	const device = expect(await signedDeviceStart(), 200, "signed ingress device bootstrap");
	const pending = expect(await edge("device-poll", alice.token, { device_code: device.device_code }), 200, "browser JWT does not replace device code");
	assert.equal(pending.status, "pending");
	expect(await request("/functions/v1/device-verify", { token: alice.token, method: "POST", headers: billingHeaders, body: { user_code: device.user_code } }), 200, "authorize device for licensed tenant");
	await new Promise((done) => setTimeout(done, (device.interval_seconds + 1) * 1000));
	const exchange = expect(await edge("device-poll", alice.token, { device_code: device.device_code }), 200, "exchange authorized device");
	assert.equal(exchange.status, "approved");
	const enrolled = expect(await edge("enroll", exchange.enrollment_token, { iid: `smoke-${suffix}`, agent_runtime: "claude-code" }), 200, "enroll agent with signed entitlement");
	assert.equal(enrolled.entitlement_signed?.snapshot?.tenant_id, tenant, "signed entitlement must belong to the licensed team");
	assert.equal(enrolled.entitlement_signed?.alg, "ed25519", "signed entitlement must not silently become null");
	const canonical = (value) => value === null || typeof value !== "object" ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
	const publicKey = JSON.parse(readFileSync(join(dir, "agent-config.json"), "utf8")).licensing.public_keys_pem[0];
	assert.ok(verifySignature(null, Buffer.from(canonical(enrolled.entitlement_signed.snapshot)), publicKey, Buffer.from(enrolled.entitlement_signed.sig_b64, "base64")), "entitlement signature verifies against distributed agent key");
	checks.push("entitlement signature matches distributed public key");
	expect(await edge("enroll", exchange.enrollment_token, { iid: `replay-${suffix}` }), 401, "enrollment token replay rejected");
	expect(await edge("billing-checkout", alice.token, { seats: 1, plan: "monthly", request_id: crypto.randomUUID() }), 410, "invoice deployment rejects disabled self-service");
	const packId = `synthetic-${suffix}`;
	const packPath = `${tenant}/${packId}.bin`;
	const packBytes = Buffer.from(`aidr-pack-transport-smoke-${suffix}`);
	expect(await request(`/rest/v1/entitlements?tenant_id=eq.${tenant}`, { method: "PATCH", body: { premium_intel: true } }), 204, "isolated premium entitlement fixture enabled");
	const uploaded = await fetch(new URL(`/storage/v1/object/aidr-packs/${packPath}`, base), {
		method: "POST",
		headers: { apikey: env.ANON_KEY, Authorization: `Bearer ${env.SERVICE_ROLE_KEY}`, "Content-Type": "application/octet-stream" },
		body: packBytes,
		signal: AbortSignal.timeout(45000),
	});
	assert.ok(uploaded.status === 200 || uploaded.status === 201, `private pack fixture upload: HTTP ${uploaded.status}`);
	checks.push("private pack fixture uploaded"); console.log("PASS private pack fixture uploaded");
	expect(await request("/rest/v1/pack_versions", { method: "POST", body: { tenant_id: tenant, pack_id: packId, version: "1", storage_path: packPath, manifest_json: { synthetic_transport_fixture: true }, manifest_sig_b64: "c3ludGhldGlj", key_id: "synthetic-smoke" } }), 201, "isolated pack metadata fixture seeded");
	const packGrant = (apiKey) => request(`/functions/v1/packs-download?pack_id=${packId}&version=1`, { token: apiKey });
	const firstPackUrl = expect(await packGrant(keys.api_key), 200, "active key receives scoped pack grant").download_url;
	assert.equal(new URL(firstPackUrl).pathname, "/functions/v1/packs-download", "pack bytes must pass through the revocable AIDR proxy");
	const packDownload = await fetch(firstPackUrl, { signal: AbortSignal.timeout(45000) });
	assert.equal(packDownload.status, 200, `active scoped pack grant: HTTP ${packDownload.status}`);
	assert.deepEqual(Buffer.from(await packDownload.arrayBuffer()), packBytes, "private pack bytes must match uploaded fixture");
	checks.push("active scoped pack grant streams private bytes"); console.log("PASS active scoped pack grant streams private bytes");
	const reputationUrl = `https://smoke-${suffix}.example.test/payload`;
	const reputationHash = randomBytes(32).toString("hex");
	expect(await request("/rest/v1/url_reputation", { method: "POST", body: { tenant_id: tenant, user_id: alice.id, url: reputationUrl, domain: new URL(reputationUrl).hostname, is_malicious: true, severity_name: "critical", type_name: "malware", flags: ["smoke"], source: "isolated-smoke", provenance_verified: true } }), 201, "isolated trusted-source URL fixture seeded");
	expect(await request("/rest/v1/file_reputation", { method: "POST", body: { tenant_id: tenant, user_id: alice.id, sha256: reputationHash, severity: "SEVERITY_CRITICAL", malware_name: ["smoke-canary"], source: "isolated-smoke", provenance_verified: true } }), 201, "isolated trusted-source file fixture seeded");
	const reputationCalls = [
		["url-check", { queries: [{ key: { "url-like": reputationUrl } }] }],
		["file-check", { requests: [{ key: { sha256: reputationHash } }] }],
	];
	for (const [name, body] of reputationCalls) {
		const result = expect(await edge(name, keys.api_key, body), 200, `${name} accepts active tenant key`);
		if (name === "url-check") {
			assert.equal(result.coverage, "complete");
			assert.ok(result.answers?.[0]?.result?.success?.classification?.result?.malicious?.findings?.length);
		} else {
			assert.ok(result.responses?.[0]?.malware_name?.includes("smoke-canary"));
		}
	}
	const unknownUrl = expect(await edge("url-check", keys.api_key, { queries: [{ key: { "url-like": `https://unknown-${suffix}.example.test/` } }] }), 200, "unlisted URL remains unknown");
	assert.equal(unknownUrl.answers?.[0]?.result?.success?.classification?.result?.unknown?.reason, "no_reputation_row");
	expect(await edge("file-check", keys.api_key, { requests: [{ key: { sha256: randomBytes(32).toString("hex") } }] }), 503, "unlisted file hash does not receive a clean verdict");
	for (const [state, mutation] of [
		["suspended tenant", [ `/rest/v1/tenants?id=eq.${tenant}`, { status: "suspended" } ]],
		["expired membership", [ `/rest/v1/tenant_members?tenant_id=eq.${tenant}&user_id=eq.${alice.id}`, { expires_at: new Date(Date.now() - 60_000).toISOString() } ]],
	]) {
		if (state === "expired membership") {
			expect(await request(`/rest/v1/tenants?id=eq.${tenant}`, { method: "PATCH", body: { status: "active" } }), 204, "tenant reactivated for membership check");
			expect(await edge("url-check", keys.api_key, reputationCalls[0][1]), 200, "reactivated tenant key works again");
			expect(await request(`/rest/v1/tenant_members?tenant_id=eq.${tenant}&user_id=eq.${bob.id}`, { method: "PATCH", body: { role: "owner" } }), 204, "second owner preserves tenant ownership during expiry check");
		}
		expect(await request(mutation[0], { method: "PATCH", body: mutation[1] }), 204, `${state} fixture applied`);
		for (const [name, body] of reputationCalls) expect(await edge(name, keys.api_key, body), state === "expired membership" ? 401 : 403, `${name} rejects ${state}`);
		expect(await packGrant(keys.api_key), state === "expired membership" ? 401 : 403, `pack grant issuance rejects ${state}`);
		const stalePack = await fetch(firstPackUrl, { signal: AbortSignal.timeout(45000) });
		assert.equal(stalePack.status, state === "expired membership" ? 401 : 403, `previous pack grant rejects ${state}`);
		checks.push(`previous pack grant rejects ${state}`); console.log(`PASS previous pack grant rejects ${state}`);
	}
	expect(await request(`/rest/v1/tenant_members?tenant_id=eq.${tenant}&user_id=eq.${alice.id}`, { method: "PATCH", body: { expires_at: null } }), 204, "membership restored for key revocation check");
	expect(await request(`/rest/v1/tenant_members?tenant_id=eq.${tenant}&user_id=eq.${bob.id}`, { method: "PATCH", body: { role: "viewer" } }), 204, "temporary second owner restored to viewer");
	expect(await edge("url-check", keys.api_key, reputationCalls[0][1]), 401, "restored membership cannot revive retired key");
	expect(await packGrant(keys.api_key), 401, "restored membership cannot revive old pack key");
	const replacementKey = expect(await request("/functions/v1/api-keys", { token: alice.token, method: "POST", headers: billingHeaders, body: { label: `replacement-${suffix}` } }), 200, "restored member issues a fresh key");
	issuedKeyHash = createHash("sha256").update(replacementKey.api_key).digest("hex");
	expect(await edge("url-check", replacementKey.api_key, reputationCalls[0][1]), 200, "fresh membership key works");
	const replacementPackUrl = expect(await packGrant(replacementKey.api_key), 200, "fresh key receives pack grant").download_url;
	expect(await request(`/rest/v1/api_keys?key_hash=eq.${issuedKeyHash}`, { method: "PATCH", body: { revoked: true } }), 204, "isolated API key revoked");
	for (const [name, body] of reputationCalls) expect(await edge(name, replacementKey.api_key, body), 401, `${name} rejects revoked key`);
	expect(await packGrant(replacementKey.api_key), 401, "pack grant issuance rejects revoked key");
	const revokedPack = await fetch(replacementPackUrl, { signal: AbortSignal.timeout(45000) });
	assert.equal(revokedPack.status, 401, "previous pack grant rejects revoked key");
	checks.push("previous pack grant rejects revoked key"); console.log("PASS previous pack grant rejects revoked key");
	issuedKeyHash = "";
	const evidence = { schema_version: 1, passed: true, checked_at: new Date().toISOString(), deployment_mode: manifest.mode, source_commit: manifest.source_commit ?? null, candidate, checks, fixture_namespace: suffix, scope: "isolated loopback; not field acceptance", migrations: manifest.migrations,
		hook_sha256: createHash("sha256").update(readFileSync(resolve("packages/claude-code/dist/pre-tool-use.cjs"))).digest("hex"),
		function_sha256: Object.fromEntries(["policy", "policy-management", "api-keys", "team-invite", "oauth-callback", "audit-export", "device-start", "device-poll", "device-verify", "enroll", "billing-checkout", "invoice-entitlement", "discovery", "url-check", "file-check", "packs-download"].map((name) => [name, sha256File(join(dir, "volumes/functions", name, "index.ts"))])) };
	writeFileSync(evidencePath, JSON.stringify(evidence, null, 2), { flag: "wx" });
	console.log(`${checks.length} checks passed. Isolated fixtures retained for inspection; evidence contains no credentials.`);
} catch (error) {
	writeFileSync(evidencePath, JSON.stringify({ schema_version: 1, passed: false, checked_at: new Date().toISOString(), candidate, checks, failure: error.message }, null, 2), { flag: "wx" });
	console.error(error.message); process.exitCode = 1;
} finally {
	if (issuedKeyHash) {
		try { await request(`/rest/v1/api_keys?key_hash=eq.${issuedKeyHash}`, { method: "PATCH", body: { revoked: true } }); }
		catch { console.error("WARN: isolated smoke key cleanup could not be confirmed"); }
	}
	if (deviceStartSigner) await new Promise((done) => deviceStartSigner.close(done));
}
