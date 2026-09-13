#!/usr/bin/env node
// Isolated loopback acceptance probe. Bearer credentials stay in memory.
import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const deployment = resolve(process.argv[2] || ".aidr-deploy");
const manifest = JSON.parse(readFileSync(join(deployment, "deployment.json"), "utf8"));
const base = new URL(manifest.supabase_url);
if (!manifest.development || !["localhost", "127.0.0.1"].includes(base.hostname)) {
	throw new Error("Live fixtures require an isolated loopback development installation");
}
const env = Object.fromEntries(readFileSync(join(deployment, ".env"), "utf8")
	.split(/\r?\n/).filter((line) => line.includes("="))
	.map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]));
const checks = [];
async function request(path, { token = env.SERVICE_ROLE_KEY, method = "GET", body, headers = {} } = {}) {
	const response = await fetch(new URL(path, base), {
		method,
		headers: { apikey: env.ANON_KEY, Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...headers },
		body: body === undefined ? undefined : JSON.stringify(body),
		signal: AbortSignal.timeout(30_000),
	});
	let data;
	try { data = await response.json(); } catch { data = {}; }
	return { status: response.status, data };
}
function expect(result, status, label) {
	assert.equal(result.status, status, `${label}: HTTP ${result.status}, code=${result.data?.error || result.data?.code || "none"}`);
	checks.push(label);
	console.log(`PASS ${label}`);
	return result.data;
}
const suffix = randomBytes(6).toString("hex");
const email = `aidr-v6-${suffix}@example.test`;
const password = randomBytes(32).toString("hex");
const user = expect(await request("/auth/v1/admin/users", {
	method: "POST", body: { email, password, email_confirm: true },
}), 200, "create isolated operator");
const login = expect(await request("/auth/v1/token?grant_type=password", {
	method: "POST", token: env.ANON_KEY, body: { email, password },
}), 200, "operator login");
const userToken = login.access_token;
const tenant = expect(await request("/rest/v1/rpc/create_team_tenant", {
	method: "POST", token: userToken, body: { p_name: `V6 ${suffix}`, p_plan: "free" },
}), 200, "create isolated tenant").id;
assert.ok(tenant);
const invoiceHeaders = { "X-AIDR-Tenant-ID": tenant };
expect(await request("/functions/v1/invoice-entitlement", { token: userToken, headers: invoiceHeaders }), 200, "invoice list initially readable");
const orderBody = { request_id: `v6accept${randomBytes(12).toString("hex")}`, requested_agents: 7, quote_reference: `local-${suffix}` };
const firstOrder = expect(await request("/functions/v1/invoice-entitlement", {
	method: "POST", token: userToken, headers: invoiceHeaders, body: orderBody,
}), 200, "invoice intake pending finance").order;
assert.equal(firstOrder?.status, "pending_finance");
const retry = expect(await request("/functions/v1/invoice-entitlement", {
	method: "POST", token: userToken, headers: invoiceHeaders, body: orderBody,
}), 200, "invoice idempotent retry").order;
assert.equal(retry?.id, firstOrder.id);
expect(await request("/functions/v1/invoice-entitlement", {
	method: "POST", token: userToken, headers: invoiceHeaders, body: { ...orderBody, requested_agents: 8 },
}), 409, "invoice changed retry rejected");
expect(await request("/functions/v1/invoice-entitlement", {
	method: "POST", token: userToken, headers: invoiceHeaders, body: { ...orderBody, paid: true },
}), 400, "caller paid state rejected");
const invoiceList = expect(await request("/functions/v1/invoice-entitlement", {
	token: userToken, headers: invoiceHeaders,
}), 200, "invoice list contains pending order");
assert.ok(invoiceList.orders.some((order) => order.id === firstOrder.id && order.status === "pending_finance"));

const collector = `v6-${suffix}`;
expect(await request("/functions/v1/discovery", {
	method: "POST", token: userToken, body: { action: "issue_credential", tenant_id: tenant, collector_id: collector },
}), 403, "collector issuance requires MFA");
// Service-role fixture issuance tests the machine transport without weakening
// the operator MFA gate in the Edge function.
const machineToken = `aidr_dc_${randomBytes(32).toString("base64url")}`;
const tokenHash = createHash("sha256").update(machineToken).digest("hex");
expect(await request("/rest/v1/rpc/issue_tenant_discovery_credential", {
	method: "POST", body: { p_tenant_id: tenant, p_actor_user_id: user.id, p_collector_id: collector,
		p_token_hash: tokenHash, p_expires_in_days: 1 },
}), 200, "fixture collector credential issued by privileged RPC");
const cursorBody = { action: "cursor", tenant_id: tenant, collector_id: collector };
const cursor = expect(await request("/functions/v1/discovery", {
	method: "POST", token: machineToken, body: cursorBody,
}), 200, "machine collector cursor");
assert.equal(cursor.next_sequence, 1);
const cycle = { action: "ingest", tenant_id: tenant, collector_id: collector, cycle_id: randomUUID(),
	sequence: 1, stale_after_ms: 60_000, complete: true, expected_targets: 1,
	items: [{ target: "https://example.test/", reachable: true, attempts: 1, error_code: null }] };
expect(await request("/functions/v1/discovery", {
	method: "POST", token: machineToken, body: cycle,
}), 201, "machine collector ingest");
expect(await request("/functions/v1/discovery", {
	method: "POST", token: machineToken, body: cycle,
}), 409, "machine collector replay rejected");
const next = expect(await request("/functions/v1/discovery", {
	method: "POST", token: machineToken, body: cursorBody,
}), 200, "machine cursor advances");
assert.equal(next.next_sequence, 2);
expect(await request("/functions/v1/discovery", {
	method: "POST", token: userToken,
	body: { action: "read", tenant_id: tenant, collector_id: collector },
}), 200, "operator reads collector inventory");
expect(await request("/rest/v1/rpc/revoke_tenant_discovery_credential", {
	method: "POST", body: { p_tenant_id: tenant, p_actor_user_id: user.id, p_collector_id: collector },
}), 200, "fixture collector revoked");
expect(await request("/functions/v1/discovery", {
	method: "POST", token: machineToken, body: cursorBody,
}), 401, "revoked machine credential rejected");

writeFileSync(join(deployment, "v6-edge-live-evidence.json"), JSON.stringify({
	schema_version: 1, checked_at: new Date().toISOString(), tenant_id: tenant,
	checks, result: "LOCAL_PASS", credentials_recorded: false,
}, null, 2));
console.log(`${checks.length} v6 live Edge checks passed; bearer credentials were not written to evidence.`);
