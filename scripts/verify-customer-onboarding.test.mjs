import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

const gate = resolve(import.meta.dirname, "verify-customer-onboarding.mjs");

function json(response, status, value) {
	response.writeHead(status, { "content-type": "application/json" });
	response.end(JSON.stringify(value));
}

test("customer onboarding uses the bootstrap receipt tenant for owner and device authorization", { timeout: 30000 }, async () => {
	const tenantId = randomUUID();
	const userId = randomUUID();
	const seen = { pilot: null, verify: null };
	const server = createServer(async (request, response) => {
		const url = new URL(request.url, "http://127.0.0.1");
		const pathname = url.pathname;
		if (pathname === "/auth/v1/health") return json(response, 200, {});
		if (pathname === "/auth/v1/admin/users") return json(response, 200, { id: userId });
		if (pathname === "/rest/v1/rpc/bootstrap_customer") {
			if (request.headers.authorization === "Bearer fixture-owner-token") return json(response, 403, {});
			return json(response, 200, { tenant_id: tenantId, user_id: userId, name: "Customer acceptance fixture", seats: 5 });
		}
		if (pathname === "/auth/v1/token") return json(response, 200, { access_token: "fixture-owner-token" });
		if (pathname === "/functions/v1/pilot-status") {
			seen.pilot = request.headers["x-aidr-tenant-id"];
			return json(response, seen.pilot === tenantId ? 200 : 403, { status: "approved", tenant_id: tenantId });
		}
		if (pathname === "/rest/v1/pilot_applications") return json(response, 200, [{ tenant_id: tenantId, status: "approved" }]);
		if (pathname === "/rest/v1/entitlements") return json(response, 200, [{ included_agents: 5 }]);
		if (pathname === "/functions/v1/device-verify") {
			seen.verify = request.headers["x-aidr-tenant-id"];
			const body = await new Promise((done) => { let text = ""; request.on("data", (chunk) => { text += chunk; }); request.on("end", () => done(JSON.parse(text || "{}"))); });
			const status = seen.verify === tenantId ? 200 : 403;
			if (body.action === "lookup") return json(response, status, { ok: true, device: { device_session_id: "d0000000-0000-4000-8000-000000000001", user_code: body.user_code } });
			return json(response, body.action === "authorize" && body.confirmed === true ? status : 400, {});
		}
		if (pathname === "/functions/v1/device-poll") return json(response, 200, { enrollment_token: "fixture-enrollment-token" });
		if (pathname === "/functions/v1/enroll") return json(response, 200, { entitlement_signed: "fixture-signature", api_key: "fixture-api-key" });
		if (pathname === "/rest/v1/agents") return json(response, 200, [{ tenant_id: tenantId }]);
		if (pathname === "/functions/v1/policy-management") return json(response, 200, { version: 1 });
		if (pathname === "/functions/v1/policy") return json(response, 200, { runtime_policy: { mcp_deny_tools: ["customer.exfiltrate"] } });
		return json(response, 404, {});
	});
	await new Promise((done) => server.listen(0, "127.0.0.1", done));
	const root = await mkdtemp(join(tmpdir(), "aidr-onboarding-header-"));
	const deployment = join(root, "deployment");
	const fixture = join(root, "fixture");
	try {
		const base = `http://127.0.0.1:${server.address().port}`;
		await mkdir(join(deployment, "ingress"), { recursive: true });
		await writeFile(join(deployment, "deployment.json"), JSON.stringify({ supabase_url: base, dashboard_url: base, development: true }));
		await writeFile(join(deployment, ".env"), "ANON_KEY=fixture-anon-key\nSERVICE_ROLE_KEY=fixture-service-role\n");
		await writeFile(join(deployment, ".env.ingress"), `AIDR_DEVICE_START_INGRESS_SECRET=fixture-secret\nAIDR_DEVICE_START_PROXY_TOKEN=fixture-proxy-token\nAIDR_DEVICE_START_UPSTREAM_URL=${base}\nAIDR_DEVICE_START_ANON_KEY=fixture-anon-key\n`);
		await writeFile(join(deployment, "ingress", "device-start.mjs"), `import { createServer } from "node:http";\nexport function createDeviceStartIngress() { return createServer((_request, response) => { response.writeHead(200, { "content-type": "application/json" }); response.end(JSON.stringify({ user_code: "TEST-CODE", device_code: "fixture-device-code", interval_seconds: 0 })); }); }\n`);
		const run = await new Promise((done, reject) => {
			const child = spawn(process.execPath, [gate, "--deployment", deployment, "--fixture-dir", fixture, "--keep-env"], {
				stdio: ["ignore", "pipe", "pipe"],
				signal: AbortSignal.timeout(25000),
				env: { ...process.env, AIDR_ONBOARDING_EVIDENCE_DIR: "" },
			});
			let stdout = "";
			let stderr = "";
			child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
			child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
			child.once("error", reject);
			child.once("close", (code) => done({ code, stdout, stderr }));
		});
		assert.equal(run.code, 0, `${run.stdout}\n${run.stderr}`);
		assert.notEqual(tenantId, userId);
		assert.equal(JSON.parse(await readFile(join(fixture, "bootstrap-receipt.json"), "utf8")).tenant_id, tenantId);
		assert.equal(seen.pilot, tenantId);
		assert.equal(seen.verify, tenantId);
		assert.match(run.stdout, /"outcome":"passed"/);
	} finally {
		server.closeAllConnections();
		await new Promise((done) => server.close(done));
		await rm(root, { recursive: true, force: true });
	}
});
