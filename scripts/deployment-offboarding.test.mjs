import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, test } from "node:test";

const tenantId = "11111111-1111-4111-8111-111111111111";
const operatorId = "22222222-2222-4222-8222-222222222222";
const runId = "33333333-3333-4333-8333-333333333333";
const temporaryDirectories = [];
const servers = [];

afterEach(async () => {
	await Promise.all(servers.splice(0).map((server) => new Promise((done) => {
		server.closeIdleConnections();
		server.close(done);
	})));
	await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function fixture(handler) {
	const server = createServer(handler);
	servers.push(server);
	await new Promise((done) => server.listen(0, "127.0.0.1", done));
	const address = server.address();
	const directory = await mkdtemp(path.join(os.tmpdir(), "aidr-offboarding-"));
	temporaryDirectories.push(directory);
	await writeFile(
		path.join(directory, "deployment.json"),
		JSON.stringify({ supabase_url: `http://127.0.0.1:${address.port}`, development: true }),
	);
	await writeFile(path.join(directory, ".env"), "SERVICE_ROLE_KEY=test-service-role\n");
	return directory;
}

function json(response, status, value) {
	response.writeHead(status, { "content-type": "application/json" });
	response.end(JSON.stringify(value));
}

async function run(directory, extraArguments = []) {
	const child = spawn(process.execPath, [path.resolve("scripts/deployment-offboarding.mjs"), directory, "--tenant", tenantId, ...extraArguments], {
		cwd: process.cwd(),
		stdio: ["ignore", "pipe", "pipe"],
	});
	let stdout = "";
	let stderr = "";
	child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
	child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
	const status = await new Promise((done) => child.on("close", done));
	return { status, stdout, stderr };
}

function policies() {
	return [
		"temporary_exports", "access_credentials", "telemetry", "endpoint_identity",
		"security_intelligence", "policy_configuration", "identity_membership",
		"commercial_records", "security_audit", "operational_ephemera",
	].map((data_class) => ({ data_class, retention_days: 0, covers_backups: false }));
}

test("dry run reads the complete policy and active hold without mutating customer data", async () => {
	const calls = [];
	const directory = await fixture((request, response) => {
		calls.push(request.method);
		if (request.url.startsWith("/rest/v1/tenants?")) return json(response, 200, [{ id: tenantId, status: "active", retention_days: 30 }]);
		if (request.url.startsWith("/rest/v1/tenant_data_retention_policies?")) return json(response, 200, policies());
		if (request.url.startsWith("/rest/v1/tenant_legal_holds?")) return json(response, 200, [{ id: "hold", hold_reference: "CASE-1" }]);
		if (request.url.startsWith("/rest/v1/tenant_offboarding_runs?")) return json(response, 200, []);
		return json(response, 404, {});
	});
	const result = await run(directory);
	assert.equal(result.status, 0, result.stderr);
	assert.deepEqual(new Set(calls), new Set(["GET"]));
	const evidence = JSON.parse(await readFile(path.join(directory, `offboarding-evidence-${tenantId}.json`), "utf8"));
	assert.equal(evidence.applied, false);
	assert.equal(evidence.active_legal_hold, true);
	assert.equal(evidence.retention_policy.length, 10);
	assert.equal(evidence.backup_scope, "excluded_external_retention");
});

test("apply deletes storage before acknowledging its ledger and completes resumable batches", async () => {
	const calls = [];
	let runCalls = 0;
	const directory = await fixture(async (request, response) => {
		let body = "";
		for await (const chunk of request) body += chunk;
		calls.push({ method: request.method, url: request.url, body: body ? JSON.parse(body) : null });
		if (request.url === "/rest/v1/rpc/request_tenant_offboarding") {
			return json(response, 200, { run_id: runId, tenant_id: tenantId, status: "requested", backup_scope: "excluded_external_retention", backup_exception: "separate backup evidence required" });
		}
		if (request.url === "/rest/v1/rpc/run_tenant_offboarding_batch") {
			runCalls += 1;
			if (runCalls === 1) return json(response, 200, { run_id: runId, status: "running", action: "delete_storage_objects", paths: [`${tenantId}/44444444-4444-4444-8444-444444444444.json`] });
			if (runCalls === 2) return json(response, 200, { run_id: runId, status: "running", phase: "events", rows_deleted: 100 });
			return json(response, 200, { run_id: runId, status: "completed", complete: true });
		}
		if (request.url.startsWith("/rest/v1/tenant_legal_holds?")) return json(response, 200, []);
		if (request.url === "/storage/v1/object/aidr-audit-exports" && request.method === "DELETE") return json(response, 200, [{ name: `${tenantId}/44444444-4444-4444-8444-444444444444.json` }]);
		if (request.url.startsWith("/storage/v1/object/info/aidr-audit-exports/")) return json(response, 404, { code: "not_found" });
		if (request.url === "/rest/v1/rpc/ack_tenant_offboarding_objects") return json(response, 200, { run_id: runId, status: "running", phase: "audit_export_objects" });
		if (request.url.startsWith("/rest/v1/tenant_offboarding_phase_receipts?")) return json(response, 200, [{ phase: "events", status: "completed", rows_deleted: 100 }]);
		return json(response, 404, {});
	});
	const result = await run(directory, ["--apply", "--requested-by", operatorId, "--batch-size", "100"]);
	assert.equal(result.status, 0, result.stderr);
	const storageIndex = calls.findIndex((call) => call.url === "/storage/v1/object/aidr-audit-exports");
	const ackIndex = calls.findIndex((call) => call.url === "/rest/v1/rpc/ack_tenant_offboarding_objects");
	assert.ok(storageIndex >= 0 && ackIndex > storageIndex);
	assert.deepEqual(calls[storageIndex].body.prefixes, [`${tenantId}/44444444-4444-4444-8444-444444444444.json`]);
	const evidence = JSON.parse(await readFile(path.join(directory, `offboarding-evidence-${tenantId}.json`), "utf8"));
	assert.equal(evidence.complete, true);
	assert.equal(evidence.storage_batches, 1);
	assert.equal(evidence.backup_scope, "excluded_external_retention");
});

test("partial successful storage deletion cannot acknowledge an object that remains", async () => {
	const firstPath = `${tenantId}/44444444-4444-4444-8444-444444444444.json`;
	const secondPath = `${tenantId}/55555555-5555-4555-8555-555555555555.json`;
	let acknowledged = false;
	const directory = await fixture((request, response) => {
		if (request.url === "/rest/v1/rpc/request_tenant_offboarding") return json(response, 200, { run_id: runId, tenant_id: tenantId, status: "requested", backup_scope: "excluded_external_retention" });
		if (request.url === "/rest/v1/rpc/run_tenant_offboarding_batch") return json(response, 200, { run_id: runId, status: "running", action: "delete_storage_objects", paths: [firstPath, secondPath] });
		if (request.url.startsWith("/rest/v1/tenant_legal_holds?")) return json(response, 200, []);
		if (request.url === "/storage/v1/object/aidr-audit-exports") return json(response, 200, [{ name: firstPath }]);
		if (request.url === `/storage/v1/object/info/aidr-audit-exports/${firstPath}`) return json(response, 404, { code: "not_found" });
		if (request.url === `/storage/v1/object/info/aidr-audit-exports/${secondPath}`) return json(response, 200, { name: secondPath });
		if (request.url === "/rest/v1/rpc/ack_tenant_offboarding_objects") acknowledged = true;
		return json(response, 404, {});
	});
	const result = await run(directory, ["--apply", "--requested-by", operatorId]);
	assert.equal(result.status, 1);
	assert.equal(acknowledged, false);
	assert.match(result.stderr, /Storage object remains after deletion/);
});

test("retry can acknowledge an object already absent from storage", async () => {
	const objectPath = `${tenantId}/44444444-4444-4444-8444-444444444444.json`;
	let acknowledged = false;
	const directory = await fixture((request, response) => {
		if (request.url === "/rest/v1/rpc/request_tenant_offboarding") return json(response, 200, { run_id: runId, tenant_id: tenantId, status: "requested", backup_scope: "excluded_external_retention" });
		if (request.url === "/rest/v1/rpc/run_tenant_offboarding_batch") return json(response, 200, { run_id: runId, status: "running", action: "delete_storage_objects", paths: [objectPath] });
		if (request.url.startsWith("/rest/v1/tenant_legal_holds?")) return json(response, 200, []);
		if (request.url === "/storage/v1/object/aidr-audit-exports") return json(response, 200, []);
		if (request.url === `/storage/v1/object/info/aidr-audit-exports/${objectPath}`) return json(response, 404, { code: "not_found" });
		if (request.url === "/rest/v1/rpc/ack_tenant_offboarding_objects") {
			acknowledged = true;
			return json(response, 200, { run_id: runId, status: "completed" });
		}
		if (request.url.startsWith("/rest/v1/tenant_offboarding_phase_receipts?")) return json(response, 200, []);
		return json(response, 404, {});
	});
	const result = await run(directory, ["--apply", "--requested-by", operatorId]);
	assert.equal(result.status, 0, result.stderr);
	assert.equal(acknowledged, true);
});

test("active legal hold stops apply with a durable non-success result", async () => {
	let storageCalled = false;
	const directory = await fixture((request, response) => {
		if (request.url === "/rest/v1/rpc/request_tenant_offboarding") return json(response, 200, { run_id: runId, tenant_id: tenantId, status: "blocked_legal_hold", backup_scope: "excluded_external_retention" });
		if (request.url === "/rest/v1/rpc/run_tenant_offboarding_batch") return json(response, 200, { run_id: runId, status: "blocked_legal_hold", complete: false });
		if (request.url.startsWith("/rest/v1/tenant_offboarding_phase_receipts?")) return json(response, 200, [{ phase: "events", status: "pending", rows_deleted: 0 }]);
		if (request.url.startsWith("/storage/")) storageCalled = true;
		return json(response, 404, {});
	});
	const result = await run(directory, ["--apply", "--requested-by", operatorId]);
	assert.equal(result.status, 2, result.stderr);
	assert.equal(storageCalled, false);
	const evidence = JSON.parse(await readFile(path.join(directory, `offboarding-evidence-${tenantId}.json`), "utf8"));
	assert.equal(evidence.status, "blocked_legal_hold");
	assert.equal(evidence.complete, false);
});

test("storage failure never acknowledges deletion", async () => {
	let acknowledged = false;
	const directory = await fixture((request, response) => {
		if (request.url === "/rest/v1/rpc/request_tenant_offboarding") return json(response, 200, { run_id: runId, tenant_id: tenantId, status: "requested", backup_scope: "excluded_external_retention" });
		if (request.url === "/rest/v1/rpc/run_tenant_offboarding_batch") return json(response, 200, { run_id: runId, status: "running", action: "delete_storage_objects", paths: [`${tenantId}/44444444-4444-4444-8444-444444444444.json`] });
		if (request.url.startsWith("/rest/v1/tenant_legal_holds?")) return json(response, 200, []);
		if (request.url === "/storage/v1/object/aidr-audit-exports") return json(response, 503, { code: "storage_unavailable" });
		if (request.url === "/rest/v1/rpc/ack_tenant_offboarding_objects") acknowledged = true;
		return json(response, 404, {});
	});
	const result = await run(directory, ["--apply", "--requested-by", operatorId]);
	assert.equal(result.status, 1);
	assert.equal(acknowledged, false);
	assert.match(result.stderr, /durable receipts remain resumable/);
});

test("an unacknowledged cache invalidation leaves the run explicitly incomplete", async () => {
	const calls = [];
	const directory = await fixture((request, response) => {
		calls.push(request.url);
		if (request.url === "/rest/v1/rpc/request_tenant_offboarding") return json(response, 200, { run_id: runId, tenant_id: tenantId, status: "requested", backup_scope: "excluded_external_retention", backup_exception: "separate backup evidence required" });
		if (request.url === "/rest/v1/rpc/run_tenant_offboarding_batch") return json(response, 200, { run_id: runId, status: "running", complete: false, phase: "tenant_cache", action: "invalidate_cache", cache_scope: tenantId });
		if (request.url.startsWith("/rest/v1/tenant_offboarding_phase_receipts?")) return json(response, 200, [{ phase: "tenant_cache", status: "running", cache_invalidation_receipt: null }]);
		return json(response, 404, {});
	});
	const result = await run(directory, ["--apply", "--requested-by", operatorId]);
	assert.equal(result.status, 2, result.stderr);
	const evidence = JSON.parse(await readFile(path.join(directory, `offboarding-evidence-${tenantId}.json`), "utf8"));
	assert.equal(evidence.complete, false);
	assert.equal(evidence.cache_invalidation.required_for_completion, true);
	assert.equal(evidence.cache_invalidation.action_returned, true);
	assert.equal(evidence.cache_invalidation.acknowledged, false);
	assert.equal(evidence.cache_invalidation.receipt, null);
	// The driver cannot purge an external cache, so it must never acknowledge it.
	assert.ok(!calls.includes("/rest/v1/rpc/ack_tenant_offboarding_cache"), "cache acknowledgement must come from the operator, not the driver");
});

test("a recorded cache receipt is visible in the offboarding evidence", async () => {
	const receipt = { invalidated: 2, keys: ["tenant:cache:1", "tenant:cache:2"] };
	const directory = await fixture((request, response) => {
		if (request.url === "/rest/v1/rpc/request_tenant_offboarding") return json(response, 200, { run_id: runId, tenant_id: tenantId, status: "requested", backup_scope: "excluded_external_retention", backup_exception: "separate backup evidence required" });
		if (request.url === "/rest/v1/rpc/run_tenant_offboarding_batch") return json(response, 200, { run_id: runId, status: "completed", complete: true });
		if (request.url.startsWith("/rest/v1/tenant_offboarding_phase_receipts?")) return json(response, 200, [{ phase: "tenant_cache", status: "completed", cache_invalidation_receipt: receipt }]);
		return json(response, 404, {});
	});
	const result = await run(directory, ["--apply", "--requested-by", operatorId]);
	assert.equal(result.status, 0, result.stderr);
	const evidence = JSON.parse(await readFile(path.join(directory, `offboarding-evidence-${tenantId}.json`), "utf8"));
	assert.equal(evidence.complete, true);
	assert.equal(evidence.cache_invalidation.action_returned, false);
	assert.equal(evidence.cache_invalidation.acknowledged, true);
	assert.deepEqual(evidence.cache_invalidation.receipt, receipt);
});

// The deployment doctor covers the retention reaper timer, which is the hourly
// job that deletes expired private exports. There is no dedicated doctor test
// file, so this lives with the retention/offboarding script tests.
async function doctorFixture() {
	const directory = await mkdtemp(path.join(os.tmpdir(), "aidr-doctor-"));
	temporaryDirectories.push(directory);
	await writeFile(
		path.join(directory, "deployment.json"),
		JSON.stringify({
			schema_version: 1,
			mode: "cloud",
			development: true,
			dashboard_url: "http://localhost:8080",
			supabase_url: "http://127.0.0.1:8000",
		}),
	);
	await writeFile(
		path.join(directory, ".env"),
		"SERVICE_ROLE_KEY=test-service-role\nDISABLE_SIGNUP=true\nS3_PROTOCOL_ACCESS_KEY_SECRET=0123456789abcdef0123456789abcdef\n",
	);
	await writeFile(path.join(directory, ".env.functions"), "AIDR_SIGNING_KEY=test-signing-key\n");
	return directory;
}

function runDoctor(directory) {
	return spawnSync(process.execPath, [path.resolve("scripts/deployment-doctor.mjs"), "--deployment", directory], {
		cwd: process.cwd(),
		encoding: "utf8",
		timeout: 60_000,
	});
}

test("the doctor reports the retention reaper timer honestly instead of assuming it is installed", async () => {
	const directory = await doctorFixture();
	const result = runDoctor(directory);
	assert.ok(existsSync(path.join(directory, "doctor-evidence.json")), result.stderr);
	const evidence = JSON.parse(await readFile(path.join(directory, "doctor-evidence.json"), "utf8"));
	const verdicts = [...(evidence.checks ?? []), ...(evidence.failures ?? []), ...(evidence.unverified ?? [])]
		// Unverified entries carry both a check label and a reason. Match the
		// declared label rather than String(object), preserving the original
		// entry so the assertions below still prove it belongs to that bucket.
		.filter((entry) => String(typeof entry === "string" ? entry : entry?.check).includes("aidr-export-retention.timer"));
	assert.equal(verdicts.length, 1, `expected exactly one retention reaper verdict: ${JSON.stringify(verdicts)}`);
	const [verdict] = verdicts;
	if (process.platform === "linux" && existsSync("/run/systemd/system")) {
		// A readable host scheduler is definitive: the timer is armed, or it is not.
		assert.ok([...(evidence.checks ?? []), ...(evidence.failures ?? [])].includes(verdict));
		assert.doesNotMatch(result.stdout, /UNVERIFIED .*aidr-export-retention\.timer/);
	} else {
		// No readable scheduler on this host: the check must stay unverified and
		// must never be reported as a passed installation check.
		assert.ok((evidence.unverified ?? []).includes(verdict), "the timer must be recorded as unverified, not assumed installed");
		assert.ok(!(evidence.checks ?? []).includes(verdict), "the timer must never be a passed check without reading the host scheduler");
		assert.match(result.stdout, /UNVERIFIED .*aidr-export-retention\.timer/, "the console must state the unverified timer");
		assert.match(result.stdout, /reported as PASS/);
	}
	assert.match(String(evidence.scope ?? ""), /Unverified checks were not confirmed/);
});
