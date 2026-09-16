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
const firstPath = `${tenantId}/44444444-4444-4444-8444-444444444444.json`;
const secondPath = `${tenantId}/55555555-5555-4555-8555-555555555555.json`;
const authorizationIds = [
	"66666666-6666-4666-8666-666666666666",
	"77777777-7777-4777-8777-777777777777",
];

function storageBatch(paths = [firstPath]) {
	return {
		run_id: runId,
		status: "running",
		complete: false,
		action: "delete_storage_objects",
		paths,
		objects: paths.map((path, index) => ({ path, authorization_id: authorizationIds[index] })),
	};
}
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
			if (runCalls === 1) return json(response, 200, storageBatch([firstPath, secondPath]));
			if (runCalls === 2) return json(response, 200, { run_id: runId, status: "running", phase: "events", rows_deleted: 100 });
			return json(response, 200, { run_id: runId, status: "completed", complete: true });
		}
		if (request.url === "/storage/v1/object/aidr-audit-exports" && request.method === "DELETE") return json(response, 200, [{ name: secondPath }, { name: firstPath }]);
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
	assert.deepEqual(calls[storageIndex].body.prefixes, [firstPath, secondPath]);
	assert.equal(calls[storageIndex].method, "DELETE");
	assert.equal(calls[ackIndex].method, "POST");
	assert.deepEqual(calls[ackIndex].body, {
		p_run_id: runId,
		p_paths: [firstPath, secondPath],
		p_authorization_ids: authorizationIds,
	});
	for (const objectPath of [firstPath, secondPath]) {
		const verificationIndex = calls.findIndex((call) => call.url === `/storage/v1/object/info/aidr-audit-exports/${objectPath}`);
		assert.ok(verificationIndex > storageIndex && verificationIndex < ackIndex, "every object must be verified absent before ACK");
		assert.equal(calls[verificationIndex].method, "GET");
	}
	assert.equal(calls.filter((call) => call.url === "/rest/v1/rpc/ack_tenant_offboarding_objects").length, 1);
	assert.equal(calls.some((call) => call.url.startsWith("/rest/v1/tenant_legal_holds?")), false, "durable authorization replaces the racy hold lookup");
	assert.equal(runCalls, 3);
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
		if (request.url === "/rest/v1/rpc/run_tenant_offboarding_batch") return json(response, 200, storageBatch([firstPath, secondPath]));
		if (request.url === "/storage/v1/object/aidr-audit-exports") return json(response, 200, [{ name: firstPath }, { name: secondPath }]);
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

test("an authorized exact deletion receipt can acknowledge an object verified absent from storage", async () => {
	const objectPath = `${tenantId}/44444444-4444-4444-8444-444444444444.json`;
	let acknowledged = false;
	const directory = await fixture((request, response) => {
		if (request.url === "/rest/v1/rpc/request_tenant_offboarding") return json(response, 200, { run_id: runId, tenant_id: tenantId, status: "requested", backup_scope: "excluded_external_retention" });
		if (request.url === "/rest/v1/rpc/run_tenant_offboarding_batch") return json(response, 200, storageBatch([objectPath]));
		if (request.url === "/storage/v1/object/aidr-audit-exports") return json(response, 200, [{ name: objectPath }]);
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

const invalidAuthorizationBatches = [
	["missing objects", { ...storageBatch(), objects: undefined }],
	["empty objects", { ...storageBatch(), objects: [] }],
	["missing token", { ...storageBatch(), objects: [{ path: firstPath }] }],
	["non-UUID token", { ...storageBatch(), objects: [{ path: firstPath, authorization_id: "not-a-uuid" }] }],
	["coercible array token", { ...storageBatch(), objects: [{ path: firstPath, authorization_id: [authorizationIds[0]] }] }],
	["missing authorized path", { ...storageBatch(), objects: [{ authorization_id: authorizationIds[0] }] }],
	["mismatched authorized path", { ...storageBatch(), objects: [{ path: secondPath, authorization_id: authorizationIds[0] }] }],
	["extra authorized object", { ...storageBatch([firstPath, secondPath]), paths: [firstPath] }],
	["duplicate paths", storageBatch([firstPath, firstPath])],
	["duplicate tokens", { ...storageBatch([firstPath, secondPath]), objects: [firstPath, secondPath].map((path) => ({ path, authorization_id: authorizationIds[0] })) }],
	["cross-tenant path", storageBatch([`${operatorId}/44444444-4444-4444-8444-444444444444.json`])],
];

for (const [label, batch] of invalidAuthorizationBatches) {
	test(`invalid storage authorization (${label}) refuses DELETE and ACK`, async () => {
		const calls = [];
		const directory = await fixture((request, response) => {
			calls.push({ method: request.method, url: request.url });
			if (request.url === "/rest/v1/rpc/request_tenant_offboarding") return json(response, 200, { run_id: runId, tenant_id: tenantId, status: "requested", backup_scope: "excluded_external_retention" });
			if (request.url === "/rest/v1/rpc/run_tenant_offboarding_batch") return json(response, 200, batch);
			return json(response, 404, {});
		});
		const result = await run(directory, ["--apply", "--requested-by", operatorId]);
		assert.equal(result.status, 1, result.stderr);
		assert.match(result.stderr, /storage|authorization/i);
		assert.equal(calls.some((call) => call.method === "DELETE" || call.url.startsWith("/storage/")), false);
		assert.equal(calls.some((call) => call.url === "/rest/v1/rpc/ack_tenant_offboarding_objects"), false);
		assert.equal(calls.filter((call) => call.url === "/rest/v1/rpc/run_tenant_offboarding_batch").length, 1);
	});
}

const mismatchedStorageResponses = [
	["empty array", []],
	["partial receipt", [{ name: firstPath }]],
	["same-size wrong path", [{ name: firstPath }, { name: `${tenantId}/88888888-8888-4888-8888-888888888888.json` }]],
	["duplicate receipt", [{ name: firstPath }, { name: firstPath }]],
	["extra receipt", [{ name: firstPath }, { name: secondPath }, { name: `${tenantId}/extra.json` }]],
	["missing names", [{}, {}]],
	["non-string names", [{ name: firstPath }, { name: 123 }]],
	["null entry", [{ name: firstPath }, null]],
	["non-array receipt", { name: firstPath }],
];

for (const [label, deletionResponse] of mismatchedStorageResponses) {
	test(`storage DELETE response (${label}) cannot acknowledge even absent objects`, async () => {
		let deletes = 0;
		let acknowledgements = 0;
		let verifications = 0;
		let batches = 0;
		const directory = await fixture((request, response) => {
			if (request.url === "/rest/v1/rpc/request_tenant_offboarding") return json(response, 200, { run_id: runId, tenant_id: tenantId, status: "requested", backup_scope: "excluded_external_retention" });
			if (request.url === "/rest/v1/rpc/run_tenant_offboarding_batch") {
				batches += 1;
				return json(response, 200, storageBatch([firstPath, secondPath]));
			}
			if (request.url === "/storage/v1/object/aidr-audit-exports" && request.method === "DELETE") {
				deletes += 1;
				return json(response, 200, deletionResponse);
			}
			if (request.url.startsWith("/storage/v1/object/info/aidr-audit-exports/")) {
				verifications += 1;
				return json(response, 404, { code: "not_found" });
			}
			if (request.url === "/rest/v1/rpc/ack_tenant_offboarding_objects") {
				acknowledgements += 1;
				return json(response, 200, { run_id: runId, status: "completed", complete: true });
			}
			if (request.url.startsWith("/rest/v1/tenant_offboarding_phase_receipts?")) return json(response, 200, []);
			return json(response, 404, {});
		});
		const evidencePath = path.join(directory, `offboarding-evidence-${tenantId}.json`);
		await writeFile(evidencePath, JSON.stringify({ tenant_id: tenantId, run_id: runId, status: "completed", complete: true }));
		const result = await run(directory, ["--apply", "--requested-by", operatorId]);
		assert.equal(result.status, 1, result.stderr);
		assert.match(result.stderr, /storage/i);
		const evidence = JSON.parse(await readFile(evidencePath, "utf8"));
		assert.equal(evidence.complete, false, "a failed attempt must replace stale success evidence");
		assert.equal(evidence.status, "incomplete");
		assert.equal(deletes, 1);
		assert.equal(acknowledgements, 0);
		assert.equal(verifications, 0, "mismatched deletion receipts must fail before absence checks");
		assert.equal(batches, 1, "an ambiguous storage result must not retry the batch");
	});
}

test("ambiguous deletion cannot become a successful ACK on a later invocation", async () => {
	let batches = 0;
	let deletes = 0;
	let acknowledgements = 0;
	const directory = await fixture((request, response) => {
		if (request.url === "/rest/v1/rpc/request_tenant_offboarding") return json(response, 200, { run_id: runId, tenant_id: tenantId, status: "running", backup_scope: "excluded_external_retention" });
		if (request.url === "/rest/v1/rpc/run_tenant_offboarding_batch") {
			batches += 1;
			return json(response, 200, batches === 1 ? storageBatch() : {
				run_id: runId, status: "running", complete: false, action: "reconcile_storage_authorizations", phase: "audit_export_objects",
			});
		}
		if (request.url === "/storage/v1/object/aidr-audit-exports" && request.method === "DELETE") {
			deletes += 1;
			return json(response, 200, []);
		}
		if (request.url.startsWith("/storage/v1/object/info/aidr-audit-exports/")) return json(response, 404, { code: "not_found" });
		if (request.url === "/rest/v1/rpc/ack_tenant_offboarding_objects") {
			acknowledgements += 1;
			return json(response, 200, { run_id: runId, status: "completed", complete: true });
		}
		if (request.url.startsWith("/rest/v1/tenant_offboarding_phase_receipts?")) return json(response, 200, [{ phase: "audit_export_objects", status: "running", rows_deleted: 0 }]);
		return json(response, 404, {});
	});
	const initial = await run(directory, ["--apply", "--requested-by", operatorId]);
	assert.equal(initial.status, 1, initial.stderr);
	assert.equal(batches, 1);
	assert.equal(deletes, 1);
	assert.equal(acknowledgements, 0);
	const retry = await run(directory, ["--apply", "--requested-by", operatorId, "--max-batches", "5"]);
	assert.equal(retry.status, 2, retry.stderr);
	assert.equal(batches, 2, "pending durable authorization stops after one batch, without reissuing a token");
	assert.equal(deletes, 1, "retry must not issue a second DELETE");
	assert.equal(acknowledgements, 0, "absence alone cannot authorize an ACK");
	const evidence = JSON.parse(await readFile(path.join(directory, `offboarding-evidence-${tenantId}.json`), "utf8"));
	assert.equal(evidence.status, "running");
	assert.equal(evidence.complete, false);
	assert.equal(evidence.batches, 1);
	assert.equal(evidence.storage_batches, 0);
});

test("pending storage authorizations stop apply without storage requests or ACK", async () => {
	const calls = [];
	const directory = await fixture((request, response) => {
		calls.push(request.url);
		if (request.url === "/rest/v1/rpc/request_tenant_offboarding") return json(response, 200, { run_id: runId, tenant_id: tenantId, status: "running", backup_scope: "excluded_external_retention" });
		if (request.url === "/rest/v1/rpc/run_tenant_offboarding_batch") return json(response, 200, { run_id: runId, status: "running", complete: false, action: "reconcile_storage_authorizations", phase: "audit_export_objects" });
		if (request.url.startsWith("/rest/v1/tenant_offboarding_phase_receipts?")) return json(response, 200, [{ phase: "audit_export_objects", status: "running", rows_deleted: 0 }]);
		return json(response, 404, {});
	});
	const result = await run(directory, ["--apply", "--requested-by", operatorId, "--max-batches", "5"]);
	assert.equal(result.status, 2, result.stderr);
	assert.equal(calls.filter((url) => url === "/rest/v1/rpc/run_tenant_offboarding_batch").length, 1);
	assert.equal(calls.some((url) => url.startsWith("/storage/")), false);
	assert.equal(calls.includes("/rest/v1/rpc/ack_tenant_offboarding_objects"), false);
	const evidence = JSON.parse(await readFile(path.join(directory, `offboarding-evidence-${tenantId}.json`), "utf8"));
	assert.equal(evidence.status, "running");
	assert.equal(evidence.complete, false);
	assert.equal(evidence.batches, 1);
	assert.equal(evidence.storage_batches, 0);
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
		if (request.url === "/rest/v1/rpc/run_tenant_offboarding_batch") return json(response, 200, storageBatch());
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
