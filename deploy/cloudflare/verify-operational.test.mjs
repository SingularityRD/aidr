import assert from "node:assert/strict";
import { test } from "node:test";
import { verifyCloudflareOperational } from "./verify-operational.mjs";

const baseUrl = "https://aidr.example.workers.dev";
const expectedVersion = "1.2.3";
const expectedSha = "a".repeat(40);
const responses = {
	"/livez": [200, { status: "alive" }],
	"/healthz": [200, { status: "alive" }],
	"/version": [200, { version: expectedVersion, git_sha: expectedSha }],
	"/readyz": [503, { status: "not_ready", component: "cloud-control-plane", checks: {
		auth: "reachable", database: "reachable", storage: "reachable", functions: "reachable",
		signing: "unverified", backup: "unverified", queue: "unverified", certificate: "unverified",
	} }],
	"/metrics": [501, { error: "metrics_not_supported" }],
};

function fetcher(overrides = {}) {
	return async (url, options) => {
		assert.equal(options.redirect, "manual");
		assert.ok(options.signal);
		const path = new URL(url).pathname;
		const [status, body] = overrides[path] ?? responses[path];
		return Response.json(body, { status, headers: { "cache-control": "no-store" } });
	};
}

test("pilot probe verifies all operational routes but cannot grant production readiness", async () => {
	const input = { baseUrl, expectedVersion, expectedSha, fetchImpl: fetcher() };
	assert.deepEqual(await verifyCloudflareOperational({ ...input, pilot: true }), {
		status: "pilot_only", production_ready: false, version: expectedVersion, git_sha: expectedSha, origin: baseUrl,
	});
	await assert.rejects(verifyCloudflareOperational(input), /production acceptance is blocked/);
});

test("rejects a stale SPA, wrong version and false successful readiness", async () => {
	const input = { baseUrl, expectedVersion, expectedSha, pilot: true };
	await assert.rejects(verifyCloudflareOperational({ ...input, fetchImpl: async (url, options) => {
		if (new URL(url).pathname === "/livez") return new Response("<html>SPA</html>", { headers: { "content-type": "text/html", "cache-control": "no-store" } });
		return fetcher()(url, options);
	} }), /\/livez did not return JSON/);
	await assert.rejects(verifyCloudflareOperational({ ...input, fetchImpl: fetcher({ "/version": [200, { version: "1.2.2", git_sha: expectedSha }] }) }), /\/version did not match/);
	await assert.rejects(verifyCloudflareOperational({ ...input, fetchImpl: fetcher({ "/readyz": [200, { status: "ready" }] }) }), /\/readyz did not match/);
});

test("accepts failed provider components only as a fail-closed pilot, not GA", async () => {
	const checks = { ...responses["/readyz"][1].checks, auth: "failed", functions: "failed" };
	const input = { baseUrl, expectedVersion, expectedSha, fetchImpl: fetcher({ "/readyz": [503, { status: "not_ready", component: "cloud-control-plane", checks }] }) };
	assert.equal((await verifyCloudflareOperational({ ...input, pilot: true })).production_ready, false);
	await assert.rejects(verifyCloudflareOperational(input), /production acceptance is blocked/);
});

test("rejects unbounded and cacheable operational responses", async () => {
	const input = { baseUrl, expectedVersion, expectedSha, pilot: true };
	await assert.rejects(verifyCloudflareOperational({ ...input, fetchImpl: async (url, options) => {
		if (new URL(url).pathname === "/livez") return Response.json({ status: "alive", padding: "x".repeat(2048) }, { headers: { "cache-control": "no-store" } });
		return fetcher()(url, options);
	} }), /\/livez response is oversized/);
	await assert.rejects(verifyCloudflareOperational({ ...input, fetchImpl: async (url, options) => {
		if (new URL(url).pathname === "/version") return Response.json(responses["/version"][1]);
		return fetcher()(url, options);
	} }), /\/version may be cached/);
});
