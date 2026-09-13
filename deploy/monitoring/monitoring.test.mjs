import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";
import { createReadinessMonitor, loadReadinessConfig } from "../dashboard/monitoring.mjs";

const NOW = Date.parse("2026-09-12T12:00:00Z");

async function fixture(t, overrides = {}) {
	const dir = await mkdtemp(join(tmpdir(), "aidr-monitoring-"));
	t.after(() => rm(dir, { recursive: true, force: true }));
	const paths = {
		signing: join(dir, "signing.json"),
		backup: join(dir, "backup.json"),
		queue: join(dir, "queue.json"),
	};
	await Promise.all([
		writeFile(paths.signing, JSON.stringify({ schema_version: 1, status: "ok", last_success_at: "2026-09-12T11:59:00Z", active_key_expires_at: "2027-09-12T12:00:00Z" })),
		writeFile(paths.backup, JSON.stringify({ schema_version: 1, status: "ok", completed_at: "2026-09-12T11:00:00Z", verified_at: "2026-09-12T11:10:00Z" })),
		writeFile(paths.queue, JSON.stringify({ schema_version: 1, status: "ok", checked_at: "2026-09-12T11:59:30Z", depth: 4, oldest_age_seconds: 12, failed_jobs: 0 })),
	]);
	const env = {
		VITE_SUPABASE_ANON_KEY: "public-probe-key",
		AIDR_HEALTH_DATABASE_URL: "http://database.internal/rest/v1/",
		AIDR_HEALTH_STORAGE_URL: "http://storage.internal/storage/v1/status",
		AIDR_HEALTH_FUNCTIONS_URL: "http://functions.internal/functions/v1/health",
		AIDR_SIGNING_HEALTH_FILE: paths.signing,
		AIDR_BACKUP_HEALTH_FILE: paths.backup,
		AIDR_QUEUE_HEALTH_FILE: paths.queue,
		AIDR_PUBLIC_HTTPS_URL: "https://aidr.example.test",
		...overrides,
	};
	return { dir, paths, config: loadReadinessConfig(env) };
}

function healthyOverrides(calls = []) {
	return {
		now: () => NOW,
		fetch: async (url, options) => {
			calls.push({ url: String(url), options });
			return { ok: true, body: { cancel: async () => {} } };
		},
		probeCertificate: async () => ({ ok: true, validTo: NOW + 30 * 86400 * 1000 }),
	};
}

test("all seven checks pass and fixed safe metrics are emitted", async (t) => {
	const { config, paths } = await fixture(t);
	const calls = [];
	const monitor = createReadinessMonitor(config, healthyOverrides(calls));
	const snapshot = await monitor.snapshot();
	assert.equal(snapshot.ready, true);
	assert.deepEqual(Object.values(snapshot.checks).map((check) => check.ok), [true, true, true, true, true, true, true]);
	assert.deepEqual(calls.map((call) => call.options.method), ["GET", "GET", "OPTIONS"]);
	assert.ok(calls.every((call) => call.options.headers.apikey === "public-probe-key"));
	const metrics = await monitor.metrics();
	assert.match(metrics, /aidr_readiness 1/);
	assert.match(metrics, /aidr_backup_age_seconds 3600/);
	assert.match(metrics, /aidr_queue_depth 4/);
	assert.match(metrics, /aidr_certificate_remaining_seconds 2592000/);
	for (const value of [paths.signing, paths.backup, paths.queue, "public-probe-key", "aidr.example.test"]) assert.equal(metrics.includes(value), false);
});

test("missing configuration fails closed without invoking network probes", async () => {
	const config = loadReadinessConfig({});
	let fetches = 0;
	const monitor = createReadinessMonitor(config, {
		now: () => NOW,
		fetch: async () => { fetches += 1; throw new Error("must not run"); },
		probeCertificate: async () => ({ ok: false, code: "unconfigured" }),
	});
	const safe = await monitor.safeSnapshot();
	assert.equal(safe.status, "not_ready");
	assert.deepEqual(Object.keys(safe.checks), ["database", "storage", "functions", "signing", "backup", "queue", "certificate"]);
	assert.ok(Object.values(safe.checks).every((status) => status === "failed"));
	assert.equal(fetches, 0);
});

test("safe readiness output excludes causes, endpoints, paths, and credentials", async (t) => {
	const { config, paths } = await fixture(t, { VITE_SUPABASE_ANON_KEY: "do-not-return-this" });
	const monitor = createReadinessMonitor(config, {
		...healthyOverrides(),
		fetch: async () => { throw new Error("private backend exception"); },
	});
	const body = JSON.stringify(await monitor.safeSnapshot());
	assert.equal(JSON.parse(body).status, "not_ready");
	for (const value of ["do-not-return-this", "private backend exception", paths.signing, "database.internal", "unavailable"]) assert.equal(body.includes(value), false);
});

test("stale backup, stale signer, queue failures, and expiring certificate fail readiness", async (t) => {
	const { config, paths } = await fixture(t);
	await Promise.all([
		writeFile(paths.signing, JSON.stringify({ schema_version: 1, status: "ok", last_success_at: "2026-09-12T10:00:00Z", active_key_expires_at: "2026-09-13T12:00:00Z" })),
		writeFile(paths.backup, JSON.stringify({ schema_version: 1, status: "ok", completed_at: "2026-09-10T00:00:00Z", verified_at: "2026-09-10T00:10:00Z" })),
		writeFile(paths.queue, JSON.stringify({ schema_version: 1, status: "ok", checked_at: "2026-09-12T11:59:30Z", depth: 4, oldest_age_seconds: 12, failed_jobs: 1 })),
	]);
	const monitor = createReadinessMonitor(config, {
		...healthyOverrides(),
		probeCertificate: async () => ({ ok: true, validTo: NOW + 86400 * 1000 }),
	});
	const snapshot = await monitor.snapshot();
	assert.equal(snapshot.ready, false);
	for (const name of ["signing", "backup", "queue", "certificate"]) assert.equal(snapshot.checks[name].ok, false);
	for (const name of ["database", "storage", "functions"]) assert.equal(snapshot.checks[name].ok, true);
});

test("malformed or oversized evidence fails closed", async (t) => {
	const { config, paths } = await fixture(t);
	await writeFile(paths.signing, JSON.stringify({ schema_version: 1, status: "ok", last_success_at: "2026-09-12T11:59:00Z", active_key_expires_at: "2027-09-12T12:00:00Z", private_key: "must-not-be-accepted" }));
	await writeFile(paths.queue, "x".repeat(16 * 1024 + 1));
	const snapshot = await createReadinessMonitor(config, healthyOverrides()).snapshot();
	assert.equal(snapshot.checks.signing.ok, false);
	assert.equal(snapshot.checks.queue.ok, false);
	assert.equal(snapshot.ready, false);
});

test("future-dated evidence cannot appear fresh", async (t) => {
	const { config, paths } = await fixture(t);
	await Promise.all([
		writeFile(paths.signing, JSON.stringify({ schema_version: 1, status: "ok", last_success_at: "2026-09-12T12:01:00Z", active_key_expires_at: "2027-09-12T12:00:00Z" })),
		writeFile(paths.backup, JSON.stringify({ schema_version: 1, status: "ok", completed_at: "2026-09-12T12:01:00Z", verified_at: "2026-09-12T12:02:00Z" })),
		writeFile(paths.queue, JSON.stringify({ schema_version: 1, status: "ok", checked_at: "2026-09-12T12:01:00Z", depth: 0, oldest_age_seconds: 0, failed_jobs: 0 })),
	]);
	const snapshot = await createReadinessMonitor(config, healthyOverrides()).snapshot();
	assert.equal(snapshot.checks.signing.ok, false);
	assert.equal(snapshot.checks.backup.ok, false);
	assert.equal(snapshot.checks.queue.ok, false);
});

test("configuration rejects secret-bearing URLs and unknown checks", () => {
	assert.throws(() => loadReadinessConfig({ AIDR_HEALTH_DATABASE_URL: "https://user:secret@example.test/rest/v1/" }), /credentials/);
	assert.throws(() => loadReadinessConfig({ AIDR_HEALTH_DATABASE_URL: "https://example.test/rest/v1/?token=secret" }), /query/);
	assert.throws(() => loadReadinessConfig({ AIDR_HEALTH_DATABASE_URL: "https://example.test/not-database" }), /rest\/v1/);
	assert.throws(() => loadReadinessConfig({ AIDR_SIGNING_HEALTH_FILE: "relative/signing.json" }), /absolute path/);
	assert.throws(() => loadReadinessConfig({ AIDR_READINESS_REQUIRED_CHECKS: "database,unknown" }), /supported check names/);
});

test("concurrent snapshots share a probe and completed snapshots use the cache", async (t) => {
	const { config } = await fixture(t, { AIDR_READINESS_REQUIRED_CHECKS: "database", AIDR_READINESS_CACHE_MS: "5000" });
	let fetches = 0;
	const monitor = createReadinessMonitor(config, {
		...healthyOverrides(),
		fetch: async () => {
			fetches += 1;
			await new Promise((done) => setTimeout(done, 10));
			return { ok: true, body: { cancel: async () => {} } };
		},
	});
	await Promise.all([monitor.snapshot(), monitor.snapshot()]);
	await monitor.snapshot();
	assert.equal(fetches, 3, "one collection performs three HTTP checks; concurrent/cache calls perform none");
});

test("server wires liveness, fail-closed readiness, and safe metrics", async (t) => {
	const dir = await mkdtemp(join(tmpdir(), "aidr-monitoring-server-"));
	t.after(() => rm(dir, { recursive: true, force: true }));
	await writeFile(join(dir, "index.html"), "ok");
	const serverPath = resolve("deploy/dashboard/server.mjs");
	const privateMarker = "private-marker-never-return";
	const privatePath = join(dir, privateMarker);
	const child = spawn(process.execPath, [serverPath], {
		cwd: resolve("."),
		env: {
			...process.env,
			PORT: "0",
			AIDR_STATIC_DIR: dir,
			VITE_SUPABASE_URL: "http://127.0.0.1:9",
			VITE_SUPABASE_ANON_KEY: "sb_publishable_test",
			AIDR_SIGNING_HEALTH_FILE: privatePath,
		},
		stdio: ["ignore", "pipe", "pipe"],
	});
	t.after(() => child.kill());
	const port = await new Promise((resolvePort, reject) => {
		const timer = setTimeout(() => reject(new Error("server start timeout")), 15000);
		child.once("exit", (code) => reject(new Error(`server exited ${code}`)));
		child.stdout.on("data", (chunk) => {
			const match = String(chunk).match(/listening on (\d+)/);
			if (match) { clearTimeout(timer); resolvePort(Number(match[1])); }
		});
	});
	const base = `http://127.0.0.1:${port}`;
	const live = await fetch(`${base}/livez`);
	assert.equal(live.status, 200);
	assert.equal((await live.json()).status, "ok");
	const health = await fetch(`${base}/healthz`);
	assert.equal(health.status, 200);
	assert.equal((await health.json()).status, "ok");
	const readiness = await fetch(`${base}/readyz`);
	assert.equal(readiness.status, 503);
	const readinessBody = await readiness.text();
	assert.equal(readinessBody.includes(privateMarker), false);
	const metrics = await fetch(`${base}/metrics`);
	assert.equal(metrics.status, 200);
	const metricsBody = await metrics.text();
	assert.match(metricsBody, /aidr_readiness 0/);
	assert.equal(metricsBody.includes(privateMarker), false);
});
