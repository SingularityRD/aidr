import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { lstat, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { runReadinessEvidenceWorker } from "./readiness-evidence-worker.mjs";

async function fixture(t) {
	const root = await mkdtemp(join(tmpdir(), "aidr-readiness-worker-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const deployment = join(root, "deployment");
	const health = join(deployment, "health");
	const queueRoot = join(root, "telemetry");
	const queueNamespace = join(queueRoot, "a".repeat(64));
	await Promise.all([mkdir(health, { recursive: true }), mkdir(queueNamespace, { recursive: true })]);
	const keys = generateKeyPairSync("ed25519");
	const delegationKeys = generateKeyPairSync("ed25519");
	const signingPrivate = keys.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
	await writeFile(join(deployment, ".env.functions"), [
		`AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64=${signingPrivate}`,
		`AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64=${signingPrivate}`,
		`AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64=${delegationKeys.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64")}`,
		`AIDR_DELEGATION_SIGNING_PUBLIC_KEY_SPKI_B64=${delegationKeys.publicKey.export({ type: "spki", format: "der" }).toString("base64")}`,
	].join("\n") + "\n", { mode: 0o600 });
	await writeFile(join(deployment, "deployment.json"), JSON.stringify({ schema_version: 1, mode: "self-hosted" }));
	await writeFile(join(deployment, "agent-config.json"), JSON.stringify({ licensing: { public_keys_pem: [keys.publicKey.export({ type: "spki", format: "pem" })] } }));
	return {
		root, deployment, health, queueRoot, keys,
		env: {
			AIDR_DEPLOYMENT_DIR: deployment,
			AIDR_HEALTH_STATE_DIR: health,
			AIDR_SIGNING_KEY_EXPIRES_AT: "2027-09-22T00:00:00.000Z",
			AIDR_DELEGATION_SIGNING_KEY_EXPIRES_AT: "2027-08-22T00:00:00.000Z",
			AIDR_TELEMETRY_QUEUE_ROOTS: queueRoot,
		},
	};
}

test("publishes real signing and bound queue evidence without identifiers", async (t) => {
	const f = await fixture(t);
	const output = [];
	const errors = [];
	const result = await runReadinessEvidenceWorker(f.env, undefined, { out: (value) => output.push(value), err: (value) => errors.push(value) });
	assert.equal(result, 0);
	assert.equal(errors.join(""), "");
	assert.deepEqual(JSON.parse(output.join("")), { type: "aidr_readiness_evidence", signing: true, queue: true });
	const signing = JSON.parse(await readFile(join(f.health, "signing.json"), "utf8"));
	const queue = JSON.parse(await readFile(join(f.health, "queue.json"), "utf8"));
	assert.deepEqual(Object.keys(signing), ["schema_version", "status", "last_success_at", "active_key_expires_at"]);
	assert.equal(signing.active_key_expires_at, "2027-08-22T00:00:00.000Z");
	assert.deepEqual(queue, { schema_version: 1, status: "ok", checked_at: signing.last_success_at, depth: 0, oldest_age_seconds: 0, failed_jobs: 0 });
	assert.equal(JSON.stringify({ signing, queue }).includes("PUBLIC KEY"), false);
	if (process.platform !== "win32") {
		assert.equal((await stat(f.health)).mode & 0o777, 0o755);
		assert.equal((await stat(join(f.health, "signing.json"))).mode & 0o777, 0o644);
	}
});

test("replaces stale green evidence with failed evidence on signer and source failure", async (t) => {
	const f = await fixture(t);
	await writeFile(join(f.health, "signing.json"), '{"schema_version":1,"status":"ok"}\n');
	await writeFile(join(f.health, "queue.json"), '{"schema_version":1,"status":"ok"}\n');
	const other = generateKeyPairSync("ed25519");
	await writeFile(join(f.deployment, "agent-config.json"), JSON.stringify({ licensing: { public_keys_pem: [other.publicKey.export({ type: "spki", format: "pem" })] } }));
	const errors = [];
	const result = await runReadinessEvidenceWorker(
		{ ...f.env, AIDR_TELEMETRY_QUEUE_ROOTS: join(f.root, "missing") },
		undefined,
		{ out: () => undefined, err: (value) => errors.push(value) },
	);
	assert.equal(result, 2);
	assert.equal(errors.join(""), "readiness_evidence_failed\n");
	for (const name of ["signing", "queue"]) {
		const evidence = JSON.parse(await readFile(join(f.health, `${name}.json`), "utf8"));
		assert.deepEqual(Object.keys(evidence), ["schema_version", "status", "checked_at"]);
		assert.equal(evidence.status, "failed");
	}
});

test("verifies the exact signing keys loaded by the functions runtime", async (t) => {
	const f = await fixture(t);
	const other = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
	const path = join(f.deployment, ".env.functions");
	const current = await readFile(path, "utf8");
	await writeFile(path, current.replace(/^AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64=.*$/m, `AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64=${other}`));
	const result = await runReadinessEvidenceWorker(f.env, undefined, { out: () => undefined, err: () => undefined });
	assert.equal(result, 2);
	assert.equal(JSON.parse(await readFile(join(f.health, "signing.json"), "utf8")).status, "failed");
});

test("managed cloud stays failed until a provider-side signing canary exists", async (t) => {
	const f = await fixture(t);
	await writeFile(join(f.deployment, "deployment.json"), JSON.stringify({ schema_version: 1, mode: "cloud" }));
	const result = await runReadinessEvidenceWorker(f.env, undefined, { out: () => undefined, err: () => undefined });
	assert.equal(result, 2);
	assert.equal(JSON.parse(await readFile(join(f.health, "signing.json"), "utf8")).status, "failed");
});

test("retry-pending telemetry namespaces fail queue evidence", async (t) => {
	const f = await fixture(t);
	const written = new Map();
	const dependencies = {
		readFile,
		lstat,
		now: () => Date.parse("2026-09-22T12:00:00.000Z"),
		writeEvidence: async (path, value) => written.set(path, value),
		readTelemetryLossSummary: async () => ({
			state: "queued", queues: 1, pendingEvents: 1, oldestAgeSeconds: 1, lostTotal: 0,
			namespaces: [{ namespace: "a".repeat(64), pendingEvents: 1, lostTotal: 0, state: "degraded" }],
		}),
		drainConfiguredSiemDelivery: async () => undefined,
		inspectConfiguredSiemDelivery: async () => { throw new Error("not used"); },
	};
	const result = await runReadinessEvidenceWorker(f.env, dependencies, { out: () => undefined, err: () => undefined });
	assert.equal(result, 2);
	assert.deepEqual(written.get(join(f.health, "queue.json")), {
		schema_version: 1,
		status: "failed",
		checked_at: "2026-09-22T12:00:00.000Z",
		depth: 1,
		oldest_age_seconds: 1,
		failed_jobs: 0,
	});
});

test("stale telemetry backlog fails readiness while fresh backlog remains healthy", async (t) => {
	const f = await fixture(t);
	const written = new Map();
	const dependencies = {
		readFile,
		lstat,
		now: () => Date.parse("2026-09-22T12:00:00.000Z"),
		writeEvidence: async (path, value) => written.set(path, value),
		readTelemetryLossSummary: async (_root, _options) => ({
			state: "queued",
			queues: 1,
			pendingEvents: 1,
			oldestAgeSeconds: 301,
			lostTotal: 0,
			namespaces: [{ namespace: "a".repeat(64), pendingEvents: 1, lostTotal: 0, state: "degraded" }],
		}),
	};
	const staleResult = await runReadinessEvidenceWorker(f.env, dependencies, {
		out: () => undefined,
		err: () => undefined,
	});
	assert.equal(staleResult, 2);
	assert.equal(written.get(join(f.health, "queue.json")).status, "failed");
	assert.equal(written.get(join(f.health, "queue.json")).oldest_age_seconds, 301);

	dependencies.readTelemetryLossSummary = async () => ({
		state: "queued",
		queues: 1,
		pendingEvents: 1,
		oldestAgeSeconds: 299,
		lostTotal: 0,
		namespaces: [{ namespace: "a".repeat(64), pendingEvents: 1, lostTotal: 0, state: "ok" }],
	});
	const freshResult = await runReadinessEvidenceWorker(f.env, dependencies, {
		out: () => undefined,
		err: () => undefined,
	});
	assert.equal(freshResult, 0);
	assert.equal(written.get(join(f.health, "queue.json")).status, "ok");
	assert.equal(written.get(join(f.health, "queue.json")).oldest_age_seconds, 299);
});

test("aggregates configured SIEM queue health as a real source", async (t) => {
	const f = await fixture(t);
	const written = new Map();
	const dependencies = {
		readFile,
		lstat,
		now: () => Date.parse("2026-09-22T12:00:00.000Z"),
		writeEvidence: async (path, value) => written.set(path, value),
		readTelemetryLossSummary: async () => { throw new Error("telemetry should not be read"); },
		drainConfiguredSiemDelivery: async (maxItems) => { assert.equal(maxItems, 25); },
		inspectConfiguredSiemDelivery: async () => ({ status: "degraded", queueDepth: 3, oldestQueuedAgeMs: 4_500, deadLettered: 1 }),
	};
	const result = await runReadinessEvidenceWorker(
		{ ...f.env, AIDR_TELEMETRY_QUEUE_ROOTS: "", SINGULARITY_AIDR_SIEM_CONFIG_PATH: join(f.root, "siem.json"), AIDR_DRAIN_SIEM: "true" },
		dependencies,
		{ out: () => undefined, err: () => undefined },
	);
	assert.equal(result, 2);
	assert.deepEqual(written.get(join(f.health, "queue.json")), {
		schema_version: 1,
		status: "failed",
		checked_at: "2026-09-22T12:00:00.000Z",
		depth: 3,
		oldest_age_seconds: 4,
		failed_jobs: 1,
	});
});

test("the single installer activates readiness and gates optional backup activation", async () => {
	const root = join(dirname(fileURLToPath(import.meta.url)), "..");
	const installer = await readFile(join(root, "deploy", "maintenance", "install-systemd.sh"), "utf8");
	assert.match(installer, /systemctl enable --now aidr-siem-delivery\.timer/);
	assert.match(installer, /if \[ "\$with_backup" = true \]/);
	assert.match(installer, /\[ -f \/etc\/aidr\/backup-offsite\.env \] && \[ -f \/etc\/aidr\/aidr-recovery\.key \]/);
	const backupPreflight = installer.indexOf("backup environment or recovery key is missing");
	const firstHostMutation = installer.indexOf("install -m 0644");
	assert.ok(backupPreflight < firstHostMutation, "all requested backup inputs must be validated before any unit is installed or enabled");
	assert.match(installer, /maintenance\/aidr-siem-delivery\.service/);
	assert.match(installer, /backup\/aidr-backup-offsite\.service/);
	assert.match(installer, /telemetry queue roots must be under \/var\/lib\/aidr-telemetry/);
	assert.match(installer, /real fleet-aggregated queue namespace/);
	assert.match(installer, /SIEM state_file must be under \/var\/lib\/aidr-siem/);
	assert.match(installer, /systemctl start aidr-siem-delivery\.service/);
});

test("the existing maintenance timer owns the only readiness cadence and writable queue roots", async () => {
	const root = join(dirname(fileURLToPath(import.meta.url)), "..");
	const service = await readFile(join(root, "deploy", "maintenance", "aidr-siem-delivery.service"), "utf8");
	const timer = await readFile(join(root, "deploy", "maintenance", "aidr-siem-delivery.timer"), "utf8");
	assert.match(service, /readiness-evidence-worker\.mjs/);
	assert.match(service, /^ExecStart=\/usr\/bin\/node \/srv\/aidr\/maintenance\/readiness-evidence-worker\.mjs$/m);
	assert.doesNotMatch(service, /\/opt\/aidr-kit/);
	assert.doesNotMatch(service, /^ConditionPathExists=/m);
	assert.doesNotMatch(service, /^LoadCredential=/m);
	assert.match(service, /^EnvironmentFile=-\/srv\/aidr\/\.env\.readiness$/m);
	assert.match(service, /^ReadWritePaths=.*\/srv\/aidr\/health .*\/var\/lib\/aidr-siem .*?-\/var\/lib\/aidr-telemetry$/m);
	assert.match(timer, /^OnUnitActiveSec=1min$/m);
	assert.equal(timer.includes("aidr-readiness-evidence"), false);
});
