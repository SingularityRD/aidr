#!/usr/bin/env node
import { createPrivateKey, createPublicKey, randomBytes, sign, verify } from "node:crypto";
import { chmod, lstat, mkdir, open, readFile, rename, rm } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const FAILURE = (checkedAt) => ({ schema_version: 1, status: "failed", checked_at: checkedAt });

async function atomicEvidence(path, value) {
	await mkdir(dirname(path), { recursive: true, mode: 0o755 });
	await chmod(dirname(path), 0o755);
	const temporary = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
	try {
		const handle = await open(temporary, "wx", 0o600);
		try {
			await handle.writeFile(`${JSON.stringify(value)}\n`, "utf8");
			await handle.sync();
		} finally {
			await handle.close();
		}
		await chmod(temporary, 0o644);
		await rename(temporary, path);
		if (process.platform !== "win32") {
			const directory = await open(dirname(path), "r");
			try { await directory.sync(); } finally { await directory.close(); }
		}
	} catch (error) {
		await rm(temporary, { force: true });
		throw error;
	}
}

function timestamp(value) {
	if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value)) return null;
	const millis = Date.parse(value);
	return Number.isFinite(millis) ? millis : null;
}

function queueRoots(raw) {
	const roots = (raw ?? "").split(",").map((value) => value.trim()).filter(Boolean);
	if (roots.some((path) => !isAbsolute(path) || path.includes("\0") || /^REPLACE_/i.test(path))) throw new Error("queue_roots_unconfigured");
	const resolved = roots.map((path) => resolve(path));
	if (new Set(resolved).size !== resolved.length) throw new Error("duplicate_queue_root");
	return resolved;
}

async function signingEvidence(env, dependencies, now) {
	const deployment = resolve(env.AIDR_DEPLOYMENT_DIR || "/srv/aidr");
	const deploymentManifest = JSON.parse(await dependencies.readFile(join(deployment, "deployment.json"), "utf8"));
	if (deploymentManifest?.mode !== "self-hosted") throw new Error("provider_signing_canary_required");
	const functionEnvPath = join(deployment, ".env.functions");
	const functionEnvInfo = await dependencies.lstat(functionEnvPath);
	if (!functionEnvInfo.isFile() || functionEnvInfo.isSymbolicLink() || functionEnvInfo.size < 32 || functionEnvInfo.size > 65_536) throw new Error("invalid_function_environment");
	const functionEnv = new Map();
	for (const line of (await dependencies.readFile(functionEnvPath, "utf8")).split(/\r?\n/)) {
		if (!line || line.startsWith("#")) continue;
		const separator = line.indexOf("=");
		if (separator <= 0) throw new Error("invalid_function_environment");
		const name = line.slice(0, separator);
		if (functionEnv.has(name)) throw new Error("duplicate_function_environment_key");
		functionEnv.set(name, line.slice(separator + 1));
	}
	function keyBytes(name) {
		const value = functionEnv.get(name);
		if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) throw new Error("invalid_signing_credential");
		const bytes = Buffer.from(value, "base64");
		if (bytes.toString("base64") !== value || bytes.length < 32 || bytes.length > 4096) throw new Error("invalid_signing_credential");
		return bytes;
	}
	function privateKey(name) {
		const key = createPrivateKey({ key: keyBytes(name), format: "der", type: "pkcs8" });
		if (key.asymmetricKeyType !== "ed25519") throw new Error("invalid_signing_key_type");
		return key;
	}
	const entitlementPrivateKey = privateKey("AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64");
	const revocationPrivateKey = privateKey("AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64");
	const delegationPrivateKey = privateKey("AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64");

	const config = JSON.parse(await dependencies.readFile(join(deployment, "agent-config.json"), "utf8"));
	const publicKeys = config?.licensing?.public_keys_pem;
	if (!Array.isArray(publicKeys) || publicKeys.length === 0) throw new Error("signing_public_key_unavailable");
	const challenge = randomBytes(32);
	for (const privateSigningKey of [entitlementPrivateKey, revocationPrivateKey]) {
		const signature = sign(null, challenge, privateSigningKey);
		const verified = publicKeys.some((value) => {
			try {
				const key = createPublicKey(value);
				return key.asymmetricKeyType === "ed25519" && verify(null, challenge, key, signature);
			} catch { return false; }
		});
		if (!verified) throw new Error("signing_canary_failed");
	}
	const delegationPublicKey = createPublicKey({ key: keyBytes("AIDR_DELEGATION_SIGNING_PUBLIC_KEY_SPKI_B64"), format: "der", type: "spki" });
	if (delegationPublicKey.asymmetricKeyType !== "ed25519" || !verify(null, challenge, delegationPublicKey, sign(null, challenge, delegationPrivateKey))) throw new Error("delegation_signing_canary_failed");

	const expiries = [timestamp(env.AIDR_SIGNING_KEY_EXPIRES_AT), timestamp(env.AIDR_DELEGATION_SIGNING_KEY_EXPIRES_AT)];
	if (expiries.some((expiry) => expiry === null || expiry <= now)) throw new Error("signing_key_expiry_invalid");
	return {
		schema_version: 1,
		status: "ok",
		last_success_at: new Date(now).toISOString(),
		active_key_expires_at: new Date(Math.min(...expiries)).toISOString(),
	};
}

async function queueEvidence(env, dependencies, now) {
	let queues = 0;
	let depth = 0;
	let oldest = 0;
	let failed = 0;
	let sourceFailed = false;
	for (const root of queueRoots(env.AIDR_TELEMETRY_QUEUE_ROOTS)) {
		const info = await dependencies.lstat(root);
		if (!info.isDirectory() || info.isSymbolicLink()) throw new Error("invalid_queue_root");
		const summary = await dependencies.readTelemetryLossSummary(root, { now: () => now });
		if (summary.state === "unavailable" || summary.queues === 0) throw new Error("queue_state_unavailable");
		queues += summary.queues;
		depth += summary.pendingEvents;
		oldest = Math.max(oldest, summary.oldestAgeSeconds);
		failed += summary.lostTotal;
		sourceFailed ||= summary.namespaces.some((namespace) => namespace.state !== "ok");
	}
	if (env.SINGULARITY_AIDR_SIEM_CONFIG_PATH) {
		if (env.AIDR_DRAIN_SIEM !== "true") throw new Error("siem_drain_unconfigured");
		await dependencies.drainConfiguredSiemDelivery(25);
		const health = await dependencies.inspectConfiguredSiemDelivery();
		queues += 1;
		depth += health.queueDepth;
		oldest = Math.max(oldest, Math.floor(health.oldestQueuedAgeMs / 1000));
		failed += health.deadLettered;
		sourceFailed ||= health.status !== "healthy";
	}
	if (queues === 0) throw new Error("queue_sources_unbound");
	return {
		schema_version: 1,
		status: !sourceFailed && failed === 0 ? "ok" : "failed",
		checked_at: new Date(now).toISOString(),
		depth,
		oldest_age_seconds: oldest,
		failed_jobs: failed,
	};
}

const defaultDependencies = {
	readFile,
	lstat,
	writeEvidence: atomicEvidence,
	async readTelemetryLossSummary(root, options) {
		const module = await import("../packages/core/dist/telemetry-queue.js");
		return module.readTelemetryLossSummary(root, options);
	},
	async inspectConfiguredSiemDelivery() {
		const module = await import("../packages/core/dist/siem-incident-producer.js");
		return module.inspectConfiguredSiemDelivery();
	},
	async drainConfiguredSiemDelivery(maxItems) {
		const module = await import("../packages/core/dist/siem-incident-producer.js");
		return module.drainConfiguredSiemDelivery(maxItems);
	},
	now: () => Date.now(),
};

export async function runReadinessEvidenceWorker(
	env = process.env,
	dependencies = defaultDependencies,
	io = { out: (value) => process.stdout.write(value), err: (value) => process.stderr.write(value) },
) {
	const healthDirectory = resolve(env.AIDR_HEALTH_STATE_DIR || "/srv/aidr/health");
	const now = dependencies.now();
	const checkedAt = new Date(now).toISOString();
	const results = { signing: false, queue: false };
	for (const [name, collect] of [["signing", signingEvidence], ["queue", queueEvidence]]) {
		try {
			const evidence = await collect(env, dependencies, now);
			await dependencies.writeEvidence(join(healthDirectory, `${name}.json`), evidence);
			results[name] = evidence.status === "ok";
		} catch {
			try { await dependencies.writeEvidence(join(healthDirectory, `${name}.json`), FAILURE(checkedAt)); } catch { /* exit remains non-zero */ }
		}
	}
	io.out(`${JSON.stringify({ type: "aidr_readiness_evidence", ...results })}\n`);
	if (!results.signing || !results.queue) {
		io.err("readiness_evidence_failed\n");
		return 2;
	}
	return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	process.exitCode = await runReadinessEvidenceWorker();
}
