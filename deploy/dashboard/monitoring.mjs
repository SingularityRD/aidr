import { readFile, stat } from "node:fs/promises";
import { isIP } from "node:net";
import { isAbsolute } from "node:path";
import { connect as tlsConnect } from "node:tls";

export const CHECK_NAMES = Object.freeze([
	"database",
	"storage",
	"functions",
	"signing",
	"backup",
	"queue",
	"certificate",
]);

const MAX_EVIDENCE_BYTES = 16 * 1024;

function integer(env, name, fallback, minimum, maximum) {
	const raw = env[name];
	if (raw === undefined || raw === "") return fallback;
	if (!/^\d+$/.test(raw)) throw new Error(`${name} must be an integer`);
	const value = Number(raw);
	if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
		throw new Error(`${name} is outside its supported range`);
	}
	return value;
}

function endpoint(raw, name, protocols = ["http:", "https:"], pathPrefix = null) {
	if (!raw) return null;
	let parsed;
	try {
		parsed = new URL(raw);
	} catch {
		throw new Error(`${name} must be an absolute URL`);
	}
	if (!protocols.includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) {
		throw new Error(`${name} must use an allowed protocol and contain no credentials, query, or fragment`);
	}
	if (pathPrefix !== null && !parsed.pathname.startsWith(pathPrefix)) throw new Error(`${name} must address ${pathPrefix}`);
	return parsed;
}

function evidencePath(raw, name) {
	if (!raw) return "";
	if (!isAbsolute(raw) || raw.includes("\0")) throw new Error(`${name} must be an absolute path`);
	return raw;
}

export function loadReadinessConfig(env = process.env) {
	const required = (env.AIDR_READINESS_REQUIRED_CHECKS || CHECK_NAMES.join(","))
		.split(",")
		.map((value) => value.trim())
		.filter(Boolean);
	if (required.length === 0 || new Set(required).size !== required.length || required.some((name) => !CHECK_NAMES.includes(name))) {
		throw new Error("AIDR_READINESS_REQUIRED_CHECKS must contain unique supported check names");
	}
	return Object.freeze({
		required: Object.freeze(required),
		requestTimeoutMs: integer(env, "AIDR_READINESS_TIMEOUT_MS", 3000, 100, 30000),
		cacheMs: integer(env, "AIDR_READINESS_CACHE_MS", 5000, 0, 60000),
		databaseUrl: endpoint(env.AIDR_HEALTH_DATABASE_URL, "AIDR_HEALTH_DATABASE_URL", undefined, "/rest/v1/"),
		storageUrl: endpoint(env.AIDR_HEALTH_STORAGE_URL, "AIDR_HEALTH_STORAGE_URL", undefined, "/storage/v1/"),
		functionsUrl: endpoint(env.AIDR_HEALTH_FUNCTIONS_URL, "AIDR_HEALTH_FUNCTIONS_URL", undefined, "/functions/v1/"),
		publicKey: env.VITE_SUPABASE_ANON_KEY || "",
		signingFile: evidencePath(env.AIDR_SIGNING_HEALTH_FILE, "AIDR_SIGNING_HEALTH_FILE"),
		backupFile: evidencePath(env.AIDR_BACKUP_HEALTH_FILE, "AIDR_BACKUP_HEALTH_FILE"),
		queueFile: evidencePath(env.AIDR_QUEUE_HEALTH_FILE, "AIDR_QUEUE_HEALTH_FILE"),
		certificateUrl: endpoint(env.AIDR_PUBLIC_HTTPS_URL, "AIDR_PUBLIC_HTTPS_URL", ["https:"]),
		signingMaxAgeSeconds: integer(env, "AIDR_SIGNING_MAX_AGE_SECONDS", 300, 1, 86400),
		signingKeyMinRemainingSeconds: integer(env, "AIDR_SIGNING_KEY_MIN_REMAINING_SECONDS", 604800, 60, 31536000),
		backupMaxAgeSeconds: integer(env, "AIDR_BACKUP_MAX_AGE_SECONDS", 90000, 60, 31536000),
		queueMaxAgeSeconds: integer(env, "AIDR_QUEUE_STATUS_MAX_AGE_SECONDS", 120, 1, 86400),
		queueMaxDepth: integer(env, "AIDR_QUEUE_MAX_DEPTH", 1000, 0, 1000000000),
		queueMaxOldestAgeSeconds: integer(env, "AIDR_QUEUE_MAX_OLDEST_AGE_SECONDS", 300, 0, 31536000),
		queueMaxFailedJobs: integer(env, "AIDR_QUEUE_MAX_FAILED_JOBS", 0, 0, 1000000000),
		certificateMinRemainingSeconds: integer(env, "AIDR_CERT_MIN_REMAINING_SECONDS", 1209600, 60, 31536000),
	});
}

function timestamp(value) {
	if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value)) return null;
	const millis = Date.parse(value);
	return Number.isFinite(millis) ? millis : null;
}

function hasExactKeys(document, keys) {
	const actual = Object.keys(document);
	return actual.length === keys.length && keys.every((key) => Object.hasOwn(document, key));
}

function nonNegativeInteger(value) {
	return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function ageSeconds(now, millis) {
	return Math.max(0, Math.floor((now - millis) / 1000));
}

async function readEvidence(path, dependencies) {
	if (!path) return { ok: false, code: "unconfigured" };
	try {
		const metadata = await dependencies.stat(path);
		if (!metadata.isFile() || metadata.size <= 0 || metadata.size > MAX_EVIDENCE_BYTES) return { ok: false, code: "invalid" };
		const document = JSON.parse(await dependencies.readFile(path, "utf8"));
		if (!document || Array.isArray(document) || typeof document !== "object") return { ok: false, code: "invalid" };
		return { ok: true, document };
	} catch {
		return { ok: false, code: "unavailable" };
	}
}

async function probeHttp(url, method, config, dependencies) {
	if (!url) return { ok: false, code: "unconfigured" };
	try {
		const headers = config.publicKey ? { apikey: config.publicKey } : {};
		const response = await dependencies.fetch(url, {
			method,
			headers,
			redirect: "error",
			signal: AbortSignal.timeout(config.requestTimeoutMs),
		});
		try {
			await response.body?.cancel();
		} catch {
			// The status is sufficient; a body is deliberately never retained.
		}
		return response.ok ? { ok: true, code: "ok" } : { ok: false, code: "http" };
	} catch {
		return { ok: false, code: "unavailable" };
	}
}

async function probeSigning(config, dependencies, now) {
	const evidence = await readEvidence(config.signingFile, dependencies);
	if (!evidence.ok) return evidence;
	const { document } = evidence;
	const lastSuccess = timestamp(document.last_success_at);
	const keyExpiry = timestamp(document.active_key_expires_at);
	if (!hasExactKeys(document, ["schema_version", "status", "last_success_at", "active_key_expires_at"]) || document.schema_version !== 1 || document.status !== "ok" || lastSuccess === null || keyExpiry === null) {
		return { ok: false, code: "invalid" };
	}
	const successAge = ageSeconds(now, lastSuccess);
	const keyRemaining = Math.floor((keyExpiry - now) / 1000);
	return {
		ok: lastSuccess <= now && successAge <= config.signingMaxAgeSeconds && keyRemaining >= config.signingKeyMinRemainingSeconds,
		code: "threshold",
		metrics: { signingLastSuccessAgeSeconds: successAge, signingKeyRemainingSeconds: Math.max(0, keyRemaining) },
	};
}

async function probeBackup(config, dependencies, now) {
	const evidence = await readEvidence(config.backupFile, dependencies);
	if (!evidence.ok) return evidence;
	const { document } = evidence;
	const completed = timestamp(document.completed_at);
	const verified = timestamp(document.verified_at);
	if (!hasExactKeys(document, ["schema_version", "status", "completed_at", "verified_at"]) || document.schema_version !== 1 || document.status !== "ok" || completed === null || verified === null) {
		return { ok: false, code: "invalid" };
	}
	const backupAge = ageSeconds(now, completed);
	const verificationAge = ageSeconds(now, verified);
	return {
		ok: completed <= now && verified >= completed && verified <= now && backupAge <= config.backupMaxAgeSeconds,
		code: "threshold",
		metrics: { backupAgeSeconds: backupAge, backupVerificationAgeSeconds: verificationAge },
	};
}

async function probeQueue(config, dependencies, now) {
	const evidence = await readEvidence(config.queueFile, dependencies);
	if (!evidence.ok) return evidence;
	const { document } = evidence;
	const checked = timestamp(document.checked_at);
	const depth = nonNegativeInteger(document.depth);
	const oldest = nonNegativeInteger(document.oldest_age_seconds);
	const failed = nonNegativeInteger(document.failed_jobs);
	if (!hasExactKeys(document, ["schema_version", "status", "checked_at", "depth", "oldest_age_seconds", "failed_jobs"]) || document.schema_version !== 1 || document.status !== "ok" || checked === null || depth === null || oldest === null || failed === null) {
		return { ok: false, code: "invalid" };
	}
	const statusAge = ageSeconds(now, checked);
	return {
		ok:
			checked <= now &&
			statusAge <= config.queueMaxAgeSeconds &&
			depth <= config.queueMaxDepth &&
			oldest <= config.queueMaxOldestAgeSeconds &&
			failed <= config.queueMaxFailedJobs,
		code: "threshold",
		metrics: { queueStatusAgeSeconds: statusAge, queueDepth: depth, queueOldestAgeSeconds: oldest, queueFailedJobs: failed },
	};
}

export function defaultCertificateProbe(url, timeoutMs) {
	if (!url) return Promise.resolve({ ok: false, code: "unconfigured" });
	return new Promise((resolve) => {
		let settled = false;
		const finish = (result, socket) => {
			if (settled) return;
			settled = true;
			socket?.destroy();
			resolve(result);
		};
		const socket = tlsConnect({
			host: url.hostname,
			port: Number(url.port || 443),
			servername: isIP(url.hostname) ? undefined : url.hostname,
			rejectUnauthorized: true,
			timeout: timeoutMs,
		}, () => {
			const certificate = socket.getPeerCertificate();
			const validTo = timestamp(certificate?.valid_to);
			finish(socket.authorized && validTo !== null ? { ok: true, code: "ok", validTo } : { ok: false, code: "invalid" }, socket);
		});
		socket.once("timeout", () => finish({ ok: false, code: "unavailable" }, socket));
		socket.once("error", () => finish({ ok: false, code: "unavailable" }, socket));
	});
}

async function probeCertificate(config, dependencies, now) {
	const result = await dependencies.probeCertificate(config.certificateUrl, config.requestTimeoutMs);
	if (!result.ok) return result;
	const remaining = Math.floor((result.validTo - now) / 1000);
	return {
		ok: remaining >= config.certificateMinRemainingSeconds,
		code: "threshold",
		metrics: { certificateRemainingSeconds: Math.max(0, remaining) },
	};
}

function safeResult(snapshot) {
	return {
		status: snapshot.ready ? "ready" : "not_ready",
		component: "control-plane",
		checks: Object.fromEntries(CHECK_NAMES.filter((name) => snapshot.required.includes(name)).map((name) => [name, snapshot.checks[name]?.ok ? "ok" : "failed"])),
	};
}

export function renderPrometheus(snapshot) {
	const lines = [
		"# HELP aidr_readiness Whether every required AIDR dependency is ready.",
		"# TYPE aidr_readiness gauge",
		`aidr_readiness ${snapshot.ready ? 1 : 0}`,
		"# HELP aidr_readiness_check Whether a required AIDR dependency is ready.",
		"# TYPE aidr_readiness_check gauge",
	];
	for (const name of CHECK_NAMES.filter((value) => snapshot.required.includes(value))) {
		lines.push(`aidr_readiness_check{check="${name}"} ${snapshot.checks[name]?.ok ? 1 : 0}`);
	}
	const metrics = Object.assign({}, ...Object.values(snapshot.checks).map((check) => check.metrics || {}));
	const gauges = [
		["aidr_signing_last_success_age_seconds", metrics.signingLastSuccessAgeSeconds],
		["aidr_signing_key_remaining_seconds", metrics.signingKeyRemainingSeconds],
		["aidr_backup_age_seconds", metrics.backupAgeSeconds],
		["aidr_backup_verification_age_seconds", metrics.backupVerificationAgeSeconds],
		["aidr_queue_status_age_seconds", metrics.queueStatusAgeSeconds],
		["aidr_queue_depth", metrics.queueDepth],
		["aidr_queue_oldest_age_seconds", metrics.queueOldestAgeSeconds],
		["aidr_queue_failed_jobs", metrics.queueFailedJobs],
		["aidr_certificate_remaining_seconds", metrics.certificateRemainingSeconds],
	];
	for (const [name, value] of gauges) {
		if (Number.isFinite(value) && value >= 0) lines.push(`# TYPE ${name} gauge`, `${name} ${value}`);
	}
	return `${lines.join("\n")}\n`;
}

export function createReadinessMonitor(config, overrides = {}) {
	const dependencies = {
		fetch: overrides.fetch || globalThis.fetch,
		readFile: overrides.readFile || readFile,
		stat: overrides.stat || stat,
		probeCertificate: overrides.probeCertificate || defaultCertificateProbe,
		now: overrides.now || (() => Date.now()),
	};
	let cached = null;
	let inFlight = null;

	async function collect() {
		const now = dependencies.now();
		const results = await Promise.all([
			probeHttp(config.databaseUrl, "GET", config, dependencies),
			probeHttp(config.storageUrl, "GET", config, dependencies),
			probeHttp(config.functionsUrl, "OPTIONS", config, dependencies),
			probeSigning(config, dependencies, now),
			probeBackup(config, dependencies, now),
			probeQueue(config, dependencies, now),
			probeCertificate(config, dependencies, now),
		]);
		const checks = Object.fromEntries(CHECK_NAMES.map((name, index) => [name, results[index]]));
		return {
			ready: config.required.every((name) => checks[name].ok),
			required: config.required,
			checks,
			collectedAt: now,
		};
	}

	async function snapshot() {
		const now = dependencies.now();
		if (cached && now >= cached.collectedAt && now - cached.collectedAt < config.cacheMs) return cached;
		if (inFlight) return inFlight;
		inFlight = collect().then((value) => {
			cached = value;
			return value;
		}).finally(() => {
			inFlight = null;
		});
		return inFlight;
	}

	return Object.freeze({
		snapshot,
		async safeSnapshot() {
			return safeResult(await snapshot());
		},
		async metrics() {
			return renderPrometheus(await snapshot());
		},
	});
}
