import { readFile, stat } from "node:fs/promises";
import { isIP } from "node:net";
import { isAbsolute } from "node:path";
import { connect as tlsConnect } from "node:tls";

const CHECK_NAMES = Object.freeze([
	"database",
	"storage",
	"functions",
	"signing",
	"backup",
	"queue",
	"certificate",
]);

const MAX_EVIDENCE_BYTES = 16 * 1024;
const MAX_FUNCTION_PROBE_BYTES = 1024;
const REQUEST_DURATION_BUCKETS = Object.freeze([0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5]);
const STATUS_CLASSES = Object.freeze(["1xx", "2xx", "3xx", "4xx", "5xx", "unknown"]);

export function createHttpRequestMetrics() {
	const requests = new Map(STATUS_CLASSES.map((name) => [name, 0]));
	const buckets = REQUEST_DURATION_BUCKETS.map(() => 0);
	let durationCount = 0;
	let durationSum = 0;

	return Object.freeze({
		observe(statusCode, durationSeconds) {
			const statusClass = Number.isInteger(statusCode) && statusCode >= 100 && statusCode <= 599
				? `${Math.floor(statusCode / 100)}xx`
				: "unknown";
			requests.set(statusClass, (requests.get(statusClass) || 0) + 1);
			if (!Number.isFinite(durationSeconds) || durationSeconds < 0) return;
			durationCount += 1;
			durationSum += durationSeconds;
			for (let index = 0; index < REQUEST_DURATION_BUCKETS.length; index += 1) {
				if (durationSeconds <= REQUEST_DURATION_BUCKETS[index]) buckets[index] += 1;
			}
		},
		renderPrometheus() {
			const lines = [
				"# HELP aidr_dashboard_http_requests_total Completed dashboard HTTP requests by status class.",
				"# TYPE aidr_dashboard_http_requests_total counter",
				...STATUS_CLASSES.map((name) => `aidr_dashboard_http_requests_total{status_class="${name}"} ${requests.get(name)}`),
				"# HELP aidr_dashboard_http_request_duration_seconds Dashboard HTTP request duration in seconds.",
				"# TYPE aidr_dashboard_http_request_duration_seconds histogram",
				...REQUEST_DURATION_BUCKETS.map((upperBound, index) => `aidr_dashboard_http_request_duration_seconds_bucket{le="${upperBound}"} ${buckets[index]}`),
				`aidr_dashboard_http_request_duration_seconds_bucket{le="+Inf"} ${durationCount}`,
				`aidr_dashboard_http_request_duration_seconds_sum ${durationSum}`,
				`aidr_dashboard_http_request_duration_seconds_count ${durationCount}`,
			];
			return `${lines.join("\n")}\n`;
		},
	});
}

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
	if (env.AIDR_DEVELOPMENT_MODE !== undefined && !["true", "false"].includes(env.AIDR_DEVELOPMENT_MODE)) {
		throw new Error("AIDR_DEVELOPMENT_MODE must be true or false");
	}
	const productionMode = env.NODE_ENV === "production" || env.AIDR_RELEASE_MODE === "commercial" || env.AIDR_FINAL_RELEASE === "1";
	const developmentMode = env.AIDR_DEVELOPMENT_MODE === "true" && !productionMode;
	if (!developmentMode && (required.length !== CHECK_NAMES.length || CHECK_NAMES.some((name) => !required.includes(name)))) {
		throw new Error("AIDR_READINESS_REQUIRED_CHECKS must contain all seven checks outside explicit development mode");
	}
	const functionsUrl = endpoint(env.AIDR_HEALTH_FUNCTIONS_URL, "AIDR_HEALTH_FUNCTIONS_URL", undefined, "/functions/v1/");
	const databaseUrl = endpoint(env.AIDR_HEALTH_DATABASE_URL, "AIDR_HEALTH_DATABASE_URL", undefined, "/rest/v1/");
	if (databaseUrl && databaseUrl.pathname !== "/rest/v1/rpc/aidr_readiness_probe") {
		throw new Error("AIDR_HEALTH_DATABASE_URL must address the exact /rest/v1/rpc/aidr_readiness_probe endpoint");
	}
	if (functionsUrl && functionsUrl.pathname !== "/functions/v1/packs-manifest") {
		throw new Error("AIDR_HEALTH_FUNCTIONS_URL must address the exact /functions/v1/packs-manifest endpoint");
	}
	return Object.freeze({
		required: Object.freeze(required),
		requestTimeoutMs: integer(env, "AIDR_READINESS_TIMEOUT_MS", 3000, 100, 30000),
		cacheMs: integer(env, "AIDR_READINESS_CACHE_MS", 5000, 0, 60000),
		databaseUrl,
		storageUrl: endpoint(env.AIDR_HEALTH_STORAGE_URL, "AIDR_HEALTH_STORAGE_URL", undefined, "/storage/v1/"),
		functionsUrl,
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

export function parseCertificateExpiry(value) {
	if (typeof value !== "string" || value.length === 0) return null;
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

async function readBoundedJson(response) {
	const declaredLength = response.headers?.get?.("content-length");
	if (/^\d+$/.test(declaredLength || "") && Number(declaredLength) > MAX_FUNCTION_PROBE_BYTES) {
		await response.body?.cancel();
		return null;
	}
	const reader = response.body?.getReader?.();
	if (!reader) return null;
	const decoder = new TextDecoder();
	let bytes = 0;
	let text = "";
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			bytes += value.byteLength;
			if (bytes > MAX_FUNCTION_PROBE_BYTES) {
				await reader.cancel();
				return null;
			}
			text += decoder.decode(value, { stream: true });
		}
		text += decoder.decode();
	} catch {
		return null;
	} finally {
		reader.releaseLock();
	}
	try {
		const document = JSON.parse(text);
		return document && !Array.isArray(document) && typeof document === "object" ? document : null;
	} catch {
		return null;
	}
}

async function probeDatabase(config, dependencies) {
	if (!config.databaseUrl || !config.publicKey) return { ok: false, code: "unconfigured" };
	try {
		const response = await dependencies.fetch(config.databaseUrl, {
			method: "GET",
			headers: { apikey: config.publicKey },
			redirect: "error",
			signal: AbortSignal.timeout(config.requestTimeoutMs),
		});
		const document = await readBoundedJson(response);
		const contentType = response.headers?.get?.("content-type") || "";
		return response.status === 200 && contentType.toLowerCase().startsWith("application/json") &&
			document && hasExactKeys(document, ["ok"]) && document.ok === true
			? { ok: true, code: "ok" }
			: { ok: false, code: "http" };
	} catch {
		return { ok: false, code: "unavailable" };
	}
}

async function probeFunctions(config, dependencies) {
	if (!config.functionsUrl || !config.publicKey) return { ok: false, code: "unconfigured" };
	try {
		const response = await dependencies.fetch(config.functionsUrl, {
			method: "GET",
			headers: { apikey: config.publicKey, authorization: `Bearer ${config.publicKey}` },
			redirect: "error",
			signal: AbortSignal.timeout(config.requestTimeoutMs),
		});
		const document = await readBoundedJson(response);
		const contentType = response.headers?.get?.("content-type") || "";
		return response.status === 401 && contentType.toLowerCase().startsWith("application/json") &&
			document && hasExactKeys(document, ["error"]) && document.error === "invalid_api_key"
			? { ok: true, code: "ok" }
			: { ok: false, code: "http" };
	} catch {
		return { ok: false, code: "unavailable" };
	}
}

async function probeSigning(config, dependencies, now) {
	const evidence = await readEvidence(config.signingFile, dependencies);
	if (!evidence.ok) return evidence;
	const { document } = evidence;
	if (hasExactKeys(document, ["schema_version", "status", "checked_at"]) && document.schema_version === 1 && document.status === "failed" && timestamp(document.checked_at) !== null) {
		return { ok: false, code: "failed" };
	}
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
	const recoveryPoint = timestamp(document.recovery_point_at);
	const completed = timestamp(document.completed_at);
	const verified = timestamp(document.verified_at);
	if (!hasExactKeys(document, ["schema_version", "status", "recovery_point_at", "completed_at", "verified_at"]) || document.schema_version !== 2 || document.status !== "ok" || recoveryPoint === null || completed === null || verified === null) {
		return { ok: false, code: "invalid" };
	}
	const backupAge = ageSeconds(now, recoveryPoint);
	const verificationAge = ageSeconds(now, verified);
	return {
		ok: recoveryPoint <= completed && completed <= verified && verified <= now && backupAge <= config.backupMaxAgeSeconds,
		code: "threshold",
		metrics: { backupAgeSeconds: backupAge, backupVerificationAgeSeconds: verificationAge },
	};
}

async function probeQueue(config, dependencies, now) {
	const evidence = await readEvidence(config.queueFile, dependencies);
	if (!evidence.ok) return evidence;
	const { document } = evidence;
	if (hasExactKeys(document, ["schema_version", "status", "checked_at"]) && document.schema_version === 1 && document.status === "failed" && timestamp(document.checked_at) !== null) {
		return { ok: false, code: "failed" };
	}
	const checked = timestamp(document.checked_at);
	const depth = nonNegativeInteger(document.depth);
	const oldest = nonNegativeInteger(document.oldest_age_seconds);
	const failed = nonNegativeInteger(document.failed_jobs);
	if (!hasExactKeys(document, ["schema_version", "status", "checked_at", "depth", "oldest_age_seconds", "failed_jobs"]) || document.schema_version !== 1 || !["ok", "failed"].includes(document.status) || checked === null || depth === null || oldest === null || failed === null) {
		return { ok: false, code: "invalid" };
	}
	const statusAge = ageSeconds(now, checked);
	return {
		ok:
			document.status === "ok" &&
			checked <= now &&
			statusAge <= config.queueMaxAgeSeconds &&
			depth <= config.queueMaxDepth &&
			oldest <= config.queueMaxOldestAgeSeconds &&
			failed <= config.queueMaxFailedJobs,
		code: "threshold",
		metrics: { queueStatusAgeSeconds: statusAge, queueDepth: depth, queueOldestAgeSeconds: oldest, queueFailedJobs: failed },
	};
}

function defaultCertificateProbe(url, timeoutMs) {
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
			const validTo = parseCertificateExpiry(certificate?.valid_to);
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

function renderPrometheus(snapshot) {
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
			probeDatabase(config, dependencies),
			probeHttp(config.storageUrl, "GET", config, dependencies),
			probeFunctions(config, dependencies),
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
