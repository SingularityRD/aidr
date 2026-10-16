import { createHash, randomUUID } from "node:crypto";
import { lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import type { Incident } from "./incidents/types.js";
import { preparePrivateLocalDirectory, preparePrivateLocalFile } from "./private-local-file.js";
import { incidentToSiemRecord } from "./siem-export.js";
import { createSyslogSender, type SyslogLookup, type SyslogSiemConfig } from "./siem-syslog.js";
import { redactTelemetryString } from "./telemetry-redaction.js";

export const SIEM_EVENT_SCHEMA_VERSION = "aidr.siem.event/v1" as const;

/** Portable schema emitted by every delivery adapter. */
export const SIEM_EVENT_JSON_SCHEMA = {
	$schema: "https://json-schema.org/draft/2020-12/schema",
	$id: "https://schemas.singularityrd.com/aidr/siem-event-v1.json",
	title: "Singularity AIDR SIEM event",
	type: "object",
	additionalProperties: false,
	required: ["schema_version", "event_id", "observed_at_ms", "source", "incident"],
	properties: {
		schema_version: { const: SIEM_EVENT_SCHEMA_VERSION },
		event_id: { type: "string", pattern: "^aidr_[a-f0-9]{40}$" },
		observed_at_ms: { type: "integer", minimum: 0 },
		source: {
			type: "object",
			additionalProperties: false,
			required: ["vendor", "product"],
			properties: {
				vendor: { const: "Singularity" },
				product: { const: "AIDR" },
			},
		},
		incident: {
			type: "object",
			additionalProperties: false,
			required: [
				"siem_type",
				"incident_id",
				"opened_at_ms",
				"last_seen_ms",
				"severity",
				"status",
				"session_id",
				"agent_iid",
				"connector",
				"plugin_key",
				"package_name",
				"domain",
				"file_path",
				"event_count",
				"events",
			],
			properties: {
				siem_type: { const: "aidr_incident" },
				incident_id: { type: "string" },
				opened_at_ms: { type: "integer", minimum: 0 },
				last_seen_ms: { type: "integer", minimum: 0 },
				severity: { enum: ["info", "warning", "high", "critical"] },
				status: { enum: ["open", "acknowledged", "contained", "resolved", "suppressed"] },
				session_id: { type: ["string", "null"] },
				agent_iid: { type: ["string", "null"] },
				connector: { type: ["string", "null"] },
				plugin_key: { type: ["string", "null"] },
				package_name: { type: ["string", "null"] },
				domain: { type: ["string", "null"] },
				file_path: { type: ["string", "null"] },
				event_count: { type: "integer", minimum: 0 },
				events: {
					type: "array",
					items: {
						type: "object",
						additionalProperties: false,
						required: ["signal_id", "timestamp_ms", "signal_type", "severity", "summary"],
						properties: {
							signal_id: { type: "string" },
							timestamp_ms: { type: "integer", minimum: 0 },
							signal_type: { type: "string" },
							severity: { enum: ["info", "warning", "high", "critical"] },
							summary: { type: "string" },
						},
					},
				},
			},
		},
	},
} as const;

export interface SiemEventEnvelope {
	schema_version: typeof SIEM_EVENT_SCHEMA_VERSION;
	event_id: string;
	observed_at_ms: number;
	source: { vendor: "Singularity"; product: "AIDR" };
	incident: Record<string, unknown>;
}

interface BaseAdapterConfig {
	endpoint: string;
	/** Plain HTTP is accepted only for loopback integration tests. */
	allowInsecureLoopback?: boolean;
}

/** Generic receivers must echo `x-aidr-event-id` before delivery is acknowledged. */
export interface WebhookSiemConfig extends BaseAdapterConfig {
	provider: "webhook";
	bearerToken?: string;
	headers?: Record<string, string>;
}

export interface SplunkHecSiemConfig extends BaseAdapterConfig {
	provider: "splunk_hec";
	token: string;
	index?: string;
	source?: string;
	sourcetype?: string;
}

export interface SentinelSiemConfig extends BaseAdapterConfig {
	provider: "sentinel";
	bearerToken: string;
	dcrImmutableId: string;
	streamName: string;
}

export interface ElasticSiemConfig extends BaseAdapterConfig {
	provider: "elastic";
	index: string;
	apiKey?: string;
	bearerToken?: string;
}

export type SiemAdapterConfig =
	| WebhookSiemConfig
	| SplunkHecSiemConfig
	| SentinelSiemConfig
	| ElasticSiemConfig
	| SyslogSiemConfig;

export type SiemProvider = SiemAdapterConfig["provider"];
/** `delivered` confirms the adapter's provider receipt contract, not downstream indexing. */
export type SiemDeliveryStatus = "queued" | "retrying" | "delivered" | "dead_letter";

export interface SiemDeliveryReceipt {
	receiptId: string;
	eventId: string;
	provider: SiemProvider;
	/** Origin only. Credentials, query parameters and paths are never recorded. */
	endpointOrigin: string;
	status: SiemDeliveryStatus;
	enqueuedAtMs: number;
	updatedAtMs: number;
	attemptCount: number;
	/** Provider receipt contract that confirmed delivery, e.g. `syslog_udp_sent_unacknowledged`. */
	deliveryCode?: string;
	nextAttemptAtMs?: number;
	lastStatusCode?: number;
	lastErrorCode?: string;
}

export interface SiemEnqueueResult {
	receipt: SiemDeliveryReceipt;
	deduplicated: boolean;
}

export interface SiemFlushResult {
	attempted: number;
	delivered: number;
	retrying: number;
	deadLettered: number;
	pending: number;
}

export interface SiemDeliveryClaim {
	receiptId: string;
	token: string;
	envelope: SiemEventEnvelope;
}

export interface SiemDeliveryClaimResult {
	claim?: SiemDeliveryClaim;
	deadLettered: number;
	pending: number;
}

export interface SiemDeliveryAttempt {
	outcome: "delivered" | "retry" | "permanent";
	code: string;
	statusCode: number;
	retryAfterMs?: number;
}

export interface SiemDeliveryCompletion {
	applied: boolean;
	delivered: number;
	retrying: number;
	deadLettered: number;
	pending: number;
}

export interface SiemDeliveryHealth {
	status: "healthy" | "degraded" | "unhealthy";
	provider: SiemProvider;
	endpointOrigin: string;
	queueDepth: number;
	queueBytes: number;
	queueCapacity: number;
	queueByteCapacity: number;
	oldestQueuedAgeMs: number;
	retrying: number;
	deadLettered: number;
	/** Cumulative delivery failures; bounded receipt trimming must not erase loss. */
	deadLetteredTotal: number;
	delivered: number;
	lastDeliveredAtMs?: number;
	lastFailureAtMs?: number;
	lastErrorCode?: string;
}

export interface SiemDeliveryOptions {
	stateFile: string;
	adapter: SiemAdapterConfig;
	maxQueueEntries?: number;
	maxQueueBytes?: number;
	maxReceipts?: number;
	maxAttempts?: number;
	minBackoffMs?: number;
	maxBackoffMs?: number;
	requestTimeoutMs?: number;
	fetch?: typeof fetch;
	/** Resolver for syslog hostnames (tests and split-horizon DNS); results are policy-checked. */
	syslogLookup?: SyslogLookup;
	now?: () => number;
	random?: () => number;
}

export class SiemQueueCapacityError extends Error {
	readonly code = "siem_queue_capacity_exceeded";

	constructor(message = "The durable SIEM delivery queue is full") {
		super(message);
		this.name = "SiemQueueCapacityError";
	}
}

export class SiemStateIntegrityError extends Error {
	readonly code = "siem_state_integrity_error";

	constructor(message: string) {
		super(message);
		this.name = "SiemStateIntegrityError";
	}
}

interface QueueItem {
	receiptId: string;
	envelope: SiemEventEnvelope;
	byteLength: number;
	claimToken?: string;
	claimExpiresAtMs?: number;
}

interface DeliveryState {
	version: 1;
	/** Binds queued events and receipts to their non-credential delivery route. */
	destinationFingerprint?: string;
	/** Optional for state files written before the cumulative loss counter existed. */
	deadLetteredTotal?: number;
	queue: QueueItem[];
	receipts: SiemDeliveryReceipt[];
}

interface StateFile {
	format: "aidr-siem-delivery-state/v1";
	payload: DeliveryState;
	sha256: string;
}

interface AdapterRequest {
	url: string;
	init: RequestInit;
}

type DeliveryClassification = SiemDeliveryAttempt;
type HttpClassification =
	| { outcome: "http_success"; code: "http_success"; statusCode: number }
	| { outcome: "retry"; code: string; statusCode: number; retryAfterMs?: number }
	| { outcome: "permanent"; code: string; statusCode: number };

interface SiemAdapter {
	provider: SiemProvider;
	endpointOrigin: string;
	/** HTTP adapters build a request and classify the response. */
	buildRequest?(envelope: SiemEventEnvelope): AdapterRequest;
	classify?(
		response: Response,
		nowMs: number,
		envelope: SiemEventEnvelope,
	): Promise<DeliveryClassification>;
	/** Socket adapters (syslog) deliver directly and classify the outcome themselves. */
	transmit?(
		envelope: SiemEventEnvelope,
		context: { timeoutMs: number; lookup?: SyslogLookup },
	): Promise<DeliveryClassification>;
	/** Credential-free route description bound into durable state. */
	fingerprintInput?(): Record<string, unknown>;
}

const DEFAULT_MAX_QUEUE_ENTRIES = 10_000;
const DEFAULT_MAX_QUEUE_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_RECEIPTS = 20_000;
const DEFAULT_MAX_ATTEMPTS = 10;
const DEFAULT_MIN_BACKOFF_MS = 1_000;
const DEFAULT_MAX_BACKOFF_MS = 5 * 60_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 64 * 1024;

function assertPositiveInteger(name: string, value: number): void {
	if (!Number.isSafeInteger(value) || value <= 0) {
		throw new TypeError(`${name} must be a positive safe integer`);
	}
}

function validateEndpoint(config: BaseAdapterConfig): URL {
	let parsed: URL;
	try {
		parsed = new URL(config.endpoint);
	} catch {
		throw new TypeError("SIEM endpoint must be an absolute URL");
	}
	if (parsed.username || parsed.password || parsed.search || parsed.hash) {
		throw new TypeError("SIEM endpoint cannot contain credentials, query parameters or a fragment");
	}
	const loopback =
		parsed.hostname === "localhost" ||
		parsed.hostname === "127.0.0.1" ||
		parsed.hostname === "[::1]";
	if (
		parsed.protocol !== "https:" &&
		!(parsed.protocol === "http:" && loopback && config.allowInsecureLoopback)
	) {
		throw new TypeError(
			"SIEM delivery requires HTTPS (plain HTTP is limited to explicitly enabled loopback)",
		);
	}
	return parsed;
}

function requiredSecret(name: string, value: string | undefined): string {
	if (!value?.trim()) throw new TypeError(`${name} is required`);
	if (/\r|\n/.test(value)) throw new TypeError(`${name} contains invalid characters`);
	return value;
}

function safeHeaderMap(headers: Record<string, string> | undefined): Record<string, string> {
	const output: Record<string, string> = {};
	for (const [name, value] of Object.entries(headers ?? {})) {
		if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || /\r|\n/.test(value)) {
			throw new TypeError("SIEM webhook contains an invalid header");
		}
		output[name] = value;
	}
	return output;
}

function endpointOrigin(url: URL): string {
	return url.origin;
}

function withPath(base: URL, path: string): string {
	const target = new URL(base.toString());
	target.pathname = path;
	return target.toString();
}

function parseRetryAfter(response: Response, nowMs: number): number | undefined {
	const value = response.headers.get("retry-after")?.trim();
	if (!value) return undefined;
	if (/^\d+(?:\.\d+)?$/.test(value)) return Math.max(0, Math.ceil(Number(value) * 1_000));
	const at = Date.parse(value);
	return Number.isFinite(at) ? Math.max(0, at - nowMs) : undefined;
}

function classifyHttp(response: Response, nowMs: number): HttpClassification {
	const statusCode = response.status;
	if (statusCode >= 200 && statusCode < 300)
		return { outcome: "http_success", code: "http_success", statusCode };
	if (statusCode === 401 || statusCode === 403) {
		return { outcome: "permanent", code: "authorization_rejected", statusCode };
	}
	if (statusCode === 408 || statusCode === 425 || statusCode === 429 || statusCode >= 500) {
		return {
			outcome: "retry",
			code:
				statusCode === 429
					? "rate_limited"
					: statusCode >= 500
						? "upstream_unavailable"
						: "request_timeout",
			statusCode,
			retryAfterMs: parseRetryAfter(response, nowMs),
		};
	}
	return { outcome: "permanent", code: "request_rejected", statusCode };
}

async function readBodyBounded(response: Response): Promise<string> {
	if (!response.body) return "";
	const reader = response.body.getReader();
	const decoder = new TextDecoder();
	let bytes = 0;
	let output = "";
	try {
		while (true) {
			const part = await reader.read();
			if (part.done) break;
			bytes += part.value.byteLength;
			if (bytes > MAX_RESPONSE_BYTES) throw new Error("response_too_large");
			output += decoder.decode(part.value, { stream: true });
		}
		return output + decoder.decode();
	} finally {
		await reader.cancel().catch(() => undefined);
	}
}

function createWebhookAdapter(config: WebhookSiemConfig, base: URL): SiemAdapter {
	const customHeaders = safeHeaderMap(config.headers);
	const bearer = config.bearerToken ? requiredSecret("bearerToken", config.bearerToken) : undefined;
	return {
		provider: config.provider,
		endpointOrigin: endpointOrigin(base),
		buildRequest(envelope) {
			return {
				url: base.toString(),
				init: {
					method: "POST",
					headers: {
						...customHeaders,
						"content-type": "application/json",
						"idempotency-key": envelope.event_id,
						"x-aidr-event-id": envelope.event_id,
						...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
					},
					body: JSON.stringify(envelope),
				},
			};
		},
		async classify(response, nowMs, envelope) {
			const basic = classifyHttp(response, nowMs);
			if (basic.outcome !== "http_success") return basic;
			return response.headers.get("x-aidr-event-id") === envelope.event_id
				? {
						outcome: "delivered",
						code: "webhook_receipt_verified",
						statusCode: response.status,
					}
				: {
						outcome: "retry",
						code: "invalid_webhook_receipt",
						statusCode: response.status,
					};
		},
	};
}

function createSplunkAdapter(config: SplunkHecSiemConfig, base: URL): SiemAdapter {
	const token = requiredSecret("token", config.token);
	const path = base.pathname === "/" ? "/services/collector/event" : base.pathname;
	return {
		provider: config.provider,
		endpointOrigin: endpointOrigin(base),
		buildRequest(envelope) {
			return {
				url: withPath(base, path),
				init: {
					method: "POST",
					headers: {
						authorization: `Splunk ${token}`,
						"content-type": "application/json",
						"x-aidr-event-id": envelope.event_id,
					},
					body: JSON.stringify({
						time: envelope.observed_at_ms / 1_000,
						event: envelope,
						source: config.source ?? "aidr",
						sourcetype: config.sourcetype ?? "aidr:incident",
						...(config.index ? { index: config.index } : {}),
					}),
				},
			};
		},
		async classify(response, nowMs) {
			const basic = classifyHttp(response, nowMs);
			if (basic.outcome !== "http_success") return basic;
			try {
				const body = JSON.parse(await readBodyBounded(response)) as { code?: unknown };
				return body.code === 0
					? {
							outcome: "delivered",
							code: "splunk_hec_accepted",
							statusCode: response.status,
						}
					: { outcome: "permanent", code: "splunk_hec_rejected", statusCode: response.status };
			} catch {
				return { outcome: "retry", code: "invalid_splunk_response", statusCode: response.status };
			}
		},
	};
}

function createSentinelAdapter(config: SentinelSiemConfig, base: URL): SiemAdapter {
	const bearer = requiredSecret("bearerToken", config.bearerToken);
	if (!/^dcr-[A-Za-z0-9._-]+$/.test(config.dcrImmutableId))
		throw new TypeError("Invalid Sentinel DCR immutable ID");
	if (!/^Custom-[A-Za-z][A-Za-z0-9_]*$/.test(config.streamName))
		throw new TypeError("Invalid Sentinel stream name");
	const path = `${base.pathname.replace(/\/$/, "")}/dataCollectionRules/${config.dcrImmutableId}/streams/${config.streamName}`;
	const target = new URL(withPath(base, path));
	target.searchParams.set("api-version", "2023-01-01");
	return {
		provider: config.provider,
		endpointOrigin: endpointOrigin(base),
		buildRequest(envelope) {
			return {
				url: target.toString(),
				init: {
					method: "POST",
					headers: { authorization: `Bearer ${bearer}`, "content-type": "application/json" },
					body: JSON.stringify([envelope]),
				},
			};
		},
		async classify(response, nowMs) {
			const basic = classifyHttp(response, nowMs);
			if (basic.outcome !== "http_success") return basic;
			return response.status === 204
				? {
						outcome: "delivered",
						code: "sentinel_request_accepted",
						statusCode: response.status,
					}
				: {
						outcome: "retry",
						code: "unexpected_sentinel_response",
						statusCode: response.status,
					};
		},
	};
}

async function classifyElasticResponse(
	response: Response,
	nowMs: number,
): Promise<DeliveryClassification> {
	const basic = classifyHttp(response, nowMs);
	if (basic.outcome !== "http_success") return basic;
	try {
		const body = JSON.parse(await readBodyBounded(response)) as {
			errors?: unknown;
			items?: Array<{ create?: { status?: unknown } }>;
		};
		const itemStatus = body.items?.[0]?.create?.status;
		const resultStatus = typeof itemStatus === "number" ? itemStatus : response.status;
		if (
			body.errors === false &&
			typeof itemStatus === "number" &&
			itemStatus >= 200 &&
			itemStatus < 300
		)
			return {
				outcome: "delivered",
				code: "elastic_item_accepted",
				statusCode: resultStatus,
			};
		if (itemStatus === 409)
			return { outcome: "delivered", code: "duplicate_accepted", statusCode: resultStatus };
		if (itemStatus === 429 || (typeof itemStatus === "number" && itemStatus >= 500)) {
			return {
				outcome: "retry",
				code: itemStatus === 429 ? "rate_limited" : "upstream_unavailable",
				statusCode: resultStatus,
			};
		}
		if (itemStatus === 401 || itemStatus === 403)
			return {
				outcome: "permanent",
				code: "authorization_rejected",
				statusCode: resultStatus,
			};
		return { outcome: "permanent", code: "elastic_bulk_rejected", statusCode: resultStatus };
	} catch {
		return { outcome: "retry", code: "invalid_elastic_response", statusCode: response.status };
	}
}

function createElasticAdapter(config: ElasticSiemConfig, base: URL): SiemAdapter {
	const apiKey = config.apiKey ? requiredSecret("apiKey", config.apiKey) : undefined;
	const bearer = config.bearerToken ? requiredSecret("bearerToken", config.bearerToken) : undefined;
	if ((apiKey ? 1 : 0) + (bearer ? 1 : 0) !== 1)
		throw new TypeError("Elastic requires exactly one API key or bearer token");
	if (!/^[a-z0-9][a-z0-9._-]*$/.test(config.index))
		throw new TypeError("Invalid Elastic index name");
	const elasticPath = `${base.pathname.replace(/\/$/, "")}/_bulk`;
	return {
		provider: config.provider,
		endpointOrigin: endpointOrigin(base),
		buildRequest(envelope) {
			return {
				url: withPath(base, elasticPath),
				init: {
					method: "POST",
					headers: {
						authorization: apiKey ? `ApiKey ${apiKey}` : `Bearer ${bearer}`,
						"content-type": "application/x-ndjson",
					},
					body: `${JSON.stringify({ create: { _index: config.index, _id: envelope.event_id } })}\n${JSON.stringify(envelope)}\n`,
				},
			};
		},
		classify: classifyElasticResponse,
	};
}

function createSyslogAdapter(config: SyslogSiemConfig): SiemAdapter {
	const sender = createSyslogSender(config);
	return {
		provider: config.provider,
		endpointOrigin: sender.origin,
		transmit: (envelope, context) => sender.send(envelope, context),
		fingerprintInput: () => sender.fingerprintInput(),
	};
}

function createAdapter(config: SiemAdapterConfig): SiemAdapter {
	if (config.provider === "syslog") return createSyslogAdapter(config);
	const base = validateEndpoint(config);
	switch (config.provider) {
		case "webhook":
			return createWebhookAdapter(config, base);
		case "splunk_hec":
			return createSplunkAdapter(config, base);
		case "sentinel":
			return createSentinelAdapter(config, base);
		case "elastic":
			return createElasticAdapter(config, base);
	}
}

function destinationFingerprint(config: SiemAdapterConfig, adapter: SiemAdapter): string {
	if (config.provider === "syslog")
		return hashJson({ provider: config.provider, ...adapter.fingerprintInput?.() });
	const endpoint = validateEndpoint(config).toString();
	switch (config.provider) {
		case "webhook": {
			const headers = Object.entries(safeHeaderMap(config.headers))
				.map(([name, value]) => [name.toLowerCase(), value] as const)
				.sort(([left], [right]) => left.localeCompare(right));
			return hashJson({ provider: config.provider, endpoint, headers });
		}
		case "splunk_hec":
			return hashJson({
				provider: config.provider,
				endpoint,
				index: config.index ?? null,
				source: config.source ?? "aidr",
				sourcetype: config.sourcetype ?? "aidr:incident",
			});
		case "sentinel":
			return hashJson({
				provider: config.provider,
				endpoint,
				dcrImmutableId: config.dcrImmutableId,
				streamName: config.streamName,
			});
		case "elastic":
			return hashJson({ provider: config.provider, endpoint, index: config.index });
	}
}

function bindDestination(
	state: DeliveryState,
	config: SiemAdapterConfig,
	adapter: SiemAdapter,
): void {
	const destination = destinationFingerprint(config, adapter);
	if (state.destinationFingerprint && state.destinationFingerprint !== destination)
		throw new SiemStateIntegrityError("SIEM delivery state belongs to a different destination");
	if (!state.destinationFingerprint && (state.queue.length > 0 || state.receipts.length > 0))
		throw new SiemStateIntegrityError("Populated legacy SIEM state has no destination binding");
	state.destinationFingerprint = destination;
}

function redactStrings(value: unknown, depth = 0): unknown {
	if (typeof value === "string") return redactTelemetryString(value);
	if (value === null || typeof value !== "object") return value;
	if (depth > 8) return "[Redacted]";
	if (Array.isArray(value)) return value.map((item) => redactStrings(item, depth + 1));
	const output: Record<string, unknown> = {};
	for (const [key, item] of Object.entries(value as Record<string, unknown>))
		output[key] = redactStrings(item, depth + 1);
	return output;
}

function hashJson(value: unknown): string {
	return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

export function createSiemEvent(incident: Incident, observedAtMs = Date.now()): SiemEventEnvelope {
	if (!Number.isSafeInteger(observedAtMs) || observedAtMs < 0)
		throw new TypeError("observedAtMs must be a non-negative safe integer");
	const record = redactStrings(incidentToSiemRecord(incident)) as Record<string, unknown>;
	const eventId = `aidr_${hashJson(record).slice(0, 40)}`;
	return {
		schema_version: SIEM_EVENT_SCHEMA_VERSION,
		event_id: eventId,
		observed_at_ms: observedAtMs,
		source: { vendor: "Singularity", product: "AIDR" },
		incident: record,
	};
}

function emptyState(): DeliveryState {
	return { version: 1, deadLetteredTotal: 0, queue: [], receipts: [] };
}

function isReceipt(value: unknown): value is SiemDeliveryReceipt {
	if (!value || typeof value !== "object") return false;
	const item = value as Partial<SiemDeliveryReceipt>;
	return (
		typeof item.receiptId === "string" &&
		typeof item.eventId === "string" &&
		typeof item.status === "string" &&
		typeof item.attemptCount === "number"
	);
}

function parseStateFile(raw: string): DeliveryState {
	let parsed: StateFile;
	try {
		parsed = JSON.parse(raw) as StateFile;
	} catch {
		throw new SiemStateIntegrityError("SIEM delivery state is not valid JSON");
	}
	if (
		parsed.format !== "aidr-siem-delivery-state/v1" ||
		!parsed.payload ||
		parsed.sha256 !== hashJson(parsed.payload)
	) {
		throw new SiemStateIntegrityError("SIEM delivery state integrity check failed");
	}
	if (
		parsed.payload.version !== 1 ||
		(parsed.payload.deadLetteredTotal !== undefined &&
			(!Number.isSafeInteger(parsed.payload.deadLetteredTotal) ||
				parsed.payload.deadLetteredTotal < 0)) ||
		(parsed.payload.destinationFingerprint !== undefined &&
			!/^([a-f0-9]{64})$/.test(parsed.payload.destinationFingerprint)) ||
		!Array.isArray(parsed.payload.queue) ||
		!Array.isArray(parsed.payload.receipts)
	) {
		throw new SiemStateIntegrityError("SIEM delivery state has an unsupported structure");
	}
	if (!parsed.payload.receipts.every(isReceipt))
		throw new SiemStateIntegrityError("SIEM delivery receipts are invalid");
	for (const item of parsed.payload.queue) {
		const hasClaim = item?.claimToken !== undefined || item?.claimExpiresAtMs !== undefined;
		if (
			!item ||
			typeof item.receiptId !== "string" ||
			typeof item.byteLength !== "number" ||
			!item.envelope ||
			typeof item.envelope.event_id !== "string" ||
			(hasClaim &&
				(typeof item.claimToken !== "string" ||
					!/^[-0-9a-f]{36}$/i.test(item.claimToken) ||
					!Number.isSafeInteger(item.claimExpiresAtMs) ||
					Number(item.claimExpiresAtMs) < 0))
		) {
			throw new SiemStateIntegrityError("SIEM delivery queue contains an invalid entry");
		}
	}
	return parsed.payload;
}

async function persistState(stateFile: string, state: DeliveryState): Promise<void> {
	const wrapper: StateFile = {
		format: "aidr-siem-delivery-state/v1",
		payload: state,
		sha256: hashJson(state),
	};
	const tempFile = `${stateFile}.${process.pid}.${randomUUID()}.tmp`;
	const handle = await open(tempFile, "wx", 0o600);
	try {
		try {
			// NTFS ignores mode 0600; secure the new file before writing queue data.
			if (process.platform === "win32") preparePrivateLocalFile(tempFile);
			await handle.writeFile(`${JSON.stringify(wrapper)}\n`, "utf8");
			await handle.sync();
		} finally {
			await handle.close();
		}
		await rename(tempFile, stateFile);
		// The file sync makes its contents durable; sync the directory too so the
		// rename itself survives a host crash on POSIX filesystems.
		if (process.platform !== "win32") {
			const directory = await open(dirname(stateFile), "r");
			try {
				await directory.sync();
			} finally {
				await directory.close();
			}
		}
	} catch (error) {
		await unlink(tempFile).catch(() => undefined);
		throw error;
	}
}

function cloneReceipt(receipt: SiemDeliveryReceipt): SiemDeliveryReceipt {
	return { ...receipt };
}

export class DurableSiemDelivery {
	readonly stateFile: string;
	private readonly adapter: SiemAdapter;
	private readonly maxQueueEntries: number;
	private readonly maxQueueBytes: number;
	private readonly maxReceipts: number;
	private readonly maxAttempts: number;
	private readonly minBackoffMs: number;
	private readonly maxBackoffMs: number;
	private readonly requestTimeoutMs: number;
	private readonly fetcher: typeof fetch;
	private readonly syslogLookup: SyslogLookup | undefined;
	private readonly now: () => number;
	private readonly random: () => number;
	private state: DeliveryState;
	private operation: Promise<void> = Promise.resolve();

	private constructor(options: SiemDeliveryOptions, state: DeliveryState) {
		this.stateFile = resolve(options.stateFile);
		this.adapter = createAdapter(options.adapter);
		bindDestination(state, options.adapter, this.adapter);
		state.deadLetteredTotal ??= state.receipts.filter(
			(item) => item.status === "dead_letter",
		).length;
		this.maxQueueEntries = options.maxQueueEntries ?? DEFAULT_MAX_QUEUE_ENTRIES;
		this.maxQueueBytes = options.maxQueueBytes ?? DEFAULT_MAX_QUEUE_BYTES;
		this.maxReceipts = options.maxReceipts ?? DEFAULT_MAX_RECEIPTS;
		this.maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
		this.minBackoffMs = options.minBackoffMs ?? DEFAULT_MIN_BACKOFF_MS;
		this.maxBackoffMs = options.maxBackoffMs ?? DEFAULT_MAX_BACKOFF_MS;
		this.requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
		this.fetcher = options.fetch ?? fetch;
		this.syslogLookup = options.syslogLookup;
		this.now = options.now ?? Date.now;
		this.random = options.random ?? Math.random;
		this.state = state;

		for (const [name, value] of [
			["maxQueueEntries", this.maxQueueEntries],
			["maxQueueBytes", this.maxQueueBytes],
			["maxReceipts", this.maxReceipts],
			["maxAttempts", this.maxAttempts],
			["minBackoffMs", this.minBackoffMs],
			["maxBackoffMs", this.maxBackoffMs],
			["requestTimeoutMs", this.requestTimeoutMs],
		] as const)
			assertPositiveInteger(name, value);
		if (this.minBackoffMs > this.maxBackoffMs)
			throw new TypeError("minBackoffMs cannot exceed maxBackoffMs");
		if (this.queueBytes() > this.maxQueueBytes || state.queue.length > this.maxQueueEntries) {
			throw new SiemStateIntegrityError("Stored SIEM queue exceeds configured capacity");
		}
	}

	static async open(options: SiemDeliveryOptions): Promise<DurableSiemDelivery> {
		const stateFile = resolve(options.stateFile);
		const stateDirectory = dirname(stateFile);
		await mkdir(stateDirectory, { recursive: true, mode: 0o700 });
		if (process.platform === "win32") {
			preparePrivateLocalDirectory(stateDirectory);
		} else {
			const directoryMetadata = await lstat(stateDirectory);
			if (!directoryMetadata.isDirectory() || (directoryMetadata.mode & 0o077) !== 0)
				throw new SiemStateIntegrityError("SIEM delivery state directory permissions are insecure");
		}
		let state = emptyState();
		let unboundState = true;
		try {
			const fileStat = await lstat(stateFile);
			if (!fileStat.isFile())
				throw new SiemStateIntegrityError("SIEM delivery state is not a regular file");
			if (process.platform !== "win32" && (fileStat.mode & 0o077) !== 0)
				throw new SiemStateIntegrityError("SIEM delivery state file permissions are insecure");
			if (process.platform === "win32") preparePrivateLocalFile(stateFile);
			state = parseStateFile(await readFile(stateFile, "utf8"));
			unboundState = state.destinationFingerprint === undefined;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		}
		const delivery = new DurableSiemDelivery(options, state);
		if (unboundState) await persistState(stateFile, state);
		return delivery;
	}

	private exclusive<T>(work: () => Promise<T>): Promise<T> {
		const result = this.operation.then(work, work);
		this.operation = result.then(
			() => undefined,
			() => undefined,
		);
		return result;
	}

	private queueBytes(): number {
		return this.state.queue.reduce((sum, item) => sum + item.byteLength, 0);
	}

	private findReceipt(receiptId: string): SiemDeliveryReceipt {
		const receipt = this.state.receipts.find((item) => item.receiptId === receiptId);
		if (!receipt)
			throw new SiemStateIntegrityError("Queue entry references a missing delivery receipt");
		return receipt;
	}

	private trimReceipts(): void {
		if (this.state.receipts.length <= this.maxReceipts) return;
		const active = new Set(this.state.queue.map((item) => item.receiptId));
		const removable = this.state.receipts
			.filter((item) => !active.has(item.receiptId))
			.sort((a, b) => a.updatedAtMs - b.updatedAtMs);
		while (this.state.receipts.length > this.maxReceipts && removable.length > 0) {
			const oldest = removable.shift();
			if (oldest)
				this.state.receipts = this.state.receipts.filter(
					(item) => item.receiptId !== oldest.receiptId,
				);
		}
	}

	async enqueue(incident: Incident): Promise<SiemEnqueueResult> {
		return this.exclusive(async () => {
			const envelope = createSiemEvent(incident, this.now());
			const duplicate = this.state.receipts.find(
				(item) => item.eventId === envelope.event_id && item.status !== "dead_letter",
			);
			if (duplicate) return { receipt: cloneReceipt(duplicate), deduplicated: true };

			const byteLength = Buffer.byteLength(JSON.stringify(envelope), "utf8");
			if (
				this.state.queue.length >= this.maxQueueEntries ||
				this.queueBytes() + byteLength > this.maxQueueBytes
			) {
				throw new SiemQueueCapacityError();
			}
			const nowMs = this.now();
			const receipt: SiemDeliveryReceipt = {
				receiptId: randomUUID(),
				eventId: envelope.event_id,
				provider: this.adapter.provider,
				endpointOrigin: this.adapter.endpointOrigin,
				status: "queued",
				enqueuedAtMs: nowMs,
				updatedAtMs: nowMs,
				attemptCount: 0,
				nextAttemptAtMs: nowMs,
			};
			this.state.queue.push({ receiptId: receipt.receiptId, envelope, byteLength });
			this.state.receipts.push(receipt);
			this.trimReceipts();
			await persistState(this.stateFile, this.state);
			return { receipt: cloneReceipt(receipt), deduplicated: false };
		});
	}

	private backoffMs(attemptCount: number, retryAfterMs: number | undefined): number {
		const exponential = Math.min(
			this.maxBackoffMs,
			this.minBackoffMs * 2 ** Math.max(0, attemptCount - 1),
		);
		const jittered = Math.max(
			this.minBackoffMs,
			Math.floor(exponential * (0.5 + Math.min(1, Math.max(0, this.random())) * 0.5)),
		);
		return Math.min(this.maxBackoffMs, Math.max(jittered, retryAfterMs ?? 0));
	}

	private async send(envelope: SiemEventEnvelope): Promise<DeliveryClassification> {
		const { buildRequest, classify, transmit } = this.adapter;
		if (transmit) {
			return transmit.call(this.adapter, envelope, {
				timeoutMs: this.requestTimeoutMs,
				lookup: this.syslogLookup,
			});
		}
		if (!buildRequest || !classify)
			throw new SiemStateIntegrityError("SIEM adapter has no delivery method");
		const request = buildRequest.call(this.adapter, envelope);
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), this.requestTimeoutMs);
		timer.unref?.();
		let response: Response | undefined;
		try {
			response = await this.fetcher(request.url, {
				...request.init,
				signal: controller.signal,
				redirect: "error",
			});
			return await classify.call(this.adapter, response, this.now(), envelope);
		} catch (error) {
			return {
				outcome: "retry",
				code:
					controller.signal.aborted || (error instanceof Error && error.name === "AbortError")
						? "delivery_timeout"
						: "network_error",
				statusCode: 0,
			};
		} finally {
			await response?.body?.cancel().catch(() => undefined);
			clearTimeout(timer);
		}
	}

	async claimNext(): Promise<SiemDeliveryClaimResult> {
		return this.exclusive(async () => {
			const nowMs = this.now();
			const item = this.state.queue.find(
				(candidate) => (this.findReceipt(candidate.receiptId).nextAttemptAtMs ?? 0) <= nowMs,
			);
			if (!item) return { deadLettered: 0, pending: this.state.queue.length };
			const receipt = this.findReceipt(item.receiptId);
			if (receipt.attemptCount >= this.maxAttempts) {
				receipt.status = "dead_letter";
				this.state.deadLetteredTotal = (this.state.deadLetteredTotal ?? 0) + 1;
				receipt.updatedAtMs = nowMs;
				receipt.nextAttemptAtMs = undefined;
				receipt.lastErrorCode = "delivery_interrupted";
				this.state.queue = this.state.queue.filter(
					(candidate) => candidate.receiptId !== receipt.receiptId,
				);
				this.trimReceipts();
				await persistState(this.stateFile, this.state);
				return { deadLettered: 1, pending: this.state.queue.length };
			}

			const token = randomUUID();
			const claimExpiresAtMs = nowMs + this.requestTimeoutMs + 5_000;
			item.claimToken = token;
			item.claimExpiresAtMs = claimExpiresAtMs;
			receipt.attemptCount += 1;
			receipt.status = "retrying";
			receipt.updatedAtMs = nowMs;
			receipt.nextAttemptAtMs = claimExpiresAtMs;
			await persistState(this.stateFile, this.state);
			return {
				claim: { receiptId: item.receiptId, token, envelope: item.envelope },
				deadLettered: 0,
				pending: this.state.queue.length,
			};
		});
	}

	async sendClaim(claim: SiemDeliveryClaim): Promise<SiemDeliveryAttempt> {
		return this.send(claim.envelope);
	}

	async completeClaim(
		claim: SiemDeliveryClaim,
		classified: SiemDeliveryAttempt,
	): Promise<SiemDeliveryCompletion> {
		return this.exclusive(async () => {
			const item = this.state.queue.find((candidate) => candidate.receiptId === claim.receiptId);
			if (!item || item.claimToken !== claim.token) {
				return {
					applied: false,
					delivered: 0,
					retrying: 0,
					deadLettered: 0,
					pending: this.state.queue.length,
				};
			}
			const receipt = this.findReceipt(item.receiptId);
			receipt.updatedAtMs = this.now();
			receipt.lastStatusCode = classified.statusCode || undefined;
			receipt.lastErrorCode = classified.outcome === "delivered" ? undefined : classified.code;
			delete item.claimToken;
			delete item.claimExpiresAtMs;
			const result: SiemDeliveryCompletion = {
				applied: true,
				delivered: 0,
				retrying: 0,
				deadLettered: 0,
				pending: 0,
			};
			if (classified.outcome === "delivered") {
				receipt.status = "delivered";
				receipt.deliveryCode = classified.code;
				receipt.nextAttemptAtMs = undefined;
				this.state.queue = this.state.queue.filter(
					(candidate) => candidate.receiptId !== receipt.receiptId,
				);
				result.delivered = 1;
			} else if (classified.outcome === "permanent" || receipt.attemptCount >= this.maxAttempts) {
				receipt.status = "dead_letter";
				this.state.deadLetteredTotal = (this.state.deadLetteredTotal ?? 0) + 1;
				receipt.nextAttemptAtMs = undefined;
				this.state.queue = this.state.queue.filter(
					(candidate) => candidate.receiptId !== receipt.receiptId,
				);
				result.deadLettered = 1;
			} else {
				receipt.status = "retrying";
				receipt.nextAttemptAtMs =
					this.now() + this.backoffMs(receipt.attemptCount, classified.retryAfterMs);
				result.retrying = 1;
			}
			this.trimReceipts();
			await persistState(this.stateFile, this.state);
			result.pending = this.state.queue.length;
			return result;
		});
	}

	async flush(maxItems = 100): Promise<SiemFlushResult> {
		assertPositiveInteger("maxItems", maxItems);
		const result: SiemFlushResult = {
			attempted: 0,
			delivered: 0,
			retrying: 0,
			deadLettered: 0,
			pending: this.state.queue.length,
		};
		for (let index = 0; index < maxItems; index++) {
			const claimed = await this.claimNext();
			result.deadLettered += claimed.deadLettered;
			result.pending = claimed.pending;
			if (!claimed.claim) {
				if (claimed.deadLettered > 0) continue;
				break;
			}
			result.attempted += 1;
			const completed = await this.completeClaim(
				claimed.claim,
				await this.sendClaim(claimed.claim),
			);
			result.delivered += completed.delivered;
			result.retrying += completed.retrying;
			result.deadLettered += completed.deadLettered;
			result.pending = completed.pending;
		}
		return result;
	}

	async getReceipt(receiptId: string): Promise<SiemDeliveryReceipt | undefined> {
		return this.exclusive(async () => {
			const receipt = this.state.receipts.find((item) => item.receiptId === receiptId);
			return receipt ? cloneReceipt(receipt) : undefined;
		});
	}

	async listReceipts(limit = 100): Promise<SiemDeliveryReceipt[]> {
		assertPositiveInteger("limit", limit);
		return this.exclusive(async () =>
			this.state.receipts.slice(-limit).reverse().map(cloneReceipt),
		);
	}

	async health(): Promise<SiemDeliveryHealth> {
		return this.exclusive(async () => {
			const nowMs = this.now();
			const delivered = this.state.receipts.filter((item) => item.status === "delivered");
			const dead = this.state.receipts.filter((item) => item.status === "dead_letter");
			const retrying = this.state.receipts.filter((item) => item.status === "retrying");
			const failures = this.state.receipts.filter((item) => item.lastErrorCode);
			const lastFailure = failures.sort((a, b) => b.updatedAtMs - a.updatedAtMs)[0];
			const lastDelivered = delivered.sort((a, b) => b.updatedAtMs - a.updatedAtMs)[0];
			const oldest = this.state.queue.reduce(
				(age, item) => Math.max(age, nowMs - this.findReceipt(item.receiptId).enqueuedAtMs),
				0,
			);
			const authorizationFailure = lastFailure?.lastErrorCode === "authorization_rejected";
			return {
				status:
					authorizationFailure || (this.state.deadLetteredTotal ?? 0) > 0
						? "unhealthy"
						: retrying.length > 0 || this.state.queue.length > 0
							? "degraded"
							: "healthy",
				provider: this.adapter.provider,
				endpointOrigin: this.adapter.endpointOrigin,
				queueDepth: this.state.queue.length,
				queueBytes: this.queueBytes(),
				queueCapacity: this.maxQueueEntries,
				queueByteCapacity: this.maxQueueBytes,
				oldestQueuedAgeMs: Math.max(0, oldest),
				retrying: retrying.length,
				deadLettered: dead.length,
				deadLetteredTotal: this.state.deadLetteredTotal ?? 0,
				delivered: delivered.length,
				lastDeliveredAtMs: lastDelivered?.updatedAtMs,
				lastFailureAtMs: lastFailure?.updatedAtMs,
				lastErrorCode: lastFailure?.lastErrorCode,
			};
		});
	}
}
