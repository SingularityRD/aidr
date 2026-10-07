/**
 * Privacy telemetry client. Implements docs/contracts/privacy-telemetry.md exactly:
 * POST {controlPlaneUrl}/functions/v1/ingest with the shared connector envelope and
 * `privacy_scan` events that carry counts only (no text, no values, no URLs), plus
 * aggregated `shadow_ai_usage` counts (catalog service id, visited|blocked, count), and
 * `aup_acknowledgement` events (notice id and version only, never the notice text).
 *
 * Events are queued in chrome.storage.local (bounded, oldest dropped) so a worker
 * restart does not lose them, flushed every 60 s by chrome.alarms or as soon as 50
 * are pending, and retried with exponential backoff plus jitter (capped at 1 h).
 * Nothing here ever blocks the user: callers fire and forget.
 */
import { AI_SERVICE_ID_PATTERN, isAiServiceId } from "../sites/catalog.js";
import {
	type AupAcknowledgementEvent,
	ENTITY_TYPES,
	type EntityType,
	type PrivacyScanEvent,
	type ShadowAiUsageEvent,
	type SiteId,
	type TelemetryConfig,
	type TelemetryEvent,
} from "../types.js";
import { NOTICE_ID_PATTERN, NOTICE_LIMITS, POLICY_ID_PATTERN, SITE_ID_LIST } from "./policy.js";
import { type GuardStorage, STORAGE_KEYS } from "./storage.js";

export const TELEMETRY_LIMITS = Object.freeze({
	queueMax: 500,
	flushThreshold: 50,
	batchMax: 200,
	flushPeriodMinutes: 1,
	backoffBaseMs: 30_000,
	backoffMaxMs: 60 * 60 * 1000,
	requestTimeoutMs: 15_000,
	countMax: 100_000,
	countKeysMax: 32,
	findingsMax: 1_000_000,
});

export const TELEMETRY_ALARM = "aidr-telemetry-flush";
export const AGENT_RUNTIME = "browser_guard";

const ACTIONS: readonly PrivacyScanEvent["action"][] = ["masked", "blocked", "warned", "allowed"];
const CHANNELS: readonly PrivacyScanEvent["channel"][] = ["prompt", "paste", "file"];
const EVENT_ID_PATTERN = /^bg:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const EVENT_KEYS = new Set([
	"event_id",
	"event_type",
	"timestamp",
	"site",
	"action",
	"channel",
	"entity_counts",
	"findings_count",
	"policy_id",
]);

/** Known entity types only, integers 1..100000, at most 32 keys. Everything else is dropped. */
export function sanitizeCounts(raw: unknown): Partial<Record<EntityType, number>> {
	const out: Partial<Record<EntityType, number>> = {};
	if (!raw || typeof raw !== "object" || Array.isArray(raw)) return out;
	let keys = 0;
	for (const type of ENTITY_TYPES) {
		if (keys >= TELEMETRY_LIMITS.countKeysMax) break;
		if (!Object.hasOwn(raw, type)) continue;
		const n = (raw as Record<string, unknown>)[type];
		if (!Number.isSafeInteger(n) || (n as number) < 1) continue;
		out[type] = Math.min(n as number, TELEMETRY_LIMITS.countMax);
		keys++;
	}
	return out;
}

function sumCounts(counts: Partial<Record<EntityType, number>>): number {
	let total = 0;
	for (const n of Object.values(counts)) total += n ?? 0;
	return Math.min(total, TELEMETRY_LIMITS.findingsMax);
}

/** Identity and classification fields: id, type, timestamp, site, action, channel. */
function hasValidHeader(e: Record<string, unknown>): boolean {
	return (
		typeof e.event_id === "string" &&
		EVENT_ID_PATTERN.test(e.event_id) &&
		e.event_type === "privacy_scan" &&
		typeof e.timestamp === "string" &&
		!Number.isNaN(Date.parse(e.timestamp)) &&
		SITE_ID_LIST.includes(e.site as SiteId) &&
		ACTIONS.includes(e.action as PrivacyScanEvent["action"]) &&
		CHANNELS.includes(e.channel as PrivacyScanEvent["channel"])
	);
}

const isFindingsCount = (raw: unknown): raw is number =>
	Number.isSafeInteger(raw) &&
	(raw as number) >= 0 &&
	(raw as number) <= TELEMETRY_LIMITS.findingsMax;

const isOptionalPolicyId = (raw: unknown): boolean =>
	raw === undefined || (typeof raw === "string" && POLICY_ID_PATTERN.test(raw));

/**
 * Re-validates an event against the contract (queued events come back from storage).
 * Returns a fresh object holding only contract fields, or null.
 */
export function sanitizeEvent(raw: unknown): PrivacyScanEvent | null {
	if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
	const e = raw as Record<string, unknown>;
	if (Object.keys(e).some((k) => !EVENT_KEYS.has(k))) return null;
	if (!hasValidHeader(e)) return null;
	const findings = e.findings_count;
	if (!isFindingsCount(findings) || !isOptionalPolicyId(e.policy_id)) return null;
	const event: PrivacyScanEvent = {
		event_id: e.event_id as string,
		event_type: "privacy_scan",
		timestamp: new Date(Date.parse(e.timestamp as string)).toISOString(),
		site: e.site as SiteId,
		action: e.action as PrivacyScanEvent["action"],
		channel: e.channel as PrivacyScanEvent["channel"],
		entity_counts: sanitizeCounts(e.entity_counts),
		findings_count: findings,
		...(typeof e.policy_id === "string" ? { policy_id: e.policy_id } : {}),
	};
	return event;
}

/** Contract fields of an `aup_acknowledgement` event, and nothing else. */
export const AUP_ACK_EVENT_KEYS: readonly string[] = Object.freeze([
	"event_id",
	"event_type",
	"timestamp",
	"site",
	"notice_id",
	"notice_version",
]);

const isNoticeVersion = (raw: unknown): raw is number =>
	Number.isSafeInteger(raw) && (raw as number) >= 1 && (raw as number) <= NOTICE_LIMITS.versionMax;

/** Re-validates an acknowledgement event; returns a fresh contract-only object or null. */
export function sanitizeAupAckEvent(raw: unknown): AupAcknowledgementEvent | null {
	if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
	const e = raw as Record<string, unknown>;
	if (Object.keys(e).some((k) => !AUP_ACK_EVENT_KEYS.includes(k))) return null;
	if (typeof e.event_id !== "string" || !EVENT_ID_PATTERN.test(e.event_id)) return null;
	if (e.event_type !== "aup_acknowledgement") return null;
	if (typeof e.timestamp !== "string" || Number.isNaN(Date.parse(e.timestamp))) return null;
	if (!SITE_ID_LIST.includes(e.site as SiteId)) return null;
	if (typeof e.notice_id !== "string" || !NOTICE_ID_PATTERN.test(e.notice_id)) return null;
	if (!isNoticeVersion(e.notice_version)) return null;
	return {
		event_id: e.event_id,
		event_type: "aup_acknowledgement",
		timestamp: new Date(Date.parse(e.timestamp)).toISOString(),
		site: e.site as SiteId,
		notice_id: e.notice_id,
		notice_version: e.notice_version,
	};
}

export interface AcknowledgementInput {
	readonly site: SiteId;
	readonly noticeId: string;
	readonly noticeVersion: number;
}

export function buildAupAckEvent(
	input: AcknowledgementInput,
	now: number,
): AupAcknowledgementEvent | null {
	return sanitizeAupAckEvent({
		event_id: `bg:${crypto.randomUUID()}`,
		event_type: "aup_acknowledgement",
		timestamp: new Date(now).toISOString(),
		site: input.site,
		notice_id: input.noticeId,
		notice_version: input.noticeVersion,
	});
}

export interface RecordInput {
	readonly site: SiteId;
	readonly action: PrivacyScanEvent["action"];
	readonly channel: PrivacyScanEvent["channel"];
	readonly counts: unknown;
	readonly policyId?: string;
}

const SHADOW_ACTIONS: readonly ShadowAiUsageEvent["action"][] = ["visited", "blocked"];
const SHADOW_EVENT_KEYS = new Set([
	"event_id",
	"event_type",
	"timestamp",
	"service_id",
	"action",
	"count",
	"sanctioned",
	"policy_id",
]);

/**
 * Re-validates a `shadow_ai_usage` event: a known catalog id, visited|blocked, a count
 * of 1..100000, a boolean `sanctioned` and nothing else (no URL can ride along).
 */
export function sanitizeShadowEvent(raw: unknown): ShadowAiUsageEvent | null {
	if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
	const e = raw as Record<string, unknown>;
	if (Object.keys(e).some((k) => !SHADOW_EVENT_KEYS.has(k))) return null;
	if (typeof e.event_id !== "string" || !EVENT_ID_PATTERN.test(e.event_id)) return null;
	if (e.event_type !== "shadow_ai_usage") return null;
	if (typeof e.timestamp !== "string" || Number.isNaN(Date.parse(e.timestamp))) return null;
	if (typeof e.service_id !== "string" || !AI_SERVICE_ID_PATTERN.test(e.service_id)) return null;
	if (!isAiServiceId(e.service_id)) return null;
	if (!SHADOW_ACTIONS.includes(e.action as ShadowAiUsageEvent["action"])) return null;
	if (!Number.isSafeInteger(e.count) || (e.count as number) < 1) return null;
	if ((e.count as number) > TELEMETRY_LIMITS.countMax) return null;
	if (typeof e.sanctioned !== "boolean" || !isOptionalPolicyId(e.policy_id)) return null;
	return {
		event_id: e.event_id,
		event_type: "shadow_ai_usage",
		timestamp: new Date(Date.parse(e.timestamp)).toISOString(),
		service_id: e.service_id,
		action: e.action as ShadowAiUsageEvent["action"],
		count: e.count as number,
		sanctioned: e.sanctioned,
		...(typeof e.policy_id === "string" ? { policy_id: e.policy_id } : {}),
	};
}

/** Any queued event, re-validated against its contract. */
export function sanitizeQueuedEvent(raw: unknown): TelemetryEvent | null {
	const type = raw && typeof raw === "object" ? (raw as { event_type?: unknown }).event_type : null;
	if (type === "shadow_ai_usage") return sanitizeShadowEvent(raw);
	if (type === "aup_acknowledgement") return sanitizeAupAckEvent(raw);
	return sanitizeEvent(raw);
}

export interface ShadowRecordInput {
	readonly serviceId: string;
	readonly action: ShadowAiUsageEvent["action"];
	readonly count: number;
	readonly sanctioned: boolean;
	readonly policyId?: string;
}

export function buildShadowEvent(input: ShadowRecordInput, now: number): ShadowAiUsageEvent | null {
	return sanitizeShadowEvent({
		event_id: `bg:${crypto.randomUUID()}`,
		event_type: "shadow_ai_usage",
		timestamp: new Date(now).toISOString(),
		service_id: input.serviceId,
		action: input.action,
		count: Math.min(input.count, TELEMETRY_LIMITS.countMax),
		sanctioned: input.sanctioned,
		...(input.policyId && POLICY_ID_PATTERN.test(input.policyId)
			? { policy_id: input.policyId }
			: {}),
	});
}

export function buildEvent(input: RecordInput, now: number): PrivacyScanEvent | null {
	const entityCounts = sanitizeCounts(input.counts);
	return sanitizeEvent({
		event_id: `bg:${crypto.randomUUID()}`,
		event_type: "privacy_scan",
		timestamp: new Date(now).toISOString(),
		site: input.site,
		action: input.action,
		channel: input.channel,
		entity_counts: entityCounts,
		findings_count: sumCounts(entityCounts),
		...(input.policyId && POLICY_ID_PATTERN.test(input.policyId)
			? { policy_id: input.policyId }
			: {}),
	});
}

interface UserAgentDataLike {
	readonly brands?: ReadonlyArray<{ readonly brand: string; readonly version: string }>;
}
export interface NavigatorLike {
	readonly userAgent?: string;
	readonly userAgentData?: UserAgentDataLike;
}

/** `chrome-NNN`, `edge-NNN` or `firefox-NNN` (browser family and major version). */
export function browserRuntimeVersion(nav: NavigatorLike | undefined): string {
	const brands = nav?.userAgentData?.brands ?? [];
	const major = (v: string | undefined) => (v && /^\d{1,4}/.exec(v)?.[0]) || undefined;
	const edge = brands.find((b) => b.brand === "Microsoft Edge");
	if (edge && major(edge.version)) return `edge-${major(edge.version)}`;
	const chrome = brands.find((b) => b.brand === "Google Chrome" || b.brand === "Chromium");
	if (chrome && major(chrome.version)) return `chrome-${major(chrome.version)}`;
	const ua = nav?.userAgent ?? "";
	const match =
		/Edg(?:e|A|iOS)?\/(\d{1,4})/.exec(ua) ??
		/Firefox\/(\d{1,4})/.exec(ua) ??
		/Chrom(?:e|ium)\/(\d{1,4})/.exec(ua);
	if (!match) return "unknown";
	const family = match[0].startsWith("Edg")
		? "edge"
		: match[0].startsWith("Firefox")
			? "firefox"
			: "chrome";
	return `${family}-${match[1]}`;
}

export interface IngestEnvelope {
	readonly iid: string;
	readonly agent_runtime: typeof AGENT_RUNTIME;
	readonly agent_runtime_version: string;
	readonly aidr_version: string;
	readonly events: readonly TelemetryEvent[];
}

interface TelemetryState {
	/** Consecutive failed deliveries. */
	failures: number;
	/** Epoch ms before which no delivery is attempted. */
	nextAttemptAt: number;
	/** Identifies the configured destination; the queue is dropped when it changes. */
	target: string | null;
}

const EMPTY_STATE: TelemetryState = { failures: 0, nextAttemptAt: 0, target: null };

export interface TelemetryDeps {
	readonly storage: GuardStorage;
	readonly fetch: typeof fetch;
	readonly now: () => number;
	readonly random: () => number;
	readonly navigator?: NavigatorLike;
	readonly aidrVersion: string;
	readonly log?: (message: string) => void;
}

export type FlushOutcome =
	| "disabled"
	| "empty"
	| "backoff"
	| "busy"
	| "sent"
	| "dropped"
	| "failed";

/** Delay before retry `failures` (1-based): equal-jitter exponential backoff, capped at 1 h. */
export function backoffDelay(failures: number, random: () => number): number {
	const exp = Math.min(
		TELEMETRY_LIMITS.backoffMaxMs,
		TELEMETRY_LIMITS.backoffBaseMs * 2 ** Math.max(0, Math.min(failures - 1, 30)),
	);
	const r = Math.min(Math.max(random(), 0), 1);
	return Math.round(exp / 2 + (exp / 2) * r);
}

export function ingestUrl(config: TelemetryConfig): string {
	return `${config.controlPlaneUrl.replace(/\/+$/, "")}/functions/v1/ingest`;
}

async function targetId(config: TelemetryConfig): Promise<string> {
	const digest = await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode(`${config.controlPlaneUrl}\n${config.apiKey}`),
	);
	return [...new Uint8Array(digest).slice(0, 12)]
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

function sameConfig(a: TelemetryConfig | null, b: TelemetryConfig | null): boolean {
	return a?.controlPlaneUrl === b?.controlPlaneUrl && a?.apiKey === b?.apiKey;
}

export class TelemetryClient {
	private config: TelemetryConfig | null = null;
	private chain: Promise<unknown> = Promise.resolve();
	private flushing: Promise<FlushOutcome> | null = null;
	private readonly log: (message: string) => void;

	constructor(private readonly deps: TelemetryDeps) {
		this.log = deps.log ?? (() => {});
	}

	get enabled(): boolean {
		return this.config !== null;
	}

	/** Applies the effective policy's telemetry config; queued events never cross destinations. */
	configure(config: TelemetryConfig | null): Promise<void> {
		this.config = config;
		return this.serial(async () => {
			const state = await this.readState();
			const target = config ? await targetId(config) : null;
			if (state.target === target) return;
			await this.deps.storage.setLocal(STORAGE_KEYS.telemetryQueue, []);
			await this.writeState({ ...EMPTY_STATE, target });
		});
	}

	/** Queues one event (dropped when telemetry is not configured). Flushes at the threshold. */
	async record(input: RecordInput): Promise<void> {
		if (!this.config) return;
		const event = buildEvent(input, this.deps.now());
		if (event) await this.enqueue(event);
	}

	/** Queues one acceptable-use acknowledgement (dropped when telemetry is not configured). */
	async recordAcknowledgement(input: AcknowledgementInput): Promise<void> {
		if (!this.config) return;
		const event = buildAupAckEvent(input, this.deps.now());
		if (event) await this.enqueue(event);
	}

	/** Queues one aggregated Shadow AI count (dropped when telemetry is not configured). */
	async recordShadow(input: ShadowRecordInput): Promise<void> {
		if (!this.config) return;
		const event = buildShadowEvent(input, this.deps.now());
		if (event) await this.enqueue(event);
	}

	private async enqueue(event: TelemetryEvent): Promise<void> {
		const size = await this.serial(async () => {
			const queue = await this.readQueue();
			queue.push(event);
			const bounded = queue.slice(-TELEMETRY_LIMITS.queueMax);
			await this.deps.storage.setLocal(STORAGE_KEYS.telemetryQueue, bounded);
			return bounded.length;
		});
		if (size >= TELEMETRY_LIMITS.flushThreshold) void this.flush();
	}

	async pending(): Promise<readonly TelemetryEvent[]> {
		return this.serial(() => this.readQueue());
	}

	/** Sends at most one batch. Concurrent callers share the in-flight attempt. */
	flush(): Promise<FlushOutcome> {
		if (this.flushing) return this.flushing;
		this.flushing = this.flushOnce().finally(() => {
			this.flushing = null;
		});
		return this.flushing;
	}

	private async flushOnce(): Promise<FlushOutcome> {
		const config = this.config;
		if (!config) return "disabled";
		const state = await this.serial(() => this.readState());
		if (state.nextAttemptAt > this.deps.now()) return "backoff";
		const batch = (await this.pending()).slice(0, TELEMETRY_LIMITS.batchMax);
		if (batch.length === 0) return "empty";

		const envelope: IngestEnvelope = {
			iid: await this.deps.storage.installationId(),
			agent_runtime: AGENT_RUNTIME,
			agent_runtime_version: browserRuntimeVersion(this.deps.navigator),
			aidr_version: this.deps.aidrVersion,
			events: batch,
		};

		let status = 0;
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), TELEMETRY_LIMITS.requestTimeoutMs);
		try {
			const response = await this.deps.fetch(ingestUrl(config), {
				method: "POST",
				headers: {
					Authorization: `Bearer ${config.apiKey}`,
					"Content-Type": "application/json",
				},
				body: JSON.stringify(envelope),
				credentials: "omit",
				cache: "no-store",
				redirect: "error",
				signal: controller.signal,
			});
			status = response.status;
		} catch {
			status = 0;
		} finally {
			clearTimeout(timer);
		}

		// Reconfigured to another destination mid-flight: configure() already reset the queue.
		if (!sameConfig(this.config, config)) return "failed";
		const sentIds = new Set(batch.map((e) => e.event_id));
		// 2xx: delivered. 400/413/422: the server will never accept this batch; retrying a
		// poison batch would wedge the queue, so it is dropped (counts only, no user data).
		const drop = status === 400 || status === 413 || status === 422;
		if ((status >= 200 && status < 300) || drop) {
			await this.serial(async () => {
				const queue = await this.readQueue();
				await this.deps.storage.setLocal(
					STORAGE_KEYS.telemetryQueue,
					queue.filter((e) => !sentIds.has(e.event_id)),
				);
				const current = await this.readState();
				await this.writeState({ ...current, failures: 0, nextAttemptAt: 0 });
			});
			if (drop) this.log(`telemetry: batch rejected with HTTP ${status}; dropped`);
			return drop ? "dropped" : "sent";
		}
		await this.serial(async () => {
			const current = await this.readState();
			const failures = current.failures + 1;
			await this.writeState({
				...current,
				failures,
				nextAttemptAt: this.deps.now() + backoffDelay(failures, this.deps.random),
			});
		});
		this.log(`telemetry: delivery failed (${status || "network"}); backing off`);
		return "failed";
	}

	private serial<T>(task: () => Promise<T>): Promise<T> {
		const next = this.chain.then(task, task);
		this.chain = next.catch(() => {});
		return next;
	}

	private async readQueue(): Promise<TelemetryEvent[]> {
		const raw = await this.deps.storage.getLocal(STORAGE_KEYS.telemetryQueue);
		if (!Array.isArray(raw)) return [];
		const out: TelemetryEvent[] = [];
		for (const item of raw.slice(-TELEMETRY_LIMITS.queueMax)) {
			const event = sanitizeQueuedEvent(item);
			if (event) out.push(event);
		}
		return out;
	}

	private async readState(): Promise<TelemetryState> {
		const raw = await this.deps.storage.getLocal(STORAGE_KEYS.telemetryState);
		if (!raw || typeof raw !== "object") return { ...EMPTY_STATE };
		const s = raw as Record<string, unknown>;
		return {
			failures: Number.isSafeInteger(s.failures) ? Math.max(0, s.failures as number) : 0,
			nextAttemptAt:
				typeof s.nextAttemptAt === "number" && Number.isFinite(s.nextAttemptAt)
					? Math.min(s.nextAttemptAt, this.deps.now() + TELEMETRY_LIMITS.backoffMaxMs)
					: 0,
			target: typeof s.target === "string" ? s.target : null,
		};
	}

	private async writeState(state: TelemetryState): Promise<void> {
		await this.deps.storage.setLocal(STORAGE_KEYS.telemetryState, state);
	}
}
