/**
 * Durable, bounded delivery queue for control-plane telemetry.
 *
 * Every event receives a stable identity before it is written to the WAL. A
 * process may therefore resend after a crash without creating another server
 * event: the ingest service owns the matching tenant + event_id uniqueness
 * constraint. Queue pressure and storage failures are returned to the caller
 * and counted; this module never reports an unpersisted event as queued.
 */

import { createHash, randomUUID } from "node:crypto";
import {
	appendFile,
	chmod,
	lstat,
	mkdir,
	open,
	readdir,
	readFile,
	rename,
	rmdir,
	unlink,
	writeFile,
} from "node:fs/promises";
import { hostname } from "node:os";
import { dirname, join } from "node:path";
import { preparePrivateLocalFile } from "./private-local-file.js";
import { redactTelemetryData } from "./telemetry-redaction.js";

const WAL_VERSION = 1;
const EVENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const EVENT_HASH_PATTERN = /^[a-f0-9]{64}$/;
const RECENT_EVENT_LIMIT = 2_048;
const DEFAULT_MAX_READY_PENDING_AGE_MS = 5 * 60 * 1_000;
const LEGACY_LOCK_OWNER_FILE = "owner.json";
const LOCK_OWNER_PREFIX = "owner-";
const LOCK_OWNER_SUFFIX = ".json";
const LOSS_REASONS = new Set<TelemetryLossReason>([
	"event_id_conflict",
	"event_too_large",
	"invalid_event",
	"max_attempts",
	"permanent_rejection",
	"queue_full",
	"storage_unavailable",
]);

export type TelemetryLossReason =
	| "event_id_conflict"
	| "event_too_large"
	| "invalid_event"
	| "max_attempts"
	| "permanent_rejection"
	| "queue_full"
	| "storage_unavailable";

type TelemetryDeliveryState = "available" | "unavailable";
type TelemetryQueueState = "delivered" | "idle" | "queued" | "unavailable";

export interface DurableTelemetryEvent extends Record<string, unknown> {
	event_id: string;
}

export interface TelemetryQueueMetrics {
	enqueuedTotal: number;
	deliveredTotal: number;
	lostTotal: number;
	deliveryFailuresTotal: number;
	duplicateEnqueuesTotal: number;
	queueFullTotal: number;
	storageErrorsTotal: number;
	pendingEvents: number;
	pendingBytes: number;
	oldestPendingAt?: string;
	lastLossReason?: TelemetryLossReason;
}

export interface TelemetryQueueStatus {
	state: TelemetryQueueState;
	deliveryState: TelemetryDeliveryState;
	reason?: string;
	metrics: TelemetryQueueMetrics;
}

/** Stable file contract consumed by the deployment readiness monitor. */
export interface TelemetryQueueReadinessEvidence {
	schema_version: 1;
	status: "degraded" | "ok";
	checked_at: string;
	depth: number;
	oldest_age_seconds: number;
	failed_jobs: number;
}

export interface TelemetryEnqueueResult extends TelemetryQueueStatus {
	acceptedEventIds: string[];
	duplicateEventIds: string[];
	pendingDuplicateEventIds: string[];
	deliveredDuplicateEventIds: string[];
	rejected: Array<{ eventId?: string; reason: TelemetryLossReason }>;
}

export interface TelemetryDeliveryResult {
	ok: boolean;
	/** Omit on success when the complete batch was durably accepted. */
	acknowledgedEventIds?: string[];
	/** A permanent rejection drops the selected records and increments loss. */
	retryable?: boolean;
	reason?: string;
}

export interface TelemetryFlushResult extends TelemetryQueueStatus {
	attemptedEventIds: string[];
	acknowledgedEventIds: string[];
}

export interface TelemetryQueueOptions {
	directory: string;
	maxEvents?: number;
	maxBytes?: number;
	maxEventBytes?: number;
	batchSize?: number;
	maxAttempts?: number;
	initialRetryMs?: number;
	maxRetryMs?: number;
	/** Pending events older than this make readiness degraded. */
	maxReadyPendingAgeMs?: number;
	lockTimeoutMs?: number;
	staleLockMs?: number;
	now?: () => number;
	/** Test-only fault injection; production callers should leave this unset. */
	faultInjector?: (operation: "append" | "compact" | "mkdir") => void | Promise<void>;
}

interface QueueEntry {
	event: DurableTelemetryEvent;
	eventHash: string;
	bytes: number;
	attempts: number;
	createdAt: number;
	nextAttemptAt: number;
}

interface LockOwner {
	v: 1;
	token: string;
	pid: number;
	host: string;
	acquiredAt: number;
	/** Absent on legacy owner markers written before process-generation tracking. */
	processStartedAtMs?: number;
}

interface LockOwnerRecord {
	owner: LockOwner;
	marker: string;
}

interface Totals {
	enqueuedTotal: number;
	deliveredTotal: number;
	lostTotal: number;
	deliveryFailuresTotal: number;
	duplicateEnqueuesTotal: number;
	queueFullTotal: number;
	storageErrorsTotal: number;
	lastLossReason?: TelemetryLossReason;
}

interface QueueSnapshot {
	pending: Map<string, QueueEntry>;
	recent: Map<string, string>;
	totals: Totals;
	recordCount: number;
	walBytes: number;
	truncatedTail: boolean;
	validBytes: number;
}

type WalRecord =
	| {
			v: typeof WAL_VERSION;
			op: "checkpoint";
			totals: Totals;
			pending: QueueEntry[];
			recent: Array<[string, string]>;
	  }
	| { v: typeof WAL_VERSION; op: "put"; entry: QueueEntry }
	| { v: typeof WAL_VERSION; op: "ack"; ids: string[] }
	| {
			v: typeof WAL_VERSION;
			op: "retry";
			id: string;
			attempts: number;
			nextAttemptAt: number;
			reason?: string;
	  }
	| { v: typeof WAL_VERSION; op: "drop"; id: string; reason: TelemetryLossReason }
	| { v: typeof WAL_VERSION; op: "loss"; count: number; reason: TelemetryLossReason }
	| { v: typeof WAL_VERSION; op: "duplicate"; count: number };

const EMPTY_TOTALS: Totals = {
	enqueuedTotal: 0,
	deliveredTotal: 0,
	lostTotal: 0,
	deliveryFailuresTotal: 0,
	duplicateEnqueuesTotal: 0,
	queueFullTotal: 0,
	storageErrorsTotal: 0,
};

const PROCESS_STARTED_AT_MS = Math.max(0, Math.trunc(Date.now() - process.uptime() * 1000));

/** Keep queue files private and refuse non-regular replacement paths. */
async function preparePrivateTelemetryQueue(directory: string, walPath: string): Promise<void> {
	const directoryInfo = await lstat(directory);
	if (directoryInfo.isSymbolicLink() || !directoryInfo.isDirectory()) {
		throw new Error("telemetry_queue_directory_not_private");
	}
	if (process.platform === "win32") {
		// Node's mode bits do not constrain inherited NTFS readers. This also
		// protects a pre-existing WAL before its first append or replay.
		preparePrivateLocalFile(walPath);
		return;
	}
	await chmod(directory, 0o700);
	try {
		const walInfo = await lstat(walPath);
		if (walInfo.isSymbolicLink() || !walInfo.isFile()) {
			throw new Error("telemetry_queue_wal_not_private");
		}
		await chmod(walPath, 0o600);
	} catch (error) {
		if (errorCode(error) !== "ENOENT") throw error;
	}
}

function cloneTotals(value: Totals = EMPTY_TOTALS): Totals {
	return { ...value };
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isCounter(value: unknown): value is number {
	return Number.isSafeInteger(value) && (value as number) >= 0;
}

function isLossReason(value: unknown): value is TelemetryLossReason {
	return typeof value === "string" && LOSS_REASONS.has(value as TelemetryLossReason);
}

function isQueueEntry(value: unknown): value is QueueEntry {
	if (!isRecord(value) || !isRecord(value.event)) return false;
	const { event, eventHash: hash, bytes, attempts, createdAt, nextAttemptAt } = value;
	return (
		typeof event.event_id === "string" &&
		EVENT_ID_PATTERN.test(event.event_id) &&
		typeof hash === "string" &&
		EVENT_HASH_PATTERN.test(hash) &&
		hash === eventHash(event as DurableTelemetryEvent) &&
		isCounter(bytes) &&
		bytes === Buffer.byteLength(JSON.stringify(event), "utf8") &&
		isCounter(attempts) &&
		isCounter(createdAt) &&
		isCounter(nextAttemptAt)
	);
}

function isTotals(value: unknown): value is Totals {
	if (!isRecord(value)) return false;
	return (
		(
			[
				"enqueuedTotal",
				"deliveredTotal",
				"lostTotal",
				"deliveryFailuresTotal",
				"duplicateEnqueuesTotal",
				"queueFullTotal",
				"storageErrorsTotal",
			] as const
		).every((field) => isCounter(value[field])) &&
		(value.lastLossReason === undefined || isLossReason(value.lastLossReason))
	);
}

function isWalRecord(value: unknown): value is WalRecord {
	if (!isRecord(value) || value.v !== WAL_VERSION) return false;
	switch (value.op) {
		case "checkpoint":
			return (
				isTotals(value.totals) &&
				Array.isArray(value.pending) &&
				value.pending.every(isQueueEntry) &&
				Array.isArray(value.recent) &&
				value.recent.every(
					(pair: unknown) =>
						Array.isArray(pair) &&
						pair.length === 2 &&
						typeof pair[0] === "string" &&
						EVENT_ID_PATTERN.test(pair[0]) &&
						typeof pair[1] === "string" &&
						EVENT_HASH_PATTERN.test(pair[1]),
				)
			);
		case "put":
			return isQueueEntry(value.entry);
		case "ack":
			return (
				Array.isArray(value.ids) &&
				value.ids.every((id: unknown) => typeof id === "string" && EVENT_ID_PATTERN.test(id))
			);
		case "retry":
			return (
				typeof value.id === "string" &&
				EVENT_ID_PATTERN.test(value.id) &&
				isCounter(value.attempts) &&
				isCounter(value.nextAttemptAt) &&
				(value.reason === undefined || typeof value.reason === "string")
			);
		case "drop":
			return (
				typeof value.id === "string" &&
				EVENT_ID_PATTERN.test(value.id) &&
				isLossReason(value.reason)
			);
		case "loss":
			return isCounter(value.count) && value.count > 0 && isLossReason(value.reason);
		case "duplicate":
			return isCounter(value.count) && value.count > 0;
		default:
			return false;
	}
}

function canonicalize(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(canonicalize);
	if (!value || typeof value !== "object") return value;
	const source = value as Record<string, unknown>;
	const output: Record<string, unknown> = {};
	for (const key of Object.keys(source).sort()) output[key] = canonicalize(source[key]);
	return output;
}

function eventHash(event: DurableTelemetryEvent): string {
	return createHash("sha256")
		.update(JSON.stringify(canonicalize(event)))
		.digest("hex");
}

function errorCode(error: unknown): string {
	return typeof error === "object" && error !== null && "code" in error
		? String((error as { code?: unknown }).code ?? "")
		: "";
}

function isMissing(error: unknown): boolean {
	return errorCode(error) === "ENOENT";
}

function isLockOwner(value: unknown): value is LockOwner {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const owner = value as Partial<LockOwner>;
	return (
		owner.v === 1 &&
		typeof owner.token === "string" &&
		owner.token.length > 0 &&
		Number.isSafeInteger(owner.pid) &&
		(owner.pid ?? 0) > 0 &&
		typeof owner.host === "string" &&
		owner.host.length > 0 &&
		Number.isFinite(owner.acquiredAt) &&
		(owner.acquiredAt ?? 0) > 0 &&
		(owner.processStartedAtMs === undefined ||
			(Number.isSafeInteger(owner.processStartedAtMs) && owner.processStartedAtMs >= 0))
	);
}

function processIsAlive(owner: LockOwner): boolean | null {
	if (owner.pid === process.pid) {
		if (owner.processStartedAtMs !== undefined) {
			return owner.processStartedAtMs === PROCESS_STARTED_AT_MS;
		}
		// Legacy markers have no generation identifier. Their acquisition time
		// still distinguishes a prior process that happened to reuse our PID.
		return owner.acquiredAt >= PROCESS_STARTED_AT_MS;
	}
	try {
		process.kill(owner.pid, 0);
		return true;
	} catch (error) {
		if (errorCode(error) === "ESRCH") return false;
		if (errorCode(error) === "EPERM") return true;
		return null;
	}
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

async function writeSyncedExclusive(path: string, content: string): Promise<void> {
	const handle = await open(path, "wx", 0o600);
	try {
		await handle.writeFile(content, "utf8");
		await handle.sync();
	} finally {
		await handle.close();
	}
}

export class DurableTelemetryQueue {
	private readonly directory: string;
	private readonly walPath: string;
	private readonly lockPath: string;
	private readonly maxEvents: number;
	private readonly maxBytes: number;
	private readonly maxEventBytes: number;
	private readonly batchSize: number;
	private readonly maxAttempts: number;
	private readonly initialRetryMs: number;
	private readonly maxRetryMs: number;
	private readonly maxReadyPendingAgeMs: number;
	private readonly lockTimeoutMs: number;
	private readonly staleLockMs: number;
	private readonly now: () => number;
	private readonly faultInjector?: TelemetryQueueOptions["faultInjector"];
	private operation: Promise<void> = Promise.resolve();
	private volatileStorageErrors = 0;
	private volatileLosses = 0;
	private volatileLastLossReason?: TelemetryLossReason;

	constructor(options: TelemetryQueueOptions) {
		if (!options.directory.trim()) throw new Error("telemetry queue directory is required");
		for (const [name, value] of Object.entries({
			maxEvents: options.maxEvents,
			maxBytes: options.maxBytes,
			maxEventBytes: options.maxEventBytes,
			batchSize: options.batchSize,
			maxAttempts: options.maxAttempts,
			initialRetryMs: options.initialRetryMs,
			maxRetryMs: options.maxRetryMs,
			maxReadyPendingAgeMs: options.maxReadyPendingAgeMs,
			lockTimeoutMs: options.lockTimeoutMs,
			staleLockMs: options.staleLockMs,
		})) {
			if (value !== undefined && (!Number.isSafeInteger(value) || value < 1)) {
				throw new Error(`telemetry queue ${name} must be a positive safe integer`);
			}
		}
		this.directory = options.directory;
		this.walPath = join(this.directory, "events.wal");
		this.lockPath = join(this.directory, ".lock");
		this.maxEvents = Math.max(1, Math.floor(options.maxEvents ?? 10_000));
		this.maxBytes = Math.max(1_024, Math.floor(options.maxBytes ?? 64 * 1024 * 1024));
		this.maxEventBytes = Math.max(256, Math.floor(options.maxEventBytes ?? 256 * 1024));
		this.batchSize = Math.max(1, Math.min(200, Math.floor(options.batchSize ?? 100)));
		this.maxAttempts = Math.max(1, Math.floor(options.maxAttempts ?? 20));
		this.initialRetryMs = Math.max(1, Math.floor(options.initialRetryMs ?? 1_000));
		this.maxRetryMs = Math.max(this.initialRetryMs, Math.floor(options.maxRetryMs ?? 300_000));
		this.maxReadyPendingAgeMs = Math.max(
			1,
			Math.floor(options.maxReadyPendingAgeMs ?? DEFAULT_MAX_READY_PENDING_AGE_MS),
		);
		this.lockTimeoutMs = Math.max(10, Math.floor(options.lockTimeoutMs ?? 1_000));
		this.staleLockMs = Math.max(this.lockTimeoutMs * 2, Math.floor(options.staleLockMs ?? 30_000));
		this.now = options.now ?? Date.now;
		this.faultInjector = options.faultInjector;
	}

	async enqueue(events: ReadonlyArray<Record<string, unknown>>): Promise<TelemetryEnqueueResult> {
		return this.serialized(async () => {
			const acceptedEventIds: string[] = [];
			const duplicateEventIds: string[] = [];
			const pendingDuplicateEventIds: string[] = [];
			const deliveredDuplicateEventIds: string[] = [];
			const rejected: TelemetryEnqueueResult["rejected"] = [];
			let snapshot: QueueSnapshot = {
				pending: new Map(),
				recent: new Map(),
				totals: cloneTotals(),
				recordCount: 0,
				walBytes: 0,
				truncatedTail: false,
				validBytes: 0,
			};

			try {
				// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: one lock-scoped WAL transaction must classify every candidate before returning its persisted result
				await this.withLock(async () => {
					snapshot = await this.loadSnapshot(true);
					for (const candidate of events) {
						let entry: QueueEntry;
						try {
							entry = this.prepareEntry(candidate);
						} catch (error) {
							const reason: TelemetryLossReason =
								error instanceof RangeError ? "event_too_large" : "invalid_event";
							await this.appendRecord({ v: WAL_VERSION, op: "loss", count: 1, reason });
							this.applyRecord(snapshot, { v: WAL_VERSION, op: "loss", count: 1, reason });
							rejected.push({ reason });
							continue;
						}

						const existing = snapshot.pending.get(entry.event.event_id);
						const recentHash = snapshot.recent.get(entry.event.event_id);
						if (existing || recentHash) {
							if ((existing?.eventHash ?? recentHash) === entry.eventHash) {
								const record: WalRecord = { v: WAL_VERSION, op: "duplicate", count: 1 };
								await this.appendRecord(record);
								this.applyRecord(snapshot, record);
								duplicateEventIds.push(entry.event.event_id);
								(existing ? pendingDuplicateEventIds : deliveredDuplicateEventIds).push(
									entry.event.event_id,
								);
							} else {
								const record: WalRecord = {
									v: WAL_VERSION,
									op: "loss",
									count: 1,
									reason: "event_id_conflict",
								};
								await this.appendRecord(record);
								this.applyRecord(snapshot, record);
								rejected.push({
									eventId: entry.event.event_id,
									reason: "event_id_conflict",
								});
							}
							continue;
						}

						const pendingBytes = this.pendingBytes(snapshot);
						if (
							snapshot.pending.size >= this.maxEvents ||
							pendingBytes + entry.bytes > this.maxBytes
						) {
							const record: WalRecord = {
								v: WAL_VERSION,
								op: "loss",
								count: 1,
								reason: "queue_full",
							};
							await this.appendRecord(record);
							this.applyRecord(snapshot, record);
							rejected.push({ eventId: entry.event.event_id, reason: "queue_full" });
							continue;
						}

						const record: WalRecord = { v: WAL_VERSION, op: "put", entry };
						await this.appendRecord(record);
						this.applyRecord(snapshot, record);
						acceptedEventIds.push(entry.event.event_id);
					}
					await this.compactIfNeeded(snapshot);
				});
			} catch (error) {
				const unpersisted =
					events.length - acceptedEventIds.length - duplicateEventIds.length - rejected.length;
				this.noteVolatileLoss(Math.max(0, unpersisted), "storage_unavailable");
				return {
					...this.unavailableStatus(
						`storage_unavailable${errorCode(error) ? `:${errorCode(error)}` : ""}`,
						this.metrics(snapshot),
					),
					acceptedEventIds,
					duplicateEventIds,
					pendingDuplicateEventIds,
					deliveredDuplicateEventIds,
					rejected: [
						...rejected,
						...Array.from({ length: Math.max(0, unpersisted) }, () => ({
							reason: "storage_unavailable" as const,
						})),
					],
				};
			}

			const status = this.statusForSnapshot(snapshot);
			if (rejected.length > 0) {
				status.state = "unavailable";
				status.deliveryState = "unavailable";
				status.reason = rejected[0]?.reason;
			}
			return {
				...status,
				acceptedEventIds,
				duplicateEventIds,
				pendingDuplicateEventIds,
				deliveredDuplicateEventIds,
				rejected,
			};
		});
	}

	async flush(
		deliver: (events: DurableTelemetryEvent[]) => Promise<TelemetryDeliveryResult>,
	): Promise<TelemetryFlushResult> {
		// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: delivery, ACK persistence and explicit recovery status form one externally atomic operation
		return this.serialized(async () => {
			let snapshot: QueueSnapshot;
			try {
				snapshot = await this.withLock(() => this.loadSnapshot(true));
			} catch (error) {
				this.noteVolatileStorageError();
				return {
					...this.unavailableStatus(
						`storage_unavailable${errorCode(error) ? `:${errorCode(error)}` : ""}`,
						this.emptyMetrics(),
					),
					attemptedEventIds: [],
					acknowledgedEventIds: [],
				};
			}

			const due = [...snapshot.pending.values()]
				.filter((entry) => entry.nextAttemptAt <= this.now())
				.sort(
					(a, b) => a.createdAt - b.createdAt || a.event.event_id.localeCompare(b.event.event_id),
				)
				.slice(0, this.batchSize);
			const attemptedEventIds = due.map((entry) => entry.event.event_id);
			if (due.length === 0) {
				return { ...this.statusForSnapshot(snapshot), attemptedEventIds, acknowledgedEventIds: [] };
			}

			let delivery: TelemetryDeliveryResult;
			try {
				const result = await deliver(due.map((entry) => entry.event));
				delivery =
					result?.ok === true
						? result
						: {
								ok: false,
								retryable: result?.retryable !== false,
								reason: "delivery_failed",
							};
			} catch {
				delivery = { ok: false, retryable: true, reason: "delivery_exception" };
			}

			let acknowledgedEventIds: string[] = [];
			let droppedPayload = false;
			try {
				// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: ACK, retry and terminal-loss records must be committed under the same lock
				await this.withLock(async () => {
					snapshot = await this.loadSnapshot(true);
					if (delivery.ok) {
						const requested = delivery.acknowledgedEventIds ?? attemptedEventIds;
						const originalById = new Map(due.map((entry) => [entry.event.event_id, entry]));
						if (
							!Array.isArray(requested) ||
							requested.some((id) => typeof id !== "string" || !originalById.has(id)) ||
							new Set(requested).size !== requested.length
						) {
							delivery = { ok: false, retryable: true, reason: "invalid_acknowledgement" };
						} else if (
							requested.some((id) => {
								const original = originalById.get(id);
								const current = snapshot.pending.get(id);
								return current
									? current.eventHash !== original?.eventHash
									: snapshot.recent.get(id) !== original?.eventHash;
							})
						) {
							// Another process may have dropped and reused the ID while this
							// delivery was in flight. Never ACK its unsent replacement.
							delivery = { ok: false, retryable: true, reason: "stale_delivery" };
						} else {
							const acknowledged = new Set(requested);
							acknowledgedEventIds = attemptedEventIds.filter((id) => acknowledged.has(id));
							const newlyAcknowledged = acknowledgedEventIds.filter((id) =>
								snapshot.pending.has(id),
							);
							if (newlyAcknowledged.length > 0) {
								const record: WalRecord = {
									v: WAL_VERSION,
									op: "ack",
									ids: newlyAcknowledged,
								};
								await this.appendRecord(record);
								this.applyRecord(snapshot, record);
							}
							if (acknowledgedEventIds.length !== attemptedEventIds.length) {
								delivery = { ok: false, retryable: true, reason: "partial_acknowledgement" };
							}
						}
					}

					if (!delivery.ok) {
						for (const original of due) {
							if (acknowledgedEventIds.includes(original.event.event_id)) continue;
							const current = snapshot.pending.get(original.event.event_id);
							if (!current || current.eventHash !== original.eventHash) continue;
							const attempts = current.attempts + 1;
							if (delivery.retryable === false || attempts >= this.maxAttempts) {
								const record: WalRecord = {
									v: WAL_VERSION,
									op: "drop",
									id: current.event.event_id,
									reason: delivery.retryable === false ? "permanent_rejection" : "max_attempts",
								};
								await this.appendRecord(record);
								this.applyRecord(snapshot, record);
								droppedPayload = true;
							} else {
								const delay = Math.min(
									this.maxRetryMs,
									this.initialRetryMs * 2 ** Math.min(attempts - 1, 30),
								);
								const record: WalRecord = {
									v: WAL_VERSION,
									op: "retry",
									id: current.event.event_id,
									attempts,
									nextAttemptAt: this.now() + delay,
								};
								await this.appendRecord(record);
								this.applyRecord(snapshot, record);
							}
						}
					}
					// Neither delivered nor terminally lost payloads remain in the WAL.
					if (acknowledgedEventIds.length > 0 || droppedPayload) await this.rewriteWal(snapshot);
					else await this.compactIfNeeded(snapshot);
				});
			} catch (error) {
				// The server may already hold the events. Keep the unacknowledged WAL
				// records for a safe idempotent resend after restart.
				this.noteVolatileStorageError();
				return {
					...this.unavailableStatus(
						`ack_storage_unavailable${errorCode(error) ? `:${errorCode(error)}` : ""}`,
						this.metrics(snapshot),
					),
					attemptedEventIds,
					acknowledgedEventIds: [],
				};
			}

			const status = this.statusForSnapshot(snapshot);
			if (!delivery.ok) {
				status.deliveryState = "unavailable";
				status.reason = delivery.reason ?? "delivery_unavailable";
			}
			return { ...status, attemptedEventIds, acknowledgedEventIds };
		});
	}

	async inspect(): Promise<TelemetryQueueStatus> {
		return this.serialized(async () => {
			try {
				const snapshot = await this.withLock(() => this.loadSnapshot(true));
				return this.statusForSnapshot(snapshot);
			} catch (error) {
				this.noteVolatileStorageError();
				return this.unavailableStatus(
					`storage_unavailable${errorCode(error) ? `:${errorCode(error)}` : ""}`,
					this.emptyMetrics(),
				);
			}
		});
	}

	async readinessEvidence(): Promise<TelemetryQueueReadinessEvidence> {
		const status = await this.inspect();
		const oldest = status.metrics.oldestPendingAt
			? Date.parse(status.metrics.oldestPendingAt)
			: this.now();
		const oldestAgeMs = Math.max(0, this.now() - oldest);
		return {
			schema_version: 1,
			status:
				status.deliveryState === "available" &&
				status.metrics.lostTotal === 0 &&
				oldestAgeMs <= this.maxReadyPendingAgeMs
					? "ok"
					: "degraded",
			checked_at: new Date(this.now()).toISOString(),
			depth: status.metrics.pendingEvents,
			oldest_age_seconds: Math.floor(oldestAgeMs / 1_000),
			failed_jobs: status.metrics.lostTotal,
		};
	}

	/**
	 * Atomically publish the monitor contract. Mode 0444 makes the completed
	 * evidence file read-only; run the writer under the deployment's root-owned
	 * readiness service when root ownership is required.
	 */
	async writeReadinessEvidence(path: string): Promise<TelemetryQueueReadinessEvidence> {
		const evidence = await this.readinessEvidence();
		await mkdir(dirname(path), { recursive: true, mode: 0o700 });
		const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
		try {
			const handle = await open(temporary, "wx", 0o600);
			try {
				await handle.writeFile(`${JSON.stringify(evidence)}\n`, "utf8");
				await handle.sync();
			} finally {
				await handle.close();
			}
			await chmod(temporary, 0o444);
			try {
				await rename(temporary, path);
			} catch (error) {
				// Windows refuses to replace a read-only destination. Keep the normal
				// POSIX path atomic and only relax the previous file for that retry.
				if (errorCode(error) !== "EPERM" && errorCode(error) !== "EACCES") throw error;
				await chmod(path, 0o600);
				await rename(temporary, path);
			}
			return evidence;
		} catch (error) {
			await unlink(temporary).catch(() => undefined);
			throw error;
		}
	}

	private prepareEntry(candidate: Record<string, unknown>): QueueEntry {
		if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
			throw new TypeError("telemetry event must be an object");
		}
		const safeCandidate = redactTelemetryData(candidate);
		const requestedId = safeCandidate.event_id;
		if (
			requestedId !== undefined &&
			(typeof requestedId !== "string" || !EVENT_ID_PATTERN.test(requestedId))
		) {
			throw new TypeError("invalid telemetry event_id");
		}
		const event = JSON.parse(
			JSON.stringify({ ...safeCandidate, event_id: requestedId ?? randomUUID() }),
		) as DurableTelemetryEvent;
		if (!event || typeof event !== "object")
			throw new TypeError("telemetry event is not serializable");
		const serialized = JSON.stringify(event);
		const bytes = Buffer.byteLength(serialized, "utf8");
		if (bytes > this.maxEventBytes) throw new RangeError("telemetry event exceeds maxEventBytes");
		const createdAt = this.now();
		return {
			event,
			eventHash: eventHash(event),
			bytes,
			attempts: 0,
			createdAt,
			nextAttemptAt: createdAt,
		};
	}

	// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: WAL replay validates and applies each supported record while distinguishing a safe crash tail from committed corruption
	private async loadSnapshot(repairTail: boolean): Promise<QueueSnapshot> {
		let raw = "";
		try {
			raw = await readFile(this.walPath, "utf8");
		} catch (error) {
			if (!isMissing(error)) throw error;
		}
		const snapshot: QueueSnapshot = {
			pending: new Map(),
			recent: new Map(),
			totals: cloneTotals(),
			recordCount: 0,
			walBytes: Buffer.byteLength(raw, "utf8"),
			truncatedTail: raw.length > 0 && !raw.endsWith("\n"),
			validBytes: raw.endsWith("\n") ? Buffer.byteLength(raw, "utf8") : 0,
		};

		const complete = raw.endsWith("\n") ? raw : raw.slice(0, raw.lastIndexOf("\n") + 1);
		if (!raw.endsWith("\n")) snapshot.validBytes = Buffer.byteLength(complete, "utf8");
		for (const line of complete.split("\n")) {
			if (!line) continue;
			let record: unknown;
			try {
				record = JSON.parse(line);
			} catch {
				throw new Error("telemetry_wal_corrupt");
			}
			if (!isRecord(record) || record.v !== WAL_VERSION) {
				throw new Error("telemetry_wal_version_unsupported");
			}
			if (!isWalRecord(record)) throw new Error("telemetry_wal_corrupt");
			this.applyRecord(snapshot, record);
			snapshot.recordCount += 1;
		}

		if (snapshot.truncatedTail && repairTail) {
			await this.rewriteWal(snapshot);
			snapshot.truncatedTail = false;
		}
		return snapshot;
	}

	private applyRecord(snapshot: QueueSnapshot, record: WalRecord): void {
		switch (record.op) {
			case "checkpoint":
				snapshot.pending = new Map(record.pending.map((entry) => [entry.event.event_id, entry]));
				snapshot.recent = new Map(record.recent);
				snapshot.totals = cloneTotals(record.totals);
				break;
			case "put":
				snapshot.pending.set(record.entry.event.event_id, record.entry);
				snapshot.totals.enqueuedTotal += 1;
				break;
			case "ack":
				for (const id of record.ids) {
					const entry = snapshot.pending.get(id);
					if (!entry) continue;
					snapshot.pending.delete(id);
					this.remember(snapshot.recent, id, entry.eventHash);
					snapshot.totals.deliveredTotal += 1;
				}
				break;
			case "retry": {
				const entry = snapshot.pending.get(record.id);
				if (entry) {
					entry.attempts = record.attempts;
					entry.nextAttemptAt = record.nextAttemptAt;
					snapshot.totals.deliveryFailuresTotal += 1;
				}
				break;
			}
			case "drop": {
				const entry = snapshot.pending.get(record.id);
				if (entry) {
					snapshot.pending.delete(record.id);
					// A lost event was never delivered; its producer may safely retry
					// the same stable ID after this terminal failure.
					snapshot.totals.lostTotal += 1;
					snapshot.totals.deliveryFailuresTotal += 1;
					snapshot.totals.lastLossReason = record.reason;
				}
				break;
			}
			case "loss":
				snapshot.totals.lostTotal += record.count;
				snapshot.totals.lastLossReason = record.reason;
				if (record.reason === "queue_full") snapshot.totals.queueFullTotal += record.count;
				if (record.reason === "storage_unavailable") {
					snapshot.totals.storageErrorsTotal += record.count;
				}
				break;
			case "duplicate":
				snapshot.totals.duplicateEnqueuesTotal += record.count;
				break;
		}
	}

	private remember(recent: Map<string, string>, id: string, hash: string): void {
		recent.delete(id);
		recent.set(id, hash);
		while (recent.size > RECENT_EVENT_LIMIT) {
			const oldest = recent.keys().next().value as string | undefined;
			if (!oldest) break;
			recent.delete(oldest);
		}
	}

	private async appendRecord(record: WalRecord): Promise<void> {
		await this.faultInjector?.("append");
		await mkdir(dirname(this.walPath), { recursive: true, mode: 0o700 });
		const handle = await open(this.walPath, "a", 0o600);
		try {
			await appendFile(handle, `${JSON.stringify(record)}\n`, "utf8");
			await handle.sync();
		} finally {
			await handle.close();
		}
	}

	private async compactIfNeeded(snapshot: QueueSnapshot): Promise<void> {
		if (snapshot.recordCount < this.maxEvents * 2 && snapshot.walBytes < this.maxBytes * 2) return;
		await this.rewriteWal(snapshot);
	}

	private async rewriteWal(snapshot: QueueSnapshot): Promise<void> {
		await this.faultInjector?.("compact");
		await mkdir(this.directory, { recursive: true, mode: 0o700 });
		const temporary = `${this.walPath}.${process.pid}.${randomUUID()}.tmp`;
		const checkpoint: WalRecord = {
			v: WAL_VERSION,
			op: "checkpoint",
			totals: snapshot.totals,
			pending: [...snapshot.pending.values()],
			recent: [...snapshot.recent.entries()],
		};
		try {
			await writeFile(temporary, `${JSON.stringify(checkpoint)}\n`, {
				encoding: "utf8",
				mode: 0o600,
			});
			const handle = await open(temporary, "r+");
			try {
				await handle.sync();
			} finally {
				await handle.close();
			}
			await rename(temporary, this.walPath);
			snapshot.recordCount = 1;
			snapshot.walBytes = Buffer.byteLength(JSON.stringify(checkpoint), "utf8") + 1;
		} catch (error) {
			await unlink(temporary).catch(() => undefined);
			throw error;
		}
	}

	private lockOwnerMarker(token: string): string {
		return `${LOCK_OWNER_PREFIX}${token}${LOCK_OWNER_SUFFIX}`;
	}

	private async readLockOwner(): Promise<LockOwnerRecord | null> {
		try {
			const markers = (await readdir(this.lockPath)).filter(
				(name) =>
					name === LEGACY_LOCK_OWNER_FILE ||
					(name.startsWith(LOCK_OWNER_PREFIX) && name.endsWith(LOCK_OWNER_SUFFIX)),
			);
			if (markers.length !== 1) return null;
			const marker = markers[0];
			if (!marker) return null;
			const parsed: unknown = JSON.parse(await readFile(join(this.lockPath, marker), "utf8"));
			if (!isLockOwner(parsed)) return null;
			if (marker !== LEGACY_LOCK_OWNER_FILE && marker !== this.lockOwnerMarker(parsed.token)) {
				return null;
			}
			return { owner: parsed, marker };
		} catch {
			return null;
		}
	}

	private async removeOwnedLock(
		token: string,
		marker = this.lockOwnerMarker(token),
	): Promise<boolean> {
		try {
			// The marker path contains this acquisition's random token. If another
			// owner replaced the directory, this unlink is ENOENT and we must not
			// proceed to rmdir its generation.
			await unlink(join(this.lockPath, marker));
		} catch (error) {
			if (isMissing(error)) return false;
			throw error;
		}
		try {
			await rmdir(this.lockPath);
			return true;
		} catch (error) {
			if (isMissing(error) || errorCode(error) === "ENOTEMPTY" || errorCode(error) === "EEXIST") {
				return false;
			}
			throw error;
		}
	}

	private async recoverDeadLock(): Promise<boolean> {
		let metadata;
		try {
			metadata = await lstat(this.lockPath);
		} catch (error) {
			if (isMissing(error)) return true;
			throw error;
		}
		if (
			Date.now() - metadata.mtimeMs <= this.staleLockMs ||
			!metadata.isDirectory() ||
			metadata.isSymbolicLink()
		) {
			return false;
		}

		const names = await readdir(this.lockPath);
		if (names.length === 0) {
			// Acquisition creates the directory before publishing its owner marker.
			// A paused live owner can therefore leave an old-looking empty lock.
			return false;
		}

		const record = await this.readLockOwner();
		if (record) {
			// A PID is only meaningful on its own host. Never reclaim a shared
			// directory lock from another host or from an ambiguous marker.
			if (record.owner.host !== hostname() || processIsAlive(record.owner) !== false) {
				return false;
			}
			return this.removeOwnedLock(record.owner.token, record.marker);
		}
		// Malformed or multiply-owned markers do not identify a process generation.
		// An old directory mtime cannot prove their owner died.
		return false;
	}

	private async withLock<T>(callback: () => Promise<T>): Promise<T> {
		await this.faultInjector?.("mkdir");
		await mkdir(this.directory, { recursive: true, mode: 0o700 });
		await preparePrivateTelemetryQueue(this.directory, this.walPath);
		const started = Date.now();
		const owner: LockOwner = {
			v: 1,
			token: randomUUID(),
			pid: process.pid,
			host: hostname(),
			acquiredAt: Date.now(),
			processStartedAtMs: PROCESS_STARTED_AT_MS,
		};
		while (true) {
			try {
				await mkdir(this.lockPath, { mode: 0o700 });
				const marker = this.lockOwnerMarker(owner.token);
				const temporary = join(this.directory, `.lock-owner-${owner.token}.tmp`);
				try {
					await writeSyncedExclusive(temporary, `${JSON.stringify(owner)}\n`);
					await rename(temporary, join(this.lockPath, marker));
				} catch (error) {
					await unlink(temporary).catch(() => undefined);
					await this.removeOwnedLock(owner.token, marker).catch(() => undefined);
					throw error;
				}
				break;
			} catch (error) {
				if (errorCode(error) !== "EEXIST") throw error;
				if (await this.recoverDeadLock()) continue;
				if (Date.now() - started >= this.lockTimeoutMs) throw new Error("telemetry_queue_locked");
				await sleep(10);
			}
		}

		try {
			return await callback();
		} finally {
			await this.removeOwnedLock(owner.token).catch(() => undefined);
		}
	}

	private serialized<T>(callback: () => Promise<T>): Promise<T> {
		const result = this.operation.then(callback, callback);
		this.operation = result.then(
			() => undefined,
			() => undefined,
		);
		return result;
	}

	private pendingBytes(snapshot: QueueSnapshot): number {
		let total = 0;
		for (const entry of snapshot.pending.values()) total += entry.bytes;
		return total;
	}

	private metrics(snapshot: QueueSnapshot): TelemetryQueueMetrics {
		const oldest = [...snapshot.pending.values()].sort((a, b) => a.createdAt - b.createdAt)[0];
		return {
			...snapshot.totals,
			lostTotal: snapshot.totals.lostTotal + this.volatileLosses,
			storageErrorsTotal: snapshot.totals.storageErrorsTotal + this.volatileStorageErrors,
			lastLossReason: this.volatileLastLossReason ?? snapshot.totals.lastLossReason,
			pendingEvents: snapshot.pending.size,
			pendingBytes: this.pendingBytes(snapshot),
			oldestPendingAt: oldest ? new Date(oldest.createdAt).toISOString() : undefined,
		};
	}

	private emptyMetrics(): TelemetryQueueMetrics {
		return {
			...cloneTotals(),
			lostTotal: this.volatileLosses,
			storageErrorsTotal: this.volatileStorageErrors,
			lastLossReason: this.volatileLastLossReason,
			pendingEvents: 0,
			pendingBytes: 0,
		};
	}

	private statusForSnapshot(snapshot: QueueSnapshot): TelemetryQueueStatus {
		const metrics = this.metrics(snapshot);
		const retryPending = [...snapshot.pending.values()].some((entry) => entry.attempts > 0);
		return {
			state:
				metrics.pendingEvents > 0 ? "queued" : metrics.deliveredTotal > 0 ? "delivered" : "idle",
			deliveryState: retryPending ? "unavailable" : "available",
			reason: retryPending ? "delivery_retry_pending" : undefined,
			metrics,
		};
	}

	private unavailableStatus(reason: string, metrics: TelemetryQueueMetrics): TelemetryQueueStatus {
		return { state: "unavailable", deliveryState: "unavailable", reason, metrics };
	}

	private noteVolatileStorageError(): void {
		this.volatileStorageErrors += 1;
	}

	private noteVolatileLoss(count: number, reason: TelemetryLossReason): void {
		this.volatileLosses += count;
		this.volatileStorageErrors += reason === "storage_unavailable" ? 1 : 0;
		this.volatileLastLossReason = reason;
	}
}

/** Aggregate queue state across every installation namespace under a root. */
export interface TelemetryLossSummary {
	/** Number of queue directories found. */
	queues: number;
	/** Events durably queued and not yet acknowledged. */
	pendingEvents: number;
	/** Seconds since the oldest pending event was written. */
	oldestAgeSeconds: number;
	/** Events the queue gave up on, across every namespace. */
	lostTotal: number;
	/** `queued` when anything is pending, `idle` when nothing is, `unavailable` when unreadable. */
	state: "idle" | "queued" | "unavailable";
	/** Per-namespace detail, so a single broken queue cannot hide behind a total. */
	namespaces: Array<{
		namespace: string;
		pendingEvents: number;
		lostTotal: number;
		state: "ok" | "degraded" | "unavailable";
	}>;
}

/**
 * Read the durable telemetry queue state without flushing it.
 *
 * The durability counters otherwise only exist inside a live control-plane
 * client, so an operator had no way to see that events were undelivered or
 * lost. This reads every namespace under the queue root and reports both the
 * totals and the per-namespace breakdown; a queue that cannot be read is
 * reported as `unavailable` rather than as an empty one.
 */
export async function readTelemetryLossSummary(
	root: string,
	options: { now?: () => number } = {},
): Promise<TelemetryLossSummary> {
	const now = options.now ?? Date.now;
	let namespaces: string[] = [];
	let unreadable = false;
	try {
		const entries = await readdir(root, { withFileTypes: true });
		unreadable = entries.some(
			(entry) => !entry.isDirectory() || !/^[a-f0-9]{64}$/.test(entry.name),
		);
		namespaces = entries
			.filter((entry) => entry.isDirectory() && /^[a-f0-9]{64}$/.test(entry.name))
			.map((entry) => entry.name);
	} catch (error) {
		// ENOENT means nothing has ever been queued, which is genuinely idle. Any
		// other failure means the state is unknown and must not read as clean.
		if (errorCode(error) !== "ENOENT") unreadable = true;
	}

	const detail: TelemetryLossSummary["namespaces"] = [];
	let pendingEvents = 0;
	let lostTotal = 0;
	let oldestAgeSeconds = 0;

	for (const namespace of namespaces) {
		try {
			const queue = new DurableTelemetryQueue({ directory: join(root, namespace), now });
			// `readinessEvidence()` deliberately collapses every non-healthy result
			// into `degraded` for the deployment monitor contract. Status needs to
			// retain the stronger distinction: a corrupt or locked WAL is unknown,
			// not an empty queue.
			const status = await queue.inspect();
			if (status.state === "unavailable") {
				unreadable = true;
				detail.push({ namespace, pendingEvents: 0, lostTotal: 0, state: "unavailable" });
				continue;
			}

			const oldestPending = status.metrics.oldestPendingAt
				? Date.parse(status.metrics.oldestPendingAt)
				: now();
			const ageMs = Math.max(0, now() - oldestPending);
			const age = Math.floor(ageMs / 1_000);
			pendingEvents += status.metrics.pendingEvents;
			lostTotal += status.metrics.lostTotal;
			oldestAgeSeconds = Math.max(oldestAgeSeconds, age);
			detail.push({
				namespace,
				pendingEvents: status.metrics.pendingEvents,
				lostTotal: status.metrics.lostTotal,
				state:
					status.deliveryState === "available" &&
					status.metrics.lostTotal === 0 &&
					(status.metrics.pendingEvents === 0 || ageMs <= DEFAULT_MAX_READY_PENDING_AGE_MS)
						? "ok"
						: "degraded",
			});
		} catch {
			unreadable = true;
			detail.push({ namespace, pendingEvents: 0, lostTotal: 0, state: "unavailable" });
		}
	}

	return {
		queues: namespaces.length,
		pendingEvents,
		oldestAgeSeconds,
		lostTotal,
		state: unreadable ? "unavailable" : pendingEvents > 0 ? "queued" : "idle",
		namespaces: detail,
	};
}
