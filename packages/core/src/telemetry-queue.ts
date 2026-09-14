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
	mkdir,
	open,
	readdir,
	readFile,
	rename,
	rmdir,
	stat,
	unlink,
	writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { redactTelemetryData } from "./telemetry-redaction.js";

const WAL_VERSION = 1;
const EVENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const EVENT_HASH_PATTERN = /^[a-f0-9]{64}$/;
const RECENT_EVENT_LIMIT = 2_048;
const DEFAULT_MAX_READY_PENDING_AGE_MS = 5 * 60 * 1_000;
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

export type TelemetryDeliveryState = "available" | "unavailable";
export type TelemetryQueueState = "delivered" | "idle" | "queued" | "unavailable";

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

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
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
			return { ...status, acceptedEventIds, duplicateEventIds, rejected };
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
				delivery = await deliver(due.map((entry) => entry.event));
			} catch (error) {
				delivery = { ok: false, retryable: true, reason: String(error) };
			}

			let acknowledgedEventIds: string[] = [];
			try {
				// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: ACK, retry and terminal-loss records must be committed under the same lock
				await this.withLock(async () => {
					snapshot = await this.loadSnapshot(true);
					if (delivery.ok) {
						const requested = delivery.acknowledgedEventIds ?? attemptedEventIds;
						const acknowledged = new Set(requested);
						if (requested.some((id) => !attemptedEventIds.includes(id))) {
							delivery = { ok: false, retryable: true, reason: "invalid_acknowledgement" };
						} else {
							acknowledgedEventIds = attemptedEventIds.filter((id) => acknowledged.has(id));
							if (acknowledgedEventIds.length > 0) {
								const record: WalRecord = {
									v: WAL_VERSION,
									op: "ack",
									ids: acknowledgedEventIds,
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
							if (!current) continue;
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
									reason: delivery.reason,
								};
								await this.appendRecord(record);
								this.applyRecord(snapshot, record);
							}
						}
					}
					await this.compactIfNeeded(snapshot);
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

	// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: bounded acquisition includes stale-lock recovery for cross-process crash safety
	private async withLock<T>(callback: () => Promise<T>): Promise<T> {
		await this.faultInjector?.("mkdir");
		await mkdir(this.directory, { recursive: true, mode: 0o700 });
		const started = Date.now();
		while (true) {
			try {
				await mkdir(this.lockPath, { mode: 0o700 });
				break;
			} catch (error) {
				if (errorCode(error) !== "EEXIST") throw error;
				try {
					const lockStat = await stat(this.lockPath);
					if (Date.now() - lockStat.mtimeMs > this.staleLockMs) {
						await rmdir(this.lockPath);
						continue;
					}
				} catch (lockError) {
					if (isMissing(lockError)) continue;
				}
				if (Date.now() - started >= this.lockTimeoutMs) throw new Error("telemetry_queue_locked");
				await sleep(10);
			}
		}

		try {
			return await callback();
		} finally {
			await rmdir(this.lockPath).catch(() => undefined);
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
	namespaces: Array<{ namespace: string; pendingEvents: number; lostTotal: number; state: string }>;
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
		namespaces = entries.filter((entry) => entry.isDirectory()).map((entry) => entry.name);
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
			const evidence = await queue.readinessEvidence();
			pendingEvents += evidence.depth;
			lostTotal += evidence.failed_jobs;
			oldestAgeSeconds = Math.max(oldestAgeSeconds, evidence.oldest_age_seconds);
			detail.push({
				namespace,
				pendingEvents: evidence.depth,
				lostTotal: evidence.failed_jobs,
				state: evidence.status,
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
