/**
 * Explicitly configured incident producer for the durable SIEM delivery queue.
 * The lock protects the queue's read/modify/write cycle across short-lived hook
 * processes; DurableSiemDelivery's own serialization only covers one process.
 */
import { randomUUID } from "node:crypto";
import { mkdir, open, readdir, readFile, rename, rmdir, stat, unlink } from "node:fs/promises";
import { hostname } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { resolvePath } from "./config.js";
import type { Incident } from "./incidents/types.js";
import {
	DurableSiemDelivery,
	type SiemAdapterConfig,
	type SiemDeliveryHealth,
} from "./siem-delivery.js";

export const SIEM_CONFIG_PATH_ENV = "SINGULARITY_AIDR_SIEM_CONFIG_PATH";
const MAX_CONFIG_BYTES = 64 * 1024;
const LOCK_WAIT_MS = 3_000;
const LIVE_OWNER_LOCK_WAIT_MS = 15_000;
const LOCK_POLL_MS = 25;
const PROCESS_STARTED_AT_MS = Math.max(0, Math.trunc(Date.now() - process.uptime() * 1000));

interface StateLockOwner {
	pid: number;
	host: string;
	token: string;
	acquired_at_ms: number;
	/** Absent on lock markers written before process-generation tracking. */
	process_started_at_ms?: number;
}

interface StateLockOwnerRecord {
	owner: StateLockOwner;
	path: string;
}

interface ProducerConfig {
	state_file: string;
	adapter: SiemAdapterConfig;
	request_timeout_ms?: number;
}

export interface SiemIncidentProductionResult {
	status: "disabled" | "delivered" | "queued" | "degraded";
	queueDepth?: number;
	lastErrorCode?: string;
}

export interface SiemDrainResult {
	status: "healthy" | "degraded" | "unhealthy";
	attempted: number;
	delivered: number;
	retrying: number;
	deadLettered: number;
	queueDepth: number;
	lastErrorCode?: string;
}

export interface SiemStateLockStatus {
	locked: boolean;
	ageMs?: number;
	ownerPid?: number;
}

function parseConfig(value: unknown): ProducerConfig {
	if (!value || typeof value !== "object" || Array.isArray(value))
		throw new TypeError("invalid_siem_config");
	const config = value as Record<string, unknown>;
	const adapter = config.adapter;
	if (
		typeof config.state_file !== "string" ||
		config.state_file.trim().length === 0 ||
		(!isAbsolute(config.state_file) && !/^~[/\\]/.test(config.state_file)) ||
		!adapter ||
		typeof adapter !== "object" ||
		Array.isArray(adapter) ||
		typeof (adapter as Record<string, unknown>).provider !== "string" ||
		typeof (adapter as Record<string, unknown>).endpoint !== "string"
	)
		throw new TypeError("invalid_siem_config");
	const timeout = config.request_timeout_ms;
	if (
		timeout !== undefined &&
		(!Number.isInteger(timeout) || Number(timeout) < 1 || Number(timeout) > 3_000)
	)
		throw new TypeError("invalid_siem_timeout");
	return {
		state_file: config.state_file,
		adapter: adapter as SiemAdapterConfig,
		request_timeout_ms: timeout as number | undefined,
	};
}

async function readConfig(configPath: string): Promise<ProducerConfig> {
	const path = resolvePath(configPath);
	const metadata = await stat(path);
	if (!metadata.isFile() || metadata.size > MAX_CONFIG_BYTES)
		throw new TypeError("invalid_siem_config_file");
	if (process.platform !== "win32" && (metadata.mode & 0o077) !== 0)
		throw new TypeError("siem_config_permissions_insecure");
	return parseConfig(JSON.parse(await readFile(path, "utf8")));
}

function errorCode(error: unknown): string | undefined {
	return error && typeof error === "object" && "code" in error && typeof error.code === "string"
		? error.code
		: undefined;
}

function pidAlive(pid: number): boolean {
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		return errorCode(error) !== "ESRCH";
	}
}

function ownerAlive(owner: StateLockOwner): boolean {
	if (owner.host !== hostname()) return true;
	if (owner.pid === process.pid) {
		return owner.process_started_at_ms === undefined
			? owner.acquired_at_ms >= PROCESS_STARTED_AT_MS
			: owner.process_started_at_ms === PROCESS_STARTED_AT_MS;
	}
	return pidAlive(owner.pid);
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

async function readLockOwner(
	ownerPath: string,
	expectedToken?: string,
): Promise<StateLockOwner | null> {
	try {
		const value = JSON.parse(await readFile(ownerPath, "utf8")) as Partial<StateLockOwner>;
		return Number.isSafeInteger(value.pid) &&
			Number(value.pid) > 0 &&
			typeof value.host === "string" &&
			value.host.length > 0 &&
			typeof value.token === "string" &&
			value.token.length > 0 &&
			(expectedToken === undefined || value.token === expectedToken) &&
			Number.isSafeInteger(value.acquired_at_ms) &&
			Number(value.acquired_at_ms) >= 0 &&
			(value.process_started_at_ms === undefined ||
				(Number.isSafeInteger(value.process_started_at_ms) &&
					Number(value.process_started_at_ms) >= 0))
			? (value as StateLockOwner)
			: null;
	} catch {
		return null;
	}
}

function ownerFileName(token: string): string {
	return `owner.${token}.json`;
}

async function currentLockOwner(lockPath: string): Promise<StateLockOwnerRecord | null> {
	let names: string[];
	try {
		names = (await readdir(lockPath)).filter((name) => /^owner\.[-0-9a-f]{36}\.json$/i.test(name));
	} catch (error) {
		if (errorCode(error) === "ENOENT") return null;
		throw error;
	}
	if (names.length !== 1) return null;
	const name = names[0] as string;
	const expectedToken = name.slice("owner.".length, -".json".length);
	const path = join(lockPath, name);
	const owner = await readLockOwner(path, expectedToken);
	return owner ? { owner, path } : null;
}

async function legacyLockOwnerPid(lockPath: string): Promise<number | null> {
	try {
		const owner = JSON.parse(await readFile(join(lockPath, "owner.json"), "utf8")) as {
			pid?: unknown;
		};
		return Number.isSafeInteger(owner.pid) && Number(owner.pid) > 0 ? Number(owner.pid) : null;
	} catch {
		return null;
	}
}

async function removeDeadOwnerGeneration(lockPath: string, ownerPath: string): Promise<boolean> {
	try {
		await unlink(ownerPath);
	} catch (error) {
		if (errorCode(error) === "ENOENT") return true;
		throw error;
	}
	try {
		await rmdir(lockPath);
		return true;
	} catch (error) {
		if (errorCode(error) === "ENOENT") return true;
		if (errorCode(error) === "ENOTEMPTY") return false;
		throw error;
	}
}

async function recoverAbandonedLock(lockPath: string): Promise<boolean> {
	try {
		await stat(lockPath);
	} catch (error) {
		if (errorCode(error) === "ENOENT") return true;
		throw error;
	}
	const current = await currentLockOwner(lockPath);
	if (current) {
		return ownerAlive(current.owner) ? false : removeDeadOwnerGeneration(lockPath, current.path);
	}
	// Empty, malformed and legacy markers do not identify the host/process
	// generation. An old mtime is not proof that the owner cannot resume.
	return false;
}

async function releaseStateLock(lockPath: string, token: string): Promise<void> {
	const ownerPath = join(lockPath, ownerFileName(token));
	try {
		await unlink(ownerPath);
	} catch (error) {
		// A recovered/replaced generation cannot contain this token-specific marker.
		if (errorCode(error) === "ENOENT") return;
		throw error;
	}
	await rmdir(lockPath).catch((error: NodeJS.ErrnoException) => {
		if (error.code !== "ENOENT" && error.code !== "ENOTEMPTY") throw error;
	});
}

async function withStateLock<T>(stateFile: string, work: () => Promise<T>): Promise<T> {
	const lockPath = `${stateFile}.lock`;
	await mkdir(dirname(stateFile), { recursive: true, mode: 0o700 });
	const startedAt = Date.now();
	const token = randomUUID();
	const ownerPath = join(lockPath, ownerFileName(token));
	const temporary = `${lockPath}.owner.${token}.tmp`;
	for (;;) {
		try {
			await mkdir(lockPath, { mode: 0o700 });
			break;
		} catch (error) {
			if (errorCode(error) !== "EEXIST") throw error;
			if (await recoverAbandonedLock(lockPath)) continue;
			const current = await currentLockOwner(lockPath);
			const liveLocalOwner =
				current?.owner.host === hostname() && ownerAlive(current.owner);
			// A newly acquired lock may not have its owner marker yet. Synchronous
			// NTFS ACL repair can also pause every waiter in this process.
			let freshUnmarkedLock = false;
			if (!current) {
				try {
					freshUnmarkedLock = Date.now() - (await stat(lockPath)).mtimeMs < LIVE_OWNER_LOCK_WAIT_MS;
				} catch (metadataError) {
					if (errorCode(metadataError) === "ENOENT") continue;
					throw metadataError;
				}
			}
			const waitMs = liveLocalOwner || freshUnmarkedLock ? LIVE_OWNER_LOCK_WAIT_MS : LOCK_WAIT_MS;
			if (Date.now() - startedAt >= waitMs) throw new Error("siem_state_lock_unavailable");
			await delay(LOCK_POLL_MS);
		}
	}
	try {
		await writeSyncedExclusive(
			temporary,
			JSON.stringify({
				pid: process.pid,
				host: hostname(),
				token,
				acquired_at_ms: Date.now(),
				process_started_at_ms: PROCESS_STARTED_AT_MS,
			}),
		);
		await rename(temporary, ownerPath);
	} catch (error) {
		await unlink(temporary).catch(() => undefined);
		let removedOwner = false;
		try {
			await unlink(ownerPath);
			removedOwner = true;
		} catch (cleanupError) {
			if (errorCode(cleanupError) !== "ENOENT") throw cleanupError;
		}
		if (removedOwner) await rmdir(lockPath).catch(() => undefined);
		throw error;
	}
	try {
		return await work();
	} finally {
		await unlink(temporary).catch(() => undefined);
		await releaseStateLock(lockPath, token);
	}
}

async function configuredState(): Promise<{ config: ProducerConfig; stateFile: string } | null> {
	const configPath = process.env[SIEM_CONFIG_PATH_ENV];
	if (!configPath) return null;
	const config = await readConfig(configPath);
	return { config, stateFile: resolvePath(config.state_file) };
}

function openDelivery(config: ProducerConfig, stateFile: string): Promise<DurableSiemDelivery> {
	return DurableSiemDelivery.open({
		stateFile,
		adapter: config.adapter,
		requestTimeoutMs: config.request_timeout_ms ?? 1_000,
	});
}

/** Read-only lock diagnostics for operators; stale locks are never auto-removed. */
export async function inspectConfiguredSiemLock(): Promise<SiemStateLockStatus> {
	const configured = await configuredState();
	if (!configured) throw new Error("siem_not_configured");
	const lockPath = `${configured.stateFile}.lock`;
	try {
		const metadata = await stat(lockPath);
		let ownerPid: number | undefined;
		try {
			const current = await currentLockOwner(lockPath);
			ownerPid = current?.owner.pid ?? (await legacyLockOwnerPid(lockPath)) ?? undefined;
		} catch {
			// A crash between mkdir and owner write still leaves a diagnosable lock.
		}
		return { locked: true, ageMs: Math.max(0, Date.now() - metadata.mtimeMs), ownerPid };
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return { locked: false };
		throw error;
	}
}

/**
 * Inspect the configured durable SIEM queue without sending or mutating receipts.
 * @public
 */
export async function inspectConfiguredSiemDelivery(): Promise<SiemDeliveryHealth> {
	const configured = await configuredState();
	if (!configured) throw new Error("siem_not_configured");
	return withStateLock(configured.stateFile, async () =>
		(await openDelivery(configured.config, configured.stateFile)).health(),
	);
}

/**
 * Called after local persistence. An unset config path never creates a file.
 * Configured incidents are durably queued without doing network I/O while the
 * cross-process state lock is held; the scheduled drain owns delivery retries.
 */
export async function produceConfiguredSiemIncident(
	incident: Incident,
): Promise<SiemIncidentProductionResult> {
	const configured = await configuredState();
	if (!configured) return { status: "disabled" };
	const { config, stateFile } = configured;
	return withStateLock(stateFile, async () => {
		const delivery = await openDelivery(config, stateFile);
		const enqueued = await delivery.enqueue(incident);
		const health = await delivery.health();
		return {
			status:
				health.status === "unhealthy" || enqueued.receipt.status === "retrying"
					? "degraded"
					: enqueued.receipt.status === "delivered"
						? "delivered"
						: "queued",
			queueDepth: health.queueDepth,
			lastErrorCode: health.lastErrorCode,
		};
	});
}

/**
 * Drain due retry records from a scheduler or service. Claim and completion
 * are persisted under the state lock; network I/O runs between them unlocked.
 */
export async function drainConfiguredSiemDelivery(maxItems = 25): Promise<SiemDrainResult> {
	if (!Number.isSafeInteger(maxItems) || maxItems < 1 || maxItems > 100)
		throw new TypeError("invalid_siem_drain_limit");
	const configured = await configuredState();
	if (!configured) throw new Error("siem_not_configured");
	const { config, stateFile } = configured;
	const result: SiemDrainResult = {
		status: "healthy",
		attempted: 0,
		delivered: 0,
		retrying: 0,
		deadLettered: 0,
		queueDepth: 0,
	};
	for (let index = 0; index < maxItems; index++) {
		const current = await withStateLock(stateFile, async () => {
			const delivery = await openDelivery(config, stateFile);
			const claimed = await delivery.claimNext();
			return { claimed, delivery, health: await delivery.health() };
		});
		result.deadLettered += current.claimed.deadLettered;
		result.status = current.health.status;
		result.queueDepth = current.health.queueDepth;
		result.lastErrorCode = current.health.lastErrorCode;
		if (!current.claimed.claim) {
			if (current.claimed.deadLettered > 0) continue;
			break;
		}

		const claim = current.claimed.claim;
		result.attempted += 1;
		const attempt = await current.delivery.sendClaim(claim);
		const completed = await withStateLock(stateFile, async () => {
			const delivery = await openDelivery(config, stateFile);
			const completion = await delivery.completeClaim(claim, attempt);
			return { completion, health: await delivery.health() };
		});
		result.delivered += completed.completion.delivered;
		result.retrying += completed.completion.retrying;
		result.deadLettered += completed.completion.deadLettered;
		result.status = completed.health.status;
		result.queueDepth = completed.health.queueDepth;
		result.lastErrorCode = completed.health.lastErrorCode;
	}
	return result;
}

/** Never include endpoint, credential or event contents in hook stderr. */
export function reportSiemProducerFailure(code: string): void {
	const safeCode = /^[a-z0-9_]+$/.test(code) ? code : "producer_unavailable";
	process.stderr.write(`AIDR SIEM delivery degraded: ${safeCode}\n`);
}
