/**
 * Explicitly configured incident producer for the durable SIEM delivery queue.
 * The lock protects the queue's read/modify/write cycle across short-lived hook
 * processes; DurableSiemDelivery's own serialization only covers one process.
 */
import { mkdir, readFile, rmdir, stat, unlink, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { resolvePath } from "./config.js";
import type { Incident } from "./incidents/types.js";
import { DurableSiemDelivery, type SiemAdapterConfig } from "./siem-delivery.js";

export const SIEM_CONFIG_PATH_ENV = "SINGULARITY_AIDR_SIEM_CONFIG_PATH";
const MAX_CONFIG_BYTES = 64 * 1024;
const LOCK_WAIT_MS = 3_000;
const LOCK_POLL_MS = 25;

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

async function withStateLock<T>(stateFile: string, work: () => Promise<T>): Promise<T> {
	const lockPath = `${stateFile}.lock`;
	const ownerPath = join(lockPath, "owner.json");
	await mkdir(dirname(stateFile), { recursive: true, mode: 0o700 });
	const until = Date.now() + LOCK_WAIT_MS;
	for (;;) {
		try {
			await mkdir(lockPath, { mode: 0o700 });
			break;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
			if (Date.now() >= until) throw new Error("siem_state_lock_unavailable");
			await delay(LOCK_POLL_MS);
		}
	}
	try {
		await writeFile(ownerPath, JSON.stringify({ pid: process.pid, acquired_at_ms: Date.now() }), {
			flag: "wx",
			mode: 0o600,
		});
		return await work();
	} finally {
		await unlink(ownerPath).catch((error: NodeJS.ErrnoException) => {
			if (error.code !== "ENOENT") throw error;
		});
		await rmdir(lockPath);
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
			const owner = JSON.parse(await readFile(join(lockPath, "owner.json"), "utf8")) as {
				pid?: unknown;
			};
			if (Number.isSafeInteger(owner.pid) && Number(owner.pid) > 0) ownerPid = Number(owner.pid);
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
 * Called after local persistence. An unset config path never creates a file or
 * makes a network request. A configured but unavailable sink remains queued and
 * returns a degraded status for the caller to surface.
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
		// A hook may be a short-lived foreground process. Bound network work to
		// one request per incident rather than draining the whole backlog here.
		const flushed = await delivery.flush(1);
		const health = await delivery.health();
		return {
			status:
				health.status === "unhealthy" || health.status === "degraded"
					? "degraded"
					: enqueued.receipt.status === "delivered" || flushed.delivered > 0
						? "delivered"
						: "queued",
			queueDepth: health.queueDepth,
			lastErrorCode: health.lastErrorCode,
		};
	});
}

/**
 * Drain due retry records from a scheduler or service. Each attempt releases
 * the cross-process lock before the next one so foreground hooks can enqueue.
 * A non-due retry remains queued for the next scheduled invocation.
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
			const flushed = await delivery.flush(1);
			return { flushed, health: await delivery.health() };
		});
		result.attempted += current.flushed.attempted;
		result.delivered += current.flushed.delivered;
		result.retrying += current.flushed.retrying;
		result.deadLettered += current.flushed.deadLettered;
		result.status = current.health.status;
		result.queueDepth = current.health.queueDepth;
		result.lastErrorCode = current.health.lastErrorCode;
		if (current.flushed.attempted === 0) break;
	}
	return result;
}

/** Never include endpoint, credential or event contents in hook stderr. */
export function reportSiemProducerFailure(code: string): void {
	const safeCode = /^[a-z0-9_]+$/.test(code) ? code : "producer_unavailable";
	process.stderr.write(`AIDR SIEM delivery degraded: ${safeCode}\n`);
}
