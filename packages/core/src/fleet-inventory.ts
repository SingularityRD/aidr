import { createHash } from "node:crypto";
import { open } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as sleepWithSignal } from "node:timers/promises";
import {
	type AigInfraScanOptions,
	type AigInfraTargetResult,
	scanTarget,
} from "./aig-infra-scan.js";
import { resolvePath } from "./config.js";
import { CloudDiscoveryEvidenceSchema } from "./discovery-cloud-http.js";
import type { CloudDiscoveryEvidence } from "./discovery-cloud-provider.js";
import { atomicWriteJson } from "./file-utils.js";

export type FleetFreshness = "fresh" | "stale" | "never_seen";
export type FleetReachability = "reachable" | "unreachable" | "not_checked";

export interface FleetInventoryEntry {
	id: string;
	kind: "ai_infrastructure";
	target: string;
	firstSeenAt: string;
	lastSeenAt: string | null;
	lastAttemptAt: string;
	freshness: FleetFreshness;
	reachability: FleetReachability;
	consecutiveFailures: number;
	attempts: number;
	nextRetryAt: string | null;
	scan: AigInfraTargetResult;
}

export interface FleetInventory {
	schemaVersion: 1;
	tenantId: string;
	collectorId: string;
	generatedAt: string;
	staleAfterMs: number;
	items: FleetInventoryEntry[];
	/** Management API observations are not endpoint reachability or vulnerability scans. */
	providerEvidence?: CloudDiscoveryEvidence;
}

export interface FleetCollectionOptions {
	staleAfterMs?: number;
	maxAttempts?: number;
	baseRetryDelayMs?: number;
	maxRetryDelayMs?: number;
	concurrency?: number;
	scanOptions?: Omit<AigInfraScanOptions, "concurrency" | "signal">;
	now?: () => number;
	sleep?: (delayMs: number) => Promise<void>;
	scanTargetImpl?: typeof scanTarget;
	signal?: AbortSignal;
}

const DEFAULT_STALE_AFTER_MS = 15 * 60 * 1000;
const DEFAULT_MAX_ATTEMPTS = 3;
const DEFAULT_BASE_RETRY_DELAY_MS = 250;
const DEFAULT_MAX_RETRY_DELAY_MS = 5_000;
export const MAX_FLEET_TARGETS = 1_000;
export const MAX_FLEET_INVENTORY_BYTES = 8 * 1024 * 1024;

function requireIdentity(label: string, value: string): string {
	const trimmed = value.trim();
	if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(trimmed)) {
		throw new Error(`${label}_invalid`);
	}
	return trimmed;
}

function clampInteger(
	value: number | undefined,
	fallback: number,
	min: number,
	max: number,
): number {
	if (!Number.isFinite(value)) return fallback;
	return Math.max(min, Math.min(max, Math.trunc(value as number)));
}

function isoAt(epochMs: number): string {
	return new Date(epochMs).toISOString();
}

function parseEpoch(value: string | null): number | null {
	if (!value) return null;
	const parsed = Date.parse(value);
	return Number.isFinite(parsed) ? parsed : null;
}

/**
 * Canonical target identity for a tenant inventory.
 *
 * Collector targets are persisted, so URLs containing user info, query strings,
 * or fragments are rejected rather than risking credential material in an
 * inventory file. HTTP(S) paths remain part of the identity because products may
 * be mounted below an origin root.
 */
export function normalizeFleetTarget(target: string): string {
	let parsed: URL;
	try {
		parsed = new URL(target.trim());
	} catch {
		throw new Error("fleet_target_invalid");
	}
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		throw new Error("fleet_target_protocol_invalid");
	}
	if (parsed.username || parsed.password || parsed.search || parsed.hash) {
		throw new Error("fleet_target_contains_private_components");
	}
	parsed.hostname = parsed.hostname.toLowerCase();
	if (parsed.pathname !== "/") parsed.pathname = parsed.pathname.replace(/\/+$/, "");
	return parsed.toString();
}

export function normalizeFleetTargets(targets: string[]): string[] {
	const unique = new Set<string>();
	for (const target of targets) unique.add(normalizeFleetTarget(target));
	return [...unique].sort();
}

export function fleetInventoryEntryId(tenantId: string, target: string): string {
	const tenant = requireIdentity("tenant_id", tenantId);
	const normalizedTarget = normalizeFleetTarget(target);
	return createHash("sha256")
		.update(`${tenant}\0ai_infrastructure\0${normalizedTarget}`)
		.digest("hex");
}

export function defaultFleetInventoryPath(tenantId: string): string {
	const tenant = requireIdentity("tenant_id", tenantId);
	const tenantKey = createHash("sha256").update(tenant).digest("hex").slice(0, 24);
	return join(resolvePath("~/.singularity-aidr/fleet-inventory"), `${tenantKey}.json`);
}

function freshnessFor(
	lastSeenAt: string | null,
	nowMs: number,
	staleAfterMs: number,
): FleetFreshness {
	const lastSeenMs = parseEpoch(lastSeenAt);
	if (lastSeenMs === null) return "never_seen";
	return lastSeenMs <= nowMs && nowMs - lastSeenMs <= staleAfterMs ? "fresh" : "stale";
}

export function refreshFleetInventoryFreshness(
	inventory: FleetInventory,
	nowMs = Date.now(),
): FleetInventory {
	return {
		...inventory,
		generatedAt: isoAt(nowMs),
		items: inventory.items.map((item) => ({
			...item,
			freshness: freshnessFor(item.lastSeenAt, nowMs, inventory.staleAfterMs),
		})),
	};
}

function terminalScanFailure(result: AigInfraTargetResult): boolean {
	return result.error === "target_not_allowed" || result.error === "invalid_target_url";
}

interface AttemptedResult {
	result: AigInfraTargetResult;
	attempts: number;
}

function abortable<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
	if (!signal) return promise;
	signal.throwIfAborted();
	return new Promise<T>((resolve, reject) => {
		const abort = () => reject(signal.reason ?? new DOMException("Aborted", "AbortError"));
		signal.addEventListener("abort", abort, { once: true });
		promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
	});
}

async function scanWithRetry(
	target: string,
	options: Required<
		Pick<
			FleetCollectionOptions,
			"maxAttempts" | "baseRetryDelayMs" | "maxRetryDelayMs" | "sleep" | "scanTargetImpl"
		>
	> & { scanOptions: Omit<AigInfraScanOptions, "concurrency"> },
): Promise<AttemptedResult> {
	let latest: AigInfraTargetResult | null = null;
	for (let attempt = 1; attempt <= options.maxAttempts; attempt++) {
		options.scanOptions.signal?.throwIfAborted();
		try {
			latest = await abortable(
				options.scanTargetImpl({ url: target }, options.scanOptions),
				options.scanOptions.signal,
			);
		} catch (error) {
			options.scanOptions.signal?.throwIfAborted();
			latest = {
				url: target,
				reachable: false,
				matched: [],
				cves: [],
				error: `collector_exception:${error instanceof Error ? error.name : "unknown"}`,
				requestsMade: 0,
			};
		}
		if (latest.reachable || terminalScanFailure(latest) || attempt === options.maxAttempts) {
			return { result: latest, attempts: attempt };
		}
		const delayMs = Math.min(
			options.maxRetryDelayMs,
			options.baseRetryDelayMs * 2 ** (attempt - 1),
		);
		await abortable(options.sleep(delayMs), options.scanOptions.signal);
	}
	throw new Error("fleet_retry_invariant_failed");
}

function emptyScan(target: string): AigInfraTargetResult {
	return {
		url: target,
		reachable: false,
		matched: [],
		cves: [],
		error: "not_checked",
		requestsMade: 0,
	};
}

function validatePreviousInventory(
	previous: FleetInventory | null | undefined,
	tenantId: string,
): FleetInventory | null {
	if (!previous) return null;
	if (
		previous.schemaVersion !== 1 ||
		previous.tenantId !== tenantId ||
		!Array.isArray(previous.items)
	) {
		throw new Error("fleet_inventory_scope_mismatch");
	}
	if (previous.items.length > MAX_FLEET_TARGETS) {
		throw new Error("fleet_inventory_entry_limit_exceeded");
	}
	return previous;
}

function mergeInventoryEntry(input: {
	tenantId: string;
	target: string;
	old?: FleetInventoryEntry;
	outcome?: AttemptedResult;
	cycleStartedAt: number;
	staleAfterMs: number;
	baseRetryDelayMs: number;
	maxRetryDelayMs: number;
	maxAttempts: number;
}): FleetInventoryEntry {
	const { tenantId, target, old, outcome, cycleStartedAt, staleAfterMs } = input;
	const id = fleetInventoryEntryId(tenantId, target);
	if (!outcome) {
		return {
			id,
			kind: "ai_infrastructure",
			target,
			firstSeenAt: old?.firstSeenAt ?? isoAt(cycleStartedAt),
			lastSeenAt: old?.lastSeenAt ?? null,
			lastAttemptAt: isoAt(cycleStartedAt),
			freshness: freshnessFor(old?.lastSeenAt ?? null, cycleStartedAt, staleAfterMs),
			reachability: "not_checked",
			consecutiveFailures: old?.consecutiveFailures ?? 0,
			attempts: 0,
			nextRetryAt: null,
			scan: old?.scan ?? emptyScan(target),
		};
	}
	const reachable = outcome.result.reachable;
	const lastSeenAt = reachable ? isoAt(cycleStartedAt) : (old?.lastSeenAt ?? null);
	const consecutiveFailures = reachable ? 0 : (old?.consecutiveFailures ?? 0) + 1;
	const retryDelayMs = Math.min(
		input.maxRetryDelayMs,
		input.baseRetryDelayMs * 2 ** Math.min(consecutiveFailures - 1, input.maxAttempts - 1),
	);
	return {
		id,
		kind: "ai_infrastructure",
		target,
		firstSeenAt: old?.firstSeenAt ?? isoAt(cycleStartedAt),
		lastSeenAt,
		lastAttemptAt: isoAt(cycleStartedAt),
		freshness: freshnessFor(lastSeenAt, cycleStartedAt, staleAfterMs),
		reachability: reachable ? "reachable" : "unreachable",
		consecutiveFailures,
		attempts: outcome.attempts,
		nextRetryAt:
			reachable || terminalScanFailure(outcome.result)
				? null
				: isoAt(cycleStartedAt + retryDelayMs),
		scan: { ...outcome.result, url: target },
	};
}

/**
 * Run one tenant-scoped collection cycle and merge it into the prior inventory.
 * Failed probes advance `lastAttemptAt`, but never `lastSeenAt`; old evidence
 * therefore becomes stale even while a disconnected collector keeps running.
 */
export async function collectFleetInventory(
	tenantIdInput: string,
	collectorIdInput: string,
	targetInputs: string[],
	previous?: FleetInventory | null,
	options: FleetCollectionOptions = {},
): Promise<FleetInventory> {
	const tenantId = requireIdentity("tenant_id", tenantIdInput);
	const collectorId = requireIdentity("collector_id", collectorIdInput);
	if (targetInputs.length > MAX_FLEET_TARGETS) {
		throw new Error("fleet_target_limit_exceeded");
	}
	options.signal?.throwIfAborted();
	const targets = normalizeFleetTargets(targetInputs);
	const prior = validatePreviousInventory(previous, tenantId);
	const now = options.now ?? Date.now;
	const staleAfterMs = clampInteger(
		options.staleAfterMs,
		prior?.staleAfterMs ?? DEFAULT_STALE_AFTER_MS,
		1_000,
		30 * 24 * 60 * 60 * 1000,
	);
	const maxAttempts = clampInteger(options.maxAttempts, DEFAULT_MAX_ATTEMPTS, 1, 5);
	const baseRetryDelayMs = clampInteger(
		options.baseRetryDelayMs,
		DEFAULT_BASE_RETRY_DELAY_MS,
		0,
		60_000,
	);
	const maxRetryDelayMs = clampInteger(
		options.maxRetryDelayMs,
		DEFAULT_MAX_RETRY_DELAY_MS,
		baseRetryDelayMs,
		5 * 60_000,
	);
	const concurrency = clampInteger(options.concurrency, 4, 1, 32);
	const sleep =
		options.sleep ??
		((delayMs: number) => sleepWithSignal(delayMs, undefined, { signal: options.signal }));
	const scanTargetImpl = options.scanTargetImpl ?? scanTarget;
	const attempted = new Map<string, AttemptedResult>();
	let cursor = 0;
	const workers = Array.from({ length: Math.min(concurrency, targets.length) }, async () => {
		while (cursor < targets.length) {
			options.signal?.throwIfAborted();
			const index = cursor++;
			const target = targets[index];
			if (!target) continue;
			attempted.set(
				target,
				await scanWithRetry(target, {
					maxAttempts,
					baseRetryDelayMs,
					maxRetryDelayMs,
					sleep,
					scanTargetImpl,
					scanOptions: { ...options.scanOptions, signal: options.signal },
				}),
			);
		}
	});
	await Promise.all(workers);
	options.signal?.throwIfAborted();
	const cycleCompletedAt = now();

	const previousById = new Map((prior?.items ?? []).map((item) => [item.id, item]));
	const items = targets.map((target) =>
		mergeInventoryEntry({
			tenantId,
			target,
			old: previousById.get(fleetInventoryEntryId(tenantId, target)),
			outcome: attempted.get(target),
			cycleStartedAt: cycleCompletedAt,
			staleAfterMs,
			baseRetryDelayMs,
			maxRetryDelayMs,
			maxAttempts,
		}),
	);

	return {
		schemaVersion: 1,
		tenantId,
		collectorId,
		generatedAt: isoAt(cycleCompletedAt),
		staleAfterMs,
		items,
	};
}

export async function loadFleetInventory(path: string): Promise<FleetInventory | null> {
	try {
		const handle = await open(path, "r");
		let raw: string;
		try {
			const buffer = Buffer.allocUnsafe(MAX_FLEET_INVENTORY_BYTES + 1);
			let bytesRead = 0;
			while (bytesRead < buffer.length) {
				const chunk = await handle.read(buffer, bytesRead, buffer.length - bytesRead, bytesRead);
				if (chunk.bytesRead === 0) break;
				bytesRead += chunk.bytesRead;
			}
			if (bytesRead > MAX_FLEET_INVENTORY_BYTES) {
				throw new Error("fleet_inventory_size_limit_exceeded");
			}
			raw = buffer.toString("utf8", 0, bytesRead);
		} finally {
			await handle.close();
		}
		const parsed = JSON.parse(raw) as FleetInventory;
		if (
			parsed.schemaVersion !== 1 ||
			typeof parsed.tenantId !== "string" ||
			typeof parsed.collectorId !== "string" ||
			!Number.isFinite(parsed.staleAfterMs) ||
			!Array.isArray(parsed.items)
		) {
			throw new Error("fleet_inventory_invalid");
		}
		if (parsed.items.length > MAX_FLEET_TARGETS) {
			throw new Error("fleet_inventory_entry_limit_exceeded");
		}
		if (
			parsed.providerEvidence !== undefined &&
			!CloudDiscoveryEvidenceSchema.safeParse(parsed.providerEvidence).success
		)
			throw new Error("fleet_inventory_provider_evidence_invalid");
		return parsed;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
		throw error;
	}
}

export async function saveFleetInventory(path: string, inventory: FleetInventory): Promise<void> {
	if (
		inventory.providerEvidence !== undefined &&
		!CloudDiscoveryEvidenceSchema.safeParse(inventory.providerEvidence).success
	)
		throw new Error("fleet_inventory_provider_evidence_invalid");
	if (inventory.items.length > MAX_FLEET_TARGETS) {
		throw new Error("fleet_inventory_entry_limit_exceeded");
	}
	if (Buffer.byteLength(`${JSON.stringify(inventory, null, 2)}\n`) > MAX_FLEET_INVENTORY_BYTES) {
		throw new Error("fleet_inventory_size_limit_exceeded");
	}
	await atomicWriteJson(path, inventory);
}
