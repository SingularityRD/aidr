/**
 * Durable, bounded, tenant-scoped baseline store for behavioural detection.
 *
 * The Claude Code (and Codex/OpenClaw/OpenCode) hooks are a fresh process per
 * tool call, so an in-memory baseline can never reach `minBaselineSamples`. This
 * module persists the accepted observations of a (tenant, session) scope under
 * the product's existing state directory so a later process can continue the
 * baseline instead of restarting it.
 *
 * Properties that the store deliberately guarantees:
 *
 * - **Tenant scoped.** Files are addressed by a digest of the tenant id and of
 *   the session id, and the raw ids are stored inside the file and re-checked on
 *   load. A file that does not belong to the requested scope is discarded, so
 *   one tenant's observations can never be read into another tenant's baseline.
 * - **Corpus bound when provisioned.** The constructor's verified corpus digest
 *   is saved and checked on each record. Corpus rotation reuses the same session
 *   slot, keeping aggregate quotas and tenant/session clearing intact. Concurrent
 *   old/new contexts may replace progress, but cannot restore each other's data.
 * - **Bounded.** The store reuses the orchestrator's own bounds (`maxTenants`,
 *   `maxSessionsPerTenant`, `maxEventsPerSession`, `maxFingerprintsPerSession`)
 *   plus its declared event retention (`maxEventAgeMs`), and prunes on every
 *   write. An attacker who can drive tool calls cannot grow the baseline without
 *   limit.
 * - **No raw tool payloads.** Only the orchestrator's hashed novelty tokens
 *   (`command:sha256:…`) are written; commands, paths and URLs never reach disk.
 * - **Best effort, never authoritative.** A read or write failure is logged and
 *   swallowed: the store can only *delay* a baseline, it can never invent one or
 *   turn a missing observation into a clean result. Failed state is discarded
 *   rather than partially trusted.
 */

import { createHash } from "node:crypto";
import { mkdir, readdir, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { BEHAVIORAL_ORCHESTRATOR_BOUNDS } from "./behavioral-orchestrator.js";
import { resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent, pruneOrphanedTmpFiles } from "./file-utils.js";
import type { Logger } from "./types.js";
import { nullLogger } from "./types.js";

/** One accepted observation, already reduced to pseudonymous tokens. */
export interface BehavioralBaselineObservation {
	toolName: string;
	timestamp: number;
	riskScore: number;
	/** `command:sha256:<hex>` token produced by the orchestrator; never the raw command. */
	commandToken?: string;
	/** `path:sha256:<hex>` token; never the raw path. */
	pathToken?: string;
	/** `url:sha256:<hex>` token; never the raw URL. */
	urlToken?: string;
	durationMs?: number;
}

/** The persisted state of one (tenant, session) scope. */
export interface BehavioralBaselineSessionState {
	baselineSamples: number;
	observations: BehavioralBaselineObservation[];
	fingerprintCounts: Record<string, number>;
}

/**
 * Injectable persistence boundary for the behavioural orchestrator. Implementations
 * must be safe to call concurrently and must never throw on a missing scope.
 */
export interface BehavioralBaselineStore {
	load(tenantId: string, sessionId: string): Promise<BehavioralBaselineSessionState | null>;
	save(tenantId: string, sessionId: string, state: BehavioralBaselineSessionState): Promise<void>;
	clearSession(tenantId: string, sessionId: string): Promise<void>;
	clearTenant(tenantId: string): Promise<void>;
}

/** Bounds shared with the orchestrator; see `BEHAVIORAL_ORCHESTRATOR_BOUNDS`. */
export interface BehavioralBaselineStoreBounds {
	maxTenants: number;
	maxSessionsPerTenant: number;
	maxEventsPerSession: number;
	maxFingerprintsPerSession: number;
	retentionMs: number;
}

export interface BehavioralBaselineStoreOptions extends Partial<BehavioralBaselineStoreBounds> {
	/** Directory holding tenant/session state. Defaults to the product state dir. */
	storeDir?: string;
	/** Verified corpus identity; a changed corpus replaces, never inherits, this session slot. */
	corpusDigest?: string;
	now?: () => number;
	logger?: Logger;
}

const SCHEMA_VERSION = 1;
const MAX_ID_LENGTH = 256;
const MAX_TOKEN_LENGTH = 512;
const MAX_TOOL_LENGTH = 512;
/** Guard against a corrupted file claiming an unbounded mature baseline. */
const MAX_BASELINE_SAMPLES = 1_000_000;
const DIGEST_LENGTH = 40;

/** The orchestrator's declared bounds are the single source of truth. */
function defaultBounds(): BehavioralBaselineStoreBounds {
	return {
		maxTenants: BEHAVIORAL_ORCHESTRATOR_BOUNDS.maxTenants,
		maxSessionsPerTenant: BEHAVIORAL_ORCHESTRATOR_BOUNDS.maxSessionsPerTenant,
		maxEventsPerSession: BEHAVIORAL_ORCHESTRATOR_BOUNDS.maxEventsPerSession,
		maxFingerprintsPerSession: BEHAVIORAL_ORCHESTRATOR_BOUNDS.maxFingerprintsPerSession,
		retentionMs: BEHAVIORAL_ORCHESTRATOR_BOUNDS.retentionMs,
	};
}

/** Digest scope names so a crafted tenant id can never escape the store directory. */
function digest(value: string): string {
	return createHash("sha256").update(value, "utf8").digest("hex").slice(0, DIGEST_LENGTH);
}

function isBoundedString(value: unknown, maxLength: number): value is string {
	return (
		typeof value === "string" &&
		value.length > 0 &&
		value.length <= maxLength &&
		!/[\u0000-\u001f\u007f]/.test(value)
	);
}

/** `undefined` when the field is absent, `null` when it is present but invalid. */
function readOptionalToken(value: unknown): string | undefined | null {
	if (value === undefined || value === null) return undefined;
	return isBoundedString(value, MAX_TOKEN_LENGTH) ? value : null;
}

function isPositiveInteger(value: unknown): value is number {
	return typeof value === "number" && Number.isInteger(value) && value > 0;
}

function decodeBaselineSamples(record: Record<string, unknown>): number | null {
	const baselineSamples = record.baseline_samples;
	if (
		typeof baselineSamples !== "number" ||
		!Number.isInteger(baselineSamples) ||
		baselineSamples < 0 ||
		baselineSamples > MAX_BASELINE_SAMPLES
	) {
		return null;
	}
	return baselineSamples;
}

function decodeFingerprintCounts(
	record: Record<string, unknown>,
	baselineSamples: number,
	maxFingerprintsPerSession: number,
): Record<string, number> | null {
	const rawCounts = record.fingerprint_counts;
	if (rawCounts === null || typeof rawCounts !== "object" || Array.isArray(rawCounts)) return null;
	const countEntries = Object.entries(rawCounts as Record<string, unknown>);
	if (countEntries.length > maxFingerprintsPerSession) return null;
	const fingerprintCounts: Record<string, number> = {};
	let countedSamples = 0;
	for (const [key, value] of countEntries) {
		if (!isBoundedString(key, MAX_TOKEN_LENGTH) || !isPositiveInteger(value)) return null;
		fingerprintCounts[key] = value;
		countedSamples += value;
	}
	// Fingerprints are only recorded while the map has room, so the recorded
	// total can be below the sample count, never above it.
	if (countedSamples > baselineSamples) return null;
	return fingerprintCounts;
}

/**
 * File-backed baseline store. Writes are atomic (temp file + rename) and every
 * write prunes expired, over-quota and over-retention state.
 */
export class FileBehavioralBaselineStore implements BehavioralBaselineStore {
	private readonly storeDir: string;
	private readonly corpusDigest: string | undefined;
	private readonly bounds: BehavioralBaselineStoreBounds;
	private readonly now: () => number;
	private readonly logger: Logger;

	constructor(options: BehavioralBaselineStoreOptions = {}) {
		if (options.corpusDigest !== undefined && !/^[a-f0-9]{64}$/.test(options.corpusDigest)) {
			throw new Error("Behavioral baseline corpus digest is invalid");
		}
		this.corpusDigest = options.corpusDigest;
		const defaults = defaultBounds();
		this.bounds = {
			maxTenants: options.maxTenants ?? defaults.maxTenants,
			maxSessionsPerTenant: options.maxSessionsPerTenant ?? defaults.maxSessionsPerTenant,
			maxEventsPerSession: options.maxEventsPerSession ?? defaults.maxEventsPerSession,
			maxFingerprintsPerSession:
				options.maxFingerprintsPerSession ?? defaults.maxFingerprintsPerSession,
			retentionMs: options.retentionMs ?? defaults.retentionMs,
		};
		this.storeDir =
			options.storeDir ?? join(resolvePath("~/.singularity-aidr"), "behavioral-baseline");
		this.now = options.now ?? Date.now;
		this.logger = options.logger ?? nullLogger;
	}

	async load(tenantId: string, sessionId: string): Promise<BehavioralBaselineSessionState | null> {
		const path = this.sessionPath(tenantId, sessionId);
		let raw: string;
		try {
			raw = await getFileContent(path);
		} catch {
			// A missing or unreadable scope is an empty scope, never an error.
			return null;
		}

		try {
			const parsed: unknown = JSON.parse(raw);
			const decoded = this.decode(parsed, tenantId, sessionId);
			if (!decoded) {
				this.logger.warn("Discarded a behavioural baseline record", { reason: "invalid_record" });
			}
			return decoded;
		} catch {
			// Corrupt state is discarded rather than trusted.
			this.logger.warn("Discarded an unreadable behavioural baseline record", {
				reason: "invalid_record",
			});
			return null;
		}
	}

	async save(
		tenantId: string,
		sessionId: string,
		state: BehavioralBaselineSessionState,
	): Promise<void> {
		const normalized = this.normalize(state);
		try {
			const path = this.sessionPath(tenantId, sessionId);
			await mkdir(join(this.storeDir, digest(tenantId)), { recursive: true, mode: 0o700 });
			await atomicWriteJson(path, {
				schema_version: SCHEMA_VERSION,
				corpus_sha256: this.corpusDigest,
				tenant_id: tenantId,
				session_id: sessionId,
				baseline_samples: normalized.baselineSamples,
				updated_at: this.now(),
				observations: normalized.observations.map((observation) => ({
					tool_name: observation.toolName,
					timestamp: observation.timestamp,
					risk_score: observation.riskScore,
					command: observation.commandToken ?? null,
					path: observation.pathToken ?? null,
					url: observation.urlToken ?? null,
					duration_ms: observation.durationMs ?? null,
				})),
				fingerprint_counts: normalized.fingerprintCounts,
			});
			await this.prune(tenantId);
		} catch (error) {
			// Persistence is an enhancement: failing it must not fail a verdict.
			this.logger.warn("Failed to persist a behavioural baseline record", {
				error: String(error),
			});
		}
	}

	async clearSession(tenantId: string, sessionId: string): Promise<void> {
		await this.remove(this.sessionPath(tenantId, sessionId));
	}

	async clearTenant(tenantId: string): Promise<void> {
		await this.remove(join(this.storeDir, digest(tenantId)));
	}

	private sessionPath(tenantId: string, sessionId: string): string {
		return join(this.storeDir, digest(tenantId), `${digest(sessionId)}.json`);
	}

	private async remove(path: string): Promise<void> {
		try {
			await rm(path, { recursive: true, force: true });
		} catch (error) {
			this.logger.warn("Failed to clear a behavioural baseline record", { error: String(error) });
		}
	}

	/** Re-derive the invariant the orchestrator maintains, then bound the payload. */
	private normalize(state: BehavioralBaselineSessionState): BehavioralBaselineSessionState {
		const observations = state.observations.slice(-this.bounds.maxEventsPerSession);
		const declared =
			Number.isInteger(state.baselineSamples) && state.baselineSamples > 0
				? Math.min(state.baselineSamples, MAX_BASELINE_SAMPLES)
				: 0;
		const entries = Object.entries(state.fingerprintCounts)
			.filter(([key, count]) => isBoundedString(key, MAX_TOKEN_LENGTH) && isPositiveInteger(count))
			.sort((a, b) => b[1] - a[1])
			.slice(0, this.bounds.maxFingerprintsPerSession);
		return {
			baselineSamples: Math.max(declared, observations.length),
			observations,
			fingerprintCounts: Object.fromEntries(entries),
		};
	}

	private decode(
		parsed: unknown,
		tenantId: string,
		sessionId: string,
	): BehavioralBaselineSessionState | null {
		if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
		const record = parsed as Record<string, unknown>;
		if (!this.decodeIdentity(record, tenantId, sessionId)) return null;

		const baselineSamples = decodeBaselineSamples(record);
		if (baselineSamples === null) return null;

		const observations = this.decodeObservations(record, baselineSamples);
		if (!observations) return null;

		const fingerprintCounts = decodeFingerprintCounts(
			record,
			baselineSamples,
			this.bounds.maxFingerprintsPerSession,
		);
		if (!fingerprintCounts) return null;

		return { baselineSamples, observations, fingerprintCounts };
	}

	/** A record belongs to exactly one scope; a renamed or forged file is inert. */
	private decodeIdentity(
		record: Record<string, unknown>,
		tenantId: string,
		sessionId: string,
	): boolean {
		return (
			record.schema_version === SCHEMA_VERSION &&
			record.corpus_sha256 === this.corpusDigest &&
			record.tenant_id === tenantId &&
			record.session_id === sessionId &&
			isBoundedString(record.tenant_id, MAX_ID_LENGTH) &&
			isBoundedString(record.session_id, MAX_ID_LENGTH)
		);
	}

	private decodeObservations(
		record: Record<string, unknown>,
		baselineSamples: number,
	): BehavioralBaselineObservation[] | null {
		const rawObservations = record.observations;
		if (!Array.isArray(rawObservations)) return null;
		// Exactly one accepted observation is retained per sample until the cap is
		// reached, so this equality is an integrity check on the whole record.
		if (rawObservations.length !== Math.min(baselineSamples, this.bounds.maxEventsPerSession)) {
			return null;
		}
		const observations: BehavioralBaselineObservation[] = [];
		for (const raw of rawObservations) {
			const observation = this.decodeObservation(raw);
			if (!observation) return null;
			observations.push(observation);
		}
		return observations;
	}

	private decodeObservation(raw: unknown): BehavioralBaselineObservation | null {
		if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return null;
		const record = raw as Record<string, unknown>;
		if (!isBoundedString(record.tool_name, MAX_TOOL_LENGTH)) return null;
		if (
			typeof record.timestamp !== "number" ||
			!Number.isInteger(record.timestamp) ||
			record.timestamp <= 0 ||
			record.timestamp > this.now() + 5 * 60 * 1000
		) {
			return null;
		}
		if (
			typeof record.risk_score !== "number" ||
			!Number.isFinite(record.risk_score) ||
			record.risk_score < 0 ||
			record.risk_score > 100
		) {
			return null;
		}
		if (
			record.duration_ms !== null &&
			(typeof record.duration_ms !== "number" ||
				!Number.isFinite(record.duration_ms) ||
				record.duration_ms < 0 ||
				record.duration_ms > 86_400_000)
		) {
			return null;
		}
		const commandToken = readOptionalToken(record.command);
		const pathToken = readOptionalToken(record.path);
		const urlToken = readOptionalToken(record.url);
		if (commandToken === null || pathToken === null || urlToken === null) return null;

		return {
			toolName: record.tool_name,
			timestamp: record.timestamp,
			riskScore: record.risk_score,
			commandToken,
			pathToken,
			urlToken,
			durationMs: record.duration_ms ?? undefined,
		};
	}

	/** Expire stale sessions, then enforce the session and tenant quotas. */
	private async prune(tenantId: string): Promise<void> {
		try {
			const tenantDir = join(this.storeDir, digest(tenantId));
			await pruneOrphanedTmpFiles(tenantDir);
			const files = (await readdir(tenantDir)).filter((entry) => entry.endsWith(".json"));
			const dated: Array<{ path: string; modifiedAt: number }> = [];
			for (const file of files) {
				const path = join(tenantDir, file);
				try {
					const info = await stat(path);
					if (this.now() - info.mtimeMs > this.bounds.retentionMs) {
						await this.remove(path);
						continue;
					}
					dated.push({ path, modifiedAt: info.mtimeMs });
				} catch {
					// A file that vanished concurrently is gone; nothing to prune.
				}
			}
			dated.sort((a, b) => b.modifiedAt - a.modifiedAt);
			for (const stale of dated.slice(this.bounds.maxSessionsPerTenant)) {
				await this.remove(stale.path);
			}
			await this.pruneTenants();
		} catch (error) {
			this.logger.warn("Failed to prune behavioural baseline state", { error: String(error) });
		}
	}

	private async pruneTenants(): Promise<void> {
		try {
			const entries = await readdir(this.storeDir, { withFileTypes: true });
			const directories: Array<{ path: string; modifiedAt: number }> = [];
			for (const entry of entries) {
				if (!entry.isDirectory()) continue;
				const path = join(this.storeDir, entry.name);
				try {
					directories.push({ path, modifiedAt: (await stat(path)).mtimeMs });
				} catch {
					// Directory disappeared concurrently.
				}
			}
			directories.sort((a, b) => b.modifiedAt - a.modifiedAt);
			for (const stale of directories.slice(this.bounds.maxTenants)) {
				await this.remove(stale.path);
			}
		} catch {
			// The store directory may not exist yet.
		}
	}
}

export function createBehavioralBaselineStore(
	options: BehavioralBaselineStoreOptions = {},
): FileBehavioralBaselineStore {
	return new FileBehavioralBaselineStore(options);
}
