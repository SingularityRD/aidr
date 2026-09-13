import { createHash, generateKeyPairSync, randomUUID, sign, verify } from "node:crypto";
import { appendFile, mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { resolvePath } from "./config.js";
import type { ResponseActionRecord } from "./response-actions.js";
import type { ResponseMode } from "./response-config.js";
import { redactTelemetryData, redactTelemetryString } from "./telemetry-redaction.js";
import type { Logger, ResponseAuditConfig, Verdict } from "./types.js";
import { nullLogger } from "./types.js";

export interface ResponseAuditEntry {
	id: string;
	timestamp: Date;
	action: "contain" | "rollback" | "quarantine" | "block" | "notify" | "snapshot";
	threatId: string;
	tool: string;
	input: string;
	verdict: Verdict;
	responseTaken: ResponseMode;
	metadata: {
		containerId?: string;
		snapshotId?: string;
		quarantineId?: string;
		notificationSent?: boolean;
		userNotified?: boolean;
	};
	outcome: "success" | "failure";
	error?: string;
}

interface SerializedAuditEntry {
	id: string;
	timestamp: string;
	action: ResponseAuditEntry["action"];
	threat_id: string;
	tool: string;
	input: string;
	verdict: Verdict;
	response_taken: ResponseMode;
	metadata: ResponseAuditEntry["metadata"];
	outcome: "success" | "failure";
	error?: string;
	_prev_hash?: string;
	_entry_hash?: string;
	_signature?: string;
}

interface AuditHeadCheckpoint {
	version: 1;
	entry_id: string;
	entry_hash: string;
	updated_at: string;
}

interface RetentionDeletionRecord {
	type: "retention_delete";
	version: 1;
	deleted_at: string;
	retention_days: number;
	entry_ids: string[];
	entry_hashes: string[];
	record_hash: string;
	_signature?: string;
}

export interface ResponseAuditorOptions {
	signEntries?: boolean;
	retentionDays?: number;
	/**
	 * Emit a retention manifest before expired signed records are purged. The
	 * manifest keeps deletion evidence without retaining the original payload.
	 * Defaults to true for signed logs and false for unsigned compatibility logs.
	 */
	retainDeletionEvidence?: boolean;
	logger?: Logger;
}

export class ResponseAuditor {
	private readonly logger: Logger;
	private readonly signEntries: boolean;
	private readonly retentionDays: number;
	private readonly retainDeletionEvidence: boolean;
	private privateKey?: string;
	private publicKey?: string;
	private keyPath: string;
	private readonly headPath: string;
	private readonly retentionManifestPath: string;

	constructor(
		private auditLogPath: string,
		options: ResponseAuditorOptions = {},
	) {
		this.logger = options.logger ?? nullLogger;
		this.signEntries = options.signEntries ?? false;
		this.retentionDays = options.retentionDays ?? 0;
		this.retainDeletionEvidence = options.retainDeletionEvidence ?? this.signEntries;
		this.keyPath = join(dirname(resolvePath(auditLogPath)), ".response-audit-key");
		const resolvedAuditPath = resolvePath(auditLogPath);
		this.headPath = `${resolvedAuditPath}.head`;
		this.retentionManifestPath = `${resolvedAuditPath}.retention.jsonl`;
	}

	private async ensureSigningReady(): Promise<void> {
		if (this.signEntries && !this.privateKey) {
			await this.initializeSigning();
		}
	}

	private async initializeSigning(): Promise<void> {
		try {
			const keyContent = await readFile(this.keyPath, "utf-8");
			const keys = JSON.parse(keyContent);
			this.privateKey = keys.privateKey;
			this.publicKey = keys.publicKey;
			this.logger.debug("Loaded existing signing keys for response audit");
		} catch {
			const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
				privateKeyEncoding: { type: "pkcs8", format: "pem" },
				publicKeyEncoding: { type: "spki", format: "pem" },
			});
			this.privateKey = privateKey;
			this.publicKey = publicKey;
			await mkdir(dirname(this.keyPath), { recursive: true });
			await writeFile(this.keyPath, JSON.stringify({ privateKey, publicKey }, null, 2), {
				mode: 0o600,
			});
			this.logger.debug("Generated new signing keys for response audit");
		}
	}

	private computeEntryHash(entry: SerializedAuditEntry): string {
		const data = JSON.stringify({
			id: entry.id,
			timestamp: entry.timestamp,
			action: entry.action,
			threat_id: entry.threat_id,
			tool: entry.tool,
			input: entry.input,
			verdict: entry.verdict,
			response_taken: entry.response_taken,
			metadata: entry.metadata,
			outcome: entry.outcome,
			error: entry.error,
			_prev_hash: entry._prev_hash,
		});
		return createHash("sha256").update(data).digest("hex");
	}

	private signEntry(entry: SerializedAuditEntry): string | undefined {
		if (!this.signEntries || !this.privateKey) return undefined;
		try {
			const data = JSON.stringify({
				id: entry.id,
				timestamp: entry.timestamp,
				action: entry.action,
				threat_id: entry.threat_id,
				tool: entry.tool,
				input: entry.input,
				verdict: entry.verdict,
				response_taken: entry.response_taken,
				metadata: entry.metadata,
				outcome: entry.outcome,
				error: entry.error,
				_prev_hash: entry._prev_hash,
				_entry_hash: entry._entry_hash,
			});
			return sign(undefined, Buffer.from(data), this.privateKey).toString("base64");
		} catch (error) {
			this.logger.warn("Failed to sign audit entry", { error: String(error) });
			return undefined;
		}
	}

	private verifySignature(entry: SerializedAuditEntry): boolean {
		if (!entry._signature || !this.publicKey) return false;
		try {
			const data = JSON.stringify({
				id: entry.id,
				timestamp: entry.timestamp,
				action: entry.action,
				threat_id: entry.threat_id,
				tool: entry.tool,
				input: entry.input,
				verdict: entry.verdict,
				response_taken: entry.response_taken,
				metadata: entry.metadata,
				outcome: entry.outcome,
				error: entry.error,
				_prev_hash: entry._prev_hash,
				_entry_hash: entry._entry_hash,
			});
			return verify(
				undefined,
				Buffer.from(data),
				this.publicKey,
				Buffer.from(entry._signature, "base64"),
			);
		} catch {
			return false;
		}
	}

	private async writeHeadCheckpoint(entryId: string, entryHash: string): Promise<void> {
		const checkpoint: AuditHeadCheckpoint = {
			version: 1,
			entry_id: entryId,
			entry_hash: entryHash,
			updated_at: new Date().toISOString(),
		};
		const temporaryPath = `${this.headPath}.${randomUUID()}.tmp`;
		await mkdir(dirname(this.headPath), { recursive: true });
		await writeFile(temporaryPath, `${JSON.stringify(checkpoint)}\n`, {
			encoding: "utf8",
			mode: 0o600,
		});
		try {
			await rename(temporaryPath, this.headPath);
		} catch {
			// Windows does not replace an existing destination with rename().
			await writeFile(this.headPath, `${JSON.stringify(checkpoint)}\n`, {
				encoding: "utf8",
				mode: 0o600,
			});
			await unlink(temporaryPath).catch(() => undefined);
		}
	}

	private async readHeadCheckpoint(): Promise<AuditHeadCheckpoint | null> {
		try {
			const parsed = JSON.parse(
				await readFile(this.headPath, "utf8"),
			) as Partial<AuditHeadCheckpoint>;
			if (
				parsed.version !== 1 ||
				typeof parsed.entry_id !== "string" ||
				!parsed.entry_id ||
				typeof parsed.entry_hash !== "string" ||
				!/^[0-9a-f]{64}$/.test(parsed.entry_hash)
			) {
				return null;
			}
			return parsed as AuditHeadCheckpoint;
		} catch {
			return null;
		}
	}

	private async appendRetentionDeletionRecord(removed: SerializedAuditEntry[]): Promise<void> {
		if (!this.retainDeletionEvidence || removed.length === 0) return;
		const base = {
			type: "retention_delete" as const,
			version: 1 as const,
			deleted_at: new Date().toISOString(),
			retention_days: this.retentionDays,
			entry_ids: removed.map((entry) => entry.id),
			entry_hashes: removed
				.map((entry) => entry._entry_hash)
				.filter((hash): hash is string => typeof hash === "string" && /^[0-9a-f]{64}$/.test(hash)),
		};
		const recordHash = createHash("sha256").update(JSON.stringify(base)).digest("hex");
		const record: RetentionDeletionRecord = { ...base, record_hash: recordHash };
		if (this.signEntries && this.privateKey) {
			record._signature = sign(
				undefined,
				Buffer.from(JSON.stringify({ ...base, record_hash: recordHash })),
				this.privateKey,
			).toString("base64");
		}
		await mkdir(dirname(this.retentionManifestPath), { recursive: true });
		await appendFile(this.retentionManifestPath, `${JSON.stringify(record)}\n`, "utf8");
	}

	private verifyRetentionDeletionRecord(record: RetentionDeletionRecord): boolean {
		const base = {
			type: record.type,
			version: record.version,
			deleted_at: record.deleted_at,
			retention_days: record.retention_days,
			entry_ids: record.entry_ids,
			entry_hashes: record.entry_hashes,
		};
		const expectedHash = createHash("sha256").update(JSON.stringify(base)).digest("hex");
		if (record.record_hash !== expectedHash) return false;
		if (!this.signEntries) return true;
		if (!record._signature || !this.publicKey) return false;
		try {
			return verify(
				undefined,
				Buffer.from(JSON.stringify({ ...base, record_hash: record.record_hash })),
				this.publicKey,
				Buffer.from(record._signature, "base64"),
			);
		} catch {
			return false;
		}
	}

	private async verifyRetentionManifest(): Promise<string[]> {
		const tampered: string[] = [];
		let content: string;
		try {
			content = await readFile(this.retentionManifestPath, "utf8");
		} catch {
			return tampered;
		}
		const lines = content.trim().split("\n").filter(Boolean);
		for (const [index, line] of lines.entries()) {
			try {
				const record = JSON.parse(line) as RetentionDeletionRecord;
				if (
					record.type !== "retention_delete" ||
					record.version !== 1 ||
					!Array.isArray(record.entry_ids) ||
					!Array.isArray(record.entry_hashes) ||
					!this.verifyRetentionDeletionRecord(record)
				) {
					tampered.push(`retention-manifest-line-${index + 1}`);
				}
			} catch {
				tampered.push(`retention-manifest-line-${index + 1}`);
			}
		}
		return tampered;
	}

	private serializeEntry(entry: ResponseAuditEntry): SerializedAuditEntry {
		return {
			id: entry.id,
			timestamp: entry.timestamp.toISOString(),
			action: entry.action,
			threat_id: entry.threatId,
			tool: entry.tool,
			input: redactTelemetryString(entry.input),
			verdict: redactTelemetryData(entry.verdict),
			response_taken: entry.responseTaken,
			metadata: redactTelemetryData(entry.metadata),
			outcome: entry.outcome,
			error: entry.error ? redactTelemetryString(entry.error) : undefined,
		};
	}

	private async attachSignature(serialized: SerializedAuditEntry): Promise<void> {
		const path = resolvePath(this.auditLogPath);
		let prevHash = "GENESIS";
		try {
			const content = await readFile(path, "utf-8");
			const lines = content.trim().split("\n").filter(Boolean);
			const lastLine = lines.at(-1);
			if (lastLine) {
				const lastEntry = JSON.parse(lastLine) as SerializedAuditEntry;
				if (lastEntry._entry_hash) prevHash = lastEntry._entry_hash;
			}
		} catch {
			// File does not exist yet; first entry starts at GENESIS.
		}
		serialized._prev_hash = prevHash;
		serialized._entry_hash = this.computeEntryHash(serialized);
		serialized._signature = this.signEntry(serialized);
		if (!serialized._signature) {
			throw new Error("response audit signing failed; refusing unsigned append");
		}
	}

	async log(entry: Omit<ResponseAuditEntry, "id" | "timestamp">): Promise<ResponseAuditEntry> {
		await this.ensureSigningReady();
		const id = randomUUID();
		const timestamp = new Date();

		const fullEntry: ResponseAuditEntry = {
			...entry,
			id,
			timestamp,
		};

		const serialized = this.serializeEntry(fullEntry);

		if (this.signEntries) {
			await this.attachSignature(serialized);
			/*
				// File doesn't exist yet — first entry
			}
			*/
		}

		const path = resolvePath(this.auditLogPath);
		await mkdir(dirname(path), { recursive: true });
		await appendFile(path, `${JSON.stringify(serialized)}\n`);
		if (this.signEntries && serialized._entry_hash) {
			await this.writeHeadCheckpoint(serialized.id, serialized._entry_hash);
		}

		if (this.retentionDays > 0) {
			await this.enforceRetention();
		}

		this.logger.debug("Logged response action", {
			id,
			action: entry.action,
			threatId: entry.threatId,
			outcome: entry.outcome,
		});

		// Return the same privacy-safe representation that was persisted. The
		// auditor must not hand raw tool input back to a telemetry caller.
		return {
			...fullEntry,
			input: serialized.input,
			verdict: serialized.verdict,
			metadata: serialized.metadata,
			error: serialized.error,
		};
	}

	async query(filters: {
		action?: ResponseAuditEntry["action"];
		threatId?: string;
		tool?: string;
		from?: Date;
		to?: Date;
		outcome?: "success" | "failure";
	}): Promise<ResponseAuditEntry[]> {
		const entries = await this.loadAllEntries();
		return entries.filter((entry) => this.matchesQueryFilter(entry, filters));
	}

	private matchesQueryFilter(
		entry: ResponseAuditEntry,
		filters: {
			action?: ResponseAuditEntry["action"];
			threatId?: string;
			tool?: string;
			from?: Date;
			to?: Date;
			outcome?: "success" | "failure";
		},
	): boolean {
		if (filters.action && entry.action !== filters.action) return false;
		if (filters.threatId && entry.threatId !== filters.threatId) return false;
		if (filters.tool && entry.tool !== filters.tool) return false;
		if (filters.outcome && entry.outcome !== filters.outcome) return false;
		if (filters.from && entry.timestamp < filters.from) return false;
		if (filters.to && entry.timestamp > filters.to) return false;
		return true;
	}

	private async loadAllEntries(): Promise<ResponseAuditEntry[]> {
		const path = resolvePath(this.auditLogPath);
		try {
			const content = await readFile(path, "utf-8");
			const lines = content.trim().split("\n").filter(Boolean);
			const entries: ResponseAuditEntry[] = [];
			for (const line of lines) {
				try {
					const serialized = JSON.parse(line) as SerializedAuditEntry;
					entries.push({
						id: serialized.id,
						timestamp: new Date(serialized.timestamp),
						action: serialized.action,
						threatId: serialized.threat_id,
						tool: serialized.tool,
						input: serialized.input,
						verdict: serialized.verdict,
						responseTaken: serialized.response_taken,
						metadata: serialized.metadata,
						outcome: serialized.outcome,
						error: serialized.error,
					});
				} catch {
					// Skip invalid lines
				}
			}
			return entries;
		} catch {
			return [];
		}
	}

	private async loadAllSerialized(): Promise<SerializedAuditEntry[]> {
		const path = resolvePath(this.auditLogPath);
		try {
			const content = await readFile(path, "utf-8");
			const lines = content.trim().split("\n").filter(Boolean);
			const entries: SerializedAuditEntry[] = [];
			for (const line of lines) {
				try {
					entries.push(JSON.parse(line) as SerializedAuditEntry);
				} catch {
					// Skip invalid lines
				}
			}
			return entries;
		} catch {
			return [];
		}
	}

	async verifyIntegrity(): Promise<{
		valid: boolean;
		tamperedEntries?: string[];
	}> {
		await this.ensureSigningReady();
		if (!this.signEntries) {
			return { valid: true };
		}

		const path = resolvePath(this.auditLogPath);
		const tamperedEntries: string[] = [];

		try {
			const content = await readFile(path, "utf-8");
			const lines = content.trim().split("\n").filter(Boolean);
			let expectedPrevHash = "GENESIS";
			let lastVerifiedEntry: SerializedAuditEntry | undefined;

			for (const [lineIndex, line] of lines.entries()) {
				try {
					const entry = JSON.parse(line) as SerializedAuditEntry;

					// Check hash chain
					if (entry._prev_hash !== expectedPrevHash) {
						tamperedEntries.push(entry.id);
						continue;
					}

					// Check entry hash
					const computedHash = this.computeEntryHash(entry);
					if (entry._entry_hash !== computedHash) {
						tamperedEntries.push(entry.id);
						continue;
					}

					// Check signature - missing or invalid signature is tampering
					if (!entry._signature) {
						tamperedEntries.push(entry.id);
						continue;
					}
					if (!this.verifySignature(entry)) {
						tamperedEntries.push(entry.id);
						continue;
					}

					expectedPrevHash = entry._entry_hash ?? expectedPrevHash;
					lastVerifiedEntry = entry;
				} catch {
					// A malformed line is tampering/corruption, not an ignorable
					// condition.  Returning valid=true here would make an audit
					// trail appear immutable while silently dropping evidence.
					tamperedEntries.push(`invalid-line-${lineIndex + 1}`);
				}
			}

			// A hash chain alone cannot detect truncation of its tail. The local
			// head checkpoint provides a best-effort deletion signal; operators
			// should additionally export/anchor this checkpoint externally.
			if (tamperedEntries.length === 0) {
				const head = await this.readHeadCheckpoint();
				if (lines.length === 0) {
					if (head) tamperedEntries.push("audit-log-truncated");
				} else if (!head) {
					tamperedEntries.push("head-checkpoint-missing");
				} else if (
					!lastVerifiedEntry ||
					head.entry_id !== lastVerifiedEntry.id ||
					head.entry_hash !== lastVerifiedEntry._entry_hash
				) {
					tamperedEntries.push("audit-log-tail-deleted");
				}
			}
			tamperedEntries.push(...(await this.verifyRetentionManifest()));

			return {
				valid: tamperedEntries.length === 0,
				tamperedEntries: tamperedEntries.length > 0 ? tamperedEntries : undefined,
			};
		} catch {
			return { valid: false, tamperedEntries: ["audit-log-unreadable"] };
		}
	}

	async exportToJSON(): Promise<string> {
		const entries = await this.loadAllEntries();
		return JSON.stringify(entries, null, 2);
	}

	private async enforceRetention(): Promise<void> {
		await this.ensureSigningReady();
		if (this.retentionDays <= 0) return;

		const cutoff = new Date();
		cutoff.setDate(cutoff.getDate() - this.retentionDays);

		const serializedEntries = await this.loadAllSerialized();
		const filtered = serializedEntries.filter((e) => {
			const ts = new Date(e.timestamp);
			return ts >= cutoff;
		});

		if (filtered.length < serializedEntries.length) {
			const removed = serializedEntries.filter((entry) => !filtered.includes(entry));
			// Write deletion evidence before replacing the active file. If this
			// fails, the old audit log remains intact and no silent purge occurs.
			await this.appendRetentionDeletionRecord(removed);
			const path = resolvePath(this.auditLogPath);

			if (this.signEntries && filtered.length > 0) {
				// Re-chain: first entry gets "GENESIS", subsequent chain correctly
				let prevHash = "GENESIS";
				const rechained: SerializedAuditEntry[] = [];
				for (const entry of filtered) {
					entry._prev_hash = prevHash;
					entry._entry_hash = this.computeEntryHash(entry);
					entry._signature = this.signEntry(entry);
					if (!entry._signature) {
						throw new Error("response audit signing failed during retention rewrite");
					}
					prevHash = entry._entry_hash;
					rechained.push(entry);
				}
				const serialized = rechained.map((e) => JSON.stringify(e));
				await writeFile(path, `${serialized.join("\n")}\n`);
				const last = rechained[rechained.length - 1];
				if (last?._entry_hash) {
					await this.writeHeadCheckpoint(last.id, last._entry_hash);
				}
			} else {
				const serialized = filtered.map((e) => JSON.stringify(e));
				await writeFile(path, `${serialized.join("\n")}\n`);
				if (this.signEntries) {
					await unlink(this.headPath).catch(() => undefined);
				}
			}

			this.logger.debug("Enforced retention policy", {
				removed: serializedEntries.length - filtered.length,
				retentionDays: this.retentionDays,
			});
		}
	}

	async getStats(): Promise<{
		totalEntries: number;
		actionBreakdown: Record<string, number>;
		outcomeBreakdown: { success: number; failure: number };
		oldestEntry?: Date;
		newestEntry?: Date;
	}> {
		const entries = await this.loadAllEntries();
		const actionBreakdown: Record<string, number> = {};
		let successCount = 0;
		let failureCount = 0;
		let oldest: Date | undefined;
		let newest: Date | undefined;

		for (const entry of entries) {
			actionBreakdown[entry.action] = (actionBreakdown[entry.action] ?? 0) + 1;
			if (entry.outcome === "success") {
				successCount++;
			} else {
				failureCount++;
			}
			if (!oldest || entry.timestamp < oldest) {
				oldest = entry.timestamp;
			}
			if (!newest || entry.timestamp > newest) {
				newest = entry.timestamp;
			}
		}

		return {
			totalEntries: entries.length,
			actionBreakdown,
			outcomeBreakdown: { success: successCount, failure: failureCount },
			oldestEntry: oldest,
			newestEntry: newest,
		};
	}
}

export function createResponseAuditor(options?: ResponseAuditorOptions): ResponseAuditor {
	return new ResponseAuditor("~/.singularity-aidr/response-audit.jsonl", options);
}

/*
 * ── Wiring the detection path into the signed chain ────────────────────────
 *
 * Everything below turns a response that actually happened into a signed,
 * chained record. It reuses the mechanism above (Ed25519 signature over the
 * serialized entry, SHA-256 hash chain, head checkpoint) — there is no second
 * signing implementation.
 *
 * Two properties matter more than completeness here:
 *
 * 1. **A record is never written without a signature.** `ResponseAuditor.log`
 *    already refuses to append when signing fails; these helpers pass
 *    `signEntries: true` always, so the only way a response reaches this file is
 *    signed. When the chain is unavailable the caller gets `written: false` plus
 *    the reason, and says so — "could not record it" is reported, never rounded
 *    up to "recorded".
 * 2. **Records carry paths and outcomes, never contents.** The snapshot payload
 *    lives in the snapshot/vault directory; the chain only ever learns which
 *    path was preserved, how large it was, and whether it worked.
 */

export interface ResponseChainContext {
	/** The decision the guard reached: "deny" | "ask" | "allow". */
	decision: "deny" | "ask" | "allow";
	toolName: string;
	/** Bounded, credential-redacted description of the call. Never file contents. */
	inputSummary: string;
	sessionId?: string;
	verdict: Verdict;
	/** Snapshot id, when the action created a restorable snapshot. */
	snapshotId?: string;
	/** Pre-operation snapshot target path. */
	snapshotTarget?: string;
}

export interface ResponseChainWrite {
	written: boolean;
	entryId?: string;
	/** Machine-readable reason the record is NOT in the chain. Never silently dropped. */
	reason?: string;
	detail?: string;
}

/** Map a response action onto the chain's own action/response-mode vocabulary. */
export function chainActionFor(
	action: ResponseActionRecord["action"],
	decision: ResponseChainContext["decision"],
): { action: ResponseAuditEntry["action"]; responseTaken: ResponseMode } {
	if (action === "rollback") return { action: "rollback", responseTaken: "rollback" };
	// A snapshot preserves prior state without moving or blocking anything: that is
	// containment. It is emphatically NOT "quarantine", which relocates the file.
	if (action === "snapshot") return { action: "snapshot", responseTaken: "contain" };
	if (decision === "ask") return { action: "notify", responseTaken: "notify" };
	return { action: "block", responseTaken: "block" };
}

/**
 * Which record the single chain entry describes.
 *
 * One entry per response, so a mixed result must pick the record that matters:
 * a failure outranks a success, and a restore outranks everything else, because
 * those are the outcomes an operator has to act on.
 */
function primaryRecord(records: ResponseActionRecord[]): ResponseActionRecord | undefined {
	const rank = (record: ResponseActionRecord): number => {
		if (record.outcome === "failure") return 4;
		if (record.action === "rollback") return 3;
		if (record.outcome === "success") return 2;
		return 1;
	};
	return records.reduce<ResponseActionRecord | undefined>(
		(best, record) => (best === undefined || rank(record) > rank(best) ? record : best),
		undefined,
	);
}

function chainOutcomeFor(records: ResponseActionRecord[]): "success" | "failure" {
	// Absence of success is failure, never "assume it worked".
	return records.some((record) => record.outcome === "success") ? "success" : "failure";
}

function chainErrorFor(records: ResponseActionRecord[]): string | undefined {
	const failed = records.filter((record) => record.outcome === "failure");
	if (failed.length === 0) return undefined;
	return failed
		.map(
			(record) => `${record.action} failed (${record.reason ?? "unknown"}): ${record.detail ?? ""}`,
		)
		.join("; ");
}

/**
 * Append one signed chain record for a response action.
 *
 * Never throws: the guard's block must survive any failure here. A caller that
 * cares whether the record landed reads the returned `written` flag — and must
 * report the failure rather than implying the chain holds something it does not.
 */
export async function logResponseActionToChain(
	auditor: ResponseAuditor,
	records: ResponseActionRecord[],
	context: ResponseChainContext,
	logger: Logger = nullLogger,
): Promise<ResponseChainWrite> {
	if (records.length === 0) {
		return { written: false, reason: "no_response_actions" };
	}

	const primary = primaryRecord(records);
	const { action, responseTaken } = chainActionFor(primary?.action ?? "snapshot", context.decision);
	const threatId = context.verdict.matchedThreatId ?? context.verdict.category ?? "unknown";
	const outcome = chainOutcomeFor(records);

	try {
		const entry = await auditor.log({
			action,
			threatId,
			tool: context.toolName,
			// Already redacted by the caller through `redactTelemetryString`; the
			// auditor redacts again on the way out. Never a contents dump.
			input: context.inputSummary,
			verdict: context.verdict,
			responseTaken,
			metadata: {
				snapshotId: context.snapshotId,
				userNotified: context.decision !== "allow",
				notificationSent: context.decision === "ask",
			},
			outcome,
			error: chainErrorFor(records),
		});

		logger.debug("Response action recorded in signed chain", {
			entryId: entry.id,
			action,
			outcome,
		});
		return { written: true, entryId: entry.id };
	} catch (error) {
		const detail = error instanceof Error ? error.message : String(error);
		// Fail honest, never fail silent: no unsigned record is written in place of
		// the signed one, and the caller is told the evidence is missing.
		logger.warn("Response action NOT recorded in signed chain", { action, error: detail });
		return { written: false, reason: "signed_chain_unavailable", detail };
	}
}

/**
 * Build the auditor described by config, or explain why there is none.
 *
 * `signEntries` is hard-coded true: this chain exists to be tamper-evident, and a
 * config flag that could turn signing off would let a deployment believe it had
 * evidence it does not have.
 */
export function responseAuditorFromConfig(
	config: ResponseAuditConfig | undefined,
	logger: Logger = nullLogger,
): { auditor?: ResponseAuditor; unavailableReason?: string } {
	// Tolerate an absent block: `response: { actions: {...} }` with no `audit` key is
	// a valid config, and absent must mean OFF rather than a throw on the security
	// path. (A nested Zod `.default({})` does not fire when a sibling key is given.)
	const resolved = config ?? DEFAULT_RESPONSE_AUDIT_CONFIG;
	if (!resolved.signed_chain) {
		return { unavailableReason: "signed_chain_disabled" };
	}
	try {
		return {
			auditor: new ResponseAuditor(resolved.path, {
				signEntries: true,
				retentionDays: resolved.retention_days,
				retainDeletionEvidence: resolved.retain_deletion_evidence,
				logger,
			}),
		};
	} catch (error) {
		return { unavailableReason: `auditor_init_failed: ${String(error)}` };
	}
}

/** The shipped defaults for the signed response chain, in one place. */
export const DEFAULT_RESPONSE_AUDIT_CONFIG: ResponseAuditConfig = {
	signed_chain: false,
	path: "~/.singularity-aidr/response-audit.jsonl",
	retention_days: 0,
	retain_deletion_evidence: true,
};
