import { createHash, generateKeyPairSync, randomUUID, sign, verify } from "node:crypto";
import { appendFile, chmod, mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { resolvePath } from "./config.js";
import type { ResponseActionRecord } from "./response-actions.js";
import type { ResponseMode } from "./response-config.js";
import { redactTelemetryData, redactTelemetryString } from "./telemetry-redaction.js";
import type { Logger, ResponseAuditConfig, Verdict } from "./types.js";
import { nullLogger } from "./types.js";

const PRIVATE_DIRECTORY_MODE = 0o700;
const PRIVATE_FILE_MODE = 0o600;
// Guard creates fresh auditors per call, so serialize at module scope by log path.
const auditWriteQueues = new Map<string, Promise<void>>();

function serializeAuditWrite<T>(path: string, operation: () => Promise<T>): Promise<T> {
	const resolvedPath = resolve(resolvePath(path));
	const queueKey = process.platform === "win32" ? resolvedPath.toLowerCase() : resolvedPath;
	const previous = auditWriteQueues.get(queueKey) ?? Promise.resolve();
	const result = previous.then(operation);
	const queued = result.then(
		() => undefined,
		() => undefined,
	);
	auditWriteQueues.set(queueKey, queued);
	void queued.then(() => {
		if (auditWriteQueues.get(queueKey) === queued) auditWriteQueues.delete(queueKey);
	});
	return result;
}

async function ensurePrivateDirectory(path: string): Promise<void> {
	await mkdir(path, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
	await chmod(path, PRIVATE_DIRECTORY_MODE);
}

async function hardenPrivateFileIfPresent(path: string): Promise<void> {
	try {
		await chmod(path, PRIVATE_FILE_MODE);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
	}
}

async function writePrivateFile(path: string, content: string): Promise<void> {
	await ensurePrivateDirectory(dirname(path));
	await hardenPrivateFileIfPresent(path);
	await writeFile(path, content, { encoding: "utf8", mode: PRIVATE_FILE_MODE });
}

async function appendPrivateFile(path: string, content: string): Promise<void> {
	await ensurePrivateDirectory(dirname(path));
	await hardenPrivateFileIfPresent(path);
	await appendFile(path, content, { encoding: "utf8", mode: PRIVATE_FILE_MODE });
}

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
		/** Machine-readable reason a response was refused, when it was. */
		reason?: string;
		/** Provider/enrollment evidence only; never an OS or hardware claim. */
		commandId?: string;
		providerId?: string;
		installationId?: string;
		keyHash?: string;
	};
	outcome: "success" | "failure";
	error?: string;
	/**
	 * Identity of the operator that authorized this response, in the same shape
	 * the installed-worker contract takes (`binding.authorizedBy`, e.g.
	 * "operator:on-call"). Absent means the response was not operator-authorized.
	 *
	 * Deliberately a first-class field rather than a `metadata` key: `serializeEntry`
	 * runs every metadata key through `SENSITIVE_KEY_RE`, which matches `auth*` and
	 * would rewrite an `authorizedBy` value to "[Redacted]" — recording an operator
	 * that was never actually named. As a top-level field it is covered by the chain
	 * hash and the Ed25519 signature instead, so it is persisted and tamper-evident.
	 */
	authorizedBy?: string;
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
	authorized_by?: string;
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

/** Where the signed chain first stops being trustworthy. */
export interface ResponseChainBrokenLink {
	/** 1-based JSONL line; 0 when the break is not tied to a line (key, log, manifest). */
	line: number;
	entryId?: string;
	reason:
		| "prev_hash_mismatch"
		| "entry_hash_mismatch"
		| "signature_missing"
		| "signature_invalid"
		| "malformed_line"
		| "head_checkpoint_missing"
		| "audit_log_tail_deleted"
		| "audit_log_truncated"
		| "retention_manifest_invalid"
		| "audit_log_missing"
		| "audit_log_unreadable"
		| "signing_key_missing";
}

export interface ResponseChainVerification {
	valid: boolean;
	/** The first broken link's reason, or `unsigned_audit_chain_not_verified`. */
	reason?: string;
	/** Non-empty JSONL lines in the active log. */
	entries: number;
	/** Entries that extend the chain from GENESIS with a valid hash and signature. */
	verifiedEntries: number;
	firstBrokenLink?: ResponseChainBrokenLink;
	tamperedEntries: string[];
}

function unverifiedChain(
	reason: string,
	link?: ResponseChainBrokenLink,
): ResponseChainVerification {
	return {
		valid: false,
		reason,
		entries: 0,
		verifiedEntries: 0,
		firstBrokenLink: link,
		tamperedEntries: link ? [link.entryId ?? link.reason] : [],
	};
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
		await ensurePrivateDirectory(dirname(this.keyPath));
		await hardenPrivateFileIfPresent(this.keyPath);
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
			await writePrivateFile(this.keyPath, JSON.stringify({ privateKey, publicKey }, null, 2));
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
			authorized_by: entry.authorized_by,
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
				authorized_by: entry.authorized_by,
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
				authorized_by: entry.authorized_by,
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
		await writePrivateFile(temporaryPath, `${JSON.stringify(checkpoint)}\n`);
		try {
			await rename(temporaryPath, this.headPath);
		} catch {
			// Windows does not replace an existing destination with rename().
			await writePrivateFile(this.headPath, `${JSON.stringify(checkpoint)}\n`);
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
		await appendPrivateFile(this.retentionManifestPath, `${JSON.stringify(record)}\n`);
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
		const serialized: SerializedAuditEntry = {
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
		// Only present when an operator identity was actually supplied, so an entry
		// that the runtime authorized on its own never claims an operator.
		if (entry.authorizedBy) {
			serialized.authorized_by = redactTelemetryString(entry.authorizedBy);
		}
		return serialized;
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
		return serializeAuditWrite(this.auditLogPath, () => this.logSerialized(entry));
	}

	private async logSerialized(
		entry: Omit<ResponseAuditEntry, "id" | "timestamp">,
	): Promise<ResponseAuditEntry> {
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
		await appendPrivateFile(path, `${JSON.stringify(serialized)}\n`);
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
			authorizedBy: serialized.authorized_by,
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
						authorizedBy: serialized.authorized_by,
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
		reason?: string;
		tamperedEntries?: string[];
	}> {
		const result = await this.verifyChain();
		if (result.reason === "unsigned_audit_chain_not_verified") {
			return { valid: false, reason: result.reason };
		}
		return {
			valid: result.valid,
			tamperedEntries: result.tamperedEntries.length > 0 ? result.tamperedEntries : undefined,
		};
	}

	/**
	 * Walk the signed chain and report the FIRST broken link, not only a boolean.
	 *
	 * `requireExistingKey` is for offline verification (`aidr audit verify`): a
	 * verifier must never mint a fresh key pair, because a brand-new key would
	 * "verify" nothing and would replace the evidence key. Without it, the auditor
	 * keeps its historical behaviour of initialising signing on demand.
	 */
	async verifyChain(
		options: { requireExistingKey?: boolean } = {},
	): Promise<ResponseChainVerification> {
		if (!this.signEntries) return unverifiedChain("unsigned_audit_chain_not_verified");
		const keyFailure = await this.prepareVerificationKey(options.requireExistingKey === true);
		if (keyFailure) return keyFailure;

		let content: string;
		try {
			content = await readFile(resolvePath(this.auditLogPath), "utf-8");
		} catch (error) {
			const reason =
				(error as NodeJS.ErrnoException).code === "ENOENT"
					? "audit_log_missing"
					: "audit_log_unreadable";
			return unverifiedChain(reason, { line: 0, entryId: "audit-log-unreadable", reason });
		}

		const lines = content.trim().split("\n").filter(Boolean);
		const walk = this.walkChain(lines);
		const breaks = [...walk.breaks];
		// A hash chain alone cannot detect truncation of its tail. The local
		// head checkpoint provides a best-effort deletion signal; operators
		// should additionally export/anchor this checkpoint externally.
		if (breaks.length === 0) {
			const headBreak = this.headCheckpointBreak(
				await this.readHeadCheckpoint(),
				lines.length,
				walk.lastVerifiedEntry,
			);
			if (headBreak) breaks.push(headBreak);
		}
		for (const id of await this.verifyRetentionManifest()) {
			breaks.push({ line: 0, entryId: id, reason: "retention_manifest_invalid" });
		}

		const firstBrokenLink = breaks[0];
		return {
			valid: breaks.length === 0,
			reason: firstBrokenLink?.reason,
			entries: lines.length,
			verifiedEntries: walk.verifiedEntries,
			firstBrokenLink,
			tamperedEntries: breaks.map((link) => link.entryId ?? link.reason),
		};
	}

	/** Load (or, outside offline verification, create) the key; a failure result when absent. */
	private async prepareVerificationKey(
		requireExistingKey: boolean,
	): Promise<ResponseChainVerification | undefined> {
		if (!requireExistingKey) {
			await this.ensureSigningReady();
			return undefined;
		}
		if (await this.loadExistingSigningKey()) return undefined;
		return unverifiedChain("signing_key_missing", {
			line: 0,
			entryId: "signing-key-missing",
			reason: "signing_key_missing",
		});
	}

	/** Walk every line from GENESIS; each line that does not extend the chain is a break. */
	private walkChain(lines: string[]): {
		breaks: ResponseChainBrokenLink[];
		verifiedEntries: number;
		lastVerifiedEntry?: SerializedAuditEntry;
	} {
		const breaks: ResponseChainBrokenLink[] = [];
		let expectedPrevHash = "GENESIS";
		let lastVerifiedEntry: SerializedAuditEntry | undefined;
		let verifiedEntries = 0;
		for (const [lineIndex, line] of lines.entries()) {
			const lineNumber = lineIndex + 1;
			let entry: SerializedAuditEntry;
			try {
				entry = JSON.parse(line) as SerializedAuditEntry;
			} catch {
				// A malformed line is tampering/corruption, not an ignorable
				// condition. Returning valid=true here would make an audit
				// trail appear immutable while silently dropping evidence.
				breaks.push({
					line: lineNumber,
					entryId: `invalid-line-${lineNumber}`,
					reason: "malformed_line",
				});
				continue;
			}
			const failure = this.linkFailure(entry, expectedPrevHash);
			if (failure) {
				breaks.push({ line: lineNumber, entryId: entry.id, reason: failure });
				continue;
			}
			expectedPrevHash = entry._entry_hash ?? expectedPrevHash;
			lastVerifiedEntry = entry;
			verifiedEntries++;
		}
		return { breaks, verifiedEntries, lastVerifiedEntry };
	}

	private headCheckpointBreak(
		head: AuditHeadCheckpoint | null,
		lineCount: number,
		lastVerifiedEntry: SerializedAuditEntry | undefined,
	): ResponseChainBrokenLink | undefined {
		if (lineCount === 0) {
			return head
				? { line: 0, entryId: "audit-log-truncated", reason: "audit_log_truncated" }
				: undefined;
		}
		if (!head) {
			return {
				line: lineCount,
				entryId: "head-checkpoint-missing",
				reason: "head_checkpoint_missing",
			};
		}
		if (
			!lastVerifiedEntry ||
			head.entry_id !== lastVerifiedEntry.id ||
			head.entry_hash !== lastVerifiedEntry._entry_hash
		) {
			return {
				line: lineCount,
				entryId: "audit-log-tail-deleted",
				reason: "audit_log_tail_deleted",
			};
		}
		return undefined;
	}

	/** Why this entry does not extend the chain, or undefined when it does. */
	private linkFailure(
		entry: SerializedAuditEntry,
		expectedPrevHash: string,
	): ResponseChainBrokenLink["reason"] | undefined {
		if (entry._prev_hash !== expectedPrevHash) return "prev_hash_mismatch";
		if (entry._entry_hash !== this.computeEntryHash(entry)) return "entry_hash_mismatch";
		// A missing or invalid signature is tampering.
		if (!entry._signature) return "signature_missing";
		if (!this.verifySignature(entry)) return "signature_invalid";
		return undefined;
	}

	/** Load the existing key pair without ever creating one; false when there is none. */
	private async loadExistingSigningKey(): Promise<boolean> {
		if (this.publicKey) return true;
		try {
			const keys = JSON.parse(await readFile(this.keyPath, "utf-8")) as {
				privateKey?: unknown;
				publicKey?: unknown;
			};
			if (typeof keys.publicKey !== "string" || keys.publicKey.length === 0) return false;
			this.publicKey = keys.publicKey;
			if (typeof keys.privateKey === "string") this.privateKey = keys.privateKey;
			return true;
		} catch {
			return false;
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
				await writePrivateFile(path, `${serialized.join("\n")}\n`);
				const last = rechained[rechained.length - 1];
				if (last?._entry_hash) {
					await this.writeHeadCheckpoint(last.id, last._entry_hash);
				}
			} else {
				const serialized = filtered.map((e) => JSON.stringify(e));
				await writePrivateFile(path, `${serialized.join("\n")}\n`);
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
