import { createHash, generateKeyPairSync, randomUUID, sign, verify } from "node:crypto";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { resolvePath } from "./config.js";
import type { ResponseMode } from "./response-config.js";
import type { Logger, Verdict } from "./types.js";
import { nullLogger } from "./types.js";

export interface ResponseAuditEntry {
	id: string;
	timestamp: Date;
	action: "contain" | "rollback" | "quarantine" | "block" | "notify";
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

export interface ResponseAuditorOptions {
	signEntries?: boolean;
	retentionDays?: number;
	logger?: Logger;
}

export class ResponseAuditor {
	private readonly logger: Logger;
	private readonly signEntries: boolean;
	private readonly retentionDays: number;
	private privateKey?: string;
	private publicKey?: string;
	private keyPath: string;

	constructor(
		private auditLogPath: string,
		options: ResponseAuditorOptions = {},
	) {
		this.logger = options.logger ?? nullLogger;
		this.signEntries = options.signEntries ?? false;
		this.retentionDays = options.retentionDays ?? 0;
		this.keyPath = join(dirname(resolvePath(auditLogPath)), ".response-audit-key");
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

	async log(entry: Omit<ResponseAuditEntry, "id" | "timestamp">): Promise<ResponseAuditEntry> {
		await this.ensureSigningReady();
		const id = randomUUID();
		const timestamp = new Date();

		const fullEntry: ResponseAuditEntry = {
			...entry,
			id,
			timestamp,
		};

		const serialized: SerializedAuditEntry = {
			id: fullEntry.id,
			timestamp: fullEntry.timestamp.toISOString(),
			action: fullEntry.action,
			threat_id: fullEntry.threatId,
			tool: fullEntry.tool,
			input: fullEntry.input,
			verdict: fullEntry.verdict,
			response_taken: fullEntry.responseTaken,
			metadata: fullEntry.metadata,
			outcome: fullEntry.outcome,
			error: fullEntry.error,
		};

		if (this.signEntries) {
			// Load previous entry to get its hash
			const path = resolvePath(this.auditLogPath);
			let prevHash = "GENESIS";
			try {
				const content = await readFile(path, "utf-8");
				const lines = content.trim().split("\n").filter(Boolean);
				if (lines.length > 0) {
					const lastLine = lines[lines.length - 1]!;
					const lastEntry = JSON.parse(lastLine) as SerializedAuditEntry;
					if (lastEntry._entry_hash) {
						prevHash = lastEntry._entry_hash;
					}
				}
			} catch {
				// File doesn't exist yet — first entry
			}
			serialized._prev_hash = prevHash;
			serialized._entry_hash = this.computeEntryHash(serialized);
			serialized._signature = this.signEntry(serialized);
		}

		const path = resolvePath(this.auditLogPath);
		await mkdir(dirname(path), { recursive: true });
		await appendFile(path, `${JSON.stringify(serialized)}\n`);

		if (this.retentionDays > 0) {
			await this.enforceRetention();
		}

		this.logger.debug("Logged response action", {
			id,
			action: entry.action,
			threatId: entry.threatId,
			outcome: entry.outcome,
		});

		return fullEntry;
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
		return entries.filter((entry) => {
			if (filters.action && entry.action !== filters.action) return false;
			if (filters.threatId && entry.threatId !== filters.threatId) return false;
			if (filters.tool && entry.tool !== filters.tool) return false;
			if (filters.outcome && entry.outcome !== filters.outcome) return false;
			if (filters.from && entry.timestamp < filters.from) return false;
			if (filters.to && entry.timestamp > filters.to) return false;
			return true;
		});
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

			for (const line of lines) {
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
				} catch {
					// Skip invalid lines
				}
			}

			return {
				valid: tamperedEntries.length === 0,
				tamperedEntries: tamperedEntries.length > 0 ? tamperedEntries : undefined,
			};
		} catch {
			return { valid: true };
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
			const path = resolvePath(this.auditLogPath);

			if (this.signEntries && filtered.length > 0) {
				// Re-chain: first entry gets "GENESIS", subsequent chain correctly
				let prevHash = "GENESIS";
				const rechained: SerializedAuditEntry[] = [];
				for (const entry of filtered) {
					entry._prev_hash = prevHash;
					entry._entry_hash = this.computeEntryHash(entry);
					entry._signature = this.signEntry(entry);
					prevHash = entry._entry_hash;
					rechained.push(entry);
				}
				const serialized = rechained.map((e) => JSON.stringify(e));
				await writeFile(path, `${serialized.join("\n")}\n`);
			} else {
				const serialized = filtered.map((e) => JSON.stringify(e));
				await writeFile(path, `${serialized.join("\n")}\n`);
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
