/**
 * Audit logger for Singularity AIDR with 30-day rotation policy
 * JSONL format: ~/.singularity-aidr/audit.log
 */

import { appendFile, mkdir, readFile, rename, stat, unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { Decision } from "./types.js";

export interface AuditLogEntry {
	timestamp: string;
	event: "decision" | "session_start" | "session_end" | "error" | "config_change";
	verdict?: Decision;
	threat_id?: string;
	tool?: string;
	user_input?: string;
	session_id?: string;
	metadata?: Record<string, unknown>;
}

export interface AuditLogConfig {
	enabled: boolean;
	path: string;
	retention_days: number;
	max_bytes: number;
	max_files: number;
}

export const DEFAULT_AUDIT_CONFIG: AuditLogConfig = {
	enabled: true,
	path: join(homedir(), ".singularity-aidr", "audit.log"),
	retention_days: 30,
	max_bytes: 50 * 1024 * 1024,
	max_files: 5,
};

function sanitizeInput(input: string, maxLength = 500): string {
	if (!input) return "";
	let sanitized = input
		.replace(/[Bb]earer\s+\S+/g, "Bearer <REDACTED_TOKEN>")
		.replace(/password[=:]\s*\S+/gi, "password=<REDACTED>")
		.replace(/token[=:]\s*\S+/gi, "token=<REDACTED>")
		.replace(/secret[=:]\s*\S+/gi, "secret=<REDACTED>")
		.replace(/key[=:]\s*\S+/gi, "key=<REDACTED>")
		.replace(/[a-zA-Z0-9_-]{15,}/g, (match) => {
			const hasUpper = /[A-Z]/.test(match);
			const hasLower = /[a-z]/.test(match);
			const hasDigit = /[0-9]/.test(match);
			const types = [hasUpper, hasLower, hasDigit].filter(Boolean).length;
			if (types >= 2) return "<REDACTED_TOKEN>";
			return match;
		});
	if (sanitized.length > maxLength) {
		sanitized = `${sanitized.slice(0, maxLength)}...`;
	}
	// Collapse runs of 20+ identical characters (log-flood prevention)
	sanitized = sanitized.replace(/(.)\1{19,}/g, "$1");
	return sanitized;
}

function getTimestamp(): string {
	return new Date().toISOString();
}

async function ensureLogDir(logPath: string): Promise<void> {
	const dir = dirname(logPath);
	await mkdir(dir, { recursive: true });
}

async function rotateIfNeeded(filePath: string, maxBytes: number, maxFiles: number): Promise<void> {
	if (maxBytes <= 0 || maxFiles <= 0) return;
	let size: number;
	try {
		const s = await stat(filePath);
		size = s.size;
	} catch {
		return;
	}
	if (size < maxBytes) return;
	try {
		await unlink(`${filePath}.${maxFiles}`);
	} catch {
		// ENOENT OK
	}
	for (let i = maxFiles - 1; i >= 1; i--) {
		try {
			await rename(`${filePath}.${i}`, `${filePath}.${i + 1}`);
		} catch {
			// ENOENT OK
		}
	}
	try {
		await rename(filePath, `${filePath}.1`);
	} catch {
		// ENOENT OK
	}
}

export async function cleanupOldLogs(
	logDir: string,
	baseName: string,
	retentionDays: number,
): Promise<void> {
	if (retentionDays <= 0) return;
	const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
	try {
		const { readdir } = await import("node:fs/promises");
		const entries = await readdir(logDir);
		for (const entry of entries) {
			if (!entry.startsWith(baseName)) continue;
			const entryPath = join(logDir, entry);
			try {
				const s = await stat(entryPath);
				if (s.mtime.getTime() < cutoff) {
					await unlink(entryPath);
				}
			} catch {
				// Ignore errors
			}
		}
	} catch {
		// Fail silently
	}
}

async function appendEntry(config: AuditLogConfig, entry: AuditLogEntry): Promise<void> {
	const path = config.path;
	await ensureLogDir(path);
	await rotateIfNeeded(path, config.max_bytes, config.max_files);
	await appendFile(path, `${JSON.stringify(entry)}\n`);
}

export async function logDecision(
	config: AuditLogConfig,
	verdict: Decision,
	tool: string,
	userInput: string,
	threatId?: string,
	sessionId?: string,
	metadata?: Record<string, unknown>,
): Promise<void> {
	if (!config.enabled) return;
	const entry: AuditLogEntry = {
		timestamp: getTimestamp(),
		event: "decision",
		verdict,
		tool,
		user_input: sanitizeInput(userInput),
		threat_id: threatId,
		session_id: sessionId,
		metadata,
	};
	try {
		await appendEntry(config, entry);
	} catch {
		// Fail-open
	}
}

export async function logSessionStart(
	config: AuditLogConfig,
	sessionId: string,
	metadata?: Record<string, unknown>,
): Promise<void> {
	if (!config.enabled) return;
	const entry: AuditLogEntry = {
		timestamp: getTimestamp(),
		event: "session_start",
		session_id: sessionId,
		metadata,
	};
	try {
		await appendEntry(config, entry);
	} catch {
		// Fail-open
	}
}

export async function logSessionEnd(
	config: AuditLogConfig,
	sessionId: string,
	metadata?: Record<string, unknown>,
): Promise<void> {
	if (!config.enabled) return;
	const entry: AuditLogEntry = {
		timestamp: getTimestamp(),
		event: "session_end",
		session_id: sessionId,
		metadata,
	};
	try {
		await appendEntry(config, entry);
	} catch {
		// Fail-open
	}
}

export async function logError(
	config: AuditLogConfig,
	error: string,
	context?: Record<string, unknown>,
	sessionId?: string,
): Promise<void> {
	if (!config.enabled) return;
	const entry: AuditLogEntry = {
		timestamp: getTimestamp(),
		event: "error",
		session_id: sessionId,
		metadata: { error: error ?? "", context },
	};
	try {
		await appendEntry(config, entry);
	} catch {
		// Fail-open
	}
}

export async function logConfigChange(
	config: AuditLogConfig,
	changes: Record<string, unknown>,
	sessionId?: string,
): Promise<void> {
	if (!config.enabled) return;
	const entry: AuditLogEntry = {
		timestamp: getTimestamp(),
		event: "config_change",
		session_id: sessionId,
		metadata: { changes },
	};
	try {
		await appendEntry(config, entry);
	} catch {
		// Fail-open
	}
}

export async function readAuditLog(config: AuditLogConfig, limit = 100): Promise<AuditLogEntry[]> {
	if (!config.enabled) return [];
	try {
		const content = await readFile(config.path, "utf-8");
		const lines = content.trim().split("\n").filter(Boolean);
		const entries: AuditLogEntry[] = [];
		for (let i = lines.length - 1; i >= 0 && entries.length < limit; i--) {
			try {
				const line = lines[i];
				if (line) {
					entries.push(JSON.parse(line) as AuditLogEntry);
				}
			} catch {
				// Skip invalid lines
			}
		}
		return entries.reverse();
	} catch {
		return [];
	}
}

export async function getAuditLogSize(config: AuditLogConfig): Promise<number> {
	try {
		const s = await stat(config.path);
		return s.size;
	} catch {
		return 0;
	}
}

export async function getAuditLogStats(config: AuditLogConfig): Promise<{
	entryCount: number;
	fileSize: number;
	firstEntry: Date | null;
	lastEntry: Date | null;
}> {
	const entries = await readAuditLog(config, Infinity);
	if (entries.length === 0) {
		return {
			entryCount: 0,
			fileSize: await getAuditLogSize(config),
			firstEntry: null,
			lastEntry: null,
		};
	}
	return {
		entryCount: entries.length,
		fileSize: await getAuditLogSize(config),
		firstEntry: entries.length > 0 ? new Date(entries[0]?.timestamp ?? Date.now()) : null,
		lastEntry:
			entries.length > 0 ? new Date(entries[entries.length - 1]?.timestamp ?? Date.now()) : null,
	};
}

export function withDefaults(overrides?: Partial<AuditLogConfig>): AuditLogConfig {
	return { ...DEFAULT_AUDIT_CONFIG, ...overrides };
}
