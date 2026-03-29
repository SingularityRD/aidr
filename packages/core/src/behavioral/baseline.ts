/**
 * User behavior baseline storage using SQLite.
 * Tracks command frequency, file access patterns, tool usage, and temporal patterns.
 */

import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { resolvePath, AIDR_DIR } from "../config.js";
import type { Logger } from "../types.js";
import { nullLogger } from "../types.js";

export interface CommandHistoryEntry {
	id?: number;
	userId: string;
	commandHash: string;
	timestamp: number;
	context: string;
}

export interface UserBaseline {
	userId: string;
	commandFrequency: number; // commands per hour
	fileAccessPattern: string; // JSON string of pattern data
	toolUsage: string; // JSON string of tool usage stats
	updatedAt: number;
}

export interface BaselineStats {
	avgCommandsPerHour: number;
	peakHourCommands: number;
	offHoursCommands: number;
	commonDirectories: string[];
	toolDistribution: Record<string, number>;
	typicalHours: number[];
}

// SQLite table schema (for reference):
// CREATE TABLE command_history (
//   id INTEGER PRIMARY KEY,
//   user_id TEXT,
//   command_hash TEXT,
//   timestamp INTEGER,
//   context TEXT
// );
// CREATE TABLE user_baselines (
//   user_id TEXT PRIMARY KEY,
//   command_frequency REAL,
//   file_access_pattern TEXT,
//   tool_usage TEXT,
//   updated_at INTEGER
// );

export class BaselineStore {
	private dbPath: string;
	private logger: Logger;
	private db: {
		exec: (sql: string) => void;
		prepare: (sql: string) => { run: (...args: unknown[]) => void; all: (...args: unknown[]) => unknown[] };
		close: () => void;
	} | null = null;
	private writeQueue: Array<() => Promise<void>> = [];
	private flushInterval: ReturnType<typeof setInterval> | null = null;

	constructor(options?: { dbPath?: string; logger?: Logger }) {
		this.dbPath = resolvePath(options?.dbPath ?? join(AIDR_DIR, "behavioral.db"));
		this.logger = options?.logger ?? nullLogger;
	}

	async initialize(): Promise<void> {
		await mkdir(dirname(this.dbPath), { recursive: true });

		// Dynamic import of node:sqlite (optional dependency)
		const sqlite = (await import("node:sqlite")) as unknown as {
			DatabaseSync: new (path: string) => {
				exec: (sql: string) => void;
				prepare: (sql: string) => { run: (...args: unknown[]) => void; all: (...args: unknown[]) => unknown[] };
				close: () => void;
			};
		};

		this.db = new sqlite.DatabaseSync(this.dbPath);
		this.createTables();
		this.startFlushInterval();
		this.logger.debug("BaselineStore initialized", { dbPath: this.dbPath });
	}

	private createTables(): void {
		if (!this.db) return;

		this.db.exec(`
			CREATE TABLE IF NOT EXISTS command_history (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id TEXT NOT NULL,
				command_hash TEXT NOT NULL,
				timestamp INTEGER NOT NULL,
				context TEXT
			);
		`);

		this.db.exec(`
			CREATE TABLE IF NOT EXISTS user_baselines (
				user_id TEXT PRIMARY KEY,
				command_frequency REAL DEFAULT 0,
				file_access_pattern TEXT DEFAULT '{}',
				tool_usage TEXT DEFAULT '{}',
				updated_at INTEGER DEFAULT 0
			);
		`);

		// Indexes for performance
		this.db.exec(`CREATE INDEX IF NOT EXISTS idx_cmd_history_user_time ON command_history(user_id, timestamp);`);
		this.db.exec(`CREATE INDEX IF NOT EXISTS idx_cmd_history_hash ON command_history(command_hash);`);

		// 10MB retention: keep ~7 days of data (prune older entries)
		this.pruneOldHistory();
	}

	private pruneOldHistory(): void {
		if (!this.db) return;
		const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
		this.db.prepare("DELETE FROM command_history WHERE timestamp < ?").run(sevenDaysAgo);
	}

	private startFlushInterval(): void {
		// Flush batched writes every 5 seconds
		this.flushInterval = setInterval(() => {
			this.flushWrites();
		}, 5000);
	}

	private async flushWrites(): Promise<void> {
		while (this.writeQueue.length > 0) {
			const write = this.writeQueue.shift();
			if (write) {
				try {
					await write();
				} catch (err) {
					this.logger.debug("Baseline write error", { error: String(err) });
				}
			}
		}
	}

	queueWrite(writeFn: () => Promise<void>): void {
		this.writeQueue.push(writeFn);
	}

	async recordCommand(userId: string, commandHash: string, context: string): Promise<void> {
		if (!this.db) return;

		const timestamp = Date.now();
		this.queueWrite(async () => {
			if (!this.db) return;
			this.db
				.prepare("INSERT INTO command_history (user_id, command_hash, timestamp, context) VALUES (?, ?, ?, ?)")
				.run(userId, commandHash, timestamp, context);
		});
	}

	async getCommandHistory(userId: string, hours: number): Promise<CommandHistoryEntry[]> {
		if (!this.db) return [];

		const since = Date.now() - hours * 60 * 60 * 1000;
		const rows = this.db
			.prepare("SELECT * FROM command_history WHERE user_id = ? AND timestamp > ? ORDER BY timestamp DESC")
			.all(userId, since) as Array<{
			id: number;
			user_id: string;
			command_hash: string;
			timestamp: number;
			context: string;
		}>;

		return rows.map((r) => ({
			id: r.id,
			userId: r.user_id,
			commandHash: r.command_hash,
			timestamp: r.timestamp,
			context: r.context,
		}));
	}

	async updateUserBaseline(userId: string, baseline: Partial<UserBaseline>): Promise<void> {
		if (!this.db) return;

		const existing = this.db
			.prepare("SELECT * FROM user_baselines WHERE user_id = ?")
			.all(userId) as Array<{
			user_id: string;
			command_frequency: number;
			file_access_pattern: string;
			tool_usage: string;
			updated_at: number;
		}>;

		if (existing.length === 0) {
			this.db
				.prepare(
					"INSERT INTO user_baselines (user_id, command_frequency, file_access_pattern, tool_usage, updated_at) VALUES (?, ?, ?, ?, ?)",
				)
				.run(
					userId,
					baseline.commandFrequency ?? 0,
					baseline.fileAccessPattern ?? "{}",
					baseline.toolUsage ?? "{}",
					Date.now(),
				);
		} else {
			const current = existing[0];
			if (!current) return;
			this.db
				.prepare(
					"UPDATE user_baselines SET command_frequency = ?, file_access_pattern = ?, tool_usage = ?, updated_at = ? WHERE user_id = ?",
				)
				.run(
					baseline.commandFrequency ?? current.command_frequency ?? 0,
					baseline.fileAccessPattern ?? current.file_access_pattern ?? "{}",
					baseline.toolUsage ?? current.tool_usage ?? "{}",
					Date.now(),
					userId,
				);
		}
	}

	async getUserBaseline(userId: string): Promise<UserBaseline | null> {
		if (!this.db) return null;

		const rows = this.db
			.prepare("SELECT * FROM user_baselines WHERE user_id = ?")
			.all(userId) as Array<{
			user_id: string;
			command_frequency: number;
			file_access_pattern: string;
			tool_usage: string;
			updated_at: number;
		}>;

		if (rows.length === 0) return null;

		const r = rows[0];
		if (!r) return null;
		return {
			userId: r.user_id,
			commandFrequency: r.command_frequency,
			fileAccessPattern: r.file_access_pattern,
			toolUsage: r.tool_usage,
			updatedAt: r.updated_at,
		};
	}

	async computeBaselineStats(userId: string, hours: number = 168): Promise<BaselineStats | null> {
		if (!this.db) return null;

		const since = Date.now() - hours * 60 * 60 * 1000;
		const rows = this.db
			.prepare("SELECT * FROM command_history WHERE user_id = ? AND timestamp > ?")
			.all(userId, since) as Array<{ context: string; timestamp: number }>;

		if (rows.length === 0) return null;

		// Compute hourly distribution
		const hourlyCounts = new Array(24).fill(0);
		const toolCounts: Record<string, number> = {};
		const dirCounts: Record<string, number> = {};

		for (const row of rows) {
			const date = new Date(row.timestamp);
			hourlyCounts[date.getHours()]++;

			// Parse context for tool and directory info
			try {
				const ctx = JSON.parse(row.context) as {
					tool?: string;
					directory?: string;
				};
				if (ctx.tool) {
					toolCounts[ctx.tool] = (toolCounts[ctx.tool] || 0) + 1;
				}
				if (ctx.directory) {
					dirCounts[ctx.directory] = (dirCounts[ctx.directory] || 0) + 1;
				}
			} catch {
				// Ignore parse errors
			}
		}

		const totalHours = hours;
		const avgCommandsPerHour = rows.length / totalHours;
		const peakHourCommands = Math.max(...hourlyCounts);
		const offHoursCommands = hourlyCounts.slice(0, 6).reduce((a, b) => a + b, 0) +
			hourlyCounts.slice(23, 24).reduce((a, b) => a + b, 0);

		// Get typical hours (hours with above-average activity)
		const avgPerHour = rows.length / 24;
		const typicalHours = hourlyCounts
			.map((count, hour) => ({ count, hour }))
			.filter((h) => h.count > avgPerHour)
			.map((h) => h.hour);

		// Get most common directories
		const commonDirectories = Object.entries(dirCounts)
			.sort((a, b) => b[1] - a[1])
			.slice(0, 5)
			.map(([dir]) => dir);

		return {
			avgCommandsPerHour,
			peakHourCommands,
			offHoursCommands,
			commonDirectories,
			toolDistribution: toolCounts,
			typicalHours,
		};
	}

	async close(): Promise<void> {
		if (this.flushInterval) {
			clearInterval(this.flushInterval);
		}
		await this.flushWrites();
		if (this.db) {
			this.db.close();
			this.db = null;
		}
	}
}

// Singleton instance for global use
let globalBaselineStore: BaselineStore | null = null;

export async function getBaselineStore(logger?: Logger): Promise<BaselineStore> {
	if (!globalBaselineStore) {
		globalBaselineStore = new BaselineStore({ logger });
		await globalBaselineStore.initialize();
	}
	return globalBaselineStore;
}

export function resetBaselineStore(): void {
	globalBaselineStore = null;
}
