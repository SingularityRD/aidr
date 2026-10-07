/**
 * Startup and session scan handlers for OpenCode.
 * Thin wrapper over core's createScanHandler.
 */

import { createHash } from "node:crypto";
import {
	createScanHandler as coreScanHandler,
	type Logger,
	type PluginInfo,
} from "@singularityrd/aidr-core";
import { getAidrVersion, getBundledDataDirs } from "./bundled-dirs.js";
import { discoverOpenCodePlugins } from "./plugin-discovery.js";

/** A cached session-scan result is reused for at most this long, even when nothing changed. */
export const SESSION_SCAN_CACHE_TTL_MS = 5 * 60 * 1000;
/** Undelivered findings for a session that never prompts are dropped after this long. */
export const PENDING_FINDINGS_TTL_MS = 60 * 60 * 1000;
/** At most this many sessions keep undelivered findings; the oldest is dropped first. */
export const MAX_PENDING_FINDINGS_SESSIONS = 256;

export function createSessionScanHandler(
	logger: Logger,
	projectDir?: string,
	onResult?: (msg: string) => void,
	discoverPlugins: () => Promise<PluginInfo[]> = () => discoverOpenCodePlugins(logger, projectDir),
): () => Promise<void> {
	const { threatsDir, allowlistsDir } = getBundledDataDirs();
	const version = getAidrVersion();

	return coreScanHandler({
		logger,
		context: "session",
		discoverPlugins,
		selfPrefix: "@singularityrd/aidr-opencode@",
		threatsDir,
		allowlistsDir,
		version,
		agentRuntime: "opencode",
		onResult,
	});
}

/** Identity of a plugin set: any install, update, removal or rule-version change alters it. */
export function pluginSetFingerprint(plugins: readonly PluginInfo[], version: string): string {
	const entries = plugins
		.map((plugin) => [plugin.key, plugin.version, plugin.lastUpdated, plugin.installPath])
		.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
	return createHash("sha256")
		.update(JSON.stringify([version, entries]))
		.digest("hex");
}

/**
 * A session scanner that reuses the last result while the discovered plugin set
 * (and the AIDR version) is unchanged and the result is younger than
 * {@link SESSION_SCAN_CACHE_TTL_MS}. Discovery still runs for every session, so
 * a newly installed or updated plugin is scanned immediately; only the full
 * content scan is skipped. A failed scan is never cached.
 */
export function createCachedSessionScanner(
	logger: Logger,
	projectDir?: string,
	options: {
		now?: () => number;
		discoverPlugins?: () => Promise<PluginInfo[]>;
	} = {},
): () => Promise<string | undefined> {
	const now = options.now ?? Date.now;
	const discover = options.discoverPlugins ?? (() => discoverOpenCodePlugins(logger, projectDir));
	const version = getAidrVersion();
	let cached: { fingerprint: string; message: string; at: number } | undefined;

	return async () => {
		let plugins: PluginInfo[] | undefined;
		try {
			plugins = await discover();
		} catch {
			plugins = undefined; // the full handler below reports the discovery failure
		}
		const fingerprint = plugins ? pluginSetFingerprint(plugins, version) : undefined;
		if (
			cached &&
			fingerprint !== undefined &&
			cached.fingerprint === fingerprint &&
			now() - cached.at < SESSION_SCAN_CACHE_TTL_MS
		) {
			return cached.message;
		}
		let message: string | undefined;
		await createSessionScanHandler(
			logger,
			projectDir,
			(msg) => {
				message = msg;
			},
			plugins ? async () => plugins : discover,
		)();
		if (message !== undefined && fingerprint !== undefined) {
			cached = { fingerprint, message, at: now() };
		}
		return message;
	};
}

/**
 * One-shot scan findings waiting for a session's first prompt. Bounded: an
 * entry expires after {@link PENDING_FINDINGS_TTL_MS} and at most
 * {@link MAX_PENDING_FINDINGS_SESSIONS} sessions are kept, so sessions that
 * are created but never prompted cannot grow the map without limit.
 */
export class PendingSessionFindings {
	private readonly entries = new Map<string, { message: string; at: number }>();

	constructor(private readonly now: () => number = Date.now) {}

	get size(): number {
		this.prune();
		return this.entries.size;
	}

	set(sessionId: string, message: string): void {
		this.prune();
		this.entries.delete(sessionId);
		this.entries.set(sessionId, { message, at: this.now() });
		while (this.entries.size > MAX_PENDING_FINDINGS_SESSIONS) {
			const oldest = this.entries.keys().next().value;
			if (oldest === undefined) break;
			this.entries.delete(oldest);
		}
	}

	/** The pending findings for a session, removed on read. */
	take(sessionId: string): string | undefined {
		this.prune();
		const entry = this.entries.get(sessionId);
		this.entries.delete(sessionId);
		return entry?.message;
	}

	private prune(): void {
		const cutoff = this.now() - PENDING_FINDINGS_TTL_MS;
		for (const [sessionId, entry] of this.entries) {
			if (entry.at > cutoff) break; // insertion order is age order
			this.entries.delete(sessionId);
		}
	}
}
