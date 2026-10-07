/**
 * Startup and session scan handlers for OpenClaw.
 * Thin wrappers over core's createScanHandler.
 */

import { createScanHandler as coreScanHandler, type Logger } from "@singularityrd/aidr-core";
import { getAidrVersion, getBundledDataDirs } from "./bundled-dirs.js";
import { discoverOpenClawPlugins } from "./plugin-discovery.js";

function createOpenClawScanHandler(
	logger: Logger,
	context: string,
	onResult?: (msg: string) => void,
): () => Promise<void> {
	const { threatsDir, allowlistsDir } = getBundledDataDirs();
	const version = getAidrVersion();

	return coreScanHandler({
		logger,
		context,
		discoverPlugins: () => discoverOpenClawPlugins(logger),
		selfPrefix: "@singularityrd/aidr-openclaw@",
		threatsDir,
		allowlistsDir,
		version,
		agentRuntime: "openclaw",
		onResult,
	});
}

export function createStartupScanHandler(
	logger: Logger,
	onResult?: (msg: string) => void,
): () => Promise<void> {
	return createOpenClawScanHandler(logger, "startup", onResult);
}

export function createSessionScanHandler(
	logger: Logger,
	onResult?: (msg: string) => void,
): () => Promise<void> {
	return createOpenClawScanHandler(logger, "session", onResult);
}

/** Undelivered session findings expire after this long. */
export const PENDING_FINDINGS_TTL_MS = 60 * 60 * 1000;
/** At most this many sessions keep undelivered findings; the oldest is dropped first. */
export const MAX_PENDING_FINDINGS_SESSIONS = 256;

/** The session an OpenClaw hook runs for (`ctx.sessionKey`, else `sessionId`). */
export function hookSessionKey(...sources: unknown[]): string | undefined {
	for (const source of sources) {
		if (!source || typeof source !== "object") continue;
		const record = source as { sessionKey?: unknown; sessionId?: unknown };
		for (const value of [record.sessionKey, record.sessionId]) {
			if (typeof value === "string" && value.trim() !== "") return value;
		}
	}
	return undefined;
}

/**
 * Plugin scan findings waiting to be surfaced, keyed by session: a
 * `session_start` scan is delivered to that session's next prompt only, never
 * to another session. Gateway-startup findings (no session) go to the next
 * prompt of any session. Bounded and expiring, so sessions that never prompt
 * cannot grow it.
 */
export class PendingScanFindings {
	private global: string | null = null;
	private readonly bySession = new Map<string, { message: string; at: number }>();

	constructor(private readonly now: () => number = Date.now) {}

	setGlobal(message: string): void {
		this.global = message;
	}

	set(sessionKey: string | undefined, message: string): void {
		if (sessionKey === undefined) {
			this.setGlobal(message);
			return;
		}
		this.prune();
		this.bySession.delete(sessionKey);
		this.bySession.set(sessionKey, { message, at: this.now() });
		while (this.bySession.size > MAX_PENDING_FINDINGS_SESSIONS) {
			const oldest = this.bySession.keys().next().value;
			if (oldest === undefined) break;
			this.bySession.delete(oldest);
		}
	}

	/** The findings for this session's prompt (plus any startup findings), removed on read. */
	take(sessionKey: string | undefined): string | null {
		this.prune();
		const parts: string[] = [];
		if (this.global) parts.push(this.global);
		this.global = null;
		if (sessionKey !== undefined) {
			const entry = this.bySession.get(sessionKey);
			this.bySession.delete(sessionKey);
			if (entry) parts.push(entry.message);
		}
		return parts.length > 0 ? parts.join("\n\n") : null;
	}

	get sessionCount(): number {
		this.prune();
		return this.bySession.size;
	}

	private prune(): void {
		const cutoff = this.now() - PENDING_FINDINGS_TTL_MS;
		for (const [key, entry] of this.bySession) {
			if (entry.at > cutoff) break; // insertion order is age order
			this.bySession.delete(key);
		}
	}
}

/**
 * Creates a before_prompt_build handler that surfaces plugin scan findings
 * as prepended context. One-shot: clears findings after first delivery.
 */
export function createBeforePromptBuildHandler(
	getFindings: () => string | null,
	clearFindings: () => void,
	logger: Logger,
): () => { prependContext: string } | undefined {
	return () => {
		const findings = getFindings();
		if (!findings) return undefined;

		clearFindings();
		logger.info("AIDR: surfacing plugin scan findings via before_prompt_build");

		const prependContext = [
			'<security-alert source="aidr-plugin-scan">',
			findings,
			"",
			"Inform the user about these security findings.",
			"</security-alert>",
		].join("\n");

		return { prependContext };
	};
}
