/**
 * Runaway guardrails for autonomous agents: loops, repeated failing calls,
 * tool-call rate spikes and optional per-session budgets.
 *
 * An autonomous agent that is stuck keeps doing the same thing — re-running the
 * same failing command, re-reading the same file, retrying an edit that never
 * applies — and one that has gone off the rails does a lot of it very fast. None
 * of those calls is dangerous on its own, so no per-call rule can see it. This
 * guard keeps a small per-session record (see `session-state-store.ts`) and,
 * when a threshold in `agent_safety.runaway` is exceeded, turns the call into an
 * `ask`: the session is paused until a human looks at it. It never denies.
 *
 * Every connector reaches it through `evaluateToolCall`, so Claude Code,
 * Cursor/VS Code, OpenClaw, OpenCode, Codex and the MCP gateway share it.
 * Repeated-failure detection additionally needs the host to report outcomes:
 * connectors that see them call {@link recordToolOutcome}.
 *
 * Failure policy (CLAUDE.md): this is a detection signal. When its state cannot
 * be read, written or trusted, the signal is skipped and logged, and an `allow`
 * verdict is marked `runaway_guard_unavailable` (audited) — never presented as
 * a clean check. Connector entry points stay fail-closed as before.
 *
 * Stored per session: counters, 20-hex-digit fingerprints of recent calls,
 * digests of written paths and timestamps. No command text, path or content.
 */

import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { AIDR_DIR, isInvalidConfig, loadConfig, resolvePath } from "../config.js";
import type { ToolEvaluationRequest } from "../evaluator.js";
import {
	SessionStateError,
	type SessionStateRecovery,
	SessionStateStore,
} from "../session-state-store.js";
import { normalizeToolEvaluationRequest, readFileEditPayload } from "../tool-normalization.js";
import { resolveFlowSessionKey } from "../toxic-flow.js";
import type { Config, Logger, RunawayConfig, Verdict } from "../types.js";
import { nullLogger } from "../types.js";

export const RUNAWAY_UNAVAILABLE_CATEGORY = "runaway_guard_unavailable";
export const RUNAWAY_CATEGORY = "agent_runaway";

/** Stable ids for the runaway signals (usable in `disabled_threats`). */
export const RUNAWAY_SIGNAL_IDS = {
	consecutiveIdentical: "CLT-AGENT-RUN-001",
	identicalInWindow: "CLT-AGENT-RUN-002",
	similarInWindow: "CLT-AGENT-RUN-003",
	repeatedFailures: "CLT-AGENT-RUN-004",
	rateSpike: "CLT-AGENT-RUN-005",
	toolCallBudget: "CLT-AGENT-RUN-006",
	sessionTimeBudget: "CLT-AGENT-RUN-007",
	filesWrittenBudget: "CLT-AGENT-RUN-008",
} as const;

/** Recent calls kept per session (enough for every configurable threshold). */
const MAX_RECENT = 1024;
const MAX_FAILURES = 256;
/** Distinct written files tracked; the budget is capped below this. */
const MAX_TRACKED_FILES = 2048;
const FINGERPRINT_HEX = 20;
/** Characters of a call that feed the near-identical fingerprint. */
const MAX_SHAPE_CHARS = 16 * 1024;
const MAX_STABLE_DEPTH = 32;
const RATE_WINDOW_MS = 60_000;

const WRITE_TOOLS: ReadonlySet<string> = new Set([
	"Write",
	"Edit",
	"MultiEdit",
	"Delete",
	"NotebookEdit",
]);

export interface RunawaySignal {
	id: string;
	reason: string;
}

export type RunawayOutcome =
	| { status: "disabled" }
	| { status: "checked"; signals: RunawaySignal[] }
	| { status: "unavailable"; reason: string };

/** Per-session record. Arrays are bounded; see the MAX_* constants. */
export interface RunawayState {
	startedAt: number;
	calls: number;
	/** Digests of distinct written file paths. */
	files: string[];
	/** `[timestampMs, exactFingerprint, similarFingerprint]`, oldest first. */
	recent: Array<[number, string, string]>;
	streakFp: string;
	streak: number;
	/** `[timestampMs, exactFingerprint]` of recorded failures since the last file edit. */
	failures: Array<[number, string]>;
}

export interface RunawayOptions {
	configPath?: string;
	/**
	 * Connector runtime. Sessions are keyed exactly like the toxic-flow session
	 * store (`resolveFlowSessionKey`), so a host that sends a generic placeholder
	 * id ("unknown", "codex-session") does not merge unrelated agents.
	 */
	agentRuntime?: string;
	logger?: Logger;
	now?: () => number;
}

const HEX = /^[0-9a-f]{1,64}$/;

function isTimestamp(value: unknown): value is number {
	return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function isCount(value: unknown): value is number {
	return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function isHex(value: unknown): value is string {
	return typeof value === "string" && HEX.test(value);
}

export function isRunawayState(value: unknown): value is RunawayState {
	if (typeof value !== "object" || value === null) return false;
	const state = value as Record<string, unknown>;
	return (
		isTimestamp(state.startedAt) &&
		isCount(state.calls) &&
		isCount(state.streak) &&
		typeof state.streakFp === "string" &&
		(state.streakFp === "" || isHex(state.streakFp)) &&
		Array.isArray(state.files) &&
		state.files.length <= MAX_TRACKED_FILES &&
		state.files.every(isHex) &&
		Array.isArray(state.recent) &&
		state.recent.length <= MAX_RECENT &&
		state.recent.every(
			(entry) =>
				Array.isArray(entry) &&
				entry.length === 3 &&
				isTimestamp(entry[0]) &&
				isHex(entry[1]) &&
				isHex(entry[2]),
		) &&
		Array.isArray(state.failures) &&
		state.failures.length <= MAX_FAILURES &&
		state.failures.every(
			(entry) =>
				Array.isArray(entry) && entry.length === 2 && isTimestamp(entry[0]) && isHex(entry[1]),
		)
	);
}

function hex(text: string): string {
	return createHash("sha256").update(text, "utf8").digest("hex").slice(0, FINGERPRINT_HEX);
}

/** JSON with sorted keys and AIDR's own normalization markers left out. */
function stableStringify(value: unknown, depth = 0): string {
	if (depth > MAX_STABLE_DEPTH) return '"…"';
	if (Array.isArray(value)) {
		return `[${value.map((item) => stableStringify(item, depth + 1)).join(",")}]`;
	}
	if (value && typeof value === "object") {
		const entries = Object.keys(value as Record<string, unknown>)
			.filter((key) => !key.startsWith("__aidr_"))
			.sort()
			.map(
				(key) =>
					`${JSON.stringify(key)}:${stableStringify((value as Record<string, unknown>)[key], depth + 1)}`,
			);
		return `{${entries.join(",")}}`;
	}
	return JSON.stringify(value) ?? "null";
}

/**
 * Two fingerprints of a (normalized) tool call: `exact` for the identical call,
 * `similar` for the same call with numbers, ids and whitespace ignored (a
 * polling loop with a changing counter, paging with a moving offset).
 */
export function toolCallFingerprints(
	toolName: string,
	toolInput: Record<string, unknown>,
): { exact: string; similar: string } {
	const canonical = stableStringify({ tool: toolName, input: toolInput });
	const shape = canonical
		.slice(0, MAX_SHAPE_CHARS)
		.toLowerCase()
		.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, "<id>")
		.replace(/\b[0-9a-f]{12,}\b/g, "<hex>")
		.replace(/\d+(?:\.\d+)?/g, "#")
		.replace(/\s+/g, " ");
	return { exact: hex(canonical), similar: hex(`shape:${shape}`) };
}

function stringField(input: Record<string, unknown>, keys: readonly string[]): string | undefined {
	for (const key of keys) {
		const value = input[key];
		if (typeof value === "string" && value.trim() !== "") return value;
	}
	return undefined;
}

/** Paths a (normalized) file-writing call touches; empty for any other call. */
export function writtenPaths(
	request: Pick<ToolEvaluationRequest, "toolName" | "toolInput">,
): string[] {
	if (!WRITE_TOOLS.has(request.toolName)) return [];
	const payload = readFileEditPayload(request.toolInput);
	if (payload.patch) {
		return [...new Set((payload.edits ?? []).map((edit) => edit.filePath).filter(Boolean))];
	}
	const path = stringField(request.toolInput, [
		"file_path",
		"notebook_path",
		"filePath",
		"path",
		"target_file",
	]);
	return path ? [path] : [];
}

/** Where the guard keeps its state: next to the active config (default `~/.singularity-aidr`). */
export function runawayStateDir(configPath?: string): string {
	const base = configPath ? dirname(resolvePath(configPath)) : resolvePath(AIDR_DIR);
	return resolve(join(base, "agent-safety"));
}

function runawayStore(
	settings: RunawayConfig,
	options: RunawayOptions,
): SessionStateStore<RunawayState> {
	return new SessionStateStore<RunawayState>(
		{
			dir: runawayStateDir(options.configPath),
			namespace: "runaway",
			ttlMs: settings.state_ttl_hours * 60 * 60 * 1000,
			maxSessions: settings.max_sessions,
			...(options.now ? { now: options.now } : {}),
		},
		isRunawayState,
	);
}

function freshState(now: number): RunawayState {
	return { startedAt: now, calls: 0, files: [], recent: [], streakFp: "", streak: 0, failures: [] };
}

function minutesLabel(ms: number): string {
	const minutes = Math.round(ms / 60_000);
	return `${minutes} minute${minutes === 1 ? "" : "s"}`;
}

/** Record one call and decide which thresholds it crosses. Pure. */
export function evaluateRunawayCall(
	current: RunawayState | undefined,
	call: { exact: string; similar: string; writtenFiles: string[] },
	now: number,
	settings: RunawayConfig,
	disabledIds: ReadonlySet<string> = new Set(),
): { next: RunawayState; signals: RunawaySignal[] } {
	const state = current ?? freshState(now);
	const windowMs = settings.window_seconds * 1000;
	const horizon = now - Math.max(windowMs, RATE_WINDOW_MS);
	const recent = state.recent.filter(([at]) => at > horizon);
	recent.push([now, call.exact, call.similar]);
	const files = [...state.files];
	for (const digest of call.writtenFiles) {
		if (!files.includes(digest) && files.length < MAX_TRACKED_FILES) files.push(digest);
	}
	// A file changed: running the same command again is the normal edit-and-retry
	// loop, not a stuck one.
	const failures =
		call.writtenFiles.length > 0 ? [] : state.failures.filter(([at]) => at > now - windowMs);
	const streak = state.streakFp === call.exact ? state.streak + 1 : 1;
	const next: RunawayState = {
		startedAt: state.startedAt,
		calls: state.calls + 1,
		files,
		recent: recent.slice(-MAX_RECENT),
		streakFp: call.exact,
		streak,
		failures,
	};

	const signals: RunawaySignal[] = [];
	const add = (id: string, reason: string): void => {
		if (!disabledIds.has(id)) signals.push({ id, reason });
	};
	const window = minutesLabel(windowMs);

	if (settings.max_tool_calls > 0 && next.calls > settings.max_tool_calls) {
		add(
			RUNAWAY_SIGNAL_IDS.toolCallBudget,
			`This session has made ${next.calls} tool calls, over its budget of ${settings.max_tool_calls}.`,
		);
	}
	const elapsed = now - next.startedAt;
	if (settings.max_session_minutes > 0 && elapsed > settings.max_session_minutes * 60_000) {
		add(
			RUNAWAY_SIGNAL_IDS.sessionTimeBudget,
			`This session has been running for ${minutesLabel(elapsed)}, over its budget of ${settings.max_session_minutes} minutes.`,
		);
	}
	if (
		settings.max_files_written > 0 &&
		call.writtenFiles.length > 0 &&
		files.length > settings.max_files_written
	) {
		add(
			RUNAWAY_SIGNAL_IDS.filesWrittenBudget,
			`This session has written ${files.length} distinct files, over its budget of ${settings.max_files_written}.`,
		);
	}
	const failed = failures.filter(([, fp]) => fp === call.exact).length;
	if (settings.max_repeated_failures > 0 && failed >= settings.max_repeated_failures) {
		add(
			RUNAWAY_SIGNAL_IDS.repeatedFailures,
			`This exact tool call already failed ${failed} times in the last ${window} with no file changed in between (limit ${settings.max_repeated_failures}); retrying it unchanged looks like a stuck loop.`,
		);
	}
	if (
		settings.max_consecutive_identical_calls > 0 &&
		streak > settings.max_consecutive_identical_calls
	) {
		add(
			RUNAWAY_SIGNAL_IDS.consecutiveIdentical,
			`The same tool call was repeated ${streak} times in a row (limit ${settings.max_consecutive_identical_calls}).`,
		);
	}
	const inWindow = next.recent.filter(([at]) => at > now - windowMs);
	const identical = inWindow.filter(([, exact]) => exact === call.exact).length;
	if (settings.max_identical_calls > 0 && identical > settings.max_identical_calls) {
		add(
			RUNAWAY_SIGNAL_IDS.identicalInWindow,
			`The same tool call was made ${identical} times in the last ${window} (limit ${settings.max_identical_calls}).`,
		);
	}
	const similar = inWindow.filter(([, , shape]) => shape === call.similar).length;
	if (settings.max_similar_calls > 0 && similar > settings.max_similar_calls) {
		add(
			RUNAWAY_SIGNAL_IDS.similarInWindow,
			`Near-identical tool calls (differing only in numbers, ids or spacing) were made ${similar} times in the last ${window} (limit ${settings.max_similar_calls}).`,
		);
	}
	const perMinute = next.recent.filter(([at]) => at > now - RATE_WINDOW_MS).length;
	if (settings.max_calls_per_minute > 0 && perMinute > settings.max_calls_per_minute) {
		add(
			RUNAWAY_SIGNAL_IDS.rateSpike,
			`${perMinute} tool calls in the last 60 seconds (limit ${settings.max_calls_per_minute}).`,
		);
	}
	return { next, signals };
}

function recoveryReason(recovered: SessionStateRecovery): string {
	switch (recovered) {
		case "integrity":
			return "failed its integrity check (possible tampering)";
		case "unsafe_path":
			return "was not a regular file (possible tampering)";
		default:
			return "was unreadable";
	}
}

function unavailable(
	logger: Logger,
	reason: string,
	detail: Record<string, unknown>,
): RunawayOutcome {
	logger.warn(`Runaway guard signal skipped: ${reason}`, detail);
	return {
		status: "unavailable",
		reason: `Runaway guard did not run for this call: ${reason}. Loop, rate and budget checks were NOT applied; this is not a clean result.`,
	};
}

/**
 * Record this call in its session and report the runaway thresholds it crosses.
 * Never throws.
 */
export async function checkRunaway(
	request: Pick<ToolEvaluationRequest, "sessionId" | "toolName" | "toolInput">,
	config: Config,
	options: RunawayOptions = {},
): Promise<RunawayOutcome> {
	const settings = config.agent_safety?.runaway;
	if (!settings?.enabled) return { status: "disabled" };
	const logger = options.logger ?? nullLogger;
	try {
		const fingerprints = toolCallFingerprints(request.toolName, request.toolInput);
		const writtenFiles = [...new Set(writtenPaths(request).map((path) => hex(`path:${path}`)))];
		const disabled = new Set(config.disabled_threats);
		const now = options.now ?? Date.now;
		const { result, recovered } = await runawayStore(settings, options).update(
			resolveFlowSessionKey(request.sessionId, options.agentRuntime, request.toolInput),
			(current) => {
				const { next, signals } = evaluateRunawayCall(
					current,
					{ ...fingerprints, writtenFiles },
					now(),
					settings,
					disabled,
				);
				return { next, result: signals };
			},
		);
		if (recovered) {
			return unavailable(logger, `its session state ${recoveryReason(recovered)} and was reset`, {
				recovered,
			});
		}
		return { status: "checked", signals: result };
	} catch (error) {
		const code = error instanceof SessionStateError ? error.code : "internal";
		return unavailable(logger, `its session state could not be used (${code})`, {
			errorType: error instanceof Error ? error.name : typeof error,
		});
	}
}

/** The `ask` verdict for crossed runaway thresholds. */
export function runawayVerdict(signals: readonly RunawaySignal[]): Verdict {
	return {
		decision: "ask",
		category: RUNAWAY_CATEGORY,
		confidence: 1,
		severity: "warning",
		source: "runaway_guard",
		artifacts: [],
		matchedThreatId: signals[0]?.id ?? null,
		// Hosts often show only the first reason, so each one names the cause.
		reasons: signals.map(
			(signal) => `Runaway guard paused this session for human review: ${signal.reason}`,
		),
	};
}

/**
 * Fold the runaway outcome into a verdict: a crossed threshold turns an `allow`
 * into an `ask` (deny and ask keep precedence, with the reasons added to an
 * ask); an unavailable guard marks an `allow` as not clean.
 */
export function applyRunawayOutcome(verdict: Verdict, outcome: RunawayOutcome): Verdict {
	if (outcome.status === "disabled") return verdict;
	if (outcome.status === "unavailable") {
		if (verdict.decision !== "allow") return verdict;
		return {
			...verdict,
			category: verdict.category === "none" ? RUNAWAY_UNAVAILABLE_CATEGORY : verdict.category,
			severity: verdict.severity === "info" ? "warning" : verdict.severity,
			reasons: [...verdict.reasons, outcome.reason],
		};
	}
	if (outcome.signals.length === 0) return verdict;
	if (verdict.decision === "allow") {
		const paused = runawayVerdict(outcome.signals);
		return verdict.delegation ? { ...paused, delegation: verdict.delegation } : paused;
	}
	if (verdict.decision === "ask") {
		const extra = runawayVerdict(outcome.signals).reasons.filter(
			(reason) => !verdict.reasons.includes(reason),
		);
		return { ...verdict, reasons: [...verdict.reasons, ...extra] };
	}
	return verdict;
}

/**
 * Report a finished tool call's outcome so a command that keeps failing
 * unchanged is recognised as a loop. Only failures are stored. Never throws;
 * returns what happened for diagnostics.
 */
export async function recordToolOutcome(
	event: {
		sessionId: string;
		toolName: string;
		toolInput: Record<string, unknown>;
		failed: boolean;
	},
	options: RunawayOptions = {},
): Promise<"recorded" | "skipped" | "unavailable"> {
	if (!event.failed) return "skipped";
	const logger = options.logger ?? nullLogger;
	try {
		const config = await loadConfig(options.configPath, logger);
		if (isInvalidConfig(config)) return "skipped";
		const settings = config.agent_safety.runaway;
		if (!settings.enabled || settings.max_repeated_failures === 0) return "skipped";
		const normalized = normalizeToolEvaluationRequest({
			sessionId: event.sessionId,
			toolName: event.toolName,
			toolInput: event.toolInput ?? {},
			artifacts: [],
		});
		const { exact } = toolCallFingerprints(normalized.toolName, normalized.toolInput);
		const now = options.now ?? Date.now;
		const windowMs = settings.window_seconds * 1000;
		const sessionKey = resolveFlowSessionKey(
			event.sessionId,
			options.agentRuntime,
			normalized.toolInput,
		);
		await runawayStore(settings, options).update(sessionKey, (current) => {
			const at = now();
			const state = current ?? freshState(at);
			const failures = state.failures.filter(([t]) => t > at - windowMs);
			failures.push([at, exact]);
			return { next: { ...state, failures: failures.slice(-MAX_FAILURES) }, result: undefined };
		});
		return "recorded";
	} catch (error) {
		logger.warn("Runaway guard could not record a tool failure", {
			errorType: error instanceof Error ? error.name : typeof error,
			code: error instanceof SessionStateError ? error.code : undefined,
		});
		return "unavailable";
	}
}
