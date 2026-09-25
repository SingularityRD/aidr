/**
 * Toxic-flow ("lethal trifecta") and behavioral chain detection across a session.
 *
 * Single-call rules judge each tool call on its own. Many real attacks are only
 * visible as a sequence: the agent reads a credential, later fetches a web page
 * carrying an injected instruction, then sends "a summary" somewhere. Each step
 * is ordinary; the combination is exfiltration. This module keeps a small,
 * bounded, integrity-protected record per agent session of which capabilities
 * the session has already exercised and flags the call that would complete a
 * dangerous combination:
 *
 *   - `lethal_trifecta`       private data + untrusted content + external
 *                             communication in one session window
 *   - `exfil_chain`           secret material read, then an egress that carries data
 *   - `injection_to_action`   untrusted content, then a destructive command
 *   - `bulk_sensitive_access` many distinct sensitive files/credential stores in the window
 *
 * See docs/toxic-flow.md for the model and docs/configuration.md (`toxic_flow`).
 *
 * ## Failure policy
 *
 * This is a detection internal. A state file that cannot be read or written is
 * a skipped signal: the call is evaluated by every other layer, the failure is
 * logged, and an `allow` is marked `toxic_flow_unavailable` so it is never
 * mistaken for a clean result. A state file that fails its integrity check is
 * NOT skipped: it is treated as a tampering signal, and the session is assumed
 * to have exercised all three capabilities for the rest of the window, so the
 * next egress needs approval.
 *
 * ## Tamper resistance
 *
 * State lives in `~/.singularity-aidr/session-flow/`, which self-defense rule
 * CLT-SELF-008 blocks the agent from reading, listing or writing. Every state
 * file also carries an HMAC-SHA256 under a per-install key kept next to it with
 * owner-only permissions, and binds its own session digest, so a hand-edited,
 * truncated or swapped file fails verification. Like the operator approval
 * store this is not a boundary against arbitrary code running as the same OS
 * user; it makes tampering detectable and turns it into a stricter posture
 * instead of a clean slate.
 *
 * ## Cost
 *
 * Classification is pure and runs on every call. The state file (one small JSON
 * document per session, at most {@link MAX_STEPS} steps) is only read when the
 * call contributes a capability, reads a file or runs a destructive command, and
 * only written when the session's record changes.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { constants as fsConstants, type Stats } from "node:fs";
import { lstat, mkdir, open, readdir, stat, unlink, utimes } from "node:fs/promises";
import { join } from "node:path";
import { isInvalidConfig, loadConfig, resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import {
	capabilityLabel,
	classifyToolCallFlow,
	DEFAULT_TOXIC_FLOW_TRUSTED_DOMAINS,
	type FlowCapability,
	type FlowClassification,
	type FlowKind,
	type FlowObservation,
	pathWithinDownload,
} from "./toxic-flow-classify.js";
import type { Artifact, Config, Logger, Verdict } from "./types.js";
import { nullLogger } from "./types.js";

// ── Constants ──────────────────────────────────────────────────────

export const TOXIC_FLOW_STATE_DIR = "~/.singularity-aidr/session-flow";
/** Most recent steps kept per session. */
export const MAX_STEPS = 64;
const MAX_DOWNLOADS = 32;
const MAX_STATE_BYTES = 256 * 1024;
const MAX_SESSION_FILES = 512;
const PRUNE_INTERVAL_MS = 10 * 60 * 1000;
const LOCK_WAIT_MS = 400;
const LOCK_STALE_MS = 5_000;
/** A repeated identical step only refreshes its timestamp after this long. */
const STEP_REFRESH_MS = 60 * 1000;
const MAC_DOMAIN = "singularity-aidr/session-flow/v1";
const KEY_FILE = ".flow-key";
const PRUNE_MARKER = ".last-prune";
const STATE_VERSION = 1;
const MAX_EARLIER_STEPS_IN_REASON = 4;

export type ToxicFlowChain =
	| "lethal_trifecta"
	| "exfil_chain"
	| "injection_to_action"
	| "bulk_sensitive_access";

/** Stable identifiers, used as `matchedThreatId` on toxic-flow verdicts. */
export const TOXIC_FLOW_THREAT_IDS: Readonly<Record<ToxicFlowChain, string>> = {
	lethal_trifecta: "AIDR-FLOW-001",
	exfil_chain: "AIDR-FLOW-002",
	injection_to_action: "AIDR-FLOW-003",
	bulk_sensitive_access: "AIDR-FLOW-004",
};

const CHAIN_PRECEDENCE: readonly ToxicFlowChain[] = [
	"exfil_chain",
	"lethal_trifecta",
	"injection_to_action",
	"bulk_sensitive_access",
];

// ── Settings ───────────────────────────────────────────────────────

export type ToxicFlowAction = "auto" | "ask" | "deny" | "monitor";

export interface ToxicFlowSettings {
	enabled: boolean;
	action: ToxicFlowAction;
	windowMs: number;
	bulkThreshold: number;
	trustedDomains: string[];
	trustedMcpServers: string[];
	trustedGitRemotes: string[];
}

/** Read `toxic_flow` defensively: a partial or mocked config means the defaults. */
export function resolveToxicFlowSettings(config: Partial<Config> | undefined): ToxicFlowSettings {
	const raw = (config?.toxic_flow ?? {}) as Partial<NonNullable<Config["toxic_flow"]>>;
	const window = Number(raw.window_minutes ?? 60);
	const threshold = Number(raw.bulk_sensitive_threshold ?? 5);
	const mcpAllow = config?.policy?.mcp?.allow_servers ?? [];
	return {
		enabled: raw.enabled !== false,
		action: raw.action ?? "auto",
		windowMs: (Number.isFinite(window) && window > 0 ? Math.min(window, 1440) : 60) * 60_000,
		bulkThreshold: Number.isFinite(threshold) && threshold >= 2 ? Math.min(threshold, 64) : 5,
		trustedDomains: [...DEFAULT_TOXIC_FLOW_TRUSTED_DOMAINS, ...(raw.trusted_domains ?? [])],
		trustedMcpServers: [...(raw.trusted_mcp_servers ?? []), ...mcpAllow],
		trustedGitRemotes: raw.trusted_git_remotes ?? ["origin"],
	};
}

function effectiveAction(
	settings: ToxicFlowSettings,
	config: Partial<Config>,
): "ask" | "deny" | "monitor" {
	if (settings.action !== "auto") return settings.action;
	return config.sensitivity === "paranoid" ? "deny" : "ask";
}

// ── State ──────────────────────────────────────────────────────────

export interface FlowStep {
	/** Epoch milliseconds. */
	t: number;
	cap: FlowCapability;
	kind: FlowKind;
	tool: string;
	summary: string;
	/** Truncated digest of the target identity, never the target itself. */
	target: string;
	secret?: boolean;
	data?: boolean;
}

export interface SessionFlowState {
	v: typeof STATE_VERSION;
	/** Digest of the session key this record belongs to. */
	sid: string;
	created: number;
	updated: number;
	steps: FlowStep[];
	downloads: Array<{ p: string; t: number }>;
	/** Set when an earlier record failed its integrity check. */
	integrity?: "lost";
}

export function emptySessionFlowState(sid: string, now: number): SessionFlowState {
	return { v: STATE_VERSION, sid, created: now, updated: now, steps: [], downloads: [] };
}

const CAPABILITIES: readonly FlowCapability[] = [
	"private_data",
	"untrusted_content",
	"external_comm",
];

/**
 * The conservative record that replaces one that failed verification: every
 * capability is assumed to have been exercised, so the rest of the window
 * requires approval for egress instead of starting from a clean slate.
 */
function integrityLostState(sid: string, now: number): SessionFlowState {
	return {
		...emptySessionFlowState(sid, now),
		integrity: "lost",
		steps: CAPABILITIES.map((cap) => ({
			t: now,
			cap,
			kind: "integrity_lost" as const,
			tool: "aidr",
			summary: "earlier session history failed its integrity check",
			target: `integrity:${cap}`,
			...(cap === "private_data" ? { secret: true } : {}),
			...(cap === "external_comm" ? { data: true } : {}),
		})),
	};
}

function targetDigest(target: string): string {
	return createHash("sha256").update(`flow-target\0${target}`).digest("hex").slice(0, 16);
}

export function sessionDigest(sessionKey: string): string {
	return createHash("sha256")
		.update(`${MAC_DOMAIN}\0session\0${sessionKey}`)
		.digest("hex")
		.slice(0, 40);
}

const GENERIC_SESSION_IDS = new Set([
	"",
	"unknown",
	"default",
	"session",
	"cursor",
	"vscode",
	"codex-session",
	"none",
	"null",
	"undefined",
]);

/**
 * The key a session's record is stored under.
 *
 * Connectors pass the host's session/conversation id. When a host provides none
 * (the connector falls back to a generic placeholder), the key is derived from
 * the connector, the parent process (the agent host that spawned the hook, or
 * the host process itself for in-process plugins) and the process working
 * directory, so two unrelated agents never share a record and one agent keeps a
 * stable one. Nothing in the tool call's own arguments takes part: a `cwd`
 * argument is chosen by the model, and letting it pick the key would let each
 * step of a chain land in a fresh, empty session.
 */
export function resolveFlowSessionKey(
	sessionId: string | undefined,
	agentRuntime: string | undefined,
): string {
	const runtime = agentRuntime ?? "agent";
	const id = typeof sessionId === "string" ? sessionId.trim() : "";
	if (!GENERIC_SESSION_IDS.has(id.toLowerCase())) return `sid:${runtime}:${id}`;
	return `derived:${runtime}:${process.ppid}:${process.cwd()}`;
}

// ── Pure evaluation ────────────────────────────────────────────────

export interface ToxicFlowFinding {
	chain: ToxicFlowChain;
	threatId: string;
	severity: "warning" | "critical";
	reason: string;
	/** Every chain this call matched, strongest first. */
	chains: ToxicFlowChain[];
	earlier: FlowStep[];
}

export interface FlowCallInput {
	tool: string;
	classification: FlowClassification;
}

export interface FlowEvaluation {
	finding: ToxicFlowFinding | null;
	/** Observations this call contributes (including reads of earlier downloads). */
	observations: FlowObservation[];
}

function withinWindow(state: SessionFlowState, windowMs: number, now: number): FlowStep[] {
	return state.steps.filter((step) => now - step.t <= windowMs && step.t <= now + 60_000);
}

function formatAge(ms: number): string {
	const minutes = Math.floor(Math.max(0, ms) / 60_000);
	if (minutes < 1) return "<1m ago";
	if (minutes < 120) return `${minutes}m ago`;
	return `${Math.floor(minutes / 60)}h ago`;
}

function describeStep(step: FlowStep, now: number): string {
	return `[${capabilityLabel(step.cap)}] ${step.tool}: ${step.summary} (${formatAge(now - step.t)})`;
}

function describeObservation(tool: string, observation: FlowObservation): string {
	return `[${capabilityLabel(observation.cap)}] ${tool}: ${observation.summary}`;
}

function latest(steps: FlowStep[], predicate: (step: FlowStep) => boolean, count = 1): FlowStep[] {
	const matching = steps.filter(predicate).sort((a, b) => b.t - a.t);
	return matching.slice(0, count);
}

function uniqueSteps(steps: FlowStep[]): FlowStep[] {
	const seen = new Set<FlowStep>();
	return steps.filter((step) => (seen.has(step) ? false : (seen.add(step), true)));
}

/** Observations for reads of files this session downloaded earlier (or in this call). */
function downloadedReads(
	classification: FlowClassification,
	state: SessionFlowState,
	windowMs: number,
	now: number,
): FlowObservation[] {
	const downloads = [
		...state.downloads.filter((entry) => now - entry.t <= windowMs).map((entry) => entry.p),
		...classification.downloads,
	];
	if (downloads.length === 0) return [];
	const out: FlowObservation[] = [];
	for (const read of classification.reads) {
		const match = downloads.find((download) => pathWithinDownload(read, download));
		if (!match) continue;
		out.push({
			cap: "untrusted_content",
			kind: "downloaded_file",
			summary: `reads ${match} (downloaded this session)`.slice(0, 96),
			target: `download:${match}`,
		});
		if (out.length >= 4) break;
	}
	return out;
}

/**
 * Decide whether this call completes a toxic flow, given the session record.
 *
 * Pure: it never mutates `state` and never touches the filesystem, so it is
 * cheap enough to run on every call and easy to test exhaustively.
 */
export function evaluateToxicFlow(
	state: SessionFlowState,
	call: FlowCallInput,
	settings: Pick<ToxicFlowSettings, "windowMs" | "bulkThreshold">,
	now: number,
): FlowEvaluation {
	const prior = withinWindow(state, settings.windowMs, now);
	const observations = [
		...call.classification.observations,
		...downloadedReads(call.classification, state, settings.windowMs, now),
	];
	const callCaps = new Set(observations.map((observation) => observation.cap));
	const priorCaps = new Set(prior.map((step) => step.cap));
	const matched = new Map<ToxicFlowChain, { earlier: FlowStep[]; current: string[] }>();

	// exfil_chain: secret-grade material read (earlier or in this call), then an
	// egress that carries data.
	const dataEgress = observations.filter((o) => o.cap === "external_comm" && o.carriesData);
	if (dataEgress.length > 0) {
		const priorSecrets = latest(
			prior,
			(step) => step.cap === "private_data" && step.secret === true,
			2,
		);
		const callSecrets = observations.filter((o) => o.cap === "private_data" && o.secret);
		if (priorSecrets.length > 0 || callSecrets.length > 0) {
			matched.set("exfil_chain", {
				earlier: priorSecrets,
				current: [...callSecrets, ...dataEgress].map((o) => describeObservation(call.tool, o)),
			});
		}
	}

	// lethal_trifecta: all three capabilities, and this call either completes the
	// set for the first time or is itself the external-communication leg.
	const union = new Set([...priorCaps, ...callCaps]);
	const completes = [...callCaps].some((cap) => !priorCaps.has(cap));
	if (union.size === 3 && callCaps.size > 0 && (completes || callCaps.has("external_comm"))) {
		const earlier = CAPABILITIES.flatMap((cap) => latest(prior, (step) => step.cap === cap));
		matched.set("lethal_trifecta", {
			earlier,
			current: observations.map((o) => describeObservation(call.tool, o)),
		});
	}

	// injection_to_action: untrusted content, then a destructive command.
	if (call.classification.destructive) {
		const untrusted = latest(prior, (step) => step.cap === "untrusted_content", 2);
		const callUntrusted = observations.filter((o) => o.cap === "untrusted_content");
		if (untrusted.length > 0 || callUntrusted.length > 0) {
			matched.set("injection_to_action", {
				earlier: untrusted,
				current: [
					...callUntrusted.map((o) => describeObservation(call.tool, o)),
					`[destructive] ${call.tool}: ${call.classification.destructive}`,
				],
			});
		}
	}

	// bulk_sensitive_access: distinct sensitive targets within the window.
	const callPrivate = observations.filter((o) => o.cap === "private_data");
	if (callPrivate.length > 0) {
		const priorTargets = new Set(
			prior.filter((s) => s.cap === "private_data").map((s) => s.target),
		);
		const callTargets = callPrivate.map((o) => targetDigest(o.target));
		const fresh = callTargets.filter((target) => !priorTargets.has(target));
		const distinct = new Set([...priorTargets, ...callTargets]);
		if (fresh.length > 0 && distinct.size >= settings.bulkThreshold) {
			matched.set("bulk_sensitive_access", {
				earlier: latest(prior, (step) => step.cap === "private_data", MAX_EARLIER_STEPS_IN_REASON),
				current: callPrivate.map((o) => describeObservation(call.tool, o)),
			});
		}
	}

	if (matched.size === 0) return { finding: null, observations };

	const chains = CHAIN_PRECEDENCE.filter((chain) => matched.has(chain));
	const chain = chains[0] as ToxicFlowChain;
	const detail = matched.get(chain) as { earlier: FlowStep[]; current: string[] };
	const earlier = uniqueSteps(detail.earlier).slice(0, MAX_EARLIER_STEPS_IN_REASON);
	const windowMinutes = Math.round(settings.windowMs / 60_000);
	const headline: Record<ToxicFlowChain, string> = {
		exfil_chain:
			"this call sends data to an external destination after secret material was read in this session",
		lethal_trifecta:
			"this call would complete private-data access, untrusted-content exposure and external communication in one session",
		injection_to_action: "destructive command after untrusted content entered this session",
		bulk_sensitive_access: `${
			new Set([
				...prior.filter((s) => s.cap === "private_data").map((s) => s.target),
				...callPrivate.map((o) => targetDigest(o.target)),
			]).size
		} distinct sensitive files or credential stores accessed within ${windowMinutes} minutes (threshold ${settings.bulkThreshold})`,
	};
	const parts = [
		`Toxic flow "${chain}": ${headline[chain]}.`,
		earlier.length > 0
			? `Earlier steps: ${earlier.map((step) => describeStep(step, now)).join("; ")}.`
			: "Earlier steps: none (the whole chain is in this call).",
		`This call: ${detail.current.slice(0, 4).join("; ")}.`,
	];
	if (chains.length > 1) parts.push(`Also matched: ${chains.slice(1).join(", ")}.`);
	if (state.integrity === "lost") {
		parts.push(
			"The session's earlier flow record failed its integrity check and was reset conservatively.",
		);
	}
	return {
		finding: {
			chain,
			threatId: TOXIC_FLOW_THREAT_IDS[chain],
			severity: chain === "exfil_chain" || chain === "lethal_trifecta" ? "critical" : "warning",
			reason: parts.join(" "),
			chains,
			earlier,
		},
		observations,
	};
}

/**
 * Add this call's observations and downloads to a session record.
 *
 * Returns null when nothing changed, so the caller can skip the write. Identical
 * steps are merged (their timestamp refreshed at most once a minute), expired
 * steps dropped and the record capped at {@link MAX_STEPS}.
 */
export function recordFlowObservations(
	state: SessionFlowState,
	tool: string,
	observations: readonly FlowObservation[],
	downloads: readonly string[],
	settings: Pick<ToxicFlowSettings, "windowMs">,
	now: number,
): SessionFlowState | null {
	const steps = withinWindow(state, settings.windowMs, now).map((step) => ({ ...step }));
	let changed = steps.length !== state.steps.length;
	for (const observation of observations) {
		const target = targetDigest(observation.target);
		const existing = steps.find(
			(step) =>
				step.cap === observation.cap && step.kind === observation.kind && step.target === target,
		);
		if (existing) {
			if (now - existing.t >= STEP_REFRESH_MS) {
				existing.t = now;
				changed = true;
			}
			if (observation.carriesData && !existing.data) {
				existing.data = true;
				changed = true;
			}
			continue;
		}
		steps.push({
			t: now,
			cap: observation.cap,
			kind: observation.kind,
			tool: tool.slice(0, 64),
			summary: observation.summary.slice(0, 96),
			target,
			...(observation.secret ? { secret: true } : {}),
			...(observation.carriesData ? { data: true } : {}),
		});
		changed = true;
	}
	const liveDownloads = state.downloads.filter((entry) => now - entry.t <= settings.windowMs);
	if (liveDownloads.length !== state.downloads.length) changed = true;
	for (const path of downloads) {
		const existing = liveDownloads.find((entry) => entry.p === path);
		if (existing) {
			if (now - existing.t >= STEP_REFRESH_MS) {
				existing.t = now;
				changed = true;
			}
			continue;
		}
		liveDownloads.push({ p: path.slice(0, 512), t: now });
		changed = true;
	}
	if (!changed) return null;
	steps.sort((a, b) => a.t - b.t);
	liveDownloads.sort((a, b) => a.t - b.t);
	return {
		...state,
		updated: now,
		steps: steps.slice(-MAX_STEPS),
		downloads: liveDownloads.slice(-MAX_DOWNLOADS),
	};
}

// ── Integrity-protected store ──────────────────────────────────────

export class ToxicFlowStateUnavailableError extends Error {
	constructor(reason: string) {
		super(reason);
		this.name = "ToxicFlowStateUnavailableError";
	}
}

export type SessionFlowLoadStatus = "new" | "ok" | "tampered";

const keyCache = new Map<string, Buffer>();

function isErrno(error: unknown, code: string): boolean {
	return (error as NodeJS.ErrnoException | undefined)?.code === code;
}

function canonicalPayload(state: SessionFlowState): string {
	return JSON.stringify({
		v: state.v,
		sid: state.sid,
		created: state.created,
		updated: state.updated,
		steps: state.steps,
		downloads: state.downloads,
		integrity: state.integrity ?? null,
	});
}

const CAPABILITY_SET = new Set<string>(CAPABILITIES);

function isStep(value: unknown): value is FlowStep {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const step = value as Record<string, unknown>;
	return (
		typeof step.t === "number" &&
		Number.isFinite(step.t) &&
		typeof step.cap === "string" &&
		CAPABILITY_SET.has(step.cap) &&
		typeof step.kind === "string" &&
		step.kind.length <= 40 &&
		typeof step.tool === "string" &&
		step.tool.length <= 64 &&
		typeof step.summary === "string" &&
		step.summary.length <= 200 &&
		typeof step.target === "string" &&
		/^[0-9a-f]{16}$|^integrity:/.test(step.target) &&
		(step.secret === undefined || step.secret === true) &&
		(step.data === undefined || step.data === true)
	);
}

function parseState(raw: string, sid: string): SessionFlowState | null {
	let value: unknown;
	try {
		value = JSON.parse(raw);
	} catch {
		return null;
	}
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const record = value as Record<string, unknown>;
	if (
		record.v !== STATE_VERSION ||
		record.sid !== sid ||
		typeof record.created !== "number" ||
		typeof record.updated !== "number" ||
		!Array.isArray(record.steps) ||
		record.steps.length > MAX_STEPS ||
		!record.steps.every(isStep) ||
		!Array.isArray(record.downloads) ||
		record.downloads.length > MAX_DOWNLOADS ||
		!record.downloads.every(
			(entry) =>
				!!entry &&
				typeof entry === "object" &&
				typeof (entry as { p?: unknown }).p === "string" &&
				typeof (entry as { t?: unknown }).t === "number",
		) ||
		(record.integrity !== undefined && record.integrity !== "lost") ||
		typeof record.mac !== "string"
	) {
		return null;
	}
	return {
		v: STATE_VERSION,
		sid,
		created: record.created,
		updated: record.updated,
		steps: record.steps as FlowStep[],
		downloads: record.downloads as Array<{ p: string; t: number }>,
		...(record.integrity === "lost" ? { integrity: "lost" as const } : {}),
		// The MAC is checked by the caller against the canonical payload.
		mac: record.mac,
	} as SessionFlowState & { mac: string };
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

export interface SessionFlowStoreOptions {
	/** Absolute state directory. Defaults to {@link TOXIC_FLOW_STATE_DIR}. */
	dir?: string;
	logger?: Logger;
	/** Session record lifetime (files older than this are pruned). */
	ttlMs?: number;
}

/**
 * One integrity-protected JSON record per session in the AIDR state directory.
 * Reads are lock-free (records are replaced atomically); writes take a short
 * per-session lock, reload, apply the change and replace the file.
 */
export class SessionFlowStore {
	readonly dir: string;
	private readonly logger: Logger;
	private readonly ttlMs: number;

	constructor(options: SessionFlowStoreOptions = {}) {
		this.dir = options.dir ?? resolvePath(TOXIC_FLOW_STATE_DIR);
		this.logger = options.logger ?? nullLogger;
		this.ttlMs = options.ttlMs ?? 60 * 60_000;
	}

	private filePath(sid: string): string {
		return join(this.dir, `${sid}.json`);
	}

	private async ensureDir(): Promise<void> {
		await mkdir(this.dir, { recursive: true, mode: 0o700 });
		const info = await lstat(this.dir);
		if (info.isSymbolicLink() || !info.isDirectory()) {
			throw new ToxicFlowStateUnavailableError("session-flow state directory is not a directory");
		}
	}

	/** The per-install MAC key; created on first use with owner-only permissions. */
	private async key(): Promise<{ key: Buffer; created: boolean }> {
		const cached = keyCache.get(this.dir);
		if (cached) return { key: cached, created: false };
		const path = join(this.dir, KEY_FILE);
		for (let attempt = 0; attempt < 3; attempt += 1) {
			try {
				const info = await lstat(path);
				if (!info.isFile())
					throw new ToxicFlowStateUnavailableError("session-flow key is not a file");
				const hex = (await getFileContent(path)).trim();
				if (!/^[0-9a-f]{64}$/.test(hex)) {
					throw new ToxicFlowStateUnavailableError("session-flow key is malformed");
				}
				const key = Buffer.from(hex, "hex");
				keyCache.set(this.dir, key);
				return { key, created: false };
			} catch (error) {
				if (!isErrno(error, "ENOENT")) throw error;
			}
			const key = randomBytes(32);
			try {
				const handle = await open(
					path,
					fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL,
					0o600,
				);
				try {
					await handle.writeFile(`${key.toString("hex")}\n`, "utf8");
					await handle.sync();
				} finally {
					await handle.close();
				}
				keyCache.set(this.dir, key);
				return { key, created: true };
			} catch (error) {
				// Another process created it first: read theirs.
				if (!isErrno(error, "EEXIST")) throw error;
			}
		}
		throw new ToxicFlowStateUnavailableError("session-flow key could not be created");
	}

	private mac(key: Buffer, state: SessionFlowState): string {
		return createHmac("sha256", key)
			.update(`${MAC_DOMAIN}\n${canonicalPayload(state)}`)
			.digest("hex");
	}

	/**
	 * Load a session's record. Lock-free: records are replaced atomically.
	 *
	 * Missing → a new empty record. Unreadable (permissions, I/O) → throws
	 * {@link ToxicFlowStateUnavailableError}: the signal is skipped. Present but
	 * malformed, oversized, a symlink, bound to another session or failing the
	 * MAC → `tampered`, with the conservative integrity-lost record.
	 */
	async load(
		sessionKey: string,
		now: number,
	): Promise<{ state: SessionFlowState; status: SessionFlowLoadStatus }> {
		const sid = sessionDigest(sessionKey);
		try {
			const path = this.filePath(sid);
			let info: Stats;
			try {
				info = await lstat(path);
			} catch (error) {
				// No record yet: nothing to verify, and nothing is created on a read.
				if (isErrno(error, "ENOENT"))
					return { state: emptySessionFlowState(sid, now), status: "new" };
				throw error;
			}
			const { key, created } = await this.key();
			if (!info.isFile() || info.size > MAX_STATE_BYTES || created) {
				// A record written before the key existed cannot be genuine.
				return { state: integrityLostState(sid, now), status: "tampered" };
			}
			const parsed = parseState(await getFileContent(path), sid) as
				| (SessionFlowState & { mac: string })
				| null;
			if (!parsed) return { state: integrityLostState(sid, now), status: "tampered" };
			const { mac, ...state } = parsed;
			const expected = Buffer.from(this.mac(key, state), "hex");
			const actual = /^[0-9a-f]{64}$/.test(mac) ? Buffer.from(mac, "hex") : Buffer.alloc(0);
			if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
				return { state: integrityLostState(sid, now), status: "tampered" };
			}
			return { state, status: "ok" };
		} catch (error) {
			if (error instanceof ToxicFlowStateUnavailableError) throw error;
			throw new ToxicFlowStateUnavailableError(
				`session-flow state could not be read (${(error as NodeJS.ErrnoException)?.code ?? "error"})`,
			);
		}
	}

	private async lock(path: string): Promise<() => Promise<void>> {
		const lockPath = `${path}.lock`;
		const deadline = Date.now() + LOCK_WAIT_MS;
		while (true) {
			try {
				const handle = await open(lockPath, "wx", 0o600);
				await handle.close();
				return async () => {
					await unlink(lockPath).catch(() => undefined);
				};
			} catch (error) {
				if (!isErrno(error, "EEXIST")) throw error;
				try {
					const info = await stat(lockPath);
					if (Date.now() - info.mtimeMs > LOCK_STALE_MS) {
						await unlink(lockPath).catch(() => undefined);
						continue;
					}
				} catch {
					continue;
				}
				if (Date.now() >= deadline) {
					throw new ToxicFlowStateUnavailableError(
						"session-flow state is locked by another process",
					);
				}
				await sleep(10);
			}
		}
	}

	/**
	 * Apply `mutate` to the freshest record under the session lock and persist
	 * the result. `mutate` returning null means "no change": nothing is written
	 * (unless the record had to be reset after a failed integrity check).
	 */
	async update(
		sessionKey: string,
		now: number,
		mutate: (state: SessionFlowState) => SessionFlowState | null,
	): Promise<{ written: boolean; status: SessionFlowLoadStatus }> {
		const sid = sessionDigest(sessionKey);
		try {
			await this.ensureDir();
			const path = this.filePath(sid);
			const release = await this.lock(path);
			try {
				const loaded = await this.load(sessionKey, now);
				const next = mutate(loaded.state) ?? (loaded.status === "tampered" ? loaded.state : null);
				if (!next) return { written: false, status: loaded.status };
				const { key } = await this.key();
				await atomicWriteJson(path, { ...next, mac: this.mac(key, next) }, { mode: 0o600 });
				return { written: true, status: loaded.status };
			} finally {
				await release();
				await this.maybePrune(now);
			}
		} catch (error) {
			if (error instanceof ToxicFlowStateUnavailableError) throw error;
			throw new ToxicFlowStateUnavailableError(
				`session-flow state could not be written (${(error as NodeJS.ErrnoException)?.code ?? "error"})`,
			);
		}
	}

	/** Drop expired records and cap the number of sessions; at most every few minutes. */
	private async maybePrune(now: number): Promise<void> {
		const marker = join(this.dir, PRUNE_MARKER);
		try {
			try {
				const info = await stat(marker);
				if (now - info.mtimeMs < PRUNE_INTERVAL_MS) return;
				await utimes(marker, new Date(now), new Date(now));
			} catch (error) {
				if (!isErrno(error, "ENOENT")) return;
				const handle = await open(marker, "w", 0o600);
				await handle.close();
			}
			const entries = await readdir(this.dir);
			const records: Array<{ path: string; mtime: number }> = [];
			for (const entry of entries) {
				const path = join(this.dir, entry);
				if (entry.endsWith(".tmp") || entry.endsWith(".lock")) {
					const info = await stat(path).catch(() => null);
					if (info && now - info.mtimeMs > 5 * 60_000) await unlink(path).catch(() => undefined);
					continue;
				}
				if (!/^[0-9a-f]{40}\.json$/.test(entry)) continue;
				const info = await stat(path).catch(() => null);
				if (!info) continue;
				if (now - info.mtimeMs > this.ttlMs) await unlink(path).catch(() => undefined);
				else records.push({ path, mtime: info.mtimeMs });
			}
			if (records.length > MAX_SESSION_FILES) {
				records.sort((a, b) => a.mtime - b.mtime);
				for (const record of records.slice(0, records.length - MAX_SESSION_FILES)) {
					await unlink(record.path).catch(() => undefined);
				}
			}
		} catch (error) {
			this.logger.warn("Session-flow state pruning did not complete", {
				error: error instanceof Error ? error.name : typeof error,
			});
		}
	}
}

// ── Verdict integration ────────────────────────────────────────────

const DECISION_RANK = { allow: 0, ask: 1, deny: 2 } as const;

export interface ToxicFlowOptions {
	agentRuntime?: string;
	logger?: Logger;
	/** The call matched the operator allowlist: record it, do not escalate it. */
	allowlisted?: boolean;
	/** Override the state directory (tests, embedders with their own state root). */
	stateDir?: string;
	now?: () => number;
}

export interface ToxicFlowRequest {
	sessionId: string;
	toolName: string;
	toolInput: Record<string, unknown>;
	artifacts: readonly Artifact[];
}

function verdictArtifacts(artifacts: readonly Artifact[]): string[] {
	return artifacts
		.filter((artifact) => artifact.type !== "content")
		.slice(0, 3)
		.map((artifact) =>
			artifact.value.length > 200 ? `${artifact.value.slice(0, 200)}…` : artifact.value,
		);
}

/** Merge a toxic-flow finding into the verdict the other layers produced. */
function mergeFinding(
	verdict: Verdict,
	finding: ToxicFlowFinding,
	action: "ask" | "deny" | "monitor",
	request: ToxicFlowRequest,
): Verdict {
	if (action === "monitor") {
		return {
			...verdict,
			...(verdict.decision === "allow" && verdict.category === "none"
				? { category: "toxic_flow_monitor", severity: "warning" as const }
				: {}),
			reasons: [...verdict.reasons, `[monitor only] ${finding.reason}`],
		};
	}
	// An ask would run the ORIGINAL input once approved, discarding a DLP
	// redaction: when the other layers required a rewrite, block instead.
	const decision: "ask" | "deny" = verdict.transformedInput ? "deny" : action;
	if (DECISION_RANK[decision] < DECISION_RANK[verdict.decision]) {
		return { ...verdict, reasons: [...verdict.reasons, finding.reason] };
	}
	const { transformedInput: _dropped, ...rest } = verdict;
	return {
		...rest,
		decision,
		category: "toxic_flow",
		confidence: 0.9,
		severity: decision === "deny" ? "critical" : finding.severity,
		source: "toxic_flow",
		artifacts:
			verdict.artifacts.length > 0 ? verdict.artifacts : verdictArtifacts(request.artifacts),
		matchedThreatId: finding.threatId,
		reasons: [finding.reason, ...(verdict.decision === "allow" ? [] : verdict.reasons)],
	};
}

function unavailable(verdict: Verdict, reason: string): Verdict {
	const note = `Session toxic-flow tracking was unavailable (${reason}); multi-step chain detection did not run for this call, so this is not a clean result.`;
	if (verdict.decision === "allow" && verdict.category === "none") {
		return {
			...verdict,
			category: "toxic_flow_unavailable",
			severity: "warning",
			reasons: [...verdict.reasons, note],
		};
	}
	return { ...verdict, reasons: [...verdict.reasons, note] };
}

function needsState(classification: FlowClassification): boolean {
	return (
		classification.observations.length > 0 ||
		classification.destructive !== null ||
		classification.downloads.length > 0 ||
		classification.reads.length > 0
	);
}

/**
 * Evaluate a tool call against its session's flow and record what it adds.
 *
 * Called by the shared evaluator after every other layer, so every connector
 * that uses `evaluateToolCall` (Claude Code, Cursor/VS Code, OpenClaw, OpenCode,
 * Codex, the MCP gateway) gets it. A `deny` from another layer is returned
 * untouched and not recorded: the call will not run. `allow` and `ask` calls
 * are recorded (an ask may run after approval).
 */
export async function applyToxicFlow(
	request: ToxicFlowRequest,
	verdict: Verdict,
	config: Partial<Config>,
	options: ToxicFlowOptions = {},
): Promise<Verdict> {
	const settings = resolveToxicFlowSettings(config);
	if (!settings.enabled || verdict.decision === "deny") return verdict;
	const logger = options.logger ?? nullLogger;
	const now = (options.now ?? Date.now)();

	let classification: FlowClassification;
	try {
		classification = classifyToolCallFlow(request, settings);
	} catch (error) {
		logger.warn("Toxic-flow classification failed; the signal was skipped", {
			error: error instanceof Error ? error.name : typeof error,
		});
		return unavailable(verdict, "classification failed");
	}
	if (!needsState(classification)) return verdict;

	const sessionKey = resolveFlowSessionKey(request.sessionId, options.agentRuntime);
	const store = new SessionFlowStore({ dir: options.stateDir, logger, ttlMs: settings.windowMs });
	let result = verdict;
	try {
		const loaded = await store.load(sessionKey, now);
		if (loaded.status === "tampered") {
			logger.warn(
				"Session-flow record failed its integrity check; assuming the full trifecta for this window",
				{
					session: sessionDigest(sessionKey).slice(0, 12),
				},
			);
		}
		const evaluation = evaluateToxicFlow(
			loaded.state,
			{ tool: request.toolName, classification },
			settings,
			now,
		);
		if (evaluation.finding && !options.allowlisted) {
			result = mergeFinding(
				verdict,
				evaluation.finding,
				effectiveAction(settings, config),
				request,
			);
		}
		if (result.decision !== "deny") {
			await store.update(sessionKey, now, (fresh) =>
				recordFlowObservations(
					fresh,
					request.toolName,
					evaluation.observations,
					classification.downloads,
					settings,
					now,
				),
			);
		} else if (loaded.status === "tampered") {
			await store.update(sessionKey, now, () => null);
		}
		return result;
	} catch (error) {
		const reason =
			error instanceof ToxicFlowStateUnavailableError ? error.message : "session-flow state error";
		logger.warn("Toxic-flow state unavailable; the signal was skipped", { reason });
		// A finding that was already made stands even if recording it failed.
		return result === verdict ? unavailable(verdict, reason) : result;
	}
}

// ── Post-execution feed ────────────────────────────────────────────

export interface ToolOutputFlowInput {
	sessionId: string;
	toolName: string;
	toolInput?: Record<string, unknown>;
	/**
	 * Output-inspection findings: the `scanModelOutput` shape (`type`) or a
	 * connector's reduced shape that only keeps the rule id (`OUT-PII-*`,
	 * `OUT-INJ-*`, `OUT-TOOL-*`).
	 */
	findings?: ReadonlyArray<{ type?: string; ruleId?: string }>;
	/** A connector-specific PII detector found personal data in the output. */
	piiDetected?: boolean;
}

export type ToolOutputFlowResult = "recorded" | "unchanged" | "disabled" | "unavailable";

function findingType(finding: { type?: string; ruleId?: string }): string {
	if (finding.type) return finding.type;
	const rule = finding.ruleId ?? "";
	if (rule.startsWith("OUT-PII-")) return "secret_leak";
	if (rule.startsWith("OUT-INJ-")) return "prompt_injection_payload";
	if (rule.startsWith("OUT-TOOL-")) return "unsafe_tool_instruction";
	return "other";
}

/** Observations a completed tool's output adds to the session. */
export function outputFlowObservations(input: ToolOutputFlowInput): FlowObservation[] {
	const out: FlowObservation[] = [];
	const types = new Set((input.findings ?? []).map(findingType));
	const tool = input.toolName.slice(0, 64);
	if (types.has("secret_leak")) {
		out.push({
			cap: "private_data",
			kind: "secret_in_output",
			summary: "secret material in tool output",
			target: `output-secret:${tool}`,
			secret: true,
		});
	}
	if (input.piiDetected) {
		out.push({
			cap: "private_data",
			kind: "pii_in_output",
			summary: "personal data in tool output",
			target: `output-pii:${tool}`,
		});
	}
	if (types.has("prompt_injection_payload") || types.has("unsafe_tool_instruction")) {
		out.push({
			cap: "untrusted_content",
			kind: "injection_in_output",
			summary: "tool output flagged by prompt-injection inspection",
			target: `output-injection:${tool}`,
		});
	}
	return out;
}

export interface ToolOutputFlowOptions extends Omit<ToxicFlowOptions, "allowlisted"> {
	/** Already-loaded runtime config; loaded from `configPath` when absent. */
	config?: Partial<Config>;
	configPath?: string;
}

/**
 * Feed a completed tool's inspected output into its session's flow record.
 *
 * Connectors with a post-execution hook call this after output inspection. It
 * never throws and never changes what the connector does with the output: the
 * tool already ran. The recorded taint is what makes the NEXT call's evaluation
 * aware that, say, a fetched page carried an injection payload.
 */
export async function recordToolOutputFlow(
	input: ToolOutputFlowInput,
	options: ToolOutputFlowOptions = {},
): Promise<ToolOutputFlowResult> {
	const logger = options.logger ?? nullLogger;
	const observations = outputFlowObservations(input);
	if (observations.length === 0) return "unchanged";
	try {
		const config = options.config ?? (await loadConfig(options.configPath, logger));
		if (!options.config && isInvalidConfig(config as Config)) return "unavailable";
		const settings = resolveToxicFlowSettings(config);
		if (!settings.enabled) return "disabled";
		const now = (options.now ?? Date.now)();
		const sessionKey = resolveFlowSessionKey(input.sessionId, options.agentRuntime);
		const store = new SessionFlowStore({ dir: options.stateDir, logger, ttlMs: settings.windowMs });
		const { written } = await store.update(sessionKey, now, (fresh) =>
			recordFlowObservations(fresh, input.toolName, observations, [], settings, now),
		);
		return written ? "recorded" : "unchanged";
	} catch (error) {
		logger.warn("Toxic-flow output feed skipped", {
			reason: error instanceof Error ? error.message : typeof error,
		});
		return "unavailable";
	}
}
