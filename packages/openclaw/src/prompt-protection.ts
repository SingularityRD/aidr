/**
 * Prompt protection for OpenClaw.
 *
 * OpenClaw's `before_agent_run` gate runs on the embedded and CLI runners after
 * prompt construction and before model submission (including `llm_input`). It
 * receives the current user input as `prompt` and returns `{ outcome: "pass" }`
 * or `{ outcome: "block", reason, message }`; the host fails CLOSED on a thrown
 * error, a timeout (15 s) or any other decision shape, and a blocked run keeps
 * only the replacement `message` in the transcript, never the original text.
 *
 * The prompt is inspected by the shared core runner: secrets block and personal
 * data warns by default (`prompt_protection`), a provisioned tenant DLP policy
 * applies, and an uninspectable or late prompt is blocked when secrets are in
 * `block` mode.
 *
 * `before_agent_run` cannot add context, so a `warn` is delivered one step
 * earlier: `before_prompt_build` (which runs before the gate, on the same
 * request) inspects `currentUserMessage` (or `prompt` on hosts that do not
 * supply it) and prepends a notice for the model, asking it to tell the user.
 * Both hooks share one memoised inspection per session, prompt text and
 * installed policy (config and managed-state fingerprint), so a prompt is
 * scanned and audited once per request, a different session never reuses
 * another session's result, and a policy change is never answered from a
 * result computed under the old policy.
 *
 * Coverage boundary (OpenClaw docs): `before_agent_run` is implemented by the
 * embedded and CLI runners only; it is not an input gate for the Codex or
 * Copilot harnesses. A non-bundled plugin needs
 * `plugins.entries.aidr-openclaw.hooks.allowConversationAccess: true` for both
 * hooks, and a host without `before_agent_run` ignores the registration.
 */

import { createHash } from "node:crypto";
import { statSync } from "node:fs";
import {
	type Config,
	inspectUserPrompt,
	type Logger,
	loadConfig,
	managedStatePath,
	type PromptInspectionOutcome,
	resolvePromptInspectionDeadlineMs,
} from "@singularityrd/aidr-core";

const OPENCLAW_PROMPT_EVENT = "before_agent_run";

/** The host fails closed after 15 s; answer well before that. */
const DEFAULT_PROMPT_DEADLINE_MS = 10_000;
const MAX_PROMPT_DEADLINE_MS = 13_000;
/** One request passes both hooks within seconds; keep results briefly, bounded. */
const MEMO_TTL_MS = 60_000;
const MAX_MEMO_ENTRIES = 128;

/** OpenClaw `InputGateDecision` (hook-decision-types.ts). */
export type InputGateDecision =
	| { outcome: "pass" }
	| { outcome: "block"; reason: string; message: string; category: string };

export interface BeforeAgentRunEvent {
	prompt?: unknown;
}

export interface BeforePromptBuildEvent {
	prompt?: unknown;
	currentUserMessage?: unknown;
}

export interface PromptHookContext {
	sessionKey?: string;
	sessionId?: string;
}

function digest(...parts: string[]): string {
	const hash = createHash("sha256");
	for (const part of parts) hash.update(part).update("\0");
	return hash.digest("hex");
}

function sessionKeyOf(ctx?: PromptHookContext): string {
	return ctx?.sessionKey ?? ctx?.sessionId ?? "openclaw";
}

/** Changes whenever the managed state (tenant DLP / prompt-safety policy) is rewritten. */
function managedStateFingerprint(): string {
	try {
		const stat = statSync(managedStatePath());
		return `${stat.size}:${stat.mtimeMs}:${stat.ino}`;
	} catch {
		return "absent";
	}
}

export function toInputGateDecision(outcome: PromptInspectionOutcome): InputGateDecision {
	if (outcome.decision !== "block") return { outcome: "pass" };
	return {
		outcome: "block",
		// Internal and treated as sensitive by the host; a static code only.
		reason: `aidr_prompt_protection:${outcome.reason}`,
		message: outcome.userMessage,
		category: "prompt_protection",
	};
}

function promptWarningContext(
	outcome: Extract<PromptInspectionOutcome, { decision: "warn" }>,
): string {
	return [
		'<security-notice source="aidr-prompt-protection">',
		outcome.modelContext,
		`Tell the user: ${outcome.userMessage}`,
		"</security-notice>",
	].join("\n");
}

export class OpenClawPromptProtection {
	private readonly memo = new Map<
		string,
		{ at: number; outcome: Promise<PromptInspectionOutcome> }
	>();

	constructor(
		private readonly logger: Logger,
		private readonly now: () => number = Date.now,
	) {}

	/** `before_agent_run` gate. Always returns an explicit decision: the host blocks on anything else. */
	readonly beforeAgentRun = async (
		event: BeforeAgentRunEvent,
		ctx?: PromptHookContext,
	): Promise<InputGateDecision> => {
		const outcome = await this.inspect(event?.prompt, ctx);
		return toInputGateDecision(outcome);
	};

	/**
	 * `before_prompt_build`: the model notice for a `warn` outcome. Returns the
	 * context to prepend, or undefined. A block is left to the gate.
	 */
	readonly warningContext = async (
		event: BeforePromptBuildEvent,
		ctx?: PromptHookContext,
	): Promise<string | undefined> => {
		const text =
			typeof event?.currentUserMessage === "string" ? event.currentUserMessage : event?.prompt;
		if (typeof text !== "string" || text === "") return undefined;
		const outcome = await this.inspect(text, ctx);
		return outcome.decision === "warn" ? promptWarningContext(outcome) : undefined;
	};

	/** A gate decision when the plugin could not initialise: the uninspected-prompt policy. */
	static async uninspectedDecision(
		logger: Logger,
		ctx?: PromptHookContext,
	): Promise<InputGateDecision> {
		const outcome = await inspectUserPrompt({
			runtime: "openclaw",
			hookEvent: OPENCLAW_PROMPT_EVENT,
			sessionId: ctx?.sessionKey ?? ctx?.sessionId ?? "openclaw",
			prompt: undefined,
			deadlineAt: Date.now() + DEFAULT_PROMPT_DEADLINE_MS,
			logger,
		});
		return toInputGateDecision(outcome);
	}

	private async inspect(
		prompt: unknown,
		ctx?: PromptHookContext,
	): Promise<PromptInspectionOutcome> {
		const sessionId = sessionKeyOf(ctx);
		// The inspection deadline counts from the hook call, config load included.
		const now = this.now();
		// The installed policy is part of the memo key: the config is loaded once
		// here and handed to the inspection, so the key and the result agree.
		let config: Config | undefined;
		try {
			config = await loadConfig(undefined, this.logger);
		} catch {
			config = undefined; // the inspection applies its own load-failure policy
		}
		for (const [key, entry] of this.memo) {
			if (now - entry.at > MEMO_TTL_MS) this.memo.delete(key);
		}
		const key =
			typeof prompt === "string" && config
				? digest(sessionId, JSON.stringify(config), managedStateFingerprint(), prompt)
				: undefined;
		const cached = key ? this.memo.get(key) : undefined;
		if (cached) return cached.outcome;

		const deadlineMs = resolvePromptInspectionDeadlineMs(
			process.env,
			DEFAULT_PROMPT_DEADLINE_MS,
			MAX_PROMPT_DEADLINE_MS,
		);
		const outcome = inspectUserPrompt({
			runtime: "openclaw",
			hookEvent: OPENCLAW_PROMPT_EVENT,
			sessionId,
			prompt,
			deadlineAt: now + deadlineMs,
			logger: this.logger,
			...(config ? { config } : {}),
		});
		if (key) {
			const entry = { at: now, outcome };
			this.memo.set(key, entry);
			while (this.memo.size > MAX_MEMO_ENTRIES) {
				const oldest = this.memo.keys().next().value;
				if (oldest === undefined) break;
				this.memo.delete(oldest);
			}
			// Only a completed inspection is reused; a retry after a deadline or
			// load failure is inspected afresh.
			void outcome.then((result) => {
				const complete =
					result.reason === "clean" || result.reason === "findings" || result.reason === "canary";
				if (!complete && this.memo.get(key) === entry) this.memo.delete(key);
			});
		}
		return outcome;
	}
}
