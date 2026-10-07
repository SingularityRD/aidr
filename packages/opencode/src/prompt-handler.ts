/**
 * Prompt protection for OpenCode.
 *
 * OpenCode calls the `chat.message` plugin hook when the user submits a message,
 * after the message parts are assembled and before they are stored and sent to
 * the model; the hook receives the parts by reference. The user's own text parts
 * (not `synthetic` parts OpenCode generates, such as attached file contents) are
 * inspected by the shared core runner: secrets block and personal data warns by
 * default (`prompt_protection`), a provisioned tenant DLP policy applies, and an
 * uninspectable or late prompt is blocked when secrets are in `block` mode.
 *
 *   - block: every inspected text part is replaced with the block notice (so the
 *     value is neither stored nor sent even if the host carried on), a toast is
 *     shown when the TUI is attached, and the hook throws, which aborts the prompt.
 *   - warn:  the message is sent; the model gets the notice on that message
 *     (`experimental.chat.messages.transform`, never persisted) and the user a toast.
 *   - allow: nothing changes.
 *
 * Findings are audited as kinds and counts; the prompt is never logged.
 */

import {
	inspectUserPrompt,
	type Logger,
	type PromptInspectionOutcome,
	resolvePromptInspectionDeadlineMs,
	uninspectedPromptOutcome,
} from "@singularityrd/aidr-core";
import { AidrVerdictBlockError } from "./error.js";

const OPENCODE_PROMPT_EVENT = "chat.message";

/** In-process: no host timeout applies, the deadline only bounds latency. */
const DEFAULT_PROMPT_DEADLINE_MS = 10_000;
const MAX_PROMPT_DEADLINE_MS = 60_000;
/** Warned messages whose notice is re-attached on every model call; oldest dropped first. */
const MAX_PENDING_NOTICES = 256;

interface TextPartLike {
	type: "text";
	text: string;
	synthetic?: boolean;
}

interface ChatMessageInput {
	sessionID: string;
	messageID?: string;
}

interface ChatMessageOutput {
	message: { id?: string };
	parts: unknown[];
}

interface TransformMessage {
	info: { id?: string; role?: string; sessionID?: string };
	parts: unknown[];
}

export type PromptToast = (message: string, variant: "warning" | "error") => Promise<void>;

export interface PromptProtectionOptions {
	logger: Logger;
	/** Best-effort user notice (the TUI toast); failures are ignored. */
	notify?: PromptToast;
	/**
	 * The plugin failed to initialise: prompts cannot be inspected, so the
	 * uninspected-prompt policy applies (block unless secrets are not `block`).
	 */
	inspectionUnavailable?: boolean;
}

function isUserTextPart(part: unknown): part is TextPartLike {
	if (!part || typeof part !== "object") return false;
	const candidate = part as Partial<TextPartLike>;
	return candidate.type === "text" && typeof candidate.text === "string" && !candidate.synthetic;
}

function modelNotice(outcome: Extract<PromptInspectionOutcome, { decision: "warn" }>): string {
	return [
		'<system-reminder source="aidr-prompt-protection">',
		outcome.modelContext,
		`Tell the user: ${outcome.userMessage}`,
		"</system-reminder>",
	].join("\n");
}

/** `chat.message` + `experimental.chat.messages.transform` handlers sharing warn notices. */
export class OpenCodePromptProtection {
	private readonly notices = new Map<string, string>();

	constructor(private readonly options: PromptProtectionOptions) {}

	/** `chat.message`: inspect the submitted text, then block (throw), warn or allow. */
	readonly chatMessage = async (
		input: ChatMessageInput,
		output: ChatMessageOutput,
	): Promise<void> => {
		const parts = Array.isArray(output?.parts) ? output.parts : [];
		const textParts = parts.filter(isUserTextPart);
		const outcome = await this.inspect(
			input?.sessionID,
			textParts.map((part) => part.text).join("\n\n"),
		);
		if (outcome.decision === "allow") return;

		if (outcome.decision === "warn") {
			const messageId = output?.message?.id ?? input?.messageID;
			if (messageId) this.remember(messageId, modelNotice(outcome));
			await this.toast(outcome.userMessage, "warning");
			return;
		}

		// Replace the text first: the value must not be stored or sent even if a
		// host version continued past the thrown error.
		for (const part of textParts) part.text = outcome.userMessage;
		await this.toast(outcome.userMessage, "error");
		throw new AidrVerdictBlockError(outcome.userMessage);
	};

	/** Re-attach the warn notice to its user message on every model call. */
	readonly transformMessages = (messages: TransformMessage[]): void => {
		if (this.notices.size === 0) return;
		for (const message of messages) {
			const id = message.info?.id;
			if (message.info?.role !== "user" || !id) continue;
			const notice = this.notices.get(id);
			if (!notice) continue;
			message.parts.push({
				id: crypto.randomUUID(),
				sessionID: message.info.sessionID,
				messageID: id,
				type: "text",
				text: notice,
				synthetic: true,
			});
		}
	};

	private async inspect(
		sessionId: string | undefined,
		prompt: string,
	): Promise<PromptInspectionOutcome> {
		if (this.options.inspectionUnavailable) {
			// Still load the configured secrets mode and audit through the runner.
			return inspectUserPrompt({
				runtime: "opencode",
				hookEvent: OPENCODE_PROMPT_EVENT,
				sessionId: sessionId ?? "opencode",
				prompt: undefined,
				deadlineAt: Date.now() + DEFAULT_PROMPT_DEADLINE_MS,
				logger: this.options.logger,
			}).catch(() => uninspectedPromptOutcome("block"));
		}
		const deadlineMs = resolvePromptInspectionDeadlineMs(
			process.env,
			DEFAULT_PROMPT_DEADLINE_MS,
			MAX_PROMPT_DEADLINE_MS,
		);
		return inspectUserPrompt({
			runtime: "opencode",
			hookEvent: OPENCODE_PROMPT_EVENT,
			sessionId: sessionId ?? "opencode",
			prompt,
			deadlineAt: Date.now() + deadlineMs,
			logger: this.options.logger,
		});
	}

	private remember(messageId: string, notice: string): void {
		this.notices.delete(messageId);
		this.notices.set(messageId, notice);
		while (this.notices.size > MAX_PENDING_NOTICES) {
			const oldest = this.notices.keys().next().value;
			if (oldest === undefined) break;
			this.notices.delete(oldest);
		}
	}

	private async toast(message: string, variant: "warning" | "error"): Promise<void> {
		if (!this.options.notify) return;
		try {
			await this.options.notify(message, variant);
		} catch (error) {
			this.options.logger.debug("Singularity AIDR prompt notice toast failed", {
				error: error instanceof Error ? error.name : typeof error,
			});
		}
	}
}

/** Toast through the OpenCode SDK client when the TUI API is available. */
export function createToastNotifier(client: unknown): PromptToast | undefined {
	const showToast = (
		client as {
			tui?: {
				showToast?: (options: {
					body: { title?: string; message: string; variant: "warning" | "error" };
				}) => Promise<unknown>;
			};
		}
	)?.tui?.showToast;
	if (typeof showToast !== "function") return undefined;
	const tui = (client as { tui: object }).tui;
	return async (message, variant) => {
		await Reflect.apply(showToast, tui, [
			{ body: { title: "Singularity AIDR", message, variant } },
		]);
	};
}
