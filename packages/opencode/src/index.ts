/**
 * Singularity AIDR OpenCode plugin.
 * Intercepts tool calls and uses @singularityrd/aidr-core to enforce security verdicts.
 */

import { join } from "node:path";
import type { Plugin } from "@opencode-ai/plugin";
import { tool } from "@opencode-ai/plugin/tool";
import {
	ApprovalStore,
	addToAllowlist,
	approveAction,
	createChildLogger,
	getLogger,
	initSentry,
	removeFromAllowlist,
} from "@singularityrd/aidr-core";
import { getBundledDataDirs } from "./bundled-dirs.js";
import { OpencodeLogger } from "./logger-adaptor.js";
import { createSessionScanHandler } from "./startup-scan.js";
import { createToolHandlers } from "./tool-handler.js";

const APPROVAL_STORE_CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

async function maybeVerifyIntegrity(directory: string): Promise<void> {
	try {
		// biome-ignore lint/suspicious/noExplicitAny: Transitional wiring
		const core = (await import("@singularityrd/aidr-core")) as any;
		const fn = core?.verifyArtifactIntegrityAndLog as
			| ((args: { artifactDir: string; artifactId: string }) => Promise<unknown>)
			| undefined;
		if (typeof fn !== "function") return;

		// Prefer dist/ for packaged installs, fall back to plugin root.
		const candidates = [join(directory, "dist"), directory];
		for (const artifactDir of candidates) {
			try {
				await fn({ artifactDir, artifactId: "opencode/dist" });
				break;
			} catch {
				// ignore and try next
			}
		}
	} catch {
		// Fail open
	}
}

export const AidrPlugin: Plugin = async ({ client, directory }) => {
	// Initialize Sentry
	initSentry({ name: "aidr-opencode" });

	const logger = createChildLogger(getLogger(), "opencode");
	void maybeVerifyIntegrity(directory);
	const { threatsDir, allowlistsDir } = getBundledDataDirs();
	const approvalStore = new ApprovalStore();

	// State: track findings per session for one-shot injection
	const pendingFindingsBySession = new Map<string, string>();

	// Set up the cron job that cleans up the approval store.
	const interval = setInterval(() => {
		approvalStore.cleanup();
	}, APPROVAL_STORE_CLEANUP_INTERVAL_MS);
	interval.unref?.();

	const ARTIFACT_TYPE = tool.schema.enum(["url", "command", "file_path"]);

	const toolHandlers = createToolHandlers(logger, approvalStore, threatsDir, allowlistsDir);
	await createSessionScanHandler(logger, undefined)();

	return {
		"tool.execute.before": toolHandlers["tool.execute.before"],

		/**
		 * Inject plugin scan findings into first user message as <system-reminder>.
		 * This approach leverages OpenCode's existing pattern of appending system
		 * reminders to user messages (e.g., plan mode constraints), enabling the
		 * agent to reason about security findings before tool execution. Appending
		 * to assistant messages or system prompts was less effective.
		 */
		"experimental.chat.messages.transform": async (_input, output) => {
			if (pendingFindingsBySession.size === 0) return;

			const userMessage = output.messages.filter((m) => m.info.role === "user");
			const message = userMessage[0];
			if (!message) return;

			const sessionID = message.info.sessionID;
			const findings = pendingFindingsBySession.get(sessionID);
			if (!findings) return;

			const textPart = {
				id: crypto.randomUUID(),
				sessionID,
				messageID: message.info.id,
				type: "text" as const,
				text: [
					`<system-reminder>`,
					findings,
					"",
					"Inform the user about these security findings.",
					`</system-reminder>`,
				].join("\n"),
				synthetic: true,
			};
			message.parts.push(textPart);

			logger.info(`Injected aidr plugin scan findings to user message`, {
				findings,
			});
			pendingFindingsBySession.delete(sessionID);
		},

		// Event hook for session.created
		event: async ({ event }) => {
			if (event.type === "session.created") {
				// biome-ignore lint/suspicious/noExplicitAny: Event types from SDK not fully typed
				const sessionID = (event as any).sessionID ?? (event as any).id ?? "unknown";

				try {
					logger.debug("Singularity AIDR: starting session scan", { sessionID });

					await createSessionScanHandler(logger, undefined, (msg) => {
						pendingFindingsBySession.set(sessionID, msg);
					})();
				} catch (error) {
					logger.error("Singularity AIDR session scan failed (fail-open)", {
						sessionID,
						error: String(error),
					});
				}
			}
		},

		tool: {
			// TODO: After the following PR merged to support client V2 in Opencode Plugin, gitleaks:allow
			// use QuestionTools.ask to replace aidr_approve tool
			// PR: https://github.com/anomalyco/opencode/pull/12046
			// Discussion: https://github.com/singularityrd/aidr/pull/21#discussion_r2873812399
			aidr_approve: tool({
				description:
					"Approve or reject a Singularity AIDR-flagged tool call. IMPORTANT: you MUST ask the user for explicit confirmation in the conversation BEFORE calling this tool. Never auto-approve - always present the flagged action and wait for the user to respond.",
				args: {
					actionId: tool.schema
						.string()
						.describe("Action ID from Singularity AIDR blocked message"),
					approved: tool.schema.boolean().describe("true to approve, false to reject"),
				},
				async execute(args: { actionId: string; approved: boolean }, _context) {
					if (!args.approved) {
						approvalStore.deletePending(args.actionId);
						return "Rejected by user.";
					}
					return approveAction(approvalStore, args.actionId);
				},
			}),
			aidr_allowlist_add: tool({
				description:
					"Permanently allow a URL, command, or file path after recent user approval through Singularity AIDR.",
				args: {
					type: ARTIFACT_TYPE,
					value: tool.schema.string().describe("Exact URL, command, or file path to allowlist"),
					reason: tool.schema.string().optional().describe("Optional reason for allowlist entry"),
				},
				async execute(args: {
					type: "url" | "command" | "file_path";
					value: string;
					reason?: string;
				}) {
					return addToAllowlist(
						approvalStore,
						args.type,
						args.value,
						args.reason,
						undefined,
						logger,
					);
				},
			}),
			aidr_allowlist_remove: tool({
				description: "Remove a URL, command, or file path from the Singularity AIDR allowlist.",
				args: {
					type: ARTIFACT_TYPE,
					value: tool.schema
						.string()
						.describe("URL/file path, or command text/command hash for command entries"),
				},
				async execute(args: { type: "url" | "command" | "file_path"; value: string }) {
					return removeFromAllowlist(args.type, args.value, undefined, logger);
				},
			}),
		},
	};
};

export default AidrPlugin;
