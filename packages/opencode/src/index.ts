/**
 * Singularity AIDR OpenCode plugin.
 * Intercepts tool calls and uses @singularityrd/aidr-core to enforce security verdicts.
 *
 * SECURITY: this plugin deliberately registers NO approval tool. Approval
 * authority must be an action the model cannot invoke, so `ask` verdicts stay
 * blocking (see README.md).
 */

import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { Plugin } from "@opencode-ai/plugin";
import { tool } from "@opencode-ai/plugin/tool";
import {
	ApprovalStore,
	addToAllowlist,
	createChildLogger,
	getLogger,
	initSentry,
	removeFromAllowlist,
	verifyArtifactIntegrityAndLog,
} from "@singularityrd/aidr-core";
import { getBundledDataDirs } from "./bundled-dirs.js";
import { createOutputHandlers, reportOpenCodeOutputCoverage } from "./output-handler.js";
import { createSessionScanHandler } from "./startup-scan.js";
import { createToolHandlers } from "./tool-handler.js";

const APPROVAL_STORE_CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

export const AidrPlugin: Plugin = async ({ client, directory }) => {
	// Initialize Sentry
	initSentry({ name: "aidr-opencode" });

	const logger = createChildLogger(getLogger(), "opencode");
	await verifyArtifactIntegrityAndLog({
		artifactDir: dirname(fileURLToPath(import.meta.url)),
		artifactId: "opencode/dist",
		logger,
	});
	await verifyArtifactIntegrityAndLog({
		artifactDir: dirname(fileURLToPath(import.meta.resolve("@singularityrd/aidr-core"))),
		artifactId: "core/dist",
		logger,
	});
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
	const outputHandlers = createOutputHandlers(logger);
	reportOpenCodeOutputCoverage(logger);
	await createSessionScanHandler(logger, directory)();

	return {
		"tool.execute.before": toolHandlers["tool.execute.before"],
		"tool.execute.after": outputHandlers["tool.execute.after"],

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

			logger.info({ findings }, "Injected aidr plugin scan findings to user message");
			pendingFindingsBySession.delete(sessionID);
		},

		// Event hook for session.created
		event: async ({ event }) => {
			if (event.type === "session.created") {
				const sessionID = event.properties.info.id;

				try {
					logger.debug({ sessionID }, "Singularity AIDR: starting session scan");

					await createSessionScanHandler(logger, directory, (msg) => {
						pendingFindingsBySession.set(sessionID, msg);
					})();
				} catch (error) {
					logger.error(
						{ sessionID, error: String(error) },
						"Singularity AIDR session scan failed (fail-open)",
					);
				}
			}
		},

		tool: {
			// SECURITY: no `aidr_approve` tool is registered. An approval tool
			// callable by the model would let a prompt-injected agent approve its
			// own blocked action (the actionId is in the block message), turning
			// every `ask` verdict into a self-service bypass. Until OpenCode
			// exposes a host-native question/confirmation API that the plugin can
			// drive from outside the model's tool surface (upstream PR:
			// https://github.com/anomalyco/opencode/pull/12046), `ask` verdicts
			// stay blocking. See README.md ("Approving a flagged action").
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
