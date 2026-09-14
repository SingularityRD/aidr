/**
 * Singularity AIDR OpenClaw plugin entry point.
 * Registers tool-input enforcement, bounded post-execution/output protection,
 * allowlist tools, startup/session scan hooks, and before_agent_start handler.
 *
 * SECURITY: this plugin deliberately registers NO approval tool. An approval
 * tool callable by the model would let a prompt-injected agent approve its own
 * blocked action (it receives the actionId in the block message). Approval
 * authority must be an action the agent cannot perform, so `ask` verdicts stay
 * blocking. See README.md ("Approving a flagged action").
 */

import { ApprovalStore, initSentry } from "@singularityrd/aidr-core";
import { createAllowlistAddTool, createAllowlistRemoveTool } from "./allowlist-tools.js";
import { getBundledDataDirs } from "./bundled-dirs.js";
import { createLogger, type PluginLogger } from "./logger-adapter.js";
import { OpenClawOutputProtection } from "./output-protection.js";
import {
	createBeforeAgentStartHandler,
	createSessionScanHandler,
	createStartupScanHandler,
} from "./startup-scan.js";
import { createToolCallHandler } from "./tool-handler.js";

interface PluginApi {
	logger: PluginLogger;
	// biome-ignore lint/suspicious/noExplicitAny: OpenClaw handler signatures vary by event
	on(event: string, handler: (...args: any[]) => any, options?: { priority?: number }): void;
	registerTool(tool: Record<string, unknown>): void;
}

declare const __dirname: string;

async function maybeVerifyIntegrity(): Promise<void> {
	try {
		// Dynamic import to avoid hard-coupling to core's public exports during transition.
		// biome-ignore lint/suspicious/noExplicitAny: Transitional wiring
		const core = (await import("@singularityrd/aidr-core")) as any;
		const fn = core?.verifyArtifactIntegrityAndLog as
			| ((args: { artifactDir: string; artifactId: string }) => Promise<unknown>)
			| undefined;
		if (typeof fn === "function") {
			await fn({ artifactDir: __dirname, artifactId: "openclaw/dist" });
		}
	} catch {
		// Fail open
	}
}

export default {
	id: "aidr-openclaw",
	name: "Singularity AIDR",
	description:
		"Singularity AIDR — Agent Detection & Response layer that guards commands, files, and web requests",
	configSchema: {
		jsonSchema: { type: "object", additionalProperties: false, properties: {} },
	},
	register(api: PluginApi) {
		// Initialize Sentry
		initSentry({ name: "aidr-openclaw" });

		const logger = createLogger(api.logger);
		void maybeVerifyIntegrity();
		const approvalStore = new ApprovalStore();
		const outputProtection = new OpenClawOutputProtection(logger);
		const { threatsDir, allowlistsDir } = getBundledDataDirs();

		const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;
		const interval = setInterval(() => approvalStore.cleanup(), CLEANUP_INTERVAL_MS);
		if (typeof interval.unref === "function") interval.unref();

		// Shared state: scan findings waiting to be surfaced to the user
		let pendingFindings: string | null = null;
		const onFindings = (msg: string) => {
			pendingFindings = msg;
		};

		api.on(
			"before_tool_call",
			createToolCallHandler(approvalStore, logger, threatsDir, allowlistsDir),
			{ priority: 100 },
		);
		api.on("after_tool_call", outputProtection.afterToolCall.bind(outputProtection));
		// OpenClaw requires this persistence hook to be synchronous. It can keep
		// future transcript reads safe, but it runs after the tool already executed.
		try {
			api.on("tool_result_persist", outputProtection.toolResultPersist.bind(outputProtection), {
				priority: 100,
			});
		} catch (error) {
			// A host without this surface keeps the original output in its transcript,
			// so a finding observed at after_tool_call cannot be carried forward.
			// Record the unenforced boundary instead of degrading silently.
			outputProtection.recordPersistBoundaryUnavailable(
				`tool_result_persist registration failed: ${error instanceof Error ? error.name : typeof error}`,
			);
		}
		// This is the enforceable output boundary: replace risky model text before
		// it is delivered, including turns influenced by a flagged tool result.
		api.on("message_sending", outputProtection.messageSending.bind(outputProtection), {
			priority: 100,
		});
		api.on("reply_payload_sending", outputProtection.replyPayloadSending.bind(outputProtection), {
			priority: 100,
		});
		// No approval tool is registered: the agent must not be able to approve
		// its own blocked actions. `ask` verdicts stay blocking until a human
		// approves out of band (see README.md).
		api.registerTool(
			createAllowlistAddTool(approvalStore, logger) as unknown as Record<string, unknown>,
		);
		api.registerTool(createAllowlistRemoveTool(logger) as unknown as Record<string, unknown>);
		api.on("gateway_start", createStartupScanHandler(logger, onFindings));
		api.on("session_start", createSessionScanHandler(logger, onFindings));
		api.on(
			"before_agent_start",
			createBeforeAgentStartHandler(
				() => pendingFindings,
				() => {
					pendingFindings = null;
				},
				logger,
			),
		);
	},
};
