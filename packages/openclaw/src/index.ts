/**
 * Singularity AIDR OpenClaw plugin entry point.
 * Registers before_tool_call handler, aidr_approve tool, allowlist tools,
 * startup/session scan hooks, and before_agent_start handler.
 */

import { ApprovalStore, initSentry } from "@singularityrd/aidr-core";
import { createAllowlistAddTool, createAllowlistRemoveTool } from "./allowlist-tools.js";
import { getBundledDataDirs } from "./bundled-dirs.js";
import { createAidrApproveTool } from "./gate-tool.js";
import { createLogger, type PluginLogger } from "./logger-adapter.js";
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
		api.registerTool(createAidrApproveTool(approvalStore) as unknown as Record<string, unknown>);
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
