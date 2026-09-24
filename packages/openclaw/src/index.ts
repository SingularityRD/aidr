/**
 * Singularity AIDR OpenClaw plugin entry point.
 * Registers tool-input enforcement, bounded post-execution/output protection,
 * allowlist tools, startup/session scan hooks, and before_prompt_build handler.
 *
 * SECURITY: this plugin deliberately registers NO approval tool. An approval
 * tool callable by the model would let a prompt-injected agent approve its own
 * blocked action (it receives the actionId in the block message). Approval
 * authority must be an action the agent cannot perform, so `ask` verdicts stay
 * blocking. See README.md ("Approving a flagged action").
 */

import {
	ApprovalStore,
	formatInitFailureMessage,
	initFailureCode,
	initSentry,
	verifyArtifactIntegrityAndLog,
} from "@singularityrd/aidr-core";
import { createAllowlistAddTool, createAllowlistRemoveTool } from "./allowlist-tools.js";
import { getBundledDataDirs } from "./bundled-dirs.js";
import { createLogger, type PluginLogger } from "./logger-adapter.js";
import { OpenClawOutputProtection } from "./output-protection.js";
import {
	createBeforePromptBuildHandler,
	createSessionScanHandler,
	createStartupScanHandler,
} from "./startup-scan.js";
import {
	type BlockResult,
	createToolCallHandler,
	type ToolCallContext,
	type ToolCallEvent,
} from "./tool-handler.js";

interface PluginApi {
	logger: PluginLogger;
	// biome-ignore lint/suspicious/noExplicitAny: OpenClaw handler signatures vary by event
	on(event: string, handler: (...args: any[]) => any, options?: { priority?: number }): void;
	registerTool(tool: Record<string, unknown>): void;
}

declare const __dirname: string;

function afterIntegrity<TArgs extends unknown[], TResult>(
	requireIntegrity: () => Promise<void>,
	handler: (...args: TArgs) => TResult,
) {
	return async (...args: TArgs) => {
		await requireIntegrity();
		return await handler(...args);
	};
}

function integrityGatedTool(
	requireIntegrity: () => Promise<void>,
	tool: Record<string, unknown>,
): Record<string, unknown> {
	const execute = tool.execute;
	if (typeof execute !== "function") return tool;
	return {
		...tool,
		execute: async (...args: unknown[]) => {
			await requireIntegrity();
			return Reflect.apply(execute, tool, args);
		},
	};
}

function initFailureBlock(error: unknown): BlockResult {
	return { block: true, blockReason: formatInitFailureMessage(initFailureCode(error)) };
}

/**
 * Wraps the tool-call gate so a failed integrity verification blocks every call with the
 * initialisation-failure reason instead of surfacing as an opaque handler rejection.
 */
function integrityGatedToolCall(
	integrityReady: Promise<unknown>,
	handler: (event: ToolCallEvent, ctx?: ToolCallContext) => Promise<BlockResult | undefined>,
) {
	return async (event: ToolCallEvent, ctx?: ToolCallContext): Promise<BlockResult | undefined> => {
		try {
			await integrityReady;
		} catch (error) {
			return initFailureBlock(error);
		}
		return await handler(event, ctx);
	};
}

/**
 * SECURITY: OpenClaw loads this plugin in-process. If `register` throws, the host never
 * registers the gate and every tool call runs uninspected (fail-open). Any initialisation
 * failure therefore still registers `before_tool_call`, blocking every call until fixed.
 */
function registerInitFailure(api: PluginApi, error: unknown): void {
	const block = initFailureBlock(error);
	try {
		api.logger.error(
			`Singularity AIDR OpenClaw initialisation failed closed (${block.blockReason}): ${String(error)}`,
		);
	} catch {
		// Logging must never undo the fail-closed registration below.
	}
	api.on("before_tool_call", async () => block, { priority: 100 });
}

function registerGuarded(api: PluginApi): void {
	// Initialize Sentry
	initSentry({ name: "aidr-openclaw" });

	const logger = createLogger(api.logger);
	const integrityReady = verifyArtifactIntegrityAndLog({
		artifactDir: __dirname,
		artifactId: "openclaw/dist",
		logger,
	});
	// Every guarded surface awaits `integrityReady` and observes the rejection itself; this
	// only stops Node from reporting it as unhandled before the first hook runs.
	integrityReady.catch(() => undefined);
	const requireIntegrity = async () => {
		// Do not convert a rejected commercial verification into a fulfilled
		// readiness promise; every guarded surface must observe the failure.
		await integrityReady;
	};
	const approvalStore = new ApprovalStore();
	const outputProtection = new OpenClawOutputProtection(logger);
	const { threatsDir, allowlistsDir } = getBundledDataDirs();
	const toolCallHandler = createToolCallHandler(approvalStore, logger, threatsDir, allowlistsDir);

	const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;
	const interval = setInterval(() => approvalStore.cleanup(), CLEANUP_INTERVAL_MS);
	if (typeof interval.unref === "function") interval.unref();

	// Shared state: scan findings waiting to be surfaced to the user
	let pendingFindings: string | null = null;
	const onFindings = (msg: string) => {
		pendingFindings = msg;
	};

	api.on("before_tool_call", integrityGatedToolCall(integrityReady, toolCallHandler), {
		priority: 100,
	});

	api.on(
		"after_tool_call",
		afterIntegrity(requireIntegrity, outputProtection.afterToolCall.bind(outputProtection)),
	);
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
	api.on(
		"message_sending",
		afterIntegrity(requireIntegrity, outputProtection.messageSending.bind(outputProtection)),
		{ priority: 100 },
	);
	api.on(
		"reply_payload_sending",
		afterIntegrity(requireIntegrity, outputProtection.replyPayloadSending.bind(outputProtection)),
		{ priority: 100 },
	);
	// No approval tool is registered: the agent must not be able to approve
	// its own blocked actions. `ask` verdicts stay blocking until a human
	// approves out of band (see README.md).
	api.registerTool(
		integrityGatedTool(
			requireIntegrity,
			createAllowlistAddTool(approvalStore, logger) as unknown as Record<string, unknown>,
		),
	);
	api.registerTool(
		integrityGatedTool(
			requireIntegrity,
			createAllowlistRemoveTool(logger) as unknown as Record<string, unknown>,
		),
	);
	api.on(
		"gateway_start",
		afterIntegrity(requireIntegrity, createStartupScanHandler(logger, onFindings)),
	);
	api.on(
		"session_start",
		afterIntegrity(requireIntegrity, createSessionScanHandler(logger, onFindings)),
	);
	api.on(
		"before_prompt_build",
		afterIntegrity(
			requireIntegrity,
			createBeforePromptBuildHandler(
				() => pendingFindings,
				() => {
					pendingFindings = null;
				},
				logger,
			),
		),
	);
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
		try {
			registerGuarded(api);
		} catch (error) {
			registerInitFailure(api, error);
		}
	},
};
