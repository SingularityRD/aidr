/**
 * Singularity AIDR OpenClaw plugin entry point.
 * Registers tool-input enforcement, bounded post-execution/output protection,
 * allowlist tools, startup/session scan hooks, the before_prompt_build handler
 * and the before_agent_run prompt-protection gate (see prompt-protection.ts).
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
	IN_PROCESS_TOOL_CALL_DEADLINE,
	initFailureCode,
	initSentry,
	nullLogger,
	resolveHookDeadlineMs,
	scanProvisionedOutput,
	verifyArtifactIntegrityAndLog,
	withHookDeadline,
} from "@singularityrd/aidr-core";
import { createAllowlistAddTool, createAllowlistRemoveTool } from "./allowlist-tools.js";
import { getBundledDataDirs } from "./bundled-dirs.js";
import { createLogger, type PluginLogger } from "./logger-adapter.js";
import {
	type AfterToolCallEvent,
	OpenClawOutputProtection,
	type OutputHookContext,
	PRE_MODEL_INSPECTION_FAILURE_NOTICE,
	quarantinedToolResult,
	type ToolResultMiddlewareContext,
	type ToolResultMiddlewareEvent,
	type ToolResultMiddlewareResult,
} from "./output-protection.js";
import {
	type BeforeAgentRunEvent,
	type BeforePromptBuildEvent,
	OpenClawPromptProtection,
	type PromptHookContext,
} from "./prompt-protection.js";
import {
	feedQuarantinedOutput,
	feedToolOutcome,
	feedToolOutputCanaries,
	feedToolOutputFlow,
} from "./session-flow-feed.js";
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
	id?: string;
	config?: unknown;
	logger: PluginLogger;
	// biome-ignore lint/suspicious/noExplicitAny: OpenClaw handler signatures vary by event
	on(event: string, handler: (...args: any[]) => any, options?: { priority?: number }): void;
	registerTool(tool: Record<string, unknown>): void;
	/**
	 * OpenClaw 2026.9.x: tool-result middleware the embedded runner awaits before a
	 * tool result enters the model context. Installed plugins need
	 * `contracts.agentToolResultMiddleware` in the manifest and explicit enablement.
	 */
	registerAgentToolResultMiddleware?(
		handler: (
			event: ToolResultMiddlewareEvent,
			ctx: ToolResultMiddlewareContext,
		) => Promise<ToolResultMiddlewareResult | undefined>,
		options?: { runtimes?: string[] },
	): void;
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

const INTEGRITY_BLOCK_REASON =
	"Singularity AIDR could not verify its own installation integrity; tool calls are blocked until the plugin is reinstalled from a trusted release.";

/**
 * Gate the tool-call boundary on integrity. OpenClaw only enforces a block it
 * receives as `{ block: true }`; a thrown error is reported as a hook failure,
 * so an integrity failure is translated into an explicit block verdict.
 */
function blockUnlessIntegrity<TArgs extends unknown[], TResult>(
	requireIntegrity: () => Promise<void>,
	handler: (...args: TArgs) => TResult,
) {
	return async (...args: TArgs) => {
		try {
			await requireIntegrity();
		} catch {
			return { block: true as const, blockReason: INTEGRITY_BLOCK_REASON };
		}
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

const PLUGIN_ID = "aidr-openclaw";
/**
 * Only the embedded `openclaw` runtime feeds the middleware's result back to the
 * model. OpenClaw's Codex native-hook relay runs the same middleware but only
 * forwards its result to `after_tool_call`, so `codex` is deliberately not claimed.
 */
const TOOL_RESULT_MIDDLEWARE_RUNTIMES = ["openclaw"];

function initFailureQuarantine(reason: string): ToolResultMiddlewareResult {
	return quarantinedToolResult(
		`Singularity AIDR quarantined this tool output before it reached the model: ${reason}`,
		"quarantine_on_init_failure",
	);
}

/**
 * Whether OpenClaw's config explicitly enables this plugin
 * (`plugins.entries.aidr-openclaw.enabled: true`), which OpenClaw requires before
 * an installed plugin may register tool-result middleware. `undefined` when the
 * host supplied no readable config.
 */
function explicitlyEnabled(api: PluginApi): boolean | undefined {
	try {
		const config = api.config;
		if (!config || typeof config !== "object") return undefined;
		const plugins = Reflect.get(config, "plugins");
		const entries =
			plugins && typeof plugins === "object" ? Reflect.get(plugins, "entries") : undefined;
		const entry =
			entries && typeof entries === "object"
				? Reflect.get(entries, typeof api.id === "string" ? api.id : PLUGIN_ID)
				: undefined;
		return Boolean(entry && typeof entry === "object" && Reflect.get(entry, "enabled") === true);
	} catch {
		return undefined;
	}
}

type ToolResultMiddlewareHandler = (
	event: ToolResultMiddlewareEvent,
	ctx: ToolResultMiddlewareContext,
) => Promise<ToolResultMiddlewareResult | undefined>;

/**
 * Register the pre-model tool-output boundary. OpenClaw reports a rejected
 * registration only as a registry diagnostic, so every condition that leaves the
 * boundary unenforced (host without the API, registration throwing, plugin not
 * explicitly enabled) is reported through `onUnavailable` rather than implied clean.
 */
function registerToolResultQuarantine(
	api: PluginApi,
	handler: ToolResultMiddlewareHandler,
	onUnavailable: (reason: string) => void,
): void {
	const register = api.registerAgentToolResultMiddleware;
	if (typeof register !== "function") {
		onUnavailable("host does not offer registerAgentToolResultMiddleware");
		return;
	}
	try {
		Reflect.apply(register, api, [handler, { runtimes: TOOL_RESULT_MIDDLEWARE_RUNTIMES }]);
	} catch (error) {
		onUnavailable(
			`tool-result middleware registration failed: ${error instanceof Error ? error.name : typeof error}`,
		);
		return;
	}
	if (explicitlyEnabled(api) === false) {
		onUnavailable(
			`OpenClaw accepts tool-result middleware only when plugins.entries.${PLUGIN_ID}.enabled is true`,
		);
	}
}

/**
 * Wraps the tool-call gate so a failed integrity verification blocks every call with the
 * initialisation-failure reason instead of surfacing as an opaque handler rejection.
 */
function integrityGatedToolCall(
	integrityReady: Promise<unknown>,
	handler: (event: ToolCallEvent, ctx?: ToolCallContext) => Promise<BlockResult | undefined>,
) {
	const gated = async (
		event: ToolCallEvent,
		ctx?: ToolCallContext,
	): Promise<BlockResult | undefined> => {
		try {
			await integrityReady;
		} catch (error) {
			return initFailureBlock(error);
		}
		return await handler(event, ctx);
	};
	// In-process, so there is no process to exit: a call whose inspection (or
	// the integrity wait) stalls past the deadline is blocked rather than held
	// open (`AIDR_TOOL_CALL_DEADLINE_MS`, default 20 s).
	return (event: ToolCallEvent, ctx?: ToolCallContext): Promise<BlockResult | undefined> =>
		withHookDeadline(
			gated(event, ctx),
			resolveHookDeadlineMs(IN_PROCESS_TOOL_CALL_DEADLINE, process.env),
			() => ({
				block: true,
				blockReason:
					"Singularity AIDR could not finish evaluating this tool call in time; execution was denied.",
			}),
		);
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
	// A tool result produced anyway (for instance the block itself) is replaced
	// before the model receives it.
	try {
		registerToolResultQuarantine(
			api,
			async () => initFailureQuarantine(block.blockReason),
			() => undefined,
		);
	} catch {
		// The tool-call gate above is the primary fail-closed boundary.
	}
	// Prompts cannot be inspected either: apply the uninspected-prompt policy
	// (block unless `prompt_protection.secrets` is not `block`). The host fails
	// closed if this handler itself throws.
	try {
		api.on(
			"before_agent_run",
			async (_event: unknown, ctx?: PromptHookContext) =>
				OpenClawPromptProtection.uninspectedDecision(nullLogger, ctx),
			{ priority: 100 },
		);
	} catch {
		// A host without this gate has no prompt boundary to close.
	}
}

function registerGuarded(api: PluginApi): void {
	// Initialize Sentry
	initSentry({ name: "aidr-openclaw" });

	const logger = createLogger(api.logger);
	const integrityReady = verifyArtifactIntegrityAndLog({
		artifactDir: __dirname,
		artifactId: "openclaw/dist",
		logger,
	}).then(async () => {
		// Initialize the fail-closed synchronous persistence snapshot. Each
		// asynchronous output hook refreshes it before inspecting its payload.
		await scanProvisionedOutput([], "openclaw");
	});
	// Every guarded surface awaits `integrityReady` and observes the rejection itself; this
	// only stops Node from reporting it as unhandled before the first hook runs.
	integrityReady.catch((error: unknown) => {
		logger.error("Singularity AIDR integrity verification failed; guarded surfaces are blocked", {
			error: error instanceof Error ? error.message : String(error),
		});
	});
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
		afterIntegrity(
			requireIntegrity,
			async (event: AfterToolCallEvent, context?: OutputHookContext) => {
				const inspection = await outputProtection.afterToolCall(event, context);
				// A result quarantined before the model already fed the flow and canary
				// records from the original output; the host hands this hook the notice.
				if (!outputProtection.wasQuarantinedBeforeModel(event?.toolCallId)) {
					// Session toxic-flow: secrets or injection payloads this output carried
					// taint the session for its next calls. Never throws.
					await feedToolOutputFlow(event, context, inspection, logger);
					// Canary value in the output: audit entry and managed incident. Never throws.
					await feedToolOutputCanaries(event, context, logger);
				}
				// Runaway guard: a failed call counts towards the repeated-failure loop.
				await feedToolOutcome(event, context, logger);
			},
		),
	);
	// Pre-model boundary: OpenClaw awaits this middleware after the tool ran and
	// before its result enters the model context, so a risky result is replaced
	// by AIDR's quarantine notice for the same-turn model. The original is never
	// handed back on error: an integrity or handler failure also quarantines.
	registerToolResultQuarantine(
		api,
		async (event, ctx) => {
			try {
				await integrityReady;
			} catch (error) {
				return initFailureQuarantine(formatInitFailureMessage(initFailureCode(error)));
			}
			try {
				// Refresh signed output-policy trust; a refresh failure quarantines below.
				await scanProvisionedOutput([], "openclaw");
				const { replacement, inspection } = outputProtection.toolResultMiddleware(event, ctx);
				if (replacement) await feedQuarantinedOutput(event, ctx, inspection, logger);
				return replacement;
			} catch {
				return quarantinedToolResult(
					PRE_MODEL_INSPECTION_FAILURE_NOTICE,
					"quarantine_on_inspection_error",
				);
			}
		},
		(reason) => outputProtection.recordPreModelBoundaryUnavailable(reason),
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
	// Prompt protection gate: blocks a prompt carrying secrets (or, per policy,
	// personal data) before the model reads it. The host fails closed on a throw.
	const prompts = new OpenClawPromptProtection(logger);
	try {
		api.on(
			"before_agent_run",
			async (event: BeforeAgentRunEvent, ctx?: PromptHookContext) => {
				try {
					await integrityReady;
				} catch {
					return OpenClawPromptProtection.uninspectedDecision(logger, ctx);
				}
				return prompts.beforeAgentRun(event, ctx);
			},
			{ priority: 100 },
		);
	} catch (error) {
		logger.warn("Singularity AIDR prompt protection unavailable: before_agent_run not registered", {
			error: error instanceof Error ? error.name : typeof error,
		});
	}
	const surfaceScanFindings = createBeforePromptBuildHandler(
		() => pendingFindings,
		() => {
			pendingFindings = null;
		},
		logger,
	);
	api.on(
		"before_prompt_build",
		afterIntegrity(
			requireIntegrity,
			async (event?: BeforePromptBuildEvent, ctx?: PromptHookContext) => {
				const findings = surfaceScanFindings()?.prependContext;
				// The prompt-protection warn notice; a block is left to the gate above.
				let warning: string | undefined;
				try {
					warning = await prompts.warningContext(event ?? {}, ctx);
				} catch {
					warning = undefined;
				}
				const context = [findings, warning].filter((part): part is string => Boolean(part));
				return context.length > 0 ? { prependContext: context.join("\n\n") } : undefined;
			},
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
