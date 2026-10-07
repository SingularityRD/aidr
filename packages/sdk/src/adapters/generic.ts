/**
 * Generic middleware adapter for AIDR SDK
 *
 * Provides a flexible middleware pattern for integrating AIDR security
 * into any AI agent framework. Supports both async and sync tool patterns
 * with before/after hooks for customization.
 */

import { type AgentRuntime, extractFromUnknownTool } from "@singularityrd/aidr-core";
import type { AIDRClient } from "../client.js";
import type { CheckRequest, CheckResult } from "../config.js";
import { enforceCheckResult, isInconsistent } from "../enforcement.js";
import {
	formatToolOutputBlockReason,
	guardProvisionedToolOutput,
	guardToolOutput,
	type ToolOutputGuardOptions,
} from "../output-guard.js";
import { assertPrivacyCallbacksAllowed } from "../privacy-text.js";

/**
 * Context passed through the middleware chain
 */
export interface MiddlewareContext {
	/** Tool name being executed */
	tool: string;
	/** Tool input as a string */
	input: string;
	/** Typed artifacts extracted from a structured tool input. */
	artifacts?: CheckRequest["artifacts"];
	/** Optional metadata for the request */
	metadata?: Record<string, unknown>;
	/** Session ID for tracking */
	sessionId?: string;
}

/**
 * Error thrown when AIDR blocks an operation through middleware
 */
export class AIDRMiddlewareError extends Error {
	constructor(
		message: string,
		public readonly verdict: CheckResult,
		public readonly context: MiddlewareContext,
	) {
		super(message);
		this.name = "AIDRMiddlewareError";
	}
}

/**
 * Options for creating generic middleware
 */
export interface MiddlewareOptions {
	/** Callback when verdict is deny */
	onDeny?: (ctx: MiddlewareContext, verdict: CheckResult) => void;
	/**
	 * Callback when verdict is ask - return true to approve, false to deny.
	 * When omitted, an `ask` verdict blocks (fail-closed).
	 */
	onAsk?: (ctx: MiddlewareContext, verdict: CheckResult) => Promise<boolean> | boolean;
	/** Callback when verdict is allow */
	onAllow?: (ctx: MiddlewareContext, verdict: CheckResult) => void;
	/** Callback before security check */
	beforeCheck?: (ctx: MiddlewareContext) => void | Promise<void>;
	/** Callback after security check (after tool execution too) */
	afterCheck?: (
		ctx: MiddlewareContext,
		verdict: CheckResult,
		result?: unknown,
	) => void | Promise<void>;
	/** Whether to throw on deny (default: true) */
	throwOnDeny?: boolean;
	/**
	 * Allow an indeterminate result (failed/inconsistent security check) to be
	 * routed to `onAsk`. Defaults to `false`.
	 */
	allowApprovalOfIndeterminateResults?: boolean;
	/** Custom error message formatter */
	formatErrorMessage?: (ctx: MiddlewareContext, verdict: CheckResult) => string;
	/** Optional metadata for the request */
	metadata?: Record<string, unknown>;
	/** Inspect the returned tool value before it is delivered to the model. */
	outputGuard?: ToolOutputGuardOptions;
	/**
	 * Fixed local connector profile for signed tenant output DLP. Set by the host
	 * at middleware construction; never inferred from a tool input or metadata.
	 */
	agentRuntime?: AgentRuntime;
}

/**
 * Next function in the middleware chain
 */
export type NextFunction = () => Promise<unknown>;

/**
 * Middleware function type
 */
export type MiddlewareFunction = (
	context: MiddlewareContext,
	next: NextFunction,
) => Promise<unknown>;

function isPromiseLike(value: unknown): value is PromiseLike<unknown> {
	return (
		typeof value === "object" &&
		value !== null &&
		"then" in value &&
		typeof (value as { then?: unknown }).then === "function"
	);
}

const COMMAND_TOOL_SUFFIX =
	/(?:^|_)(?:bash|batch(?:_file)?|cmd(?:_exe)?|command(?:_execution)?|execute_command|fish|powershell|pwsh|run_command|run_shell(?:_command)?|sh|shell(?:_command|_exec)?|terminal|zsh)$/;

/** Name tokens of tools that run code: every string they receive is treated as a command. */
const CODE_TOKENS = new Set([
	"code_interpreter",
	"eval",
	"evaluate",
	"exec",
	"execute",
	"interpreter",
	"javascript",
	"jupyter",
	"node",
	"notebook",
	"python",
	"repl",
	"ruby",
	"sandbox",
	"script",
	"shell",
	"subprocess",
]);
/** "run" alone is too generic; with one of these it is a code-running tool. */
const RUN_OBJECT_TOKENS = new Set(["code", "js", "program", "py", "script", "snippet"]);
const FETCH_TOKENS = new Set([
	"browse",
	"browser",
	"crawl",
	"curl",
	"download",
	"fetch",
	"http",
	"https",
	"navigate",
	"request",
	"scrape",
	"uri",
	"url",
	"urls",
	"web",
	"webpage",
	"website",
	"wget",
]);
const WRITE_TOKENS = new Set([
	"append",
	"create",
	"delete",
	"edit",
	"mkdir",
	"move",
	"patch",
	"remove",
	"rename",
	"replace",
	"rm",
	"save",
	"upload",
	"write",
]);
const READ_TOKENS = new Set([
	"cat",
	"dir",
	"directory",
	"file",
	"files",
	"glob",
	"grep",
	"head",
	"list",
	"load",
	"ls",
	"open",
	"path",
	"read",
	"tail",
	"view",
]);

function toolNameTokens(tool: string): string[] {
	const normalized = tool
		.trim()
		.replace(/([a-z0-9])([A-Z])/g, "$1_$2")
		.toLowerCase()
		.replace(/[.\s/:-]+/g, "_")
		.replace(/_+/g, "_")
		.replace(/^_|_$/g, "");
	return normalized === "" ? [] : normalized.split("_");
}

type ToolKind = "execute" | "fetch" | "write" | "read" | "other";

/**
 * Classify a tool by its name. Code-running tools are checked first so a name
 * such as `run_python_file` is never downgraded to a plain file read; an
 * unrecognised name keeps the tool name as the action and is checked as
 * content plus every artifact the generic extractor finds in its input.
 */
function toolKind(tool: string): ToolKind {
	const tokens = toolNameTokens(tool);
	const joined = tokens.join("_");
	if (COMMAND_TOOL_SUFFIX.test(joined)) return "execute";
	if (joined.includes("code_interpreter")) return "execute";
	if (tokens.some((token) => CODE_TOKENS.has(token))) return "execute";
	if (tokens.includes("run") && tokens.some((token) => RUN_OBJECT_TOKENS.has(token))) {
		return "execute";
	}
	if (tokens.some((token) => FETCH_TOKENS.has(token))) return "fetch";
	if (tokens.some((token) => WRITE_TOKENS.has(token))) return "write";
	if (tokens.some((token) => READ_TOKENS.has(token))) return "read";
	return "other";
}

/** Parse the middleware input string into the object shape the extractor walks. */
function parsedToolInput(input: string): Record<string, unknown> {
	let parsed: unknown;
	try {
		parsed = JSON.parse(input);
	} catch {
		return { input };
	}
	if (Array.isArray(parsed)) {
		const only = parsed.length === 1 ? parsed[0] : undefined;
		return typeof only === "object" && only !== null && !Array.isArray(only)
			? (only as Record<string, unknown>)
			: { args: parsed };
	}
	return typeof parsed === "object" && parsed !== null
		? (parsed as Record<string, unknown>)
		: { input: parsed };
}

type Artifacts = NonNullable<CheckRequest["artifacts"]>;

/**
 * Build the check request for one tool call.
 *
 * - Typed artifacts: the caller's `context.artifacts`, or (when absent) the
 *   core generic extractor run on the parsed input, so URL, command, file-path
 *   and content rules all apply whatever the tool is called.
 * - `fetch`/`read`/`write` tools: the first URL / file path becomes the
 *   resource, so URL reputation and file-path rules run on that value.
 * - Code-running tools (`execute`): every extracted string is also inspected
 *   as a command, so `run_code({"code": "curl … | bash"})` is checked exactly
 *   like a shell tool.
 */
export function toCheckRequest(context: MiddlewareContext): CheckRequest {
	const kind = toolKind(context.tool);
	const extracted: Artifacts =
		context.artifacts ?? extractFromUnknownTool(context.tool, parsedToolInput(context.input));
	let artifacts: Artifacts = extracted;
	let action = context.tool;
	let resource = context.input;

	if (kind === "execute") {
		action = "execute";
		const asCommands: Artifacts = extracted
			.filter((artifact) => artifact.type === "content" && !artifact.context?.startsWith("aidr:"))
			.map((artifact) => ({ ...artifact, type: "command" as const }));
		artifacts = [...extracted, ...asCommands];
	} else if (kind !== "other") {
		const wanted = kind === "fetch" ? "url" : "file_path";
		const primary = extracted.find((artifact) => artifact.type === wanted);
		if (primary) {
			action = kind;
			resource = primary.value;
			// The raw input is still inspected as content.
			artifacts = [...extracted, { type: "content", value: context.input, context: "tool_input" }];
		}
	}

	return {
		action,
		resource,
		artifacts,
		sessionId: context.sessionId,
		metadata: context.metadata,
	};
}

function outputBlockedResult(reason: string): CheckResult {
	return {
		allowed: false,
		decision: "deny",
		confidence: 1,
		reason,
		metadata: { outputInspection: true },
	};
}

async function guardResult(
	result: unknown,
	context: MiddlewareContext,
	options: MiddlewareOptions,
	agentRuntime: AgentRuntime | undefined,
): Promise<unknown> {
	await assertPrivacyCallbacksAllowed();
	const guarded =
		agentRuntime === undefined
			? guardToolOutput(result, options.outputGuard)
			: await guardProvisionedToolOutput(result, agentRuntime, options.outputGuard);
	await assertPrivacyCallbacksAllowed();
	if (guarded.delivery !== "block") return guarded.output;

	const reason = formatToolOutputBlockReason(guarded.inspection);
	const blockedVerdict = outputBlockedResult(reason);
	if (options.afterCheck) {
		await assertPrivacyCallbacksAllowed();
		await options.afterCheck(context, blockedVerdict, undefined);
	}
	await assertPrivacyCallbacksAllowed();
	if (options.throwOnDeny === false) return undefined;
	throw new AIDRMiddlewareError(reason, blockedVerdict, context);
}

/**
 * Shared fail-closed enforcement for the async and sync middleware.
 *
 * Uses the same semantic as every other SDK surface: `deny` never executes,
 * `ask` executes only after an explicit approval from the caller-supplied
 * `onAsk` callback, and an indeterminate/failed check is never approved.
 * `throwOnDeny: false` only softens `deny` (return without calling `next()`);
 * `ask` and indeterminate results still throw.
 */
async function enforceVerdict(
	context: MiddlewareContext,
	verdict: CheckResult,
	options: MiddlewareOptions,
): Promise<void> {
	const onAskOption = options.onAsk;
	const outcome = await enforceCheckResult(verdict, {
		onAsk: onAskOption
			? async (result) => {
					await assertPrivacyCallbacksAllowed();
					return onAskOption(context, result);
				}
			: undefined,
		allowApprovalOfIndeterminateResults: options.allowApprovalOfIndeterminateResults,
	});

	if (outcome.execute) return;

	if (options.formatErrorMessage) await assertPrivacyCallbacksAllowed();
	const message = options.formatErrorMessage
		? options.formatErrorMessage(context, verdict)
		: outcome.message;

	await assertPrivacyCallbacksAllowed();
	throw new AIDRMiddlewareError(message, verdict, context);
}

async function enforceConsistency(
	context: MiddlewareContext,
	verdict: CheckResult,
	options: MiddlewareOptions,
): Promise<void> {
	if (isInconsistent(verdict)) await enforceVerdict(context, verdict, options);
}

/**
 * Creates a generic AIDR middleware function.
 *
 * This middleware:
 * 1. Calls beforeCheck hook
 * 2. Performs security check via AIDR client
 * 3. Handles verdict (deny/ask/allow) with callbacks
 * 4. Executes next() if allowed
 * 5. Calls afterCheck hook
 *
 * @param aidrClient - AIDR client for security checks
 * @param options - Middleware options with callbacks
 * @returns Middleware function for use in any framework
 *
 * @example
 * ```typescript
 * const middleware = createMiddleware(aidrClient, {
 *   onDeny: (ctx, verdict) => console.error(`Blocked: ${verdict.reason}`),
 *   onAsk: async (ctx, verdict) => {
 *     // Show approval dialog
 *     return await showApprovalDialog(ctx, verdict);
 *   }
 * });
 *
 * // Use in any framework
 * app.use(middleware);
 * ```
 */
export function createMiddleware(
	aidrClient: AIDRClient,
	options: MiddlewareOptions = {},
): MiddlewareFunction {
	const agentRuntime = options.agentRuntime;
	return async (context: MiddlewareContext, next: NextFunction): Promise<unknown> => {
		await assertPrivacyCallbacksAllowed();
		// Call beforeCheck hook
		if (options.beforeCheck) {
			await options.beforeCheck(context);
		}

		// Build check request from context
		const checkRequest = toCheckRequest(context);

		// Perform security check
		const verdict = await aidrClient.check(checkRequest);
		await enforceConsistency(context, verdict, options);

		// Handle deny verdict
		if (verdict.decision === "deny") {
			if (options.onDeny) {
				await assertPrivacyCallbacksAllowed();
				options.onDeny(context, verdict);
			}

			if (options.throwOnDeny !== false) {
				if (options.formatErrorMessage) await assertPrivacyCallbacksAllowed();
				const message = options.formatErrorMessage
					? options.formatErrorMessage(context, verdict)
					: `Blocked: ${verdict.reason}`;
				await assertPrivacyCallbacksAllowed();
				throw new AIDRMiddlewareError(message, verdict, context);
			}

			// Return null/undefined if not throwing
			if (options.afterCheck) {
				await assertPrivacyCallbacksAllowed();
				await options.afterCheck(context, verdict, undefined);
			}
			return undefined;
		}

		// Handle ask verdict (and indeterminate/failed checks) - fail-closed
		if (verdict.decision !== "allow") {
			await enforceVerdict(context, verdict, options);
		}

		// Call onAllow hook
		if (verdict.decision === "allow" && options.onAllow) {
			await assertPrivacyCallbacksAllowed();
			options.onAllow(context, verdict);
		}

		// Execute the next function (actual tool/operation)
		let result: unknown;
		try {
			await aidrClient.assertCallerOperationAllowed();
			result = await next();
		} catch (error) {
			await assertPrivacyCallbacksAllowed();
			// Still call afterCheck on error
			if (options.afterCheck) {
				await assertPrivacyCallbacksAllowed();
				await options.afterCheck(context, verdict, undefined);
			}
			await assertPrivacyCallbacksAllowed();
			throw error;
		}
		result = await guardResult(result, context, options, agentRuntime);

		// Call afterCheck hook
		if (options.afterCheck) {
			await assertPrivacyCallbacksAllowed();
			await options.afterCheck(context, verdict, result);
		}

		await assertPrivacyCallbacksAllowed();
		return result;
	};
}

/**
 * Creates a sync-compatible middleware that works with both sync and async tools.
 *
 * This is useful for frameworks that expect synchronous execution but still
 * need async security checks.
 *
 * @param aidrClient - AIDR client for security checks
 * @param options - Middleware options
 * @returns Object with async and sync variants
 *
 * @example
 * ```typescript
 * const middleware = createSyncCompatibleMiddleware(aidrClient, {
 *   onDeny: (ctx, verdict) => console.error('Blocked!')
 * });
 *
 * // Use async version
 * await middleware.async(ctx, async () => tool.run());
 *
 * // Use sync version (returns Promise)
 * middleware.sync(ctx, () => syncTool.run());
 * ```
 */
export function createSyncCompatibleMiddleware(
	aidrClient: AIDRClient,
	options: MiddlewareOptions = {},
): {
	async: MiddlewareFunction;
	sync: (context: MiddlewareContext, next: () => unknown) => Promise<unknown>;
} {
	const asyncMiddleware = createMiddleware(aidrClient, options);
	const agentRuntime = options.agentRuntime;

	return {
		async: asyncMiddleware,
		sync: async (context: MiddlewareContext, next: () => unknown): Promise<unknown> => {
			await assertPrivacyCallbacksAllowed();
			// Call beforeCheck hook
			if (options.beforeCheck) {
				await options.beforeCheck(context);
			}

			// Build check request
			const checkRequest = toCheckRequest(context);

			// Perform security check
			const verdict = await aidrClient.check(checkRequest);
			await enforceConsistency(context, verdict, options);

			// Handle deny
			if (verdict.decision === "deny") {
				if (options.onDeny) {
					await assertPrivacyCallbacksAllowed();
					options.onDeny(context, verdict);
				}
				if (options.throwOnDeny !== false) {
					if (options.formatErrorMessage) await assertPrivacyCallbacksAllowed();
					const message = options.formatErrorMessage
						? options.formatErrorMessage(context, verdict)
						: `Blocked: ${verdict.reason}`;
					await assertPrivacyCallbacksAllowed();
					throw new AIDRMiddlewareError(message, verdict, context);
				}
				return undefined;
			}

			// Handle ask (and indeterminate/failed checks) - fail-closed
			if (verdict.decision !== "allow") {
				await enforceVerdict(context, verdict, options);
			}

			// Call onAllow
			if (verdict.decision === "allow" && options.onAllow) {
				await assertPrivacyCallbacksAllowed();
				options.onAllow(context, verdict);
			}

			// Execute sync next()
			let result: unknown;
			try {
				await aidrClient.assertCallerOperationAllowed();
				const candidate = next();
				// Handle if next() returns a Promise
				result = isPromiseLike(candidate) ? await candidate : candidate;
			} catch (error) {
				await assertPrivacyCallbacksAllowed();
				if (options.afterCheck) {
					await assertPrivacyCallbacksAllowed();
					await options.afterCheck(context, verdict, undefined);
				}
				await assertPrivacyCallbacksAllowed();
				throw error;
			}
			result = await guardResult(result, context, options, agentRuntime);

			// Call afterCheck
			if (options.afterCheck) {
				await assertPrivacyCallbacksAllowed();
				await options.afterCheck(context, verdict, result);
			}

			await assertPrivacyCallbacksAllowed();
			return result;
		},
	};
}

/**
 * Composes multiple middleware functions into a single middleware.
 *
 * @param middlewares - Array of middleware functions to compose
 * @returns Composed middleware function
 *
 * @example
 * ```typescript
 * const composed = composeMiddleware([
 *   loggingMiddleware,
 *   aidrMiddleware,
 *   metricsMiddleware
 * ]);
 * ```
 */
export function composeMiddleware(middlewares: MiddlewareFunction[]): MiddlewareFunction {
	return async (context: MiddlewareContext, next: NextFunction): Promise<unknown> => {
		let index = -1;

		async function dispatch(i: number): Promise<unknown> {
			if (i <= index) {
				throw new Error("next() called multiple times in middleware");
			}
			index = i;
			await assertPrivacyCallbacksAllowed();

			const middleware = middlewares[i];
			if (!middleware) {
				// All middleware consumed, call final next
				return next();
			}

			return middleware(context, () => dispatch(i + 1));
		}

		return dispatch(0);
	};
}

/**
 * Creates a tool wrapper using the generic middleware pattern.
 *
 * @param tool - The tool to wrap
 * @param aidrClient - AIDR client for security checks
 * @param options - Middleware options
 * @returns Wrapped tool with AIDR security
 *
 * @example
 * ```typescript
 * const secureTool = wrapToolWithMiddleware(
 *   myTool,
 *   aidrClient,
 *   {
 *     onDeny: (ctx) => console.error(`Tool ${ctx.tool} blocked`)
 *   }
 * );
 * ```
 */
export function wrapToolWithMiddleware(
	tool: { name: string; run: (...args: unknown[]) => unknown },
	aidrClient: AIDRClient,
	options: MiddlewareOptions = {},
): { name: string; run: (...args: unknown[]) => Promise<unknown> } {
	const middleware = createMiddleware(aidrClient, options);

	return {
		name: tool.name,
		run: async (...args: unknown[]): Promise<unknown> => {
			await assertPrivacyCallbacksAllowed();
			const input = JSON.stringify(args);
			if (typeof input !== "string") {
				throw new TypeError("Tool input could not be serialized for security inspection");
			}
			const parsedArgs = JSON.parse(input) as unknown[];
			const firstArg = parsedArgs.length === 1 ? parsedArgs[0] : undefined;
			const toolInput =
				typeof firstArg === "object" && firstArg !== null && !Array.isArray(firstArg)
					? (firstArg as Record<string, unknown>)
					: { args: parsedArgs };
			const context: MiddlewareContext = {
				tool: tool.name,
				input,
				artifacts: extractFromUnknownTool(tool.name, toolInput),
				sessionId:
					typeof options.metadata?.sessionId === "string" ? options.metadata.sessionId : undefined,
				metadata: options.metadata,
			};

			// Execute the same JSON snapshot that was inspected, so toJSON hooks or
			// caller mutations cannot replace checked input with an unchecked value.
			return middleware(context, async () => tool.run(...parsedArgs));
		},
	};
}

/**
 * Creates a pipeline of middleware functions that executes in sequence.
 *
 * @param aidrClient - AIDR client for security checks
 * @param pipelineOptions - Array of middleware options for each stage
 * @returns Pipeline function
 *
 * @example
 * ```typescript
 * const pipeline = createMiddlewarePipeline(aidrClient, [
 *   { onDeny: (ctx, v) => log('Stage 1', ctx) },
 *   { onDeny: (ctx, v) => log('Stage 2', ctx) }
 * ]);
 *
 * const result = await pipeline({ tool: 'bash', input: 'ls' }, async () => execute());
 * ```
 */
export function createMiddlewarePipeline(
	aidrClient: AIDRClient,
	pipelineOptions: MiddlewareOptions[],
): MiddlewareFunction {
	const middlewares = pipelineOptions.map((opts) => createMiddleware(aidrClient, opts));
	return composeMiddleware(middlewares);
}
