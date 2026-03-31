/**
 * Generic middleware adapter for AIDR SDK
 *
 * Provides a flexible middleware pattern for integrating AIDR security
 * into any AI agent framework. Supports both async and sync tool patterns
 * with before/after hooks for customization.
 */

import type { AIDRClient } from "../client.js";
import type { CheckRequest, CheckResult } from "../config.js";

/**
 * Context passed through the middleware chain
 */
export interface MiddlewareContext {
	/** Tool name being executed */
	tool: string;
	/** Tool input as a string */
	input: string;
	/** Optional metadata for the request */
	metadata?: Record<string, any>;
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
	/** Callback when verdict is ask - return true to approve, false to deny */
	onAsk?: (ctx: MiddlewareContext, verdict: CheckResult) => Promise<boolean> | boolean;
	/** Callback when verdict is allow */
	onAllow?: (ctx: MiddlewareContext, verdict: CheckResult) => void;
	/** Callback before security check */
	beforeCheck?: (ctx: MiddlewareContext) => void | Promise<void>;
	/** Callback after security check (after tool execution too) */
	afterCheck?: (ctx: MiddlewareContext, verdict: CheckResult, result?: any) => void | Promise<void>;
	/** Whether to throw on deny (default: true) */
	throwOnDeny?: boolean;
	/** Custom error message formatter */
	formatErrorMessage?: (ctx: MiddlewareContext, verdict: CheckResult) => string;
	/** Optional metadata for the request */
	metadata?: Record<string, any>;
}

/**
 * Next function in the middleware chain
 */
export type NextFunction = () => Promise<any>;

/**
 * Middleware function type
 */
export type MiddlewareFunction = (context: MiddlewareContext, next: NextFunction) => Promise<any>;

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
	return async (context: MiddlewareContext, next: NextFunction): Promise<any> => {
		// Call beforeCheck hook
		if (options.beforeCheck) {
			await options.beforeCheck(context);
		}

		// Build check request from context
		const checkRequest: CheckRequest = {
			action: context.tool,
			resource: context.input,
			sessionId: context.sessionId,
			metadata: context.metadata,
		};

		// Perform security check
		const verdict = await aidrClient.check(checkRequest);

		// Handle deny verdict
		if (verdict.decision === "deny") {
			options.onDeny?.(context, verdict);

			if (options.throwOnDeny !== false) {
				const message = options.formatErrorMessage
					? options.formatErrorMessage(context, verdict)
					: `Blocked: ${verdict.reason}`;
				throw new AIDRMiddlewareError(message, verdict, context);
			}

			// Return null/undefined if not throwing
			if (options.afterCheck) {
				await options.afterCheck(context, verdict, undefined);
			}
			return undefined;
		}

		// Handle ask verdict
		if (verdict.decision === "ask") {
			const approved = await options.onAsk?.(context, verdict);
			if (!approved) {
				const message = options.formatErrorMessage
					? options.formatErrorMessage(context, verdict)
					: "User denied";
				throw new AIDRMiddlewareError(message, verdict, context);
			}
		}

		// Call onAllow hook
		if (verdict.decision === "allow" && options.onAllow) {
			options.onAllow(context, verdict);
		}

		// Execute the next function (actual tool/operation)
		let result: any;
		try {
			result = await next();
		} catch (error) {
			// Still call afterCheck on error
			if (options.afterCheck) {
				await options.afterCheck(context, verdict, undefined);
			}
			throw error;
		}

		// Call afterCheck hook
		if (options.afterCheck) {
			await options.afterCheck(context, verdict, result);
		}

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
	sync: (context: MiddlewareContext, next: () => any) => Promise<any>;
} {
	const asyncMiddleware = createMiddleware(aidrClient, options);

	return {
		async: asyncMiddleware,
		sync: async (context: MiddlewareContext, next: () => any): Promise<any> => {
			// Call beforeCheck hook
			if (options.beforeCheck) {
				await options.beforeCheck(context);
			}

			// Build check request
			const checkRequest: CheckRequest = {
				action: context.tool,
				resource: context.input,
				sessionId: context.sessionId,
				metadata: context.metadata,
			};

			// Perform security check
			const verdict = await aidrClient.check(checkRequest);

			// Handle deny
			if (verdict.decision === "deny") {
				options.onDeny?.(context, verdict);
				if (options.throwOnDeny !== false) {
					const message = options.formatErrorMessage
						? options.formatErrorMessage(context, verdict)
						: `Blocked: ${verdict.reason}`;
					throw new AIDRMiddlewareError(message, verdict, context);
				}
				return undefined;
			}

			// Handle ask
			if (verdict.decision === "ask") {
				const approved = await options.onAsk?.(context, verdict);
				if (!approved) {
					const message = options.formatErrorMessage
						? options.formatErrorMessage(context, verdict)
						: "User denied";
					throw new AIDRMiddlewareError(message, verdict, context);
				}
			}

			// Call onAllow
			if (verdict.decision === "allow" && options.onAllow) {
				options.onAllow(context, verdict);
			}

			// Execute sync next()
			let result: any;
			try {
				result = next();
				// Handle if next() returns a Promise
				if (result && typeof result.then === "function") {
					result = await result;
				}
			} catch (error) {
				if (options.afterCheck) {
					await options.afterCheck(context, verdict, undefined);
				}
				throw error;
			}

			// Call afterCheck
			if (options.afterCheck) {
				await options.afterCheck(context, verdict, result);
			}

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
	return async (context: MiddlewareContext, next: NextFunction): Promise<any> => {
		let index = -1;

		async function dispatch(i: number): Promise<any> {
			if (i <= index) {
				throw new Error("next() called multiple times in middleware");
			}
			index = i;

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
	tool: { name: string; run: (...args: any[]) => any },
	aidrClient: AIDRClient,
	options: MiddlewareOptions = {},
): { name: string; run: (...args: any[]) => Promise<any> } {
	const middleware = createMiddleware(aidrClient, options);

	return {
		name: tool.name,
		run: async (...args: any[]): Promise<any> => {
			const context: MiddlewareContext = {
				tool: tool.name,
				input: JSON.stringify(args),
				sessionId: options?.metadata?.sessionId,
				metadata: options.metadata,
			};

			return middleware(context, async () => tool.run(...args));
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
