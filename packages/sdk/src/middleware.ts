import { randomUUID } from "node:crypto";
import { type AIDRClient, HTTP_REQUEST_ACTION, MAX_CONTEXT_BODY_CHARS } from "./client.js";
import type { CheckRequest, CheckResult, MiddlewareFn } from "./config.js";
import { type ApprovalCallback, enforceCheckResult } from "./enforcement.js";
import { type IncomingHeaderValue, partitionHeaders } from "./http-headers.js";
import { assertPrivacyCallbacksAllowed } from "./privacy-text.js";

/**
 * A blocked or failed HTTP request, reported to the server-side
 * `onBlocked` hook. This is where the full verdict goes: the remote caller
 * only ever sees the generic body plus `requestId`, so the two can be joined
 * in the application's own (trusted) logs.
 */
export type BlockedRequestEvent =
	| {
			kind: "blocked";
			requestId: string;
			method: string;
			/** Enforcement message (deny / ask / indeterminate), as `wrap()` would throw. */
			reason: string;
			result: CheckResult;
	  }
	| {
			kind: "error";
			requestId: string;
			method: string;
			/** The original error (may name filesystem paths); never sent to the client. */
			error: Error;
	  };

/** Generic body of every SDK 403. Deliberately carries no rule id or reason. */
export const BLOCKED_RESPONSE_ERROR = "Request blocked by security policy";
/** Generic message of the error passed to `next()` / returned when the check itself fails. */
export const CHECK_UNAVAILABLE_ERROR = "Security check unavailable";

/**
 * The error Express receives through `next(err)` when the security check could
 * not run (rule data missing, invalid configuration, ...). Its message and stack
 * are fixed so Express's development error page cannot render internal paths;
 * the original error goes to `onBlocked` only.
 */
export class AIDRSecurityCheckUnavailableError extends Error {
	readonly status = 503;
	readonly statusCode = 503;
	readonly expose = false;
	constructor(readonly requestId: string) {
		super(CHECK_UNAVAILABLE_ERROR);
		this.name = "AIDRSecurityCheckUnavailableError";
		this.stack = `${this.name}: ${this.message} (request ${requestId})`;
	}
}

/**
 * Options for the SDK middleware surface (`wrap`, `express`, `nextjs`).
 *
 * Enforcement is fail-closed: `wrap()` executes the wrapped function only on an
 * explicit `allow` verdict. An `ask` verdict (or an indeterminate/failed check)
 * blocks unless the caller supplies `onAsk` AND that callback explicitly
 * returns true. See `enforcement.ts` for the full semantic.
 */
export interface MiddlewareEnforcementOptions {
	/**
	 * Caller-supplied human-approval callback for `ask` verdicts. It is the
	 * caller's responsibility to route this to a real human. When omitted, an
	 * `ask` verdict throws instead of executing.
	 */
	onAsk?: ApprovalCallback;
	/**
	 * Allow an indeterminate result (the security check itself failed, or the
	 * result is inconsistent) to be routed to `onAsk`. Defaults to `false`: a
	 * broken check can never be turned into an approval.
	 */
	allowApprovalOfIndeterminateResults?: boolean;
	/**
	 * `express()` / `nextjs()` only. Include the enforcement `reason` and the full
	 * `CheckResult` (rule id, matched reasons) in 403 bodies. Defaults to `false`:
	 * the remote caller is untrusted, and returning the rule that fired gives it an
	 * oracle for evading detection. Enable only for trusted internal callers; for
	 * logs use `onBlocked` instead.
	 */
	exposeDecisionDetails?: boolean;
	/**
	 * `express()` / `nextjs()` only. Server-side hook called for every blocked
	 * request and every failed check, with the full verdict or error and the
	 * `requestId` the client received. A throwing hook is ignored (the request
	 * stays blocked). Suppressed while installed mandatory privacy routing is on.
	 */
	onBlocked?: (event: BlockedRequestEvent) => void | Promise<void>;
	/**
	 * `express()` / `nextjs()` only. Inspect request header values (default
	 * `true`). Credential headers are never inspected or forwarded; see
	 * `http-headers.ts`.
	 */
	inspectHeaders?: boolean;
	/** Extra header names to treat as credentials (withheld from inspection and context). */
	sensitiveHeaders?: readonly string[];
}

/**
 * Read at most `MAX_CONTEXT_BODY_CHARS + 1` characters of a fetch `Request`
 * body from a clone, leaving the original body for the route handler. A body
 * longer than the limit comes back longer than the limit, so the client check
 * reports it as not fully inspected (deny) instead of judging a prefix.
 */
async function readBoundedBody(request: Request): Promise<string | undefined> {
	if (!request.body || request.method === "GET" || request.method === "HEAD") return undefined;
	const reader = request.clone().body?.getReader();
	if (!reader) return undefined;
	const decoder = new TextDecoder();
	let text = "";
	try {
		while (text.length <= MAX_CONTEXT_BODY_CHARS) {
			const { done, value } = await reader.read();
			if (done) break;
			text += decoder.decode(value, { stream: true });
		}
		text += decoder.decode();
	} finally {
		await reader.cancel().catch(() => {});
	}
	return text.length > MAX_CONTEXT_BODY_CHARS ? text.slice(0, MAX_CONTEXT_BODY_CHARS + 1) : text;
}

/**
 * Middleware chain for framework integration
 */
class MiddlewareChain {
	private middlewares: MiddlewareFn[] = [];

	use(middleware: MiddlewareFn): this {
		this.middlewares.push(middleware);
		return this;
	}

	async execute(request: CheckRequest, result?: CheckResult, error?: Error): Promise<void> {
		for (const middleware of this.middlewares) {
			await assertPrivacyCallbacksAllowed();
			await middleware({ request, result, error, next: async () => {} });
		}
	}
}

/**
 * Create middleware chain with AIDR client integration
 *
 * @param client - AIDR client used for every security check
 * @param options - Enforcement options (approval callback, indeterminate policy)
 */
export function createMiddleware(client: AIDRClient, options: MiddlewareEnforcementOptions = {}) {
	const chain = new MiddlewareChain();

	/**
	 * Single enforcement rule for every API in this module: a request may only
	 * proceed on an explicit `allow` (or a genuine human approval of an `ask`).
	 * `express()` / `nextjs()` / `wrap()` previously disagreed on the same
	 * result object; they now all go through `enforceCheckResult`.
	 */
	const onAsk = options.onAsk;
	const enforce = (result: CheckResult) =>
		enforceCheckResult(result, {
			...options,
			onAsk: onAsk
				? async (verdict) => {
						await assertPrivacyCallbacksAllowed();
						return onAsk(verdict);
					}
				: undefined,
		});

	/** Header context for an HTTP check: non-credential values plus withheld names. */
	const headerContext = (
		headers: Record<string, IncomingHeaderValue> | undefined,
	): Record<string, unknown> => {
		if (options.inspectHeaders === false) return {};
		const { inspected, withheld } = partitionHeaders(headers, options.sensitiveHeaders);
		return {
			headers: inspected,
			...(withheld.length > 0 ? { withheldHeaders: withheld } : {}),
		};
	};

	const report = async (event: BlockedRequestEvent): Promise<void> => {
		if (!options.onBlocked) return;
		try {
			await assertPrivacyCallbacksAllowed();
			await options.onBlocked(event);
		} catch {
			// A logging hook can neither unblock the request nor leak through it.
		}
	};

	const reportError = (requestId: string, method: string, error: unknown): Promise<void> =>
		report({
			kind: "error",
			requestId,
			method,
			error: error instanceof Error ? error : new Error(String(error)),
		});

	const blockedBody = (requestId: string, reason: string, result: CheckResult) =>
		options.exposeDecisionDetails
			? { error: BLOCKED_RESPONSE_ERROR, requestId, reason, details: result }
			: { error: BLOCKED_RESPONSE_ERROR, requestId };

	const api = {
		/**
		 * Add a middleware function
		 */
		use: (middleware: MiddlewareFn) => {
			chain.use(middleware);
			return api;
		},

		/**
		 * Execute security check with middleware chain.
		 *
		 * Returns the raw result without enforcing it — callers that act on the
		 * result themselves must enforce it (use `enforceCheckResult`, exported
		 * from this package, or one of the wrapping helpers below).
		 */
		check: async (request: CheckRequest): Promise<CheckResult> => {
			let result: CheckResult | undefined;
			let error: Error | undefined;

			try {
				result = await client.check(request);
			} catch (e) {
				error = e instanceof Error ? e : new Error(String(e));
			}

			await chain.execute(request, result, error);

			if (error) throw error;
			if (!result) {
				throw new Error("Security check returned no result");
			}
			return result;
		},

		/**
		 * Wrap a function with security check.
		 *
		 * The wrapped function runs only when the check explicitly allows it.
		 * `deny` always throws. `ask` throws unless `onAsk` is configured and
		 * approves. An indeterminate (failed) check always throws unless the
		 * caller opted in with `allowApprovalOfIndeterminateResults`.
		 */
		wrap: <T extends (...args: unknown[]) => unknown>(
			fn: T,
			requestFactory: (...args: Parameters<T>) => CheckRequest,
		): ((...args: Parameters<T>) => Promise<ReturnType<T>>) => {
			return async (...args: Parameters<T>): Promise<ReturnType<T>> => {
				await assertPrivacyCallbacksAllowed();
				const request = requestFactory(...args);
				const result = await client.check(request);

				const outcome = await enforce(result);
				if (!outcome.execute) {
					throw new Error(outcome.message);
				}

				// Execute middleware chain
				await chain.execute(request, result);

				await client.assertCallerOperationAllowed();
				let output: unknown;
				try {
					output = await fn(...args);
				} catch (error) {
					await assertPrivacyCallbacksAllowed();
					throw error;
				}
				await assertPrivacyCallbacksAllowed();
				return output as ReturnType<T>;
			};
		},

		/**
		 * Express/Connect compatible middleware.
		 *
		 * The request is checked as an `http_request`: `req.url` (route + query) is
		 * inspected as content with embedded URLs extracted (never as a local file
		 * path), a parsed `req.body` is walked by the core generic extractor, and
		 * non-credential header values are inspected the same way (credential
		 * headers such as `Authorization` / `Cookie` are withheld entirely).
		 * A body over `MAX_CONTEXT_BODY_CHARS` is denied as not fully inspected.
		 * Mount a body parser before this middleware for bodies to be inspected.
		 *
		 * Responds 403 for anything that is not an explicit allow (deny, ask
		 * without an approving `onAsk`, indeterminate/failed check, inconsistent
		 * result). The body is generic, `{ error, requestId }`, unless
		 * `exposeDecisionDetails` is set; the verdict goes to `onBlocked`. A check
		 * that cannot run calls `next()` with an `AIDRSecurityCheckUnavailableError`
		 * whose message and stack carry no internal detail.
		 */
		express: () => {
			return async (
				req: {
					method: string;
					url: string;
					body?: unknown;
					headers?: Record<string, IncomingHeaderValue>;
				},
				res: { status: (code: number) => { json: (data: unknown) => void } },
				next: (error?: Error) => void,
			): Promise<void> => {
				const requestId = randomUUID();
				try {
					const checkRequest: CheckRequest = {
						action: HTTP_REQUEST_ACTION,
						resource: req.url,
						context: {
							method: req.method,
							...headerContext(req.headers),
							body: req.body,
						},
					};

					const result = await client.check(checkRequest);
					const outcome = await enforce(result);

					// Execute middleware chain
					await chain.execute(checkRequest, result);

					if (!outcome.execute) {
						await report({
							kind: "blocked",
							requestId,
							method: req.method,
							reason: outcome.message,
							result,
						});
						res.status(403).json(blockedBody(requestId, outcome.message, result));
						return;
					}

					await client.assertCallerOperationAllowed();
					next();
				} catch (error) {
					await reportError(requestId, req.method, error);
					next(new AIDRSecurityCheckUnavailableError(requestId));
				}
			};
		},

		/**
		 * Next.js API route middleware.
		 *
		 * Checked like `express()`: the path + query as an `http_request` route,
		 * non-credential headers and, for methods with a body, a bounded copy of the
		 * body read from a clone (the handler still receives the original stream).
		 *
		 * Returns a generic 403 response for anything that is not an explicit allow
		 * (see `express()` above), a generic 503 when the check cannot run, or
		 * `null` to continue to the route handler.
		 */
		nextjs: () => {
			return async (request: Request): Promise<Response | null> => {
				const requestId = randomUUID();
				const json = (status: number, body: unknown) =>
					new Response(JSON.stringify(body), {
						status,
						headers: { "Content-Type": "application/json" },
					});
				try {
					const url = new URL(request.url);
					const body = await readBoundedBody(request);
					const checkRequest: CheckRequest = {
						action: HTTP_REQUEST_ACTION,
						resource: `${url.pathname}${url.search}`,
						context: {
							method: request.method,
							...headerContext(Object.fromEntries(request.headers)),
							...(body === undefined ? {} : { body }),
						},
					};

					const result = await client.check(checkRequest);
					const outcome = await enforce(result);

					// Execute middleware chain
					await chain.execute(checkRequest, result);

					if (!outcome.execute) {
						await report({
							kind: "blocked",
							requestId,
							method: request.method,
							reason: outcome.message,
							result,
						});
						return json(403, blockedBody(requestId, outcome.message, result));
					}

					await client.assertCallerOperationAllowed();
					return null; // Continue to handler
				} catch (error) {
					await reportError(requestId, request.method, error);
					return json(503, { error: CHECK_UNAVAILABLE_ERROR, requestId });
				}
			};
		},
	};
	return api;
}
