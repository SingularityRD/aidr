import { type AIDRClient, HTTP_REQUEST_ACTION, MAX_CONTEXT_BODY_CHARS } from "./client.js";
import type { CheckRequest, CheckResult, MiddlewareFn } from "./config.js";
import { type ApprovalCallback, enforceCheckResult } from "./enforcement.js";
import { assertPrivacyCallbacksAllowed } from "./privacy-text.js";

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
		 * path), and a parsed `req.body` is walked by the core generic extractor.
		 * A body over `MAX_CONTEXT_BODY_CHARS` is denied as not fully inspected.
		 * Mount a body parser before this middleware for bodies to be inspected.
		 *
		 * Responds 403 for anything that is not an explicit allow (deny, ask
		 * without an approving `onAsk`, indeterminate/failed check, inconsistent
		 * result). The response `reason` states which case applied.
		 */
		express: () => {
			return async (
				req: { method: string; url: string; body?: unknown; headers?: Record<string, string> },
				res: { status: (code: number) => { json: (data: unknown) => void } },
				next: (error?: Error) => void,
			): Promise<void> => {
				try {
					const checkRequest: CheckRequest = {
						action: HTTP_REQUEST_ACTION,
						resource: req.url,
						context: {
							method: req.method,
							headers: req.headers,
							body: req.body,
						},
					};

					const result = await client.check(checkRequest);
					const outcome = await enforce(result);

					// Execute middleware chain
					await chain.execute(checkRequest, result);

					if (!outcome.execute) {
						res.status(403).json({
							error: "Security check failed",
							reason: outcome.message,
							details: result,
						});
						return;
					}

					await client.assertCallerOperationAllowed();
					next();
				} catch (error) {
					next(error instanceof Error ? error : new Error(String(error)));
				}
			};
		},

		/**
		 * Next.js API route middleware.
		 *
		 * Checked like `express()`: the path + query as an `http_request` route and,
		 * for methods with a body, a bounded copy of the body read from a clone (the
		 * handler still receives the original stream).
		 *
		 * Returns a 403 response for anything that is not an explicit allow (see
		 * `express()` above), or `null` to continue to the route handler.
		 */
		nextjs: () => {
			return async (request: Request): Promise<Response | null> => {
				const url = new URL(request.url);
				const body = await readBoundedBody(request);
				const checkRequest: CheckRequest = {
					action: HTTP_REQUEST_ACTION,
					resource: `${url.pathname}${url.search}`,
					context: {
						method: request.method,
						headers: Object.fromEntries(request.headers),
						...(body === undefined ? {} : { body }),
					},
				};

				const result = await client.check(checkRequest);
				const outcome = await enforce(result);

				// Execute middleware chain
				await chain.execute(checkRequest, result);

				if (!outcome.execute) {
					return new Response(
						JSON.stringify({
							error: "Security check failed",
							reason: outcome.message,
							details: result,
						}),
						{
							status: 403,
							headers: { "Content-Type": "application/json" },
						},
					);
				}

				await client.assertCallerOperationAllowed();
				return null; // Continue to handler
			};
		},
	};
	return api;
}
