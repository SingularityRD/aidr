import type { AIDRClient } from "./client.js";
import type { CheckRequest, CheckResult, MiddlewareFn } from "./config.js";

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
		let index = 0;

		const next = async (): Promise<void> => {
			if (index >= this.middlewares.length) return;
			const middleware = this.middlewares[index++];
			await middleware({ request, result, error, next });
		};

		await next();
	}
}

/**
 * Create middleware chain with AIDR client integration
 */
export function createMiddleware(client: AIDRClient) {
	const chain = new MiddlewareChain();

	return {
		/**
		 * Add a middleware function
		 */
		use: (middleware: MiddlewareFn) => {
			chain.use(middleware);
			return createMiddleware(client);
		},

		/**
		 * Execute security check with middleware chain
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
			return result!;
		},

		/**
		 * Wrap a function with security check
		 */
		wrap: <T extends (...args: unknown[]) => unknown>(
			fn: T,
			requestFactory: (...args: Parameters<T>) => CheckRequest,
		): ((...args: Parameters<T>) => Promise<ReturnType<T>>) => {
			return async (...args: Parameters<T>): Promise<ReturnType<T>> => {
				const request = requestFactory(...args);
				const result = await client.check(request);

				if (!result.allowed && result.decision === "deny") {
					throw new Error(`Security check denied: ${result.reason || "Unknown threat"}`);
				}

				// Execute middleware chain
				await chain.execute(request, result);

				return fn(...args) as ReturnType<T>;
			};
		},

		/**
		 * Express/Connect compatible middleware
		 */
		express: () => {
			return async (
				req: { method: string; url: string; body?: unknown; headers?: Record<string, string> },
				res: { status: (code: number) => { json: (data: unknown) => void } },
				next: (error?: Error) => void,
			): Promise<void> => {
				try {
					const checkRequest: CheckRequest = {
						action: req.method === "GET" ? "read" : "write",
						resource: req.url,
						context: {
							method: req.method,
							headers: req.headers,
							body: req.body,
						},
					};

					const result = await client.check(checkRequest);

					// Execute middleware chain
					await chain.execute(checkRequest, result);

					if (!result.allowed) {
						res.status(403).json({
							error: "Security check failed",
							details: result,
						});
						return;
					}

					next();
				} catch (error) {
					next(error instanceof Error ? error : new Error(String(error)));
				}
			};
		},

		/**
		 * Next.js API route middleware
		 */
		nextjs: () => {
			return async (request: Request): Promise<Response | null> => {
				const url = new URL(request.url);
				const checkRequest: CheckRequest = {
					action: request.method === "GET" ? "read" : "write",
					resource: url.pathname,
					context: {
						method: request.method,
						headers: Object.fromEntries(request.headers),
					},
				};

				const result = await client.check(checkRequest);

				// Execute middleware chain
				await chain.execute(checkRequest, result);

				if (!result.allowed) {
					return new Response(JSON.stringify({ error: "Security check failed", details: result }), {
						status: 403,
						headers: { "Content-Type": "application/json" },
					});
				}

				return null; // Continue to handler
			};
		},
	};
}
