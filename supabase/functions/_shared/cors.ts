import { buildCorsHeaders, parseAllowedOrigins, resolveAllowedOrigin } from "./origin.ts";
import { getRequestId } from "./response.ts";

const ALLOWED_ORIGINS = parseAllowedOrigins(
	Deno.env.get("AIDR_ALLOWED_ORIGINS"),
	Deno.env.get("AIDR_DEVELOPMENT_MODE") === "true",
);

/**
 * Return a browser-safe JSON response for dashboard-facing Edge Functions.
 * Origins are echoed only after an explicit allowlist check; an empty
 * allowlist therefore fails closed for cross-origin browser calls.
 */
export function corsJson(
	req: Request,
	status: number,
	body: Record<string, unknown>,
	headers: Record<string, string> = {},
): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			...buildCorsHeaders(req.headers.get("Origin"), ALLOWED_ORIGINS),
			"X-Request-ID": getRequestId(req),
			...headers,
		},
	});
}

/**
 * Handle CORS policy and OPTIONS preflight before an Edge Function parses a
 * body or performs an authenticated/database operation.
 */
export function handleCors(req: Request): Response | null {
	const origin = req.headers.get("Origin");
	const allowedOrigin = resolveAllowedOrigin(origin, ALLOWED_ORIGINS);
	if (origin && !allowedOrigin) return corsJson(req, 403, { error: "origin_not_allowed" });
	if (req.method === "OPTIONS") return corsJson(req, 200, { ok: true });
	return null;
}
