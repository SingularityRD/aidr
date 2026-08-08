/** Common response boundary for Edge Functions.
 *
 * Every public response gets a caller-safe request id. The id is accepted
 * only when it matches the constrained token format; otherwise a fresh UUID
 * is generated so clients cannot inject log delimiters or PII.
 */
export function getRequestId(req: Request): string {
	const supplied = (req.headers.get("x-request-id") ?? "").trim();
	return /^[A-Za-z0-9._:-]{1,128}$/.test(supplied) ? supplied : crypto.randomUUID();
}

export function jsonResponse(
	req: Request,
	status: number,
	body: Record<string, unknown>,
	headers: Record<string, string> = {},
): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			"Content-Type": "application/json",
			"Cache-Control": "no-store",
			"X-Request-ID": getRequestId(req),
			...headers,
		},
	});
}

export function requestCorsHeaders(
	req: Request,
	allowedOrigin: string | null,
): Record<string, string> {
	const headers: Record<string, string> = {
		"Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
		"Access-Control-Allow-Headers":
			"Content-Type,Authorization,apikey,x-client-info,x-supabase-api-version,Idempotency-Key,X-Request-ID,X-AIDR-Tenant-ID",
		"Access-Control-Expose-Headers": "X-Request-ID",
		Vary: "Origin",
	};
	if (allowedOrigin) headers["Access-Control-Allow-Origin"] = allowedOrigin;
	return headers;
}
