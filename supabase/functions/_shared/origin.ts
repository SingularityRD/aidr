export function parseAllowedOrigins(raw: string | undefined): Set<string> {
	const out = new Set<string>();
	if (!raw) return out;
	for (const entry of raw.split(",")) {
		const trimmed = entry.trim();
		if (trimmed) out.add(trimmed);
	}
	return out;
}

export function resolveAllowedOrigin(
	requestOrigin: string | null,
	allowedOrigins: Set<string>,
): string | null {
	if (!requestOrigin) return null;
	if (allowedOrigins.has("*")) return requestOrigin;
	return allowedOrigins.has(requestOrigin) ? requestOrigin : null;
}

export function buildCorsHeaders(
	requestOrigin: string | null,
	allowedOrigins: Set<string>,
): Record<string, string> {
	const allowed = resolveAllowedOrigin(requestOrigin, allowedOrigins);
	const headers: Record<string, string> = {
		"Content-Type": "application/json",
		"Cache-Control": "no-store",
		"Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
		"Access-Control-Allow-Headers":
			"Content-Type,Authorization,apikey,x-client-info,x-supabase-api-version,Idempotency-Key,X-Request-ID,X-AIDR-Tenant-ID",
		"Access-Control-Expose-Headers": "X-Request-ID",
		Vary: "Origin",
	};
	if (allowed) headers["Access-Control-Allow-Origin"] = allowed;
	return headers;
}
