function normalizeOrigin(value: string): string | null {
	if (value !== value.trim() || value === "*") return null;
	let parsed: URL;
	try {
		parsed = new URL(value);
	} catch {
		return null;
	}
	if (
		parsed.username || parsed.password || parsed.pathname !== "/" ||
		parsed.search || parsed.hash || !["http:", "https:"].includes(parsed.protocol)
	) return null;
	return parsed.origin;
}

export function parseAllowedOrigins(raw: string | undefined, localDevelopment = false): Set<string> {
	const out = new Set<string>();
	if (!raw) return out;
	for (const entry of raw.split(",")) {
		const trimmed = entry.trim();
		const origin = normalizeOrigin(trimmed);
		if (!origin) continue;
		const parsed = new URL(origin);
		const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
		if (parsed.protocol === "https:" || (localDevelopment && loopback && parsed.protocol === "http:")) {
			out.add(origin);
		}
	}
	return out;
}

export function resolveAllowedOrigin(
	requestOrigin: string | null,
	allowedOrigins: Set<string>,
): string | null {
	if (!requestOrigin) return null;
	const origin = normalizeOrigin(requestOrigin);
	return origin && allowedOrigins.has(origin) ? origin : null;
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
		"Access-Control-Expose-Headers": "X-Request-ID,RateLimit-Remaining,Retry-After",
		Vary: "Origin",
	};
	if (allowed) headers["Access-Control-Allow-Origin"] = allowed;
	return headers;
}
