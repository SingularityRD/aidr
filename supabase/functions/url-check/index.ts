// Supabase Edge Function: POST /url-check
//
// Auth: Authorization: Bearer <api_key_plaintext>
//
// Compatible with @singularityrd/aidr-core UrlCheckClient:
// Body: { queries: [{ key: { "url-like": "https://..." } }], "client-info": {...} }
// Resp: { answers: [{ key: "<url>", result: { success: { classification: { result: { malicious?: { findings: [...] } } }, flags: [...] } } }] }
//
// This is a self-hostable replacement for proprietary URL reputation providers.

import { createClient } from "npm:@supabase/supabase-js@2";
import { authenticateTenantApiKey } from "../_shared/api-key-auth.ts";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import {
	consumeTenantRateLimit,
	rateLimitHeaders,
	readBoundedJson,
} from "../_shared/request-limits.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 128 * 1024;
const MAX_QUERIES = 50;

function json(
	status: number,
	body: Record<string, unknown>,
	headers: Record<string, string> = {},
) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers },
	});
}

function extractUrlLike(query: unknown): string | null {
	if (!query || typeof query !== "object" || Array.isArray(query)) return null;
	const q = query as Record<string, unknown>;
	const key = q.key;
	if (key && typeof key === "object" && !Array.isArray(key)) {
		const urlLike = (key as Record<string, unknown>)["url-like"];
		if (typeof urlLike === "string" && urlLike.trim()) return urlLike.trim();
	}
	// Fallback: accept { key: "<url>" } style
	if (typeof q.key === "string" && q.key.trim()) return q.key.trim();
	return null;
}

function domainFromUrl(raw: string): string | null {
	try {
		const u = new URL(raw);
		const host = u.hostname?.toLowerCase();
		return host ? host : null;
	} catch {
		return null;
	}
}

function domainSuffixes(domain: string, maxParts = 4): string[] {
	const parts = domain.split(".").filter(Boolean);
	if (parts.length < 2) return [domain];
	const suffixes: string[] = [];
	for (let i = 0; i < parts.length - 1; i++) {
		const suffix = parts.slice(i).join(".");
		if (suffix.split(".").length >= 2 && suffix.split(".").length <= maxParts) {
			suffixes.push(suffix);
		}
	}
	return [...new Set(suffixes)];
}

type UrlRepRow = {
	url: string | null;
	domain: string | null;
	is_malicious: boolean | null;
	severity_name: string | null;
	type_name: string | null;
	flags: string[] | null;
};

Deno.serve(async (req) => {
	if (req.method !== "POST") {
		return json(405, { error: "method_not_allowed" });
	}

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) return configFailure("url-check", config.error, json);
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

	const apiKey = getBearerToken(req.headers.get("Authorization"));
	if (!apiKey) {
		return json(401, { error: "missing_api_key" });
	}
	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});
	const auth = await authenticateTenantApiKey(supabase, apiKey);
	if (!auth.ok) {
		return json(auth.status, { error: auth.error });
	}
	const { tenantId, userId } = auth;

	const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
	if (!parsed.ok) return json(parsed.status, { error: parsed.error });
	if (!parsed.value || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
		return json(400, { error: "invalid_json" });
	}
	const body = parsed.value as Record<string, unknown>;

	const rawQueries = Array.isArray(body.queries) ? (body.queries as unknown[]) : [];
	if (rawQueries.length > MAX_QUERIES) {
		return json(413, { error: "query_limit_exceeded", max_queries: MAX_QUERIES });
	}
	const urls = rawQueries
		.map((q) => extractUrlLike(q))
		.filter((u): u is string => Boolean(u));

	const rate = await consumeTenantRateLimit(supabase, {
		tenantId,
		subject: userId,
		endpoint: "url-check",
		perSubject: 600,
		perTenant: 30_000,
		cost: Math.max(1, rawQueries.length),
	});
	if (!rate.ok) return json(rate.status, { error: rate.error }, rateLimitHeaders(rate));

	if (urls.length === 0) {
		return json(200, { answers: [] }, rateLimitHeaders(rate));
	}

	const domains = urls
		.map((u) => domainFromUrl(u))
		.filter((d): d is string => Boolean(d));
	const domainCandidates = [...new Set(domains.flatMap((d) => domainSuffixes(d)))].slice(0, 200);

	const { data: urlRows } = await supabase
		.from("url_reputation")
		.select("url,domain,is_malicious,severity_name,type_name,flags")
		.eq("tenant_id", tenantId)
		.in("url", urls);

	const { data: domainRows } =
		domainCandidates.length > 0
			? await supabase
					.from("url_reputation")
					.select("url,domain,is_malicious,severity_name,type_name,flags")
					.eq("tenant_id", tenantId)
					.in("domain", domainCandidates)
			: { data: [] as UrlRepRow[] };

	const byUrl = new Map<string, UrlRepRow>();
	for (const row of (urlRows ?? []) as UrlRepRow[]) {
		if (row.url) byUrl.set(row.url, row);
	}

	const byDomain = new Map<string, UrlRepRow>();
	for (const row of (domainRows ?? []) as UrlRepRow[]) {
		if (row.domain) byDomain.set(row.domain, row);
	}

	const answers = urls.map((u) => {
		const urlRow = byUrl.get(u);
		const domain = domainFromUrl(u);
		let domRow: UrlRepRow | undefined;
		if (!urlRow && domain) {
			for (const suffix of domainSuffixes(domain)) {
				const hit = byDomain.get(suffix);
				if (hit) {
					domRow = hit;
					break;
				}
			}
		}

		const row = urlRow ?? domRow ?? null;
		const isMalicious = Boolean(row?.is_malicious);
		const flags = Array.isArray(row?.flags) ? row?.flags.filter((f) => typeof f === "string") : [];

		const classification = isMalicious
			? {
					result: {
						malicious: {
							findings: [
								{
									"severity-name": row?.severity_name ?? "high",
									"type-name": row?.type_name ?? "phishing",
								},
							],
						},
					},
				}
			: { result: {} };

		return {
			key: u,
			result: {
				success: {
					classification,
					flags,
				},
			},
		};
	});

	return json(200, { answers }, rateLimitHeaders(rate));
});
