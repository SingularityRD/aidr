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

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

function json(status: number, body: Record<string, unknown>) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function getBearerToken(req: Request): string | null {
	const header = req.headers.get("Authorization") ?? "";
	const m = header.match(/^Bearer\s+(.+)$/i);
	return m?.[1]?.trim() ? m[1].trim() : null;
}

async function sha256Hex(input: string): Promise<string> {
	const data = new TextEncoder().encode(input);
	const digest = await crypto.subtle.digest("SHA-256", data);
	const bytes = new Uint8Array(digest);
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
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

	if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
		return json(500, { error: "misconfigured_supabase_env" });
	}

	const apiKey = getBearerToken(req);
	if (!apiKey) {
		return json(401, { error: "missing_api_key" });
	}

	let body: Record<string, unknown>;
	try {
		const parsed = await req.json();
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
			return json(400, { error: "invalid_json" });
		}
		body = parsed as Record<string, unknown>;
	} catch {
		return json(400, { error: "invalid_json" });
	}

	const rawQueries = Array.isArray(body.queries) ? (body.queries as unknown[]) : [];
	const urls = rawQueries
		.map((q) => extractUrlLike(q))
		.filter((u): u is string => Boolean(u))
		.slice(0, 50);

	if (urls.length === 0) {
		return json(200, { answers: [] });
	}

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	// api_key -> user_id (hash-only)
	const keyHash = await sha256Hex(apiKey);
	const { data: keyRow, error: keyErr } = await supabase
		.from("api_keys")
		.select("user_id, revoked")
		.eq("key_hash", keyHash)
		.maybeSingle();

	if (keyErr || !keyRow || keyRow.revoked) {
		return json(401, { error: "invalid_api_key" });
	}

	const userId = keyRow.user_id as string;

	const domains = urls
		.map((u) => domainFromUrl(u))
		.filter((d): d is string => Boolean(d));
	const domainCandidates = [...new Set(domains.flatMap((d) => domainSuffixes(d)))].slice(0, 200);

	const { data: urlRows } = await supabase
		.from("url_reputation")
		.select("url,domain,is_malicious,severity_name,type_name,flags")
		.eq("user_id", userId)
		.in("url", urls);

	const { data: domainRows } =
		domainCandidates.length > 0
			? await supabase
					.from("url_reputation")
					.select("url,domain,is_malicious,severity_name,type_name,flags")
					.eq("user_id", userId)
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

	return json(200, { answers });
});
