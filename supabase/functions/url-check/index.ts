// Supabase Edge Function: POST /url-check
//
// Auth: Authorization: Bearer <api_key_plaintext>
//
// Compatible with @singularityrd/aidr-core UrlCheckClient:
// Body: { queries: [{ key: { "url-like": "https://..." } }], "client-info": {...} }
// Resp: { coverage: "complete"|"partial"|"none", answers: [{ key: "<url>", coverage: "covered"|"no_data", result: { success: { classification: { result: { malicious?: { findings: [...] }, unknown?: { reason } } }, flags: [...] } } }] }
//
// This is a self-hostable replacement for proprietary URL reputation providers.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { authenticateTenantApiKeyBudgeted } from "../_shared/api-key-auth.ts";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { isFreshReputationRow, reputationFreshUntil } from "../_shared/reputation-freshness.ts";
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

type UrlRepRow = {
	url: string | null;
	domain: string | null;
	created_at: string | null;
	provenance_verified: boolean | null;
	is_malicious: boolean | null;
	severity_name: string | null;
	type_name: string | null;
	flags: string[] | null;
};

// Tenant reads can contain one row per user for the same target. Never let
// PostgREST row order decide whether a conflicting target is clean.
function mergeFreshRow(
	rows: Map<string, UrlRepRow>,
	conflicts: Set<string>,
	target: string,
	row: UrlRepRow,
): void {
	if (conflicts.has(target)) return;
	if (typeof row.is_malicious !== "boolean") {
		rows.delete(target);
		conflicts.add(target);
		return;
	}
	const previous = rows.get(target);
	if (!previous) {
		rows.set(target, row);
		return;
	}
	const classification = (value: UrlRepRow) =>
		JSON.stringify([value.is_malicious, value.severity_name, value.type_name, value.flags]);
	if (classification(previous) !== classification(row)) {
		rows.delete(target);
		conflicts.add(target);
		return;
	}
	// Identical classifications use the older source timestamp so a newer
	// duplicate cannot extend the cache lifetime of older evidence.
	if (Date.parse(row.created_at ?? "") < Date.parse(previous.created_at ?? "")) rows.set(target, row);
}

/**
 * Whether the tenant's reputation store holds a row for a queried URL.
 *
 * A missing row is not a clean verdict. This endpoint used to answer an empty
 * `classification.result` for a URL it has no row for, which the client read as
 * `isMalicious: false` - "we have no data about this URL" was reported to the
 * caller as "this URL is clean". The state is now explicit and
 * machine-readable:
 *
 *   - `covered` - a row exists. A malicious row keeps its historical
 *     `classification.result.malicious` shape; a benign row keeps the empty
 *     `classification.result` shape, because a row that says "not malicious" is
 *     a genuine clean answer;
 *   - `no_data` - no row covers this URL, so no classification was performed.
 *     The per-answer classification carries `result.unknown` and the top-level
 *     `coverage` summary reports the gap, so a caller can never mistake absent
 *     data for a passed check.
 */
const COVERED = "covered";
const NO_COVERAGE = "no_data";

type UrlCheckCoverage = typeof COVERED | typeof NO_COVERAGE;

type UrlCheckAnswer = {
	key: string;
	coverage: UrlCheckCoverage;
	cache_valid_until?: string;
	result: {
		success: {
			classification: Record<string, unknown>;
			flags: string[];
			coverage: UrlCheckCoverage;
		};
	};
};

export interface UrlCheckDeps {
	/** Overrides the service-role client; used by the contract suite. */
	db?: ReturnType<typeof createClient>;
}

// The runtime entry point is declared above the factory on purpose: the
// repository's contract gates anchor a function's request path at the first
// `Deno.serve(` occurrence in the file and require the configuration guard,
// the authorization check and every database call to appear after it.
Deno.serve(createUrlCheckHandler());

/** Build the request handler. Exported so the contract suite can drive it. */
export function createUrlCheckHandler(deps: UrlCheckDeps = {}) {
	return async function handle(req: Request): Promise<Response> {
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
		const supabase = deps.db ?? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
			auth: { persistSession: false },
		});
		const auth = await authenticateTenantApiKeyBudgeted(supabase, apiKey, "url-check");
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
		const domainCandidates = [...new Set(domains)].slice(0, 200);

		const urlLookup = await supabase
			.from("url_reputation")
			.select("url,domain,created_at,provenance_verified,is_malicious,severity_name,type_name,flags")
			.eq("tenant_id", tenantId)
			.eq("provenance_verified", true)
			.in("url", urls);
		if (urlLookup.error) {
			return json(503, { error: "reputation_lookup_unavailable" }, rateLimitHeaders(rate));
		}

		let domainRows: UrlRepRow[] = [];
		if (domainCandidates.length > 0) {
			const domainLookup = await supabase
				.from("url_reputation")
				.select("url,domain,created_at,provenance_verified,is_malicious,severity_name,type_name,flags")
				.eq("tenant_id", tenantId)
				.eq("provenance_verified", true)
				.in("domain", domainCandidates);
			if (domainLookup.error) {
				return json(503, { error: "reputation_lookup_unavailable" }, rateLimitHeaders(rate));
			}
			domainRows = (domainLookup.data ?? []) as UrlRepRow[];
		}

		const byUrl = new Map<string, UrlRepRow>();
		const conflictingUrls = new Set<string>();
		const staleUrls = new Set<string>();
		const nowMs = Date.now();
		for (const row of (urlLookup.data ?? []) as UrlRepRow[]) {
			if (!row.url) continue;
			if (isFreshReputationRow(row.created_at, nowMs))
				mergeFreshRow(byUrl, conflictingUrls, row.url, row);
			else staleUrls.add(row.url);
		}

		const byDomain = new Map<string, UrlRepRow>();
		const conflictingDomains = new Set<string>();
		const staleDomains = new Set<string>();
		for (const row of domainRows) {
			if (!row.domain) continue;
			if (isFreshReputationRow(row.created_at, nowMs))
				mergeFreshRow(byDomain, conflictingDomains, row.domain, row);
			else staleDomains.add(row.domain);
		}

		const answers: UrlCheckAnswer[] = urls.map((u) => {
			const urlRow = byUrl.get(u);
			const domain = domainFromUrl(u);
			const domRow = domain ? byDomain.get(domain) : undefined;
			const conflictingEvidence =
				conflictingUrls.has(u) ||
				Boolean(domain && conflictingDomains.has(domain)) ||
				Boolean(urlRow && domRow && urlRow.is_malicious !== domRow.is_malicious);

			const row = conflictingEvidence ? null : urlRow ?? domRow ?? null;
			const coverage: UrlCheckCoverage = row ? COVERED : NO_COVERAGE;
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
				: row
					? { result: {} }
					: // No row: no classification was performed. `unknown` is the
						// machine-readable marker the client maps to an unavailable
						// reputation leg rather than to `isMalicious: false`.
						{ result: { unknown: { reason: conflictingEvidence ? "conflicting_reputation_rows" : staleUrls.has(u) || (domain && staleDomains.has(domain)) ? "stale_reputation_row" : "no_reputation_row" } } };

			return {
				key: u,
				coverage,
				...(row ? { cache_valid_until: reputationFreshUntil(row.created_at) ?? undefined } : {}),
				result: {
					success: {
						classification,
						flags,
						coverage,
					},
				},
			};
		});

		const covered = answers.filter((answer) => answer.coverage === COVERED).length;
		const coverage =
			covered === answers.length ? "complete" : covered === 0 ? "none" : "partial";

		return json(200, { coverage, answers }, rateLimitHeaders(rate));
	};
}
