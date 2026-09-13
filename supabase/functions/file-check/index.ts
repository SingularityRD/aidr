// Supabase Edge Function: POST /file-check
//
// Auth: Authorization: Bearer <api_key_plaintext>
//
// Compatible with @singularityrd/aidr-core FileCheckClient:
// Body (batch): { requests: [{ key: { sha256: "<hash>" } }], client_info: {...} }
// Resp: { responses: [{ key: { sha256 }, severity, malware_name: [...] }, ...] }
//
// This is a self-hostable replacement for proprietary file hash reputation providers.

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
const MAX_REQUESTS = 50;

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

function extractSha256(reqEntry: unknown): string | null {
	if (!reqEntry || typeof reqEntry !== "object" || Array.isArray(reqEntry)) return null;
	const r = reqEntry as Record<string, unknown>;
	const key = r.key;
	if (key && typeof key === "object" && !Array.isArray(key)) {
		const sha256 = (key as Record<string, unknown>).sha256;
		if (typeof sha256 === "string" && sha256.trim()) return sha256.trim().toLowerCase();
	}
	return null;
}

type FileRepRow = {
	sha256: string;
	severity: string | null;
	malware_name: string[] | null;
};

Deno.serve(async (req) => {
	if (req.method !== "POST") {
		return json(405, { error: "method_not_allowed" });
	}

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) return configFailure("file-check", config.error, json);
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

	const rawRequests = Array.isArray(body.requests) ? (body.requests as unknown[]) : [];
	if (rawRequests.length > MAX_REQUESTS) {
		return json(413, { error: "request_limit_exceeded", max_requests: MAX_REQUESTS });
	}
	const hashes = rawRequests
		.map((r) => extractSha256(r))
		.filter((h): h is string => Boolean(h));

	const rate = await consumeTenantRateLimit(supabase, {
		tenantId,
		subject: userId,
		endpoint: "file-check",
		perSubject: 600,
		perTenant: 30_000,
		cost: Math.max(1, rawRequests.length),
	});
	if (!rate.ok) return json(rate.status, { error: rate.error }, rateLimitHeaders(rate));

	if (hashes.length === 0) {
		return json(200, { responses: [] }, rateLimitHeaders(rate));
	}

	const { data: rows } = await supabase
		.from("file_reputation")
		.select("sha256,severity,malware_name")
		.eq("tenant_id", tenantId)
		.in("sha256", hashes);

	const byHash = new Map<string, FileRepRow>();
	for (const row of (rows ?? []) as FileRepRow[]) {
		byHash.set(row.sha256.toLowerCase(), row);
	}

	const responses = hashes.map((h) => {
		const row = byHash.get(h);
		const malwareNames = Array.isArray(row?.malware_name)
			? row?.malware_name.filter((n) => typeof n === "string" && n.length > 0)
			: [];
		return {
			key: { sha256: h },
			severity: row?.severity ?? "SEVERITY_UNKNOWN",
			malware_name: malwareNames,
		};
	});

	return json(200, { responses }, rateLimitHeaders(rate));
});
