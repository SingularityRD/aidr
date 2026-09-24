// Supabase Edge Function: GET /v1/packs/manifest
//
// Auth: Authorization: Bearer <api_key_plaintext>
//
// Returns revocable scoped download URLs for premium intel packs.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { authenticateTenantApiKey } from "../_shared/api-key-auth.ts";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { sha256 } from "../_shared/runtime-policy.ts";
import {
	boundedPackCandidates,
	MAX_PACKS_PER_MANIFEST,
	packSigningTtlSeconds,
	packUrlTtlSeconds,
} from "../_shared/pack-delivery.ts";
import {
	packDownloadUrl,
	packKeyFingerprint,
	publicPackDownloadOrigin,
	signPackDownloadGrant,
	validPackDownloadGrantSecret,
} from "../_shared/pack-download-grant.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "AIDR_PACK_DOWNLOAD_GRANT_SECRET"] as const;

const URL_TTL_SECONDS = packUrlTtlSeconds(Deno.env.get("AIDR_PACK_URL_TTL_SECONDS"));

function json(status: number, body: Record<string, unknown>) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
	});
}

type PackVersionRow = {
	pack_id: string;
	version: string;
	tenant_id?: string | null;
	storage_path: string;
	manifest_json: unknown;
	manifest_sig_b64: string;
	key_id: string;
	issued_at: string;
	expires_at: string | null;
};

Deno.serve(async (req) => {
	if (req.method !== "GET") return json(405, { error: "method_not_allowed" });

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) return configFailure("packs-manifest", config.error, json);
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, AIDR_PACK_DOWNLOAD_GRANT_SECRET } = config.values;
	if (!validPackDownloadGrantSecret(AIDR_PACK_DOWNLOAD_GRANT_SECRET)) {
		return json(500, { error: "server_misconfigured", invalid: ["AIDR_PACK_DOWNLOAD_GRANT_SECRET"] });
	}
	const publicOrigin = publicPackDownloadOrigin(SUPABASE_URL, Deno.env.get("AIDR_PUBLIC_API_ORIGIN"), Deno.env.get("AIDR_DEVELOPMENT_MODE") === "true");
	if (!publicOrigin) return json(500, { error: "server_misconfigured", invalid: ["AIDR_PUBLIC_API_ORIGIN"] });

	const apiKey = getBearerToken(req.headers.get("Authorization"));
	if (!apiKey) return json(401, { error: "missing_api_key" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	const auth = await authenticateTenantApiKey(supabase, apiKey);
	if (!auth.ok) return json(auth.status, { error: auth.error });
	if (!auth.apiKeyId) return json(503, { error: "authorization_unavailable" });
	const { tenantId } = auth;
	const keyFingerprint = await packKeyFingerprint(await sha256(apiKey), AIDR_PACK_DOWNLOAD_GRANT_SECRET);
	const { data: entRow, error: entErr } = await supabase
		.from("entitlements")
		.select("premium_intel,premium_pkg_plugin")
		.eq("tenant_id", tenantId)
		.maybeSingle();
	if (entErr || !entRow) return json(500, { error: "missing_entitlements" });

	// Only premium tiers receive managed pack delivery.
	if (entRow.premium_intel !== true && entRow.premium_pkg_plugin !== true) {
		return json(200, { ok: true, packs: [] });
	}

	const { data: rows, error: rowsErr } = await supabase
		.from("pack_versions")
		.select("pack_id,version,tenant_id,storage_path,manifest_json,manifest_sig_b64,key_id,issued_at,expires_at")
		.or(`tenant_id.is.null,tenant_id.eq.${tenantId}`)
		.order("issued_at", { ascending: false })
		.limit(MAX_PACKS_PER_MANIFEST);
	if (rowsErr) return json(500, { error: "db_error" });
	const candidates = boundedPackCandidates(rows);
	if (!candidates) return json(500, { error: "db_error" });

	const packs: Array<Record<string, unknown>> = [];
	for (const candidate of candidates) {
		if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) continue;
		const row = candidate as PackVersionRow;
		if (row.tenant_id !== null && row.tenant_id !== tenantId) continue;
		if (
			typeof row.pack_id !== "string" || !row.pack_id.trim() ||
			row.pack_id.length > 256 ||
			typeof row.version !== "string" || !row.version.trim() || row.version.length > 256 ||
			typeof row.storage_path !== "string" || !row.storage_path.trim()
		) continue;
		const signedUrlTtl = packSigningTtlSeconds(row.expires_at, URL_TTL_SECONDS);
		if (signedUrlTtl === null) continue;
		const grant = await signPackDownloadGrant({
			key_id: auth.apiKeyId,
			key_fingerprint: keyFingerprint,
			tenant_id: tenantId,
			pack_id: row.pack_id,
			version: row.version,
			expires_at: Math.floor(Date.now() / 1_000) + signedUrlTtl,
		}, AIDR_PACK_DOWNLOAD_GRANT_SECRET);

		packs.push({
			pack_id: row.pack_id,
			version: row.version,
			key_id: row.key_id,
			issued_at: row.issued_at,
			expires_at: row.expires_at,
			manifest: row.manifest_json,
			manifest_sig_b64: row.manifest_sig_b64,
			download_url: packDownloadUrl(publicOrigin, grant),
		});
		if (packs.length >= MAX_PACKS_PER_MANIFEST) break;
	}

	return json(200, { ok: true, packs });
});
