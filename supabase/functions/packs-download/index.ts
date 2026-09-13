// Supabase Edge Function: GET /v1/packs/download?pack_id=...&version=...
//
// Auth: Authorization: Bearer <api_key_plaintext>
//
// Returns a short-lived signed URL for a single pack version.

import { createClient } from "npm:@supabase/supabase-js@2";
import { authenticateTenantApiKey } from "../_shared/api-key-auth.ts";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

const PACKS_BUCKET = (Deno.env.get("AIDR_PACKS_BUCKET") ?? "aidr-packs").trim();
const URL_TTL_SECONDS = Number(Deno.env.get("AIDR_PACK_URL_TTL_SECONDS") ?? "600");

function json(status: number, body: Record<string, unknown>) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
	});
}

Deno.serve(async (req) => {
	if (req.method !== "GET") return json(405, { error: "method_not_allowed" });

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) return configFailure("packs-download", config.error, json);
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

	const apiKey = getBearerToken(req.headers.get("Authorization"));
	if (!apiKey) return json(401, { error: "missing_api_key" });

	const url = new URL(req.url);
	const packId = (url.searchParams.get("pack_id") ?? "").trim();
	const version = (url.searchParams.get("version") ?? "").trim();
	if (!packId || !version) return json(400, { error: "missing_pack_id_or_version" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	const auth = await authenticateTenantApiKey(supabase, apiKey);
	if (!auth.ok) return json(auth.status, { error: auth.error });
	const { tenantId } = auth;
	const { data: entRow, error: entErr } = await supabase
		.from("entitlements")
		.select("premium_intel,premium_pkg_plugin")
		.eq("tenant_id", tenantId)
		.maybeSingle();
	if (entErr || !entRow) return json(500, { error: "missing_entitlements" });
	if (entRow.premium_intel !== true && entRow.premium_pkg_plugin !== true) {
		return json(403, { error: "premium_required" });
	}

	const { data: row, error: rowErr } = await supabase
		.from("pack_versions")
		.select("storage_path,tenant_id")
		.eq("pack_id", packId)
		.eq("version", version)
		.maybeSingle();
	if (rowErr || !row) return json(404, { error: "pack_not_found" });
	if (row.tenant_id && row.tenant_id !== tenantId) return json(404, { error: "pack_not_found" });

	const { data: signed, error: signErr } = await supabase.storage
		.from(PACKS_BUCKET)
		.createSignedUrl(row.storage_path as string, Math.max(60, URL_TTL_SECONDS));
	if (signErr || !signed?.signedUrl) return json(500, { error: "sign_url_failed" });

	return json(200, { ok: true, download_url: signed.signedUrl });
});
