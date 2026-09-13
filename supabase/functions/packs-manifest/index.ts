// Supabase Edge Function: GET /v1/packs/manifest
//
// Auth: Authorization: Bearer <api_key_plaintext>
//
// Returns signed download URLs for premium intel packs, gated by entitlements.

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
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

	const apiKey = getBearerToken(req.headers.get("Authorization"));
	if (!apiKey) return json(401, { error: "missing_api_key" });

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

	// Only premium tiers receive managed pack delivery.
	if (entRow.premium_intel !== true && entRow.premium_pkg_plugin !== true) {
		return json(200, { ok: true, packs: [] });
	}

	const { data: rows, error: rowsErr } = await supabase
		.from("pack_versions")
		.select("pack_id,version,tenant_id,storage_path,manifest_json,manifest_sig_b64,key_id,issued_at,expires_at")
		.order("issued_at", { ascending: false })
		.limit(200);
	if (rowsErr) return json(500, { error: "db_error" });

	const packs: Array<Record<string, unknown>> = [];
	for (const row of (rows ?? []) as PackVersionRow[]) {
		if (row.tenant_id && row.tenant_id !== tenantId) continue;
		if (!row.pack_id || !row.version || !row.storage_path) continue;
		const { data: signed, error: signErr } = await supabase.storage
			.from(PACKS_BUCKET)
			.createSignedUrl(row.storage_path, Math.max(60, URL_TTL_SECONDS));
		if (signErr || !signed?.signedUrl) continue;

		packs.push({
			pack_id: row.pack_id,
			version: row.version,
			key_id: row.key_id,
			issued_at: row.issued_at,
			expires_at: row.expires_at,
			manifest: row.manifest_json,
			manifest_sig_b64: row.manifest_sig_b64,
			download_url: signed.signedUrl,
		});
	}

	return json(200, { ok: true, packs });
});
