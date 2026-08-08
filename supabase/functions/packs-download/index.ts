// Supabase Edge Function: GET /v1/packs/download?pack_id=...&version=...
//
// Auth: Authorization: Bearer <api_key_plaintext>
//
// Returns a short-lived signed URL for a single pack version.

import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

const PACKS_BUCKET = (Deno.env.get("AIDR_PACKS_BUCKET") ?? "aidr-packs").trim();
const URL_TTL_SECONDS = Number(Deno.env.get("AIDR_PACK_URL_TTL_SECONDS") ?? "600");

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

Deno.serve(async (req) => {
	if (req.method !== "GET") return json(405, { error: "method_not_allowed" });
	if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
		return json(500, { error: "misconfigured_supabase_env" });
	}

	const apiKey = getBearerToken(req);
	if (!apiKey) return json(401, { error: "missing_api_key" });

	const url = new URL(req.url);
	const packId = (url.searchParams.get("pack_id") ?? "").trim();
	const version = (url.searchParams.get("version") ?? "").trim();
	if (!packId || !version) return json(400, { error: "missing_pack_id_or_version" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	const keyHash = await sha256Hex(apiKey);
	const { data: keyRow, error: keyErr } = await supabase
		.from("api_keys")
		.select("user_id, tenant_id, revoked")
		.eq("key_hash", keyHash)
		.maybeSingle();
	if (keyErr || !keyRow || keyRow.revoked) return json(401, { error: "invalid_api_key" });

	const userId = keyRow.user_id as string;
	const tenantId = (keyRow.tenant_id as string | null) ?? userId;
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
