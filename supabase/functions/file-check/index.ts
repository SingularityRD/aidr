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

	const rawRequests = Array.isArray(body.requests) ? (body.requests as unknown[]) : [];
	const hashes = rawRequests
		.map((r) => extractSha256(r))
		.filter((h): h is string => Boolean(h))
		.slice(0, 50);

	if (hashes.length === 0) {
		return json(200, { responses: [] });
	}

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	// api_key -> user_id (hash-only)
	const keyHash = await sha256Hex(apiKey);
	const { data: keyRow, error: keyErr } = await supabase
		.from("api_keys")
		.select("user_id, tenant_id, revoked")
		.eq("key_hash", keyHash)
		.maybeSingle();

	if (keyErr || !keyRow || keyRow.revoked) {
		return json(401, { error: "invalid_api_key" });
	}

	const userId = keyRow.user_id as string;
	const tenantId = (keyRow.tenant_id as string | null) ?? userId;

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

	return json(200, { responses });
});
