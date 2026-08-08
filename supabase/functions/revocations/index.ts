// Supabase Edge Function: GET /v1/revocations
//
// Auth: Authorization: Bearer <api_key_plaintext>
//
// Returns a signed revocations payload used by commercial runtimes to:
// - revoke entitlement serials
// - revoke pack ids / versions
// - revoke artifact ids
// - revoke key ids
//
// NOTE: This is a minimal v1 implementation for managed-first deployments.

import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

const REVOCATION_SIGNING_KEY_ID = (Deno.env.get("AIDR_REVOCATION_SIGNING_KEY_ID") ?? "").trim();
const REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64 = (
	Deno.env.get("AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64") ?? ""
).trim();
const REVOCATION_EPOCH = Number(Deno.env.get("AIDR_REVOCATION_EPOCH") ?? "1");
const REVOCATION_TTL_HOURS = Number(Deno.env.get("AIDR_REVOCATION_TTL_HOURS") ?? "24");

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

function canonicalizeForSigning(value: unknown): unknown {
	if (Array.isArray(value)) return value.map((v) => canonicalizeForSigning(v));
	if (!value || typeof value !== "object") return value;
	const obj = value as Record<string, unknown>;
	const out: Record<string, unknown> = {};
	for (const key of Object.keys(obj).sort()) out[key] = canonicalizeForSigning(obj[key]);
	return out;
}

function canonicalJson(value: unknown): string {
	return JSON.stringify(canonicalizeForSigning(value));
}

function bytesToBase64(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin);
}

async function signEd25519Detached(payloadJson: string): Promise<string | null> {
	if (!REVOCATION_SIGNING_KEY_ID || !REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64) return null;
	try {
		const pkcs8 = Uint8Array.from(
			atob(REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64),
			(c) => c.charCodeAt(0),
		);
		const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, [
			"sign",
		]);
		const sig = await crypto.subtle.sign("Ed25519", key, new TextEncoder().encode(payloadJson));
		return bytesToBase64(new Uint8Array(sig));
	} catch {
		return null;
	}
}

function addHoursIso(hours: number): string {
	const safe = Number.isFinite(hours) ? Math.max(0, hours) : 0;
	return new Date(Date.now() + safe * 60 * 60 * 1000).toISOString();
}

type RevocationRow = {
	kind: string;
	value: string;
	tenant_id?: string | null;
};

Deno.serve(async (req) => {
	if (req.method !== "GET") {
		return json(405, { error: "method_not_allowed" });
	}

	if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
		return json(500, { error: "misconfigured_supabase_env" });
	}

	const apiKey = getBearerToken(req);
	if (!apiKey) {
		return json(401, { error: "missing_api_key" });
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
	const tenantId = (keyRow.tenant_id as string | null) ?? (keyRow.user_id as string);

	const { data: rows, error: rowsErr } = await supabase
		.from("revocations")
		.select("kind,value,tenant_id")
		.order("id", { ascending: false })
		.limit(5000);
	if (rowsErr) {
		return json(500, { error: "db_error" });
	}

	const artifacts: string[] = [];
	const packs: string[] = [];
	const keys: string[] = [];
	const entitlementSerials: string[] = [];

	for (const row of (rows ?? []) as RevocationRow[]) {
		if (!row || typeof row.kind !== "string" || typeof row.value !== "string") continue;
		if (row.tenant_id && row.tenant_id !== tenantId) continue;
		const kind = row.kind.trim();
		const value = row.value.trim();
		if (!kind || !value) continue;
		if (kind === "artifact_id") artifacts.push(value);
		else if (kind === "pack_id") packs.push(value);
		else if (kind === "key_id") keys.push(value);
		else if (kind === "entitlement_serial") entitlementSerials.push(value);
	}

	const payload = {
		schema_version: 1,
		issued_at: new Date().toISOString(),
		expires_at: addHoursIso(REVOCATION_TTL_HOURS),
		revocation_epoch: Number.isFinite(REVOCATION_EPOCH) ? Math.max(1, Math.floor(REVOCATION_EPOCH)) : 1,
		revocations: {
			artifact_ids: artifacts,
			pack_ids: packs,
			key_ids: keys,
			entitlement_serials: entitlementSerials,
		},
	};

	const payloadJson = canonicalJson(payload);
	const sig = await signEd25519Detached(payloadJson);

	return json(200, {
		revocations_signed: sig
			? {
					alg: "ed25519",
					key_id: REVOCATION_SIGNING_KEY_ID,
					sig_b64: sig,
					payload: JSON.parse(payloadJson),
				}
			: null,
	});
});
