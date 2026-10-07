// GET /functions/v1/packs-download?pack_id=...&version=... returns a
// backwards-compatible download_url. Fetching that URL streams the pack while
// rechecking the API key, membership, tenant and entitlement on every request.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { authenticateTenantApiKeyBudgeted, authenticateTenantApiKeyHash } from "../_shared/api-key-auth.ts";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { retiredSecretActive } from "../_shared/key-rotation.ts";
import { packSigningTtlSeconds, packUrlTtlSeconds } from "../_shared/pack-delivery.ts";
import {
	packDownloadUrl,
	packKeyFingerprint,
	publicPackDownloadOrigin,
	readPackDownloadGrant,
	signPackDownloadGrant,
	validPackDownloadGrantSecret,
	verifyPackKeyFingerprint,
} from "../_shared/pack-download-grant.ts";
import { consumeTenantRateLimit, rateLimitHeaders } from "../_shared/request-limits.ts";
import { sha256 } from "../_shared/runtime-policy.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "AIDR_PACK_DOWNLOAD_GRANT_SECRET"] as const;
const PACKS_BUCKET = (Deno.env.get("AIDR_PACKS_BUCKET") ?? "aidr-packs").trim();
const URL_TTL_SECONDS = packUrlTtlSeconds(Deno.env.get("AIDR_PACK_URL_TTL_SECONDS"));

type DownloadQuery = {
	select(columns: string): DownloadQuery;
	eq(column: string, value: unknown): DownloadQuery;
	maybeSingle(): PromiseLike<{ data: Record<string, unknown> | null; error: unknown }>;
};
type DownloadDatabase = {
	from(table: string): DownloadQuery;
	storage: {
		from(bucket: string): {
			createSignedUrl(path: string, ttl: number): Promise<{ data: { signedUrl?: string } | null; error: unknown }>;
		};
	};
};

function json(status: number, body: Record<string, unknown>, extra: Record<string, string> = {}) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...extra },
	});
}

// One per-key bucket shared by both paths (grant minting and grant streaming), so
// a single API key cannot drive unbounded signing, storage URLs or pack egress.
const PACK_DOWNLOADS_PER_KEY_PER_MINUTE = 120;
const PACK_DOWNLOADS_PER_TENANT_PER_MINUTE = 3000;

async function consumePackDownloadQuota(supabase: unknown, tenantId: string, apiKeyId: string): Promise<Response | null> {
	const rate = await consumeTenantRateLimit(supabase, {
		tenantId,
		subject: apiKeyId,
		endpoint: "packs-download",
		perSubject: PACK_DOWNLOADS_PER_KEY_PER_MINUTE,
		perTenant: PACK_DOWNLOADS_PER_TENANT_PER_MINUTE,
	});
	return rate.ok ? null : json(rate.status, { error: rate.error }, rateLimitHeaders(rate));
}

function trustedStorageUrl(value: unknown, supabaseUrl: string): string | null {
	if (typeof value !== "string" || !value) return null;
	try {
		const base = new URL(supabaseUrl);
		const target = new URL(value, base);
		const prefix = `/storage/v1/object/sign/${encodeURIComponent(PACKS_BUCKET)}/`;
		if (target.origin !== base.origin || !target.pathname.startsWith(prefix) || !target.searchParams.has("token")) return null;
		return target.toString();
	} catch {
		return null;
	}
}

function downloadHeaders(source: Headers): Headers {
	const headers = new Headers({
		"Cache-Control": "private, no-store",
		"X-Content-Type-Options": "nosniff",
		"Content-Disposition": "attachment; filename=\"aidr-pack.bin\"",
	});
	const contentType = source.get("Content-Type");
	if (contentType && !/[\r\n]/.test(contentType)) headers.set("Content-Type", contentType);
	else headers.set("Content-Type", "application/octet-stream");
	const contentLength = source.get("Content-Length");
	if (contentLength && /^\d+$/.test(contentLength)) headers.set("Content-Length", contentLength);
	const contentRange = source.get("Content-Range");
	if (contentRange && /^(?:bytes \d+-\d+\/\d+|bytes \*\/\d+)$/.test(contentRange)) headers.set("Content-Range", contentRange);
	if (source.get("Accept-Ranges")?.toLowerCase() === "bytes") headers.set("Accept-Ranges", "bytes");
	const etag = source.get("ETag");
	if (etag && !/[\r\n]/.test(etag)) headers.set("ETag", etag);
	return headers;
}

async function streamGrantedPack(
	req: Request,
	grantToken: string,
	supabase: unknown,
	supabaseUrl: string,
	grantSecret: string,
): Promise<Response> {
	const db = supabase as DownloadDatabase;
	const grant = await readPackDownloadGrant(grantToken, grantSecret);
	if (!grant) return json(401, { error: "invalid_or_expired_download" });

	const { data: keyRow, error: keyError } = await db
		.from("api_keys")
		.select("key_hash,previous_hash,previous_hash_expires_at,revoked")
		.eq("id", grant.key_id)
		.maybeSingle();
	if (keyError) return json(503, { error: "authorization_unavailable" });
	if (!keyRow || keyRow.revoked !== false) return json(401, { error: "invalid_api_key" });

	const now = Date.now();
	let presentedHash: string | null = null;
	if (typeof keyRow.key_hash === "string" && await verifyPackKeyFingerprint(keyRow.key_hash, grant.key_fingerprint, grantSecret)) {
		presentedHash = keyRow.key_hash;
	} else if (
		typeof keyRow.previous_hash === "string" &&
		retiredSecretActive(keyRow, keyRow.previous_hash, now) &&
		await verifyPackKeyFingerprint(keyRow.previous_hash, grant.key_fingerprint, grantSecret)
	) {
		presentedHash = keyRow.previous_hash;
	}
	if (!presentedHash) return json(401, { error: "invalid_api_key" });

	const auth = await authenticateTenantApiKeyHash(supabase, presentedHash, now);
	if (!auth.ok) return json(auth.status, { error: auth.error });
	if (auth.apiKeyId !== grant.key_id || auth.tenantId !== grant.tenant_id) {
		return json(401, { error: "invalid_download_grant" });
	}
	const limited = await consumePackDownloadQuota(supabase, auth.tenantId, grant.key_id);
	if (limited) return limited;

	const { data: entRow, error: entError } = await db
		.from("entitlements")
		.select("premium_intel,premium_pkg_plugin")
		.eq("tenant_id", auth.tenantId)
		.maybeSingle();
	if (entError || !entRow) return json(503, { error: "authorization_unavailable" });
	if (entRow.premium_intel !== true && entRow.premium_pkg_plugin !== true) return json(403, { error: "premium_required" });

	const { data: pack, error: packError } = await db
		.from("pack_versions")
		.select("storage_path,tenant_id,expires_at")
		.eq("pack_id", grant.pack_id)
		.eq("version", grant.version)
		.maybeSingle();
	if (packError) return json(503, { error: "pack_unavailable" });
	if (!pack || (pack.tenant_id !== null && pack.tenant_id !== auth.tenantId)) return json(404, { error: "pack_not_found" });
	if (typeof pack.storage_path !== "string" || !pack.storage_path.trim()) return json(404, { error: "pack_not_found" });
	const storageTtl = packSigningTtlSeconds(pack.expires_at, Math.min(URL_TTL_SECONDS, 60), now);
	if (storageTtl === null) return json(404, { error: "pack_not_found" });

	const { data: signed, error: signError } = await db.storage
		.from(PACKS_BUCKET)
		.createSignedUrl(pack.storage_path, storageTtl);
	if (signError) return json(502, { error: "download_unavailable" });
	const storageUrl = trustedStorageUrl(signed?.signedUrl, supabaseUrl);
	if (!storageUrl) return json(502, { error: "download_unavailable" });

	const headers = new Headers({ "Accept-Encoding": "identity" });
	const range = req.headers.get("Range");
	if (range) headers.set("Range", range);
	const ifRange = req.headers.get("If-Range");
	if (ifRange) headers.set("If-Range", ifRange);
	let upstream: Response;
	try {
		upstream = await fetch(storageUrl, { method: req.method, headers, redirect: "manual", signal: req.signal });
	} catch {
		return json(502, { error: "download_unavailable" });
	}
	if (upstream.status === 404) return json(404, { error: "pack_not_found" });
	if (upstream.status !== 200 && upstream.status !== 206 && upstream.status !== 416) {
		return json(502, { error: "download_unavailable" });
	}
	return new Response(req.method === "HEAD" || upstream.status === 416 ? null : upstream.body, {
		status: upstream.status,
		headers: downloadHeaders(upstream.headers),
	});
}

Deno.serve(async (req) => {
	const url = new URL(req.url);
	const grantToken = url.searchParams.get("grant");
	if (req.method !== "GET" && !(grantToken !== null && req.method === "HEAD")) {
		return json(405, { error: "method_not_allowed" });
	}

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) return configFailure("packs-download", config.error, json);
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, AIDR_PACK_DOWNLOAD_GRANT_SECRET } = config.values;
	if (!validPackDownloadGrantSecret(AIDR_PACK_DOWNLOAD_GRANT_SECRET)) {
		return json(500, { error: "server_misconfigured", invalid: ["AIDR_PACK_DOWNLOAD_GRANT_SECRET"] });
	}
	const publicOrigin = publicPackDownloadOrigin(SUPABASE_URL, Deno.env.get("AIDR_PUBLIC_API_ORIGIN"), Deno.env.get("AIDR_DEVELOPMENT_MODE") === "true");
	if (!publicOrigin) return json(500, { error: "server_misconfigured", invalid: ["AIDR_PUBLIC_API_ORIGIN"] });
	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});
	if (grantToken !== null) return streamGrantedPack(req, grantToken, supabase, SUPABASE_URL, AIDR_PACK_DOWNLOAD_GRANT_SECRET);
	if (req.method !== "GET") return json(405, { error: "method_not_allowed" });

	const apiKey = getBearerToken(req.headers.get("Authorization"));
	if (!apiKey) return json(401, { error: "missing_api_key" });
	const packId = (url.searchParams.get("pack_id") ?? "").trim();
	const version = (url.searchParams.get("version") ?? "").trim();
	if (!packId || !version || packId.length > 256 || version.length > 256) return json(400, { error: "missing_pack_id_or_version" });

	const auth = await authenticateTenantApiKeyBudgeted(supabase, apiKey, "packs-download");
	if (!auth.ok) return json(auth.status, { error: auth.error });
	if (!auth.apiKeyId) return json(503, { error: "authorization_unavailable" });
	const limited = await consumePackDownloadQuota(supabase, auth.tenantId, auth.apiKeyId);
	if (limited) return limited;
	const { data: entRow, error: entErr } = await supabase
		.from("entitlements")
		.select("premium_intel,premium_pkg_plugin")
		.eq("tenant_id", auth.tenantId)
		.maybeSingle();
	if (entErr || !entRow) return json(500, { error: "missing_entitlements" });
	if (entRow.premium_intel !== true && entRow.premium_pkg_plugin !== true) {
		return json(403, { error: "premium_required" });
	}

	const { data: pack, error: packErr } = await supabase
		.from("pack_versions")
		.select("storage_path,tenant_id,expires_at")
		.eq("pack_id", packId)
		.eq("version", version)
		.maybeSingle();
	if (packErr || !pack) return json(404, { error: "pack_not_found" });
	if (pack.tenant_id !== null && pack.tenant_id !== auth.tenantId) return json(404, { error: "pack_not_found" });
	const grantTtl = packSigningTtlSeconds(pack.expires_at, URL_TTL_SECONDS);
	if (grantTtl === null || typeof pack.storage_path !== "string" || !pack.storage_path.trim()) {
		return json(404, { error: "pack_not_found" });
	}

	try {
		const token = await signPackDownloadGrant({
			key_id: auth.apiKeyId,
			key_fingerprint: await packKeyFingerprint(await sha256(apiKey), AIDR_PACK_DOWNLOAD_GRANT_SECRET),
			tenant_id: auth.tenantId,
			pack_id: packId,
			version,
			expires_at: Math.floor(Date.now() / 1_000) + grantTtl,
		}, AIDR_PACK_DOWNLOAD_GRANT_SECRET);
		return json(200, { ok: true, download_url: packDownloadUrl(publicOrigin, token) });
	} catch {
		return json(500, { error: "download_grant_failed" });
	}
});
