// Installer self-update for enrolled endpoints (`aidr update`, docs/installation/desktop-installers.md#updating).
//
// The dashboard Download page (installer-download) authenticates a person's
// Supabase session. An endpoint has no session: it holds the tenant API key it
// received at managed enrollment. This function is the device path to the SAME
// signed catalog and bucket, with the device credential's own checks:
//
// GET   Authorization: Bearer <tenant API key>. Returns the EXACT signed bytes of
//       latest.json and the versioned manifest.json with their signature
//       envelopes (base64). The endpoint verifies both signatures and the pointer
//       digest itself with the installer-catalog key its installer pinned; this
//       function verifies them too and serves nothing that does not verify.
// POST  { version, platform, format? }. Returns a short-lived signed Storage URL
//       for that one installer of the CURRENT version and records the same audit
//       row as a dashboard download (action installer.download, actor = the key's
//       owner). `format` names the installer matching how the endpoint was
//       installed (msi, deb, rpm, tar.gz) and must be one the catalog lists for
//       that platform; without it the platform's default format is served.
//       The endpoint checks the downloaded bytes against the SHA-256 and size of
//       the catalog it verified, never against this response.
//
// Authorization is re-derived for every request and fails closed: a tenant API
// key (scope `tenant` only; unknown keys are charged to the unresolved-key
// budget), bound to an active owner/admin/member of an active tenant
// (api-key-auth), and an ACTIVE admission from get_tenant_admission (expired,
// revoked or unentitled tenants get 403; an unreadable admission is 503). Rate
// limits are per key and per tenant. installer-download is unchanged.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { authenticateTenantApiKeyBudgeted } from "../_shared/api-key-auth.ts";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, type EnvReader, loadConfig } from "../_shared/config.ts";
import { parseActiveAdmission } from "../_shared/effective-seats.ts";
import {
	INSTALLER_PLATFORMS,
	installerPublicKey,
	installerUrlTtlSeconds,
	loadVerifiedCatalog,
	type ObjectReader,
	publicInstallerUrl,
	requestedFormat,
	selectInstallerFile,
} from "../_shared/installer-catalog.ts";
import { publicPackDownloadOrigin } from "../_shared/pack-download-grant.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64"] as const;
const BUCKET = /^[a-z0-9][a-z0-9._-]{1,62}$/;
const MAX_BODY_BYTES = 1024;
const NOT_ADMITTED = ["expired", "revoked", "none", "not_entitled", "unconfigured"];
// Per API key and per tenant, per minute. An endpoint checks at most a few
// times a day; a fleet rollout downloads once per endpoint.
const CATALOG_RATE_LIMIT = { endpoint: "installer-update-catalog", perSubject: 30, perTenant: 6000 } as const;
const DOWNLOAD_RATE_LIMIT = { endpoint: "installer-update-download", perSubject: 10, perTenant: 3000 } as const;

const readRuntimeEnv: EnvReader = (name) => {
	try {
		const value = Deno.env.get(name);
		if (value !== undefined && value !== null) return value;
	} catch {
		// Node contract tests use process.env when Deno is unavailable.
	}
	return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[name];
};

type DatabaseClient = ReturnType<typeof createClient<any, "public">>;

export interface InstallerUpdateDeps {
	env?: EnvReader;
	client?: (url: string, key: string) => DatabaseClient;
	now?: () => number;
}

function json(status: number, body: Record<string, unknown>, extra: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...extra },
	});
}

function base64(bytes: Uint8Array): string {
	let binary = "";
	for (let index = 0; index < bytes.length; index += 0x8000) {
		binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
	}
	return btoa(binary);
}

type DownloadRequest = { version: string; platform: string; format: string | null };

function parseDownloadRequest(value: unknown): DownloadRequest | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const body = value as Record<string, unknown>;
	if (Object.keys(body).some((key) => !["version", "platform", "format"].includes(key))) return null;
	if (typeof body.version !== "string" || body.version.length < 1 || body.version.length > 96) return null;
	if (typeof body.platform !== "string" || !(INSTALLER_PLATFORMS as readonly string[]).includes(body.platform)) return null;
	const format = requestedFormat(body.format);
	if (format === undefined) return null;
	return { version: body.version, platform: body.platform, format };
}

function storageReader(db: DatabaseClient, bucket: string): ObjectReader {
	return async (path, maxBytes) => {
		const { data, error } = await db.storage.from(bucket).download(path);
		if (error) {
			const status = Number((error as { statusCode?: unknown; status?: unknown }).statusCode ?? (error as { status?: unknown }).status);
			const message = String((error as { message?: unknown }).message ?? "");
			return status === 404 || status === 400 || /not.?found/i.test(message) ? null : "error";
		}
		if (!data || data.size > maxBytes) return "error";
		return new Uint8Array(await data.arrayBuffer());
	};
}

export function createInstallerUpdateHandler(deps: InstallerUpdateDeps = {}) {
	const runtimeEnv = deps.env ?? readRuntimeEnv;
	const now = deps.now ?? Date.now;
	const makeClient = deps.client ?? ((url, key) => createClient(url, key, {
		auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
	}));

	return async function handle(req: Request): Promise<Response> {
		if (req.method !== "GET" && req.method !== "POST") return json(405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) return configFailure("installer-update", config.error, json);
		const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64 } = config.values;
		const spki = installerPublicKey(AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64);
		const bucket = (runtimeEnv("AIDR_INSTALLERS_BUCKET") ?? "aidr-installers").trim();
		const development = runtimeEnv("AIDR_DEVELOPMENT_MODE") === "true";
		const publicOrigin = publicPackDownloadOrigin(SUPABASE_URL, runtimeEnv("AIDR_PUBLIC_API_ORIGIN") ?? undefined, development);
		const invalid = [
			...(spki ? [] : ["AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64"]),
			...(BUCKET.test(bucket) ? [] : ["AIDR_INSTALLERS_BUCKET"]),
			...(publicOrigin ? [] : ["AIDR_PUBLIC_API_ORIGIN"]),
		];
		if (!spki || !publicOrigin || invalid.length > 0) return json(500, { error: "server_misconfigured", invalid });

		const apiKey = getBearerToken(req.headers.get("Authorization"));
		if (!apiKey) return json(401, { error: "missing_api_key" });

		let download: DownloadRequest | null = null;
		if (req.method === "POST") {
			const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
			if (!parsed.ok) return json(parsed.status, { error: parsed.error });
			download = parseDownloadRequest(parsed.value);
			if (!download) return json(400, { error: "invalid_request" });
		}

		try {
			const db = makeClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
			const auth = await authenticateTenantApiKeyBudgeted(db, apiKey, "installer-update", now());
			if (!auth.ok) {
				return json(auth.status, { error: auth.error }, auth.status === 429 ? { "Retry-After": "60" } : {});
			}
			if (!auth.apiKeyId) return json(503, { error: "authorization_unavailable" });

			const { data: admissionData, error: admissionError } = await db.rpc("get_tenant_admission", {
				p_tenant_id: auth.tenantId,
				p_user_id: auth.userId,
			});
			if (admissionError) return json(503, { error: "admission_unavailable" });
			const admissionStatus = String((admissionData as { status?: unknown } | null)?.status ?? "");
			if (NOT_ADMITTED.includes(admissionStatus)) return json(403, { error: "entitlement_required" });
			if (!parseActiveAdmission(admissionData, now())) return json(503, { error: "admission_unavailable" });

			const rate = await consumeTenantRateLimit(db, {
				tenantId: auth.tenantId,
				subject: auth.apiKeyId,
				...(download ? DOWNLOAD_RATE_LIMIT : CATALOG_RATE_LIMIT),
				now: now(),
			});
			if (!rate.ok) return json(rate.status, { error: rate.error }, rateLimitHeaders(rate));

			const loaded = await loadVerifiedCatalog(storageReader(db, bucket), spki);
			if (!loaded.ok) return json(loaded.status, { error: loaded.error });
			const { catalog, documents } = loaded;

			if (!download) {
				return json(200, {
					ok: true,
					version: catalog.version,
					pointer: { document_b64: base64(documents.pointer), signature_b64: base64(documents.pointerSignature) },
					catalog: { document_b64: base64(documents.catalog), signature_b64: base64(documents.catalogSignature) },
				});
			}

			const file = download.version === catalog.version
				? selectInstallerFile(catalog, download.platform, download.format)
				: undefined;
			if (!file) return json(404, { error: "installer_not_found" });
			const ttl = installerUrlTtlSeconds(runtimeEnv("AIDR_INSTALLER_URL_TTL_SECONDS"));
			const { data: signed, error: signError } = await db.storage
				.from(bucket)
				.createSignedUrl(file.path, ttl, { download: file.file });
			if (signError) return json(503, { error: "download_unavailable" });
			const url = publicInstallerUrl(signed?.signedUrl, SUPABASE_URL, publicOrigin, bucket);
			if (!url) return json(503, { error: "download_unavailable" });

			const { data: audit, error: auditError } = await db.rpc("record_installer_download", {
				p_actor_user_id: auth.userId,
				p_tenant_id: auth.tenantId,
				p_version: catalog.version,
				p_platform: file.platform,
				p_format: file.format,
				p_file_name: file.file,
				p_sha256: file.sha256,
			});
			if (auditError) return json(503, { error: "audit_unavailable" });
			const auditStatus = (audit as { status?: unknown } | null)?.status;
			if (auditStatus === "forbidden") return json(403, { error: "tenant_access_denied" });
			if (auditStatus !== "recorded") return json(503, { error: "audit_unavailable" });

			return json(200, {
				ok: true,
				url,
				expires_at: new Date(now() + ttl * 1000).toISOString(),
				version: catalog.version,
				platform: file.platform,
				format: file.format,
				file: file.file,
				size: file.size,
				sha256: file.sha256,
			});
		} catch {
			return json(503, { error: "installer_update_unavailable" });
		}
	};
}

Deno.serve(createInstallerUpdateHandler());
