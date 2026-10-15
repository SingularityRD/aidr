// Customer installer downloads for the dashboard Download page.
//
// GET   Header X-AIDR-Tenant-ID. Returns the current installer catalog (version,
//       release notes URL, one file per platform and format with size, SHA-256 and
//       minimum OS) and, when this control plane offers managed enrollment to the
//       caller, its public URL.
// POST  { tenant_id, version, platform, format? }. Returns a short-lived signed
//       Storage URL for that one installer of the CURRENT version and records an
//       audit row (tenant, user, version, platform, format, file, SHA-256; no IP
//       address). `format` (msi, deb, rpm, tar.gz, ...) must be one the catalog
//       lists for that platform; without it the platform's default format is served.
//
// Authorization is re-derived for every request and fails closed: a Supabase
// session (401), the identity barrier, an active membership of an active tenant
// (403), and an ACTIVE admission from get_tenant_admission (expired, revoked or
// unentitled tenants get 403; an unreadable admission is 503). The catalog is
// served only after its Ed25519 signature, the signed latest.json pointer and the
// pointer digest verify (_shared/installer-catalog.ts); otherwise nothing is
// listed and no URL is minted. A URL is returned only after the audit row commits.
//
// Storage contract and operator setup: docs/installation/download-portal.md.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, type EnvReader, loadConfig } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { parseActiveAdmission } from "../_shared/effective-seats.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import {
	INSTALLER_PLATFORMS,
	type InstallerCatalog,
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
import { membershipActive } from "../_shared/runtime-policy.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64"] as const;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const BUCKET = /^[a-z0-9][a-z0-9._-]{1,62}$/;
const MAX_BODY_BYTES = 2048;
const MEMBER_ROLES = ["owner", "admin", "member", "viewer"];
const ENROLLING_ROLES = ["owner", "admin", "member"];
const NOT_ADMITTED = ["expired", "revoked", "none", "not_entitled", "unconfigured"];
// Per user and per tenant, per minute. Reads are cheap but verify two signatures;
// a download mints a URL and writes an audit row.
const CATALOG_RATE_LIMIT = { endpoint: "installer-catalog", perSubject: 60, perTenant: 3000 } as const;
const DOWNLOAD_RATE_LIMIT = { endpoint: "installer-download", perSubject: 20, perTenant: 600 } as const;

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

export interface InstallerDownloadDeps {
	env?: EnvReader;
	client?: (url: string, key: string) => DatabaseClient;
	now?: () => number;
}

type DownloadRequest = { tenantId: string; version: string; platform: string; format: string | null };

function parseDownloadRequest(value: unknown): DownloadRequest | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const body = value as Record<string, unknown>;
	if (Object.keys(body).some((key) => !["tenant_id", "version", "platform", "format"].includes(key))) return null;
	if (typeof body.tenant_id !== "string" || !UUID.test(body.tenant_id)) return null;
	if (typeof body.version !== "string" || body.version.length < 1 || body.version.length > 96) return null;
	if (typeof body.platform !== "string" || !(INSTALLER_PLATFORMS as readonly string[]).includes(body.platform)) return null;
	const format = requestedFormat(body.format);
	if (format === undefined) return null;
	return { tenantId: body.tenant_id.toLowerCase(), version: body.version, platform: body.platform, format };
}

function catalogView(catalog: InstallerCatalog) {
	return {
		version: catalog.version,
		published_at: catalog.published_at,
		release_notes_url: catalog.release_notes_url,
		release_tag: catalog.release.tag,
		files: catalog.files.map(({ platform, os, arch, file, size, sha256, minimum_os, format }) => ({
			platform,
			os,
			arch,
			file,
			size,
			sha256,
			minimum_os,
			format,
		})),
	};
}

function storageReader(db: DatabaseClient, bucket: string): ObjectReader {
	return async (path, maxBytes) => {
		const { data, error } = await db.storage.from(bucket).download(path);
		if (error) {
			const status = Number((error as { statusCode?: unknown; status?: unknown }).statusCode ?? (error as { status?: unknown }).status);
			const message = String((error as { message?: unknown }).message ?? "");
			return status === 404 || status === 400 || /not.?found/i.test(message) ? null : "error";
		}
		if (!data) return "error";
		if (data.size > maxBytes) return "error";
		return new Uint8Array(await data.arrayBuffer());
	};
}

export function createInstallerDownloadHandler(deps: InstallerDownloadDeps = {}) {
	const runtimeEnv = deps.env ?? readRuntimeEnv;
	const now = deps.now ?? Date.now;
	const makeClient = deps.client ?? ((url, key) => createClient(url, key, {
		auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
	}));

	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "GET" && req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) {
			return configFailure("installer-download", config.error, (status, body) => corsJson(req, status, body));
		}
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
		if (!spki || !publicOrigin || invalid.length > 0) return corsJson(req, 500, { error: "server_misconfigured", invalid });

		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });

		let download: DownloadRequest | null = null;
		let tenantId: string;
		if (req.method === "GET") {
			const header = (req.headers.get("X-AIDR-Tenant-ID") ?? "").trim();
			if (!UUID.test(header)) return corsJson(req, 400, { error: "invalid_request" });
			tenantId = header.toLowerCase();
		} else {
			const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
			if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
			download = parseDownloadRequest(parsed.value);
			if (!download) return corsJson(req, 400, { error: "invalid_request" });
			tenantId = download.tenantId;
		}

		try {
			const db = makeClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
			const { data: auth, error: authError } = await db.auth.getUser(token);
			if (authError || !auth.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
			const userId = auth.user.id;
			const barrier = await checkIdentityBarrier(db, token, userId, tenantId);
			if (!barrier.ok) return corsJson(req, barrier.status, { error: barrier.error });

			const [{ data: member, error: memberError }, { data: tenant, error: tenantError }] = await Promise.all([
				db.from("tenant_members").select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle(),
				db.from("tenants").select("id,status").eq("id", tenantId).maybeSingle(),
			]);
			if (memberError || tenantError) return corsJson(req, 503, { error: "authorization_unavailable" });
			const role = String((member as { role?: unknown } | null)?.role ?? "");
			if (
				!membershipActive(member as { role?: string; expires_at?: string | null } | null, now()) ||
				!MEMBER_ROLES.includes(role) ||
				(tenant as { status?: unknown } | null)?.status !== "active"
			) {
				return corsJson(req, 403, { error: "tenant_not_authorized" });
			}

			const { data: admissionData, error: admissionError } = await db.rpc("get_tenant_admission", {
				p_tenant_id: tenantId,
				p_user_id: userId,
			});
			if (admissionError) return corsJson(req, 503, { error: "admission_unavailable" });
			const admissionStatus = String((admissionData as { status?: unknown } | null)?.status ?? "");
			if (NOT_ADMITTED.includes(admissionStatus)) return corsJson(req, 403, { error: "entitlement_required" });
			if (!parseActiveAdmission(admissionData, now())) return corsJson(req, 503, { error: "admission_unavailable" });

			const rate = await consumeTenantRateLimit(db, {
				tenantId,
				subject: userId,
				...(download ? DOWNLOAD_RATE_LIMIT : CATALOG_RATE_LIMIT),
				now: now(),
			});
			if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));

			const loaded = await loadVerifiedCatalog(storageReader(db, bucket), spki);
			if (!loaded.ok) return corsJson(req, loaded.status, { error: loaded.error });
			const { catalog } = loaded;

			if (!download) {
				return corsJson(req, 200, {
					ok: true,
					catalog: catalogView(catalog),
					managed_enrollment: ENROLLING_ROLES.includes(role)
						? { available: true, control_plane_url: publicOrigin }
						: { available: false },
				}, { "Cache-Control": "no-store" });
			}

			const file = download.version === catalog.version
				? selectInstallerFile(catalog, download.platform, download.format)
				: undefined;
			if (!file) return corsJson(req, 404, { error: "installer_not_found" });
			const ttl = installerUrlTtlSeconds(runtimeEnv("AIDR_INSTALLER_URL_TTL_SECONDS"));
			const { data: signed, error: signError } = await db.storage
				.from(bucket)
				.createSignedUrl(file.path, ttl, { download: file.file });
			if (signError) return corsJson(req, 503, { error: "download_unavailable" });
			const url = publicInstallerUrl(signed?.signedUrl, SUPABASE_URL, publicOrigin, bucket);
			if (!url) return corsJson(req, 503, { error: "download_unavailable" });

			const { data: audit, error: auditError } = await db.rpc("record_installer_download", {
				p_actor_user_id: userId,
				p_tenant_id: tenantId,
				p_version: catalog.version,
				p_platform: file.platform,
				p_format: file.format,
				p_file_name: file.file,
				p_sha256: file.sha256,
			});
			if (auditError) return corsJson(req, 503, { error: "audit_unavailable" });
			const auditStatus = (audit as { status?: unknown } | null)?.status;
			if (auditStatus === "forbidden") return corsJson(req, 403, { error: "tenant_not_authorized" });
			if (auditStatus !== "recorded") return corsJson(req, 503, { error: "audit_unavailable" });

			return corsJson(req, 200, {
				ok: true,
				url,
				expires_at: new Date(now() + ttl * 1000).toISOString(),
				version: catalog.version,
				platform: file.platform,
				format: file.format,
				file: file.file,
				size: file.size,
				sha256: file.sha256,
			}, { "Cache-Control": "no-store" });
		} catch {
			return corsJson(req, 503, { error: "installer_download_unavailable" });
		}
	};
}

Deno.serve(createInstallerDownloadHandler());
