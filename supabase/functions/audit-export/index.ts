import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";
import { ADMIN_AUDIT_EXPORT_COLUMNS, AUDIT_EXPORT_COLUMNS, serializeAuditExport } from "../_shared/audit-export.ts";
import { type PlanEntitlementDb, requireFeature } from "../_shared/plan-entitlements.ts";
import { readAuditCursor, signAuditCursor } from "../_shared/export-cursor.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import {
	AUDIT_EXPORT_MAX_OBJECT_BYTES,
	registerAuditExportObject,
	tenantStorageLimitBytes,
} from "../_shared/tenant-quotas.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 8 * 1024;
const AUDIT_EXPORT_ROLES: ReadonlySet<string> = new Set(["owner", "admin"]);
const AUDIT_EXPORT_PER_USER_PER_MINUTE = 30;
const AUDIT_EXPORT_PER_TENANT_PER_MINUTE = 60;

export interface AuditExportDeps {
	/** Overrides the service-role client; used by the contract suite. */
	db?: ReturnType<typeof createClient>;
}

/** Build the request handler. Exported so the contract suite can drive it. */
export function createAuditExportHandler(deps: AuditExportDeps = {}) {
	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) return configFailure("audit-export", config.error, (status, body) => corsJson(req, status, body));
		try {
			const db = deps.db ?? createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
			const token = getBearerToken(req.headers.get("Authorization"));
			if (!token) return corsJson(req, 401, { error: "missing_access_token" });
			const { data: auth, error } = await db.auth.getUser(token);
			if (error || !auth.user) return corsJson(req, 401, { error: "invalid_access_token" });
			const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
			if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
			const body = parsed.value as Record<string, unknown>;
			if (!body || typeof body.team_id !== "string" || !/^[0-9a-f-]{36}$/i.test(body.team_id) || !["json", "csv"].includes(String(body.format))) return corsJson(req, 400, { error: "invalid_export" });
			// `source: "admin"` exports the administrative trail (admin_audit_logs);
			// absent or "audit" exports the tenant audit_logs trail as before.
			if (body.source !== undefined && body.source !== "audit" && body.source !== "admin") return corsJson(req, 400, { error: "invalid_export" });
			const adminTrail = body.source === "admin";
			const identity = await checkIdentityBarrier(db, token, auth.user.id, body.team_id);
			if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });
			const { data: member, error: memberError } = await db.from("tenant_members").select("role,expires_at").eq("tenant_id", body.team_id).eq("user_id", auth.user.id).maybeSingle();
			if (memberError) return corsJson(req, 503, { error: "authorization_unavailable" });
			if (!membershipActive(member)) return corsJson(req, 403, { error: "team_forbidden" });
			// Product decision: bulk audit export (a copy of the whole tenant audit
			// trail) is an owner/admin capability. Viewers and members keep in-app
			// read access but cannot export.
			if (!AUDIT_EXPORT_ROLES.has(String((member as { role?: unknown } | null)?.role ?? ""))) {
				return corsJson(req, 403, { error: "audit_export_forbidden" });
			}
			const { data: tenant, error: tenantError } = await db.from("tenants").select("status").eq("id", body.team_id).maybeSingle();
			if (tenantError) return corsJson(req, 503, { error: "authorization_unavailable" });
			if ((tenant as { status?: string } | null)?.status !== "active") return corsJson(req, 403, { error: "tenant_inactive" });
			// Bulk export to a SIEM or archive is a BUSINESS feature. Checked after
			// the caller is bound to the tenant and before any audit read; fails closed.
			const plan = await requireFeature(db as unknown as PlanEntitlementDb, body.team_id, "siem_export");
			if (!plan.ok) return corsJson(req, plan.status, plan.body);
			// Each page signs a cursor, uploads an object and mints a URL; bound it per
			// exporter and per tenant before any audit read or Storage work.
			const rate = await consumeTenantRateLimit(db, {
				tenantId: body.team_id,
				subject: auth.user.id,
				endpoint: "audit-export",
				perSubject: AUDIT_EXPORT_PER_USER_PER_MINUTE,
				perTenant: AUDIT_EXPORT_PER_TENANT_PER_MINUTE,
			});
			if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
			// An active legal hold preserves this tenant's records for litigation, so
			// no export may copy them out until the hold is released. This barrier is
			// unconditional: it is not a plan, flag or configuration toggle, and an
			// unreadable hold row fails closed instead of producing an export.
			const { data: hold, error: holdError } = await db.from("tenant_legal_holds").select("id").eq("tenant_id", body.team_id).is("released_at", null).limit(1).maybeSingle();
			if (holdError) return corsJson(req, 503, { error: "legal_hold_unavailable" });
			if (hold) return corsJson(req, 409, { error: "legal_hold_active" });
			const binding = { tenant: body.team_id, user: auth.user.id, format: body.format as "csv" | "json", ...(adminTrail ? { source: "admin" as const } : {}) };
			let cursor;
			try { cursor = body.cursor === undefined ? null : await readAuditCursor(body.cursor, config.values.SUPABASE_SERVICE_ROLE_KEY, binding); }
			catch { return corsJson(req, 400, { error: "invalid_or_expired_export_cursor" }); }
			const snapshot = cursor?.snapshot ?? new Date().toISOString();
			const expires = cursor?.expires ?? Date.now() + 900000;
			let query = db.from(adminTrail ? "admin_audit_logs" : "audit_logs").select((adminTrail ? ADMIN_AUDIT_EXPORT_COLUMNS : AUDIT_EXPORT_COLUMNS).join(",")).eq("tenant_id", body.team_id).lte("created_at", snapshot).order("created_at", { ascending: true }).order("id", { ascending: true }).limit(501);
			if (cursor) query = query.or(`created_at.gt.${cursor.after.created_at},and(created_at.eq.${cursor.after.created_at},id.gt.${cursor.after.id})`);
			const { data: rows, error: rowsError } = await query;
			if (rowsError || !rows) return corsJson(req, 503, { error: "export_unavailable" });
			const page = rows.slice(0, 500) as unknown as Array<{ created_at: string; id: string | number } & Record<string, unknown>>;
			const last = page[page.length - 1];
			const nextCursor = rows.length > 500 ? await signAuditCursor({ ...binding, snapshot, expires, after: { created_at: last.created_at, id: String(last.id) } }, config.values.SUPABASE_SERVICE_ROLE_KEY) : null;
			const path = `${body.team_id}/${crypto.randomUUID()}.${body.format}`;
			const content = serializeAuditExport(page, body.format as "csv" | "json", adminTrail ? ADMIN_AUDIT_EXPORT_COLUMNS : AUDIT_EXPORT_COLUMNS);
			const contentBytes = new TextEncoder().encode(content);
			const bytes = contentBytes.byteLength;
			if (bytes > AUDIT_EXPORT_MAX_OBJECT_BYTES) return corsJson(req, 413, { error: "export_page_too_large" });
			const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", contentBytes));
			const sha256 = Array.from(digest, (value) => value.toString(16).padStart(2, "0")).join("");
			// The bytes are reserved in the tenant ledger before the object exists:
			// an over-quota export is refused here and no object is ever uploaded.
			const reservation = await registerAuditExportObject(db, {
				tenantId: body.team_id,
				actorUserId: auth.user.id,
				path,
				bytes,
				limitBytes: tenantStorageLimitBytes(runtimeEnv),
			});
			if (!reservation.ok) {
				return corsJson(req, reservation.status, {
					error: reservation.error,
					tenant_storage_bytes_remaining: reservation.remainingBytes,
				});
			}
			const exportRpc = db.rpc.bind(db) as (name: string, args: Record<string, unknown>) => PromiseLike<{ data: unknown; error: unknown }>;
			let published = false;
			let uploadConfirmed = false;
			try {
				const { error: uploadError } = await db.storage.from("aidr-audit-exports").upload(path, content, { contentType: body.format === "json" ? "application/json" : "text/csv", upsert: false });
				if (uploadError) return corsJson(req, 503, { error: "export_storage_unavailable" });
				uploadConfirmed = true;
				const { data, error: signError } = await db.storage.from("aidr-audit-exports").createSignedUrl(path, 60, { download: `aidr-audit.${body.format}` });
				if (signError || !data?.signedUrl) return corsJson(req, 503, { error: "export_unavailable" });
				const signed = new URL(data.signedUrl);
				const publicBase = new URL(runtimeEnv("SUPABASE_PUBLIC_URL") || config.values.SUPABASE_URL);
				const downloadUrl = new URL(signed.pathname + signed.search, publicBase.origin).href;
				// Publication is the linearization point with hold placement. A hold
				// placed during Storage HTTP wins and no signed URL leaves this route.
				const { data: publication, error: publicationError } = await exportRpc("finalize_audit_export_object", {
					p_tenant_id: body.team_id,
					p_actor_user_id: auth.user.id,
					p_path: path,
				});
				if (publicationError) return corsJson(req, 503, { error: "export_unavailable" });
				if (publication === "legal_hold_active") return corsJson(req, 409, { error: "legal_hold_active" });
				if (publication !== "published") return corsJson(req, 503, { error: "export_unavailable" });
				const response = corsJson(req, 200, { ok: true, url: downloadUrl, rows: page.length, bytes, sha256, expires_in: 60, snapshot, next_cursor: nextCursor, complete: nextCursor === null, tenant_storage_bytes_remaining: reservation.remainingBytes });
				published = true;
				return response;
			} finally {
				if (!published && uploadConfirmed) {
					// A confirmed upload can be cleaned immediately. Ambiguous upload
					// failures retain the normal expiry before Storage reconciliation.
					try {
						await exportRpc("abandon_audit_export_object", {
							p_tenant_id: body.team_id,
							p_actor_user_id: auth.user.id,
							p_path: path,
						});
					} catch { /* normal expiry remains the fail-safe */ }
				}
			}
		} catch { return corsJson(req, 503, { error: "export_unavailable" }); }
	};
}

Deno.serve(createAuditExportHandler());
