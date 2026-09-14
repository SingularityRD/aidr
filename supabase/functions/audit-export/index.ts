import { createClient } from "npm:@supabase/supabase-js@2";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";
import { serializeAuditExport } from "../_shared/audit-export.ts";
import { readAuditCursor, signAuditCursor } from "../_shared/export-cursor.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

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
			let body: Record<string, unknown>;
			try { body = await req.json(); } catch { return corsJson(req, 400, { error: "invalid_json" }); }
			if (!body || typeof body.team_id !== "string" || !/^[0-9a-f-]{36}$/i.test(body.team_id) || !["json", "csv"].includes(String(body.format))) return corsJson(req, 400, { error: "invalid_export" });
			const identity = await checkIdentityBarrier(db, token, auth.user.id, body.team_id);
			if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });
			const { data: member, error: memberError } = await db.from("tenant_members").select("role,expires_at").eq("tenant_id", body.team_id).eq("user_id", auth.user.id).maybeSingle();
			if (memberError) return corsJson(req, 503, { error: "authorization_unavailable" });
			if (!membershipActive(member)) return corsJson(req, 403, { error: "team_forbidden" });
			const { data: tenant, error: tenantError } = await db.from("tenants").select("status").eq("id", body.team_id).maybeSingle();
			if (tenantError) return corsJson(req, 503, { error: "authorization_unavailable" });
			if (tenant?.status !== "active") return corsJson(req, 403, { error: "tenant_inactive" });
			// An active legal hold preserves this tenant's records for litigation, so
			// no export may copy them out until the hold is released. This barrier is
			// unconditional: it is not a plan, flag or configuration toggle, and an
			// unreadable hold row fails closed instead of producing an export.
			const { data: hold, error: holdError } = await db.from("tenant_legal_holds").select("id").eq("tenant_id", body.team_id).is("released_at", null).limit(1).maybeSingle();
			if (holdError) return corsJson(req, 503, { error: "legal_hold_unavailable" });
			if (hold) return corsJson(req, 409, { error: "legal_hold_active" });
			const binding = { tenant: body.team_id, user: auth.user.id, format: body.format as "csv" | "json" };
			let cursor;
			try { cursor = body.cursor === undefined ? null : await readAuditCursor(body.cursor, config.values.SUPABASE_SERVICE_ROLE_KEY, binding); }
			catch { return corsJson(req, 400, { error: "invalid_or_expired_export_cursor" }); }
			const snapshot = cursor?.snapshot ?? new Date().toISOString();
			const expires = cursor?.expires ?? Date.now() + 900000;
			let query = db.from("audit_logs").select("id,created_at,user_id,action,verdict").eq("tenant_id", body.team_id).lte("created_at", snapshot).order("created_at", { ascending: true }).order("id", { ascending: true }).limit(501);
			if (cursor) query = query.or(`created_at.gt.${cursor.after.created_at},and(created_at.eq.${cursor.after.created_at},id.gt.${cursor.after.id})`);
			const { data: rows, error: rowsError } = await query;
			if (rowsError || !rows) return corsJson(req, 503, { error: "export_unavailable" });
			const page = rows.slice(0, 500);
			const last = page[page.length - 1];
			const nextCursor = rows.length > 500 ? await signAuditCursor({ ...binding, snapshot, expires, after: { created_at: last.created_at, id: last.id } }, config.values.SUPABASE_SERVICE_ROLE_KEY) : null;
			const path = `${body.team_id}/${crypto.randomUUID()}.${body.format}`;
			const content = serializeAuditExport(page, body.format as "csv" | "json");
			if (new TextEncoder().encode(content).length > 8 * 1024 * 1024) return corsJson(req, 413, { error: "export_page_too_large" });
			const registration = await db.from("audit_export_objects").insert({ path, tenant_id: body.team_id, created_by: auth.user.id });
			if (registration.error) return corsJson(req, 503, { error: "export_retention_unavailable" });
			const { error: uploadError } = await db.storage.from("aidr-audit-exports").upload(path, content, { contentType: body.format === "json" ? "application/json" : "text/csv", upsert: false });
			if (uploadError) return corsJson(req, 503, { error: "export_storage_unavailable" });
			const { data, error: signError } = await db.storage.from("aidr-audit-exports").createSignedUrl(path, 60, { download: `aidr-audit.${body.format}` });
			if (signError || !data?.signedUrl) return corsJson(req, 503, { error: "export_unavailable" });
			const signed = new URL(data.signedUrl);
			const publicBase = new URL(runtimeEnv("SUPABASE_PUBLIC_URL") || config.values.SUPABASE_URL);
			const downloadUrl = new URL(signed.pathname + signed.search, publicBase.origin).href;
			return corsJson(req, 200, { ok: true, url: downloadUrl, rows: page.length, expires_in: 60, snapshot, next_cursor: nextCursor, complete: nextCursor === null });
		} catch { return corsJson(req, 503, { error: "export_unavailable" }); }
	};
}

Deno.serve(createAuditExportHandler());
