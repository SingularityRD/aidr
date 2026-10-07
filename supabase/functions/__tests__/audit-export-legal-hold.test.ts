// Contract suite for the legal-hold barrier on the private audit-export route.
//
// `supabase/migrations/20260912140000_tenant_offboarding_retention.sql` defines
// `public.tenant_legal_holds` and blocks the offboarding run while a hold is
// unreleased. The export route is the other way tenant records leave the
// system, so it must consult the same table before producing anything: a hold
// that is still in force means the records are preserved for litigation and no
// export may copy them out. The barrier is unconditional (no flag or plan can
// turn it off) and an unreadable hold row fails closed.
//
// The Edge Function imports Supabase through Deno's `npm:` specifier, which a
// Node test runner cannot resolve. The runtime factory only needs to exist, and
// it must never be reached: the suite always injects `deps.db`.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through AuditExportDeps.db");
	},
}));

// The Edge runtime provides `Deno.env` and `Deno.serve`; the test process does
// not. The env stub delegates to `process.env` so `vi.stubEnv` drives the same
// values the production `runtimeEnv` reader would see, and `serve` is a no-op
// because the suite drives the exported handler factory directly.
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: {
		get: (name: string) => process.env[name],
	},
	serve: () => undefined,
};

const TENANT = "22222222-2222-4222-8222-222222222222";
const USER = "11111111-1111-4111-8111-111111111111";
const ROW_ID = "44444444-4444-4444-8444-444444444444";
const HOLD_ID = "55555555-5555-4555-8555-555555555555";
const EXPORT_URL = "https://project.supabase.co/functions/v1/audit-export";

/** A database row shaped exactly like the export's `audit_logs` projection. */
function auditRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		id: ROW_ID,
		created_at: "2026-09-13T00:00:00.000Z",
		user_id: USER,
		action: "policy.published",
		verdict: { decision: "deny" },
		...overrides,
	};
}

describe("audit-export legal-hold barrier", () => {
	interface DbOptions {
		member?: { role: string; expires_at: string | null } | null;
		memberError?: boolean;
		/** The active hold row the route must find, or an explicit absence. */
		hold?: { id: string } | null;
		holdError?: boolean;
		uploadError?: boolean;
		signError?: boolean;
		publication?: "published" | "legal_hold_active" | "reservation_unavailable";
		publicationError?: boolean;
		rows?: unknown[];
		rateAllowed?: boolean;
	}

	/**
	 * Minimal PostgREST-shaped client. Every table read is recorded so a test can
	 * prove the export never reached the records, and the export's own writes
	 * (ledger insert, storage upload, signed URL) are recorded separately so a
	 * refusal can be shown to have produced nothing at all.
	 */
	function database(options: DbOptions = {}) {
		const tables: string[] = [];
		const filters: Array<{ table: string; column: string; value: unknown }> = [];
		const inserts: Array<{ table: string; values: unknown }> = [];
		const rpcs: Array<{ name: string; args: Record<string, unknown> }> = [];
		const quotaCalls: Array<Record<string, unknown>> = [];
		const uploads: string[] = [];
		const uploadContents: string[] = [];
		const signedUrls: string[] = [];
		const queryFor = (table: string) => {
			tables.push(table);
			const query = {
				select: () => query,
				eq: (column: string, value: unknown) => {
					filters.push({ table, column, value });
					return query;
				},
				lte: () => query,
				is: () => query,
				order: () => query,
				limit: () => query,
				or: () => query,
				maybeSingle: async () => {
					if (table === "identity_user_session_state") return { data: { revoked_before: null }, error: null };
					if (table === "tenant_identity_policies") return { data: { require_mfa: false }, error: null };
					if (table === "tenant_members") {
						if (options.memberError) return { data: null, error: { code: "08006" } };
						return {
							data: options.member === undefined ? { role: "owner", expires_at: null } : options.member,
							error: null,
						};
					}
					if (table === "tenants") return { data: { status: "active" }, error: null };
					if (table === "tenant_legal_holds") {
						return options.holdError
							? { data: null, error: { code: "08006", message: "connection failure" } }
							: { data: options.hold ?? null, error: null };
					}
					return { data: null, error: null };
				},
				insert: async (values: unknown) => {
					inserts.push({ table, values });
					return { error: null };
				},
				// The rows query is awaited directly (not through `maybeSingle`).
				then: (onFulfilled: (value: unknown) => unknown, onRejected?: (reason: unknown) => unknown) =>
					Promise.resolve({
						data: table === "audit_logs" ? (options.rows ?? [auditRow()]) : null,
						error: null,
					}).then(onFulfilled, onRejected),
			};
			return query;
		};
		return {
			db: {
				auth: {
					getUser: vi.fn(async (token: string) =>
						token === "valid-token"
							? { data: { user: { id: USER } }, error: null }
							: { data: { user: null }, error: new Error("invalid") },
					),
				},
				from: vi.fn((table: string) => queryFor(table)),
				rpc: async (name: string, args: Record<string, unknown>) => {
					// The per-tenant export quota is recorded separately so the ledger
					// assertions below keep addressing the export's own RPCs.
					if (name === "consume_tenant_rate_limit") {
						quotaCalls.push(args);
						return { data: { allowed: options.rateAllowed !== false, remaining: 10 }, error: null };
					}
					rpcs.push({ name, args });
					// `register_audit_export_object` is the reviewed byte reservation and
					// it is the retention-ledger write: it inserts the export row under
					// the tenant advisory lock, before any object is uploaded.
					if (name === "register_audit_export_object") {
						return { data: [{ allowed: true, remaining_bytes: 4096 }], error: null };
					}
					if (name === "finalize_audit_export_object") {
						return options.publicationError
							? { data: null, error: { code: "08006" } }
							: { data: options.publication ?? "published", error: null };
					}
					if (name === "abandon_audit_export_object") return { data: true, error: null };
					return { data: null, error: null };
				},
				storage: {
					from: (bucket: string) => ({
						upload: async (path: string, content: string) => {
							uploads.push(`${bucket}/${path}`);
							uploadContents.push(content);
							return { error: options.uploadError ? { message: "storage unavailable" } : null };
						},
						createSignedUrl: async (path: string) => {
							signedUrls.push(`${bucket}/${path}`);
							return {
								data: options.signError ? null : {
									signedUrl: `https://project.supabase.co/storage/v1/object/sign/${bucket}/${path}?token=test`,
								},
								error: options.signError ? { message: "signing unavailable" } : null,
							};
						},
					}),
				},
			},
			tables,
			filters,
			inserts,
			rpcs,
			quotaCalls,
			uploads,
			uploadContents,
			signedUrls,
		};
	}

	beforeEach(() => {
		vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
		vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "service-role-key");
	});
	afterEach(() => {
		vi.unstubAllEnvs();
		vi.resetModules();
	});

	async function handlerWith(options: DbOptions = {}) {
		const fake = database(options);
		const mod = await import("../audit-export/index.ts");
		return { handle: mod.createAuditExportHandler({ db: fake.db as never }), ...fake };
	}

	function post(
		body: unknown = { team_id: TENANT, format: "json" },
		headers: Record<string, string> = {},
	): Request {
		return new Request(EXPORT_URL, {
			method: "POST",
			headers: { Authorization: "Bearer valid-token", "Content-Type": "application/json", ...headers },
			body: typeof body === "string" ? body : JSON.stringify(body),
		});
	}

	it("refuses an export while an unreleased legal hold exists", async () => {
		const { handle, tables, inserts, rpcs, uploads, signedUrls } = await handlerWith({ hold: { id: HOLD_ID } });
		const response = await handle(post());

		expect(response.status).toBe(409);
		expect(await response.json()).toMatchObject({ error: "legal_hold_active" });

		// The hold is consulted before any record is read and before any byte is
		// produced: no page query, no byte reservation, no retention ledger row, no
		// stored object and no download link may exist for a held tenant.
		expect(tables).toContain("tenant_legal_holds");
		expect(tables).not.toContain("audit_logs");
		expect(inserts).toEqual([]);
		expect(rpcs).toEqual([]);
		expect(uploads).toEqual([]);
		expect(signedUrls).toEqual([]);
	});

	it("proceeds with the export when no unreleased hold exists", async () => {
		const { handle, tables, filters, inserts, rpcs, uploads, uploadContents, signedUrls } = await handlerWith({ hold: null });
		const response = await handle(post());

		expect(response.status).toBe(200);
		const body = (await response.json()) as Record<string, unknown>;
		expect(body.ok).toBe(true);
		expect(body.rows).toBe(1);
		expect(body.complete).toBe(true);
		const uploadedBytes = new TextEncoder().encode(uploadContents[0]);
		const uploadedDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", uploadedBytes));
		expect(body.bytes).toBe(uploadedBytes.byteLength);
		expect(body.sha256).toBe(Array.from(uploadedDigest, (value) => value.toString(16).padStart(2, "0")).join(""));
		expect(response.headers.get("Cache-Control")).toContain("no-store");
		expect(tables).toContain("tenant_legal_holds");
		expect(tables).toContain("audit_logs");
		expect(filters).toContainEqual({ table: "tenant_members", column: "tenant_id", value: TENANT });
		expect(filters).toContainEqual({ table: "tenant_members", column: "user_id", value: USER });
		expect(filters).toContainEqual({ table: "audit_logs", column: "tenant_id", value: TENANT });
		// The retention ledger row is written by the reviewed byte-reservation RPC
		// under the tenant advisory lock, not by a second client-side insert: `path`
		// is the primary key, so a duplicate write would fail every export.
		expect(inserts).toEqual([]);
		expect(rpcs.map((entry) => entry.name)).toEqual(["register_audit_export_object", "finalize_audit_export_object"]);
		expect(rpcs[0]?.args).toMatchObject({ p_tenant_id: TENANT, p_limit_bytes: 536870912 });
		expect(rpcs[0]?.args.p_bytes).toBeGreaterThan(0);
		expect(uploads).toHaveLength(1);
		// The reserved path is the stored object: the bytes were accounted for the
		// exact object that was uploaded.
		expect(rpcs[0]?.args.p_path).toBe(uploads[0]?.replace("aidr-audit-exports/", ""));
		expect(signedUrls).toHaveLength(1);
		expect(String(body.url)).toContain("/storage/v1/object/sign/aidr-audit-exports/");
	});

	it.each(["viewer", "member", "support_jit"])("refuses an export for an active %s (owner/admin only)", async (role) => {
		const { handle, tables, rpcs, uploads, signedUrls, quotaCalls } = await handlerWith({ member: { role, expires_at: null } });
		const response = await handle(post());
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "audit_export_forbidden" });
		expect(tables).not.toContain("audit_logs");
		expect(quotaCalls).toEqual([]);
		expect(rpcs).toEqual([]);
		expect(uploads).toEqual([]);
		expect(signedUrls).toEqual([]);
	});

	it("allows an active admin and charges the per-user/per-tenant export quota first", async () => {
		const { handle, quotaCalls } = await handlerWith({ member: { role: "admin", expires_at: null } });
		const response = await handle(post());
		expect(response.status).toBe(200);
		expect(quotaCalls).toEqual([expect.objectContaining({
			p_tenant_id: TENANT, p_subject: USER, p_endpoint: "audit-export", p_subject_limit: 30, p_tenant_limit: 60,
		})]);
	});

	it("refuses a rate-limited export before reading records or touching Storage", async () => {
		const { handle, tables, rpcs, uploads } = await handlerWith({ rateAllowed: false });
		const response = await handle(post());
		expect(response.status).toBe(429);
		expect(await response.json()).toEqual({ error: "rate_limited" });
		expect(response.headers.get("Retry-After")).not.toBeNull();
		expect(tables).not.toContain("audit_logs");
		expect(rpcs).toEqual([]);
		expect(uploads).toEqual([]);
	});

	it.each([
		["missing", null],
		["expired", { role: "owner", expires_at: "2000-01-01T00:00:00.000Z" }],
	] as const)("refuses an export for a %s membership", async (_case, member) => {
		const { handle, tables, rpcs, uploads, signedUrls } = await handlerWith({ member });
		const response = await handle(post());
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "team_forbidden" });
		expect(tables).not.toContain("audit_logs");
		expect(rpcs).toEqual([]);
		expect(uploads).toEqual([]);
		expect(signedUrls).toEqual([]);
	});

	it("fails closed when membership authorization cannot be read", async () => {
		const { handle, tables, rpcs, uploads } = await handlerWith({ memberError: true });
		const response = await handle(post());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "authorization_unavailable" });
		expect(tables).not.toContain("audit_logs");
		expect(rpcs).toEqual([]);
		expect(uploads).toEqual([]);
	});

	it.each([
		["upload", { uploadError: true }, "export_storage_unavailable", false],
		["sign", { signError: true }, "export_unavailable", true],
	] as const)("retains a bounded ledger after failed %s", async (_stage, options, error, immediatelyDue) => {
		const { handle, rpcs, uploads, signedUrls } = await handlerWith(options);
		const response = await handle(post());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error });
		expect(rpcs.map((entry) => entry.name)).toEqual(immediatelyDue
			? ["register_audit_export_object", "abandon_audit_export_object"]
			: ["register_audit_export_object"]);
		if (immediatelyDue) expect(rpcs[1]?.args.p_path).toBe(rpcs[0]?.args.p_path);
		expect(uploads).toHaveLength(1);
		expect(signedUrls).toHaveLength(options.signError ? 1 : 0);
	});

	it("withholds the signed URL when a legal hold wins during Storage upload", async () => {
		const { handle, rpcs, signedUrls } = await handlerWith({ publication: "legal_hold_active" });
		const response = await handle(post());
		expect(response.status).toBe(409);
		expect(await response.json()).toEqual({ error: "legal_hold_active" });
		expect(signedUrls).toHaveLength(1);
		expect(rpcs.map((entry) => entry.name)).toEqual([
			"register_audit_export_object", "finalize_audit_export_object", "abandon_audit_export_object",
		]);
	});

	it("fails closed and schedules cleanup when publication cannot be confirmed", async () => {
		const { handle, rpcs } = await handlerWith({ publicationError: true });
		const response = await handle(post());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "export_unavailable" });
		expect(rpcs.map((entry) => entry.name)).toEqual([
			"register_audit_export_object", "finalize_audit_export_object", "abandon_audit_export_object",
		]);
	});

	it("fails closed, never open, when the hold state cannot be read", async () => {
		const { handle, tables, inserts, rpcs, uploads } = await handlerWith({ holdError: true });
		const response = await handle(post());

		expect(response.status).toBe(503);
		expect(await response.json()).toMatchObject({ error: "legal_hold_unavailable" });
		expect(tables).not.toContain("audit_logs");
		expect(inserts).toEqual([]);
		expect(rpcs).toEqual([]);
		expect(uploads).toEqual([]);
	});
});
