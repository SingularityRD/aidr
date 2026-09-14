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

vi.mock("npm:@supabase/supabase-js@2", () => ({
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
		/** The active hold row the route must find, or an explicit absence. */
		hold?: { id: string } | null;
		holdError?: boolean;
		rows?: unknown[];
	}

	/**
	 * Minimal PostgREST-shaped client. Every table read is recorded so a test can
	 * prove the export never reached the records, and the export's own writes
	 * (ledger insert, storage upload, signed URL) are recorded separately so a
	 * refusal can be shown to have produced nothing at all.
	 */
	function database(options: DbOptions = {}) {
		const tables: string[] = [];
		const inserts: Array<{ table: string; values: unknown }> = [];
		const uploads: string[] = [];
		const signedUrls: string[] = [];
		const queryFor = (table: string) => {
			tables.push(table);
			const query = {
				select: () => query,
				eq: () => query,
				lte: () => query,
				is: () => query,
				order: () => query,
				limit: () => query,
				or: () => query,
				maybeSingle: async () => {
					if (table === "identity_user_session_state") return { data: { revoked_before: null }, error: null };
					if (table === "tenant_identity_policies") return { data: { require_mfa: false }, error: null };
					if (table === "tenant_members") {
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
				storage: {
					from: (bucket: string) => ({
						upload: async (path: string) => {
							uploads.push(`${bucket}/${path}`);
							return { error: null };
						},
						createSignedUrl: async (path: string) => {
							signedUrls.push(`${bucket}/${path}`);
							return {
								data: {
									signedUrl: `https://project.supabase.co/storage/v1/object/sign/${bucket}/${path}?token=test`,
								},
								error: null,
							};
						},
					}),
				},
			},
			tables,
			inserts,
			uploads,
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
		const { handle, tables, inserts, uploads, signedUrls } = await handlerWith({ hold: { id: HOLD_ID } });
		const response = await handle(post());

		expect(response.status).toBe(409);
		expect(await response.json()).toMatchObject({ error: "legal_hold_active" });

		// The hold is consulted before any record is read and before any byte is
		// produced: no page query, no retention ledger row, no stored object and
		// no download link may exist for a held tenant.
		expect(tables).toContain("tenant_legal_holds");
		expect(tables).not.toContain("audit_logs");
		expect(inserts).toEqual([]);
		expect(uploads).toEqual([]);
		expect(signedUrls).toEqual([]);
	});

	it("proceeds with the export when no unreleased hold exists", async () => {
		const { handle, tables, inserts, uploads, signedUrls } = await handlerWith({ hold: null });
		const response = await handle(post());

		expect(response.status).toBe(200);
		const body = (await response.json()) as Record<string, unknown>;
		expect(body.ok).toBe(true);
		expect(body.rows).toBe(1);
		expect(body.complete).toBe(true);
		expect(tables).toContain("tenant_legal_holds");
		expect(tables).toContain("audit_logs");
		expect(inserts.map((entry) => entry.table)).toEqual(["audit_export_objects"]);
		expect(uploads).toHaveLength(1);
		expect(signedUrls).toHaveLength(1);
		expect(String(body.url)).toContain("/storage/v1/object/sign/aidr-audit-exports/");
	});

	it("fails closed, never open, when the hold state cannot be read", async () => {
		const { handle, tables, inserts, uploads } = await handlerWith({ holdError: true });
		const response = await handle(post());

		expect(response.status).toBe(503);
		expect(await response.json()).toMatchObject({ error: "legal_hold_unavailable" });
		expect(tables).not.toContain("audit_logs");
		expect(inserts).toEqual([]);
		expect(uploads).toEqual([]);
	});
});
