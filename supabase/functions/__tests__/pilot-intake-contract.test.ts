// Contract suite for the pilot intake gate: `pilot-apply` (the intake) and
// `pilot-status` (the status lookup) that the dashboard invokes from browser
// code.
//
// Both functions are named in
// `docs/production-readiness/edge-function-contract-manifest.json`, which points
// at this single file for both. One file is intentional: the two functions are
// the two halves of the same approval gate, and the security properties that
// matter (no identity from the body, no cross-applicant disclosure, fail-closed
// storage errors, origin/method guards) only hold if both halves are checked
// together.
//
// The Edge runtime is not available in the Node test runner, so this suite
// follows the established style of `billing-portal.test.ts`: the Supabase
// module is mocked, `Deno` is stubbed onto `globalThis`, and the exported
// handler factories are driven directly with an injected fake database.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The Edge Functions import Supabase through Deno's `npm:` specifier, which a
// Node test runner cannot resolve. The client is never constructed here: every
// handler is driven through its `deps.db` injection point, so a fallback to the
// real `createClient` fails loudly instead of reaching the network.
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through PilotApplyDeps.db / PilotStatusDeps.db");
	},
}));

// The Edge runtime provides `Deno.env` and `Deno.serve`; the test process does
// not. The env stub delegates to `process.env` so `vi.stubEnv` drives exactly
// the values the production `runtimeEnv` reader would see, and `serve` is a
// no-op because the suite calls the exported factories instead of booting a
// listener.
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: {
		get: (name: string) => process.env[name],
	},
	serve: () => undefined,
};

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const applySource = readFileSync(
	join(ROOT, "supabase", "functions", "pilot-apply", "index.ts"),
	"utf8",
);
const statusSource = readFileSync(
	join(ROOT, "supabase", "functions", "pilot-status", "index.ts"),
	"utf8",
);
const scopeMigrationSource = readFileSync(
	join(ROOT, "supabase", "migrations", "20260923000010_pilot_application_tenant_scope.sql"),
	"utf8",
);
const tenancyMigrationSource = readFileSync(
	join(ROOT, "supabase", "migrations", "20260805000000_hybrid_tenancy.sql"),
	"utf8",
);

const APPLY_URL = "https://project.supabase.co/functions/v1/pilot-apply";
const STATUS_URL = "https://project.supabase.co/functions/v1/pilot-status";

const USER = "11111111-1111-4111-8111-111111111111";
const OTHER_USER = "22222222-2222-4222-8222-222222222222";
const TENANT = "33333333-3333-4333-8333-333333333333";
const OTHER_TENANT = "44444444-4444-4444-8444-444444444444";
const applicationKey = (userId: string, tenantId: string) => `${userId}:${tenantId}`;

const ORIGIN = "https://app.aidr.example";
const EVIL_ORIGIN = "https://app.aidr.example.evil.example";

const VALID_TOKEN = "valid-token";
const OTHER_TOKEN = "other-token";
const LEGAL_TERMS = { version: "approved-test-v1", sha256: "a".repeat(64), url: "https://aidr.example/terms" };
const LEGAL_PRIVACY = { version: "approved-test-v1", sha256: "b".repeat(64), url: "https://aidr.example/privacy" };
const CONSENT = {
	action: "start_trial", accepted: true,
	terms: { version: LEGAL_TERMS.version, sha256: LEGAL_TERMS.sha256 },
	privacy: { version: LEGAL_PRIVACY.version, sha256: LEGAL_PRIVACY.sha256 },
};
const TOKENS: Record<string, string> = {
	[VALID_TOKEN]: USER,
	[OTHER_TOKEN]: OTHER_USER,
};

const INTENT = {
	email: "pilot@aidr.example",
	org: "AIDR Fixture",
	useCase: "Guarding Claude Code and Cursor agents in CI.",
};

interface ApplicationRow {
	user_id: string;
	tenant_id: string;
	status: string;
	cohort?: string | null;
	notes?: string | null;
}

interface Write {
	table: string;
	op: "insert" | "update" | "upsert";
	row: Record<string, unknown>;
	filters?: Record<string, unknown>;
	onConflict?: string;
}

interface Query {
	table: string;
	filter: Record<string, unknown>;
}

interface DbOptions {
	revokedBefore?: string | null;
	identityError?: boolean;
	requireMfa?: boolean;
	assuranceLevel?: string | null;
	applications?: ApplicationRow[];
	applicationReadError?: boolean;
	applicationWriteError?: boolean;
	auditError?: boolean;
	rpcError?: string;
	rpcData?: unknown;
	admission?: Record<string, unknown> | null;
	admissionError?: boolean;
	trialStartStatus?: string;
	legal?: unknown;
	legalError?: boolean;
	memberships?: Array<{
		tenant_id: string;
		role: string;
		expires_at: string | null;
		user_id?: string;
	}>;
	membershipError?: boolean;
	tenantStatus?: string | null;
	tenantError?: boolean;
}

/**
 * Minimal PostgREST-shaped fake for status reads and a transactional pilot
 * submission RPC. Query records make cross-applicant reads falsifiable.
 */
function database(options: DbOptions = {}) {
	const rows = new Map<string, ApplicationRow>();
	const key = (userId: string, tenantId: string) => `${userId}:${tenantId}`;
	for (const row of options.applications ?? []) rows.set(key(row.user_id, row.tenant_id), { ...row });
	const writes: Write[] = [];
	const queries: Query[] = [];
	let admission: unknown = options.admission === undefined
		? { mode: "pilot", status: "active", access_kind: "pilot", allowed_agents: 1, expires_at: null, trial_available: false }
		: options.admission;
	let filter: Record<string, unknown> = {};

	const settle = async (table: string, single = true, limit: number | null = null): Promise<{ data: unknown; error: unknown }> => {
		queries.push({ table, filter: { ...filter } });
		if (table === "identity_user_session_state") {
			return {
				data: { revoked_before: options.revokedBefore ?? null },
				error: options.identityError ? { message: "db_down" } : null,
			};
		}
		if (table === "tenant_identity_policies") {
			return { data: { require_mfa: options.requireMfa === true }, error: null };
		}
		if (table === "tenant_members") {
			const memberships = options.memberships ?? [
				{ tenant_id: TENANT, role: "owner", expires_at: null },
			];
			const found = memberships.find(
				(row) =>
					row.tenant_id === filter.tenant_id &&
					(row.user_id === undefined || row.user_id === filter.user_id),
			);
			return {
				data: found ?? null,
				error: options.membershipError ? { message: "db_down" } : null,
			};
		}
		if (table === "tenants") {
			return {
				data: { status: options.tenantStatus ?? "active" },
				error: options.tenantError ? { message: "db_down" } : null,
			};
		}
		if (table === "pilot_applications") {
			if (options.applicationReadError) return { data: null, error: { message: "db_down" } };
			const matches = [...rows.values()].filter((row) =>
				Object.entries(filter).every(([column, value]) => row[column as keyof ApplicationRow] === value),
			);
			const bounded = limit === null ? matches : matches.slice(0, limit);
			if (!single) return { data: bounded, error: null };
			return bounded.length > 1
				? { data: null, error: { code: "PGRST116", message: "multiple rows" } }
				: { data: bounded[0] ?? null, error: null };
		}
		return { data: null, error: null };
	};

	const write = (
		table: string,
		op: "insert" | "update" | "upsert",
		row: Record<string, unknown>,
		filters: Record<string, unknown> = {},
		onConflict?: string,
	) => {
		writes.push({ table, op, row, filters: { ...filters }, onConflict });
		if (table === "pilot_applications" && options.applicationWriteError) {
			return Promise.resolve({ data: null, error: { message: "db_down" } });
		}
		if (table === "admin_audit_logs" && options.auditError) {
			return Promise.resolve({ data: null, error: { message: "db_down" } });
		}
		if (table === "pilot_applications") {
			const rowKey = key(String(row.user_id ?? filters.user_id), String(row.tenant_id ?? filters.tenant_id));
			const current = rows.get(rowKey);
			if (op === "insert" && current) return Promise.resolve({ data: null, error: { code: "23505" } });
			if (op === "update" && !current) return Promise.resolve({ data: null, error: null });
			const saved = { ...(current ?? {}), ...row, user_id: String(row.user_id ?? filters.user_id), tenant_id: String(row.tenant_id ?? filters.tenant_id) } as ApplicationRow;
			rows.set(rowKey, saved);
			return Promise.resolve({ data: op === "update" ? { status: saved.status } : null, error: null });
		}
		return Promise.resolve({ data: null, error: null });
	};

	const submit = async (name: string, args: Record<string, unknown>) => {
		if (name === "get_tenant_admission") {
			return { data: admission, error: options.admissionError ? { message: "db_down" } : null };
		}
		if (name === "get_ga_legal_documents") {
			return { data: options.legal ?? { configured: true, terms: LEGAL_TERMS, privacy: LEGAL_PRIVACY },
				error: options.legalError ? { message: "db_down" } : null };
		}
		if (name === "start_verified_trial") {
			const status = options.trialStartStatus ?? "started";
			if (status === "started" || status === "existing") {
				admission = { mode: "cloud", status: "active", access_kind: "trial", allowed_agents: 1, expires_at: "2026-10-07T00:00:00.000Z", trial_available: false };
			}
			return { data: { status }, error: null };
		}
		if (name !== "submit_pilot_application") throw new Error(`unexpected RPC: ${name}`);
		if (options.rpcError) return { data: null, error: { message: options.rpcError } };
		if (options.membershipError || options.tenantError || options.applicationReadError || options.applicationWriteError) {
			return { data: null, error: { message: "db_down" } };
		}
		const userId = String(args.p_user_id);
		const tenantId = String(args.p_tenant_id);
		const membership = (options.memberships ?? [
			{ tenant_id: TENANT, user_id: USER, role: "owner", expires_at: null },
			{ tenant_id: TENANT, user_id: OTHER_USER, role: "member", expires_at: null },
		]).find((row) => row.tenant_id === tenantId && row.user_id === userId);
		if (!membership || (options.tenantStatus != null && options.tenantStatus !== "active") ||
			!(["owner", "admin", "member", "viewer", "support_jit"].includes(membership.role)) ||
			(membership.expires_at !== null && new Date(membership.expires_at) <= new Date())) {
			return { data: null, error: { message: "tenant_access_denied" } };
		}
		const rowKey = key(userId, tenantId);
		const previous = rows.get(rowKey);
		if (previous && !["pending", "approved", "denied"].includes(previous.status)) {
			return { data: null, error: { message: "invalid_pilot_application_state" } };
		}
		const notes = typeof args.p_notes === "string" ? args.p_notes : null;
		const saved: ApplicationRow = previous
			? { ...previous, notes }
			: { user_id: userId, tenant_id: tenantId, status: "pending", notes };
		// Stage both writes; an audit failure rolls the whole submission back.
		if (options.auditError) return { data: null, error: { message: "db_down" } };
		rows.set(rowKey, saved);
		writes.push({ table: "pilot_applications", op: previous ? "update" : "insert", row: { ...saved } });
		writes.push({
			table: "admin_audit_logs", op: "insert",
			row: {
				actor_user_id: userId, tenant_id: tenantId, action: "pilot.apply",
				target_user_id: userId, detail: { has_use_case: notes !== null && notes !== "" },
			},
		});
		return { data: "rpcData" in options ? options.rpcData : { status: saved.status }, error: null };
	};

	const builder = (table: string) => {
		filter = {};
		let updateRow: Record<string, unknown> | null = null;
		const query = {
			select: () => query,
			eq: (column: string, value: unknown) => {
				filter[column] = value;
				return query;
			},
			limit: (value: number) => { return Object.assign(query, { _limit: value }); },
			maybeSingle: () => updateRow ? write(table, "update", updateRow, filter) : settle(table, true, (query as typeof query & { _limit?: number })._limit ?? null),
			insert: (row: Record<string, unknown>) => write(table, "insert", row, filter),
			update: (row: Record<string, unknown>) => { updateRow = row; return query; },
			upsert: (row: Record<string, unknown>, opts?: { onConflict?: string }) =>
				write(table, "upsert", row, filter, opts?.onConflict),
			then: (
				onFulfilled: (value: unknown) => unknown,
				onRejected?: (reason: unknown) => unknown,
			) => settle(table, false, (query as typeof query & { _limit?: number })._limit ?? null).then(onFulfilled, onRejected),
		};
		return query;
	};

	const db = {
		auth: {
			getUser: vi.fn(async (token: string) => {
				const id = TOKENS[token];
				return id
					? { data: { user: { id } }, error: null }
					: { data: { user: null }, error: { message: "invalid_token" } };
			}),
			mfa: {
				getAuthenticatorAssuranceLevel: vi.fn(async () => ({
					data: { currentLevel: options.assuranceLevel ?? "aal1" },
					error: null,
				})),
			},
		},
		from: vi.fn((table: string) => builder(table)),
		rpc: vi.fn(submit),
	};

	return { db, rows, writes, queries };
}

interface Harness {
	handle: (req: Request) => Promise<Response>;
	db: ReturnType<typeof database>["db"];
	rows: Map<string, ApplicationRow>;
	writes: Write[];
	queries: Query[];
}

async function loadApply(options: DbOptions = {}): Promise<Harness> {
	const fake = database(options);
	const mod = await import("../pilot-apply/index.ts");
	return { handle: mod.createPilotApplyHandler({ db: fake.db as never }), ...fake };
}

async function loadStatus(options: DbOptions = {}): Promise<Harness> {
	const fake = database(options);
	const mod = await import("../pilot-status/index.ts");
	return { handle: mod.createPilotStatusHandler({ db: fake.db as never }), ...fake };
}

function applyRequest(body: unknown, headers: Record<string, string> = {}): Request {
	return new Request(APPLY_URL, {
		method: "POST",
		headers: {
			Authorization: `Bearer ${VALID_TOKEN}`,
			"Content-Type": "application/json",
			Origin: ORIGIN,
			"X-AIDR-Tenant-ID": TENANT,
			...headers,
		},
		body: typeof body === "string" ? body : JSON.stringify(body),
	});
}

function statusRequest(headers: Record<string, string> = {}, method = "GET"): Request {
	return new Request(STATUS_URL, {
		method,
		headers: { Authorization: `Bearer ${VALID_TOKEN}`, Origin: ORIGIN, ...headers },
	});
}

const environment: Record<string, string> = {
	SUPABASE_URL: "https://project.supabase.co",
	SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
	AIDR_ALLOWED_ORIGINS: ORIGIN,
};

// `cors.ts` resolves the allowlist at module scope, so the environment must be
// stubbed before the handler module is imported, and the module registry must be
// reset between tests for a new allowlist to take effect.
beforeEach(() => {
	for (const [key, value] of Object.entries(environment)) vi.stubEnv(key, value);
});

afterEach(() => {
	vi.unstubAllEnvs();
	vi.resetModules();
});

describe("pilot-apply intake contract", () => {
	it("accepts the documented intake body and records exactly one application", async () => {
		const { handle, rows, writes, db } = await loadApply();
		const response = await handle(applyRequest(INTENT));

		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, status: "pending" });
		expect(response.headers.get("access-control-allow-origin")).toBe(ORIGIN);

		expect(rows.size).toBe(1);
		expect(rows.get(applicationKey(USER, TENANT))).toMatchObject({
			user_id: USER,
			tenant_id: TENANT,
			status: "pending",
			notes: INTENT.useCase,
		});

		const applicationWrites = writes.filter((entry) => entry.table === "pilot_applications");
		expect(applicationWrites).toHaveLength(1);
		expect(applicationWrites[0]?.op).toBe("insert");
		expect(applicationWrites[0]?.row).toMatchObject({ user_id: USER, tenant_id: TENANT, status: "pending" });

		const audits = writes.filter((entry) => entry.table === "admin_audit_logs");
		expect(audits).toHaveLength(1);
		expect(audits[0]?.row).toMatchObject({
			actor_user_id: USER,
			tenant_id: TENANT,
			action: "pilot.apply",
			target_user_id: USER,
			detail: { has_use_case: true },
		});
		expect(db.rpc).toHaveBeenCalledWith("submit_pilot_application", {
			p_user_id: USER, p_tenant_id: TENANT, p_notes: INTENT.useCase,
		});
		expect(db.from.mock.calls.map(([table]) => table)).not.toContain("pilot_applications");
		expect(db.from.mock.calls.map(([table]) => table)).not.toContain("admin_audit_logs");
	});

	it.each(["cloud", "onprem", "unconfigured"])("disables pilot intake in %s admission mode", async (mode) => {
		const { handle, db, writes } = await loadApply({ admission: {
			mode, status: "none", access_kind: null, allowed_agents: 0, expires_at: null, trial_available: false,
		} });
		const response = await handle(applyRequest(INTENT));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "pilot_not_enabled" });
		expect(db.rpc).toHaveBeenCalledWith("get_tenant_admission", { p_user_id: USER, p_tenant_id: TENANT });
		expect(db.rpc.mock.calls.some(([name]) => name === "submit_pilot_application")).toBe(false);
		expect(writes).toHaveLength(0);
	});

	it("fails closed if the admission mode cannot be read", async () => {
		const { handle, db, writes } = await loadApply({ admissionError: true });
		const response = await handle(applyRequest(INTENT));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "pilot_mode_unavailable" });
		expect(db.rpc.mock.calls.some(([name]) => name === "submit_pilot_application")).toBe(false);
		expect(writes).toHaveLength(0);
	});

	it("returns the same application for the same caller and never creates a second record", async () => {
		const { handle, rows, writes } = await loadApply();
		const first = await handle(applyRequest(INTENT));
		const second = await handle(applyRequest(INTENT));

		expect(first.status).toBe(200);
		expect(second.status).toBe(200);
		expect(await second.json()).toEqual(await first.json());
		expect(rows.size).toBe(1);
		expect(rows.get(applicationKey(USER, TENANT))?.user_id).toBe(USER);
		// Existing rows are updated by their composite scope; no user-only upsert.
		expect(writes.filter((entry) => entry.table === "pilot_applications").map((entry) => entry.op)).toEqual([
			"insert",
			"update",
		]);
	});

	it("preserves an approved application when it is re-submitted in the same tenant", async () => {
		const { handle, rows } = await loadApply({
			applications: [{ user_id: USER, tenant_id: TENANT, status: "approved", cohort: "cohort-a" }],
		});
		const response = await handle(applyRequest({ ...INTENT, useCase: "A different story entirely." }));

		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, status: "approved" });
		expect(rows.get(applicationKey(USER, TENANT))).toMatchObject({
			status: "approved",
			tenant_id: TENANT,
			cohort: "cohort-a",
		});
	});

	it("creates a team application without moving the existing personal application", async () => {
		const { handle, rows, writes, db } = await loadApply({
			applications: [{ user_id: USER, tenant_id: USER, status: "pending" }],
		});
		const response = await handle(applyRequest(INTENT));

		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, status: "pending" });
		expect(rows.size).toBe(2);
		expect(rows.get(applicationKey(USER, USER))).toMatchObject({ tenant_id: USER, status: "pending" });
		expect(rows.get(applicationKey(USER, TENANT))).toMatchObject({ tenant_id: TENANT, status: "pending" });
		expect(writes.filter((entry) => entry.table === "pilot_applications").map((entry) => entry.op)).toEqual(["insert"]);
		expect(db.rpc).toHaveBeenCalledWith("submit_pilot_application", {
			p_user_id: USER, p_tenant_id: TENANT, p_notes: INTENT.useCase,
		});
	});

	it("requires a valid tenant header before writing", async () => {
		const { handle, writes, db } = await loadApply();
		const response = await handle(applyRequest(INTENT, { "X-AIDR-Tenant-ID": "bad" }));

		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "invalid_tenant" });
		expect(db.from).not.toHaveBeenCalled();
		expect(db.rpc).not.toHaveBeenCalled();
		expect(writes).toHaveLength(0);
	});

	it("requires an active tenant membership before creating an application", async () => {
		const { handle, writes, db } = await loadApply({ memberships: [] });
		const response = await handle(applyRequest(INTENT));

		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "tenant_access_denied" });
		expect(writes).toHaveLength(0);
		expect(db.rpc).toHaveBeenCalledWith("submit_pilot_application", {
			p_user_id: USER, p_tenant_id: TENANT, p_notes: INTENT.useCase,
		});
	});

	it.each([
		["another user", { memberships: [{ tenant_id: TENANT, user_id: OTHER_USER, role: "owner", expires_at: null }] }],
		["another tenant", { memberships: [{ tenant_id: OTHER_TENANT, user_id: USER, role: "owner", expires_at: null }] }],
		["expired", { memberships: [{ tenant_id: TENANT, user_id: USER, role: "owner", expires_at: "2000-01-01T00:00:00Z" }] }],
		["suspended tenant", { tenantStatus: "suspended" }],
	] as Array<[string, DbOptions]>)("rejects a membership for %s", async (_case, options) => {
		const { handle, rows, writes } = await loadApply(options);
		const response = await handle(applyRequest(INTENT));

		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "tenant_access_denied" });
		expect(rows.size).toBe(0);
		expect(writes).toHaveLength(0);
	});

	it("fails closed when tenant authorization storage is unavailable", async () => {
		const { handle, writes } = await loadApply({ tenantError: true });
		const response = await handle(applyRequest(INTENT));

		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "pilot_application_unavailable" });
		expect(writes).toHaveLength(0);
	});

	it("rejects a body that tries to assert user_id, tenant_id or status", async () => {
		const { handle, writes, db } = await loadApply();
		const injections: Array<[string, Record<string, unknown>]> = [
			["user_id", { user_id: OTHER_USER }],
			["tenant_id", { tenant_id: OTHER_TENANT }],
			["status", { status: "approved" }],
			["cohort", { cohort: "cohort-a" }],
		];
		for (const [label, injection] of injections) {
			const response = await handle(applyRequest({ ...INTENT, ...injection }));
			expect(response.status, label).toBe(400);
			expect(await response.json(), label).toEqual({ error: "unsupported_field" });
		}
		expect(writes.filter((entry) => entry.table === "pilot_applications")).toHaveLength(0);
		expect(db.rpc).not.toHaveBeenCalled();
	});

	it("binds each application to its own caller", async () => {
		const { handle, rows, db } = await loadApply();
		const first = await handle(applyRequest(INTENT));
		const second = await handle(applyRequest(INTENT, { Authorization: `Bearer ${OTHER_TOKEN}` }));

		expect(first.status).toBe(200);
		expect(second.status).toBe(200);
		expect(rows.size).toBe(2);
		expect(rows.get(applicationKey(USER, TENANT))?.user_id).toBe(USER);
		expect(rows.get(applicationKey(OTHER_USER, TENANT))?.user_id).toBe(OTHER_USER);
		expect(db.rpc.mock.calls).toEqual([
			["get_tenant_admission", { p_user_id: USER, p_tenant_id: TENANT }],
			["submit_pilot_application", { p_user_id: USER, p_tenant_id: TENANT, p_notes: INTENT.useCase }],
			["get_tenant_admission", { p_user_id: OTHER_USER, p_tenant_id: TENANT }],
			["submit_pilot_application", { p_user_id: OTHER_USER, p_tenant_id: TENANT, p_notes: INTENT.useCase }],
		]);
	});

	it("rejects a malformed intake body with 400 and records nothing", async () => {
		const { handle, writes } = await loadApply();
		const cases: Array<[string, unknown]> = [
			["body is not an object", [1, 2, 3]],
			["missing email", { org: "AIDR Fixture", useCase: "x" }],
			["blank email", { ...INTENT, email: "   " }],
			["null email", { ...INTENT, email: null }],
			["non-string email", { ...INTENT, email: 42 }],
			["email without a domain", { ...INTENT, email: "pilot@localhost" }],
			["email with whitespace", { ...INTENT, email: "pilot @aidr.example" }],
			["over-length email", { ...INTENT, email: `${"a".repeat(320)}@aidr.example` }],
			["over-length organisation", { ...INTENT, org: "x".repeat(201) }],
			["over-length use case", { ...INTENT, useCase: "x".repeat(4001) }],
			["control character in the use case", { ...INTENT, useCase: "line\u0000break" }],
			["control character in the organisation", { ...INTENT, org: "AIDR\u0007" }],
			["unknown field", { ...INTENT, role: "admin" }],
		];
		for (const [label, body] of cases) {
			const response = await handle(applyRequest(body));
			expect(response.status, label).toBe(400);
			const payload = (await response.json()) as Record<string, unknown>;
			expect(typeof payload.error, label).toBe("string");
			expect(payload.ok, label).not.toBe(true);
		}
		expect(writes.filter((entry) => entry.table === "pilot_applications")).toHaveLength(0);
	});

	it("rejects an oversized body with 413 before it is parsed", async () => {
		const { handle, writes } = await loadApply();
		const response = await handle(applyRequest({ ...INTENT, useCase: "x".repeat(5000) }));

		expect(response.status).toBe(413);
		expect(await response.json()).toEqual({ error: "request_too_large" });
		expect(writes.filter((entry) => entry.table === "pilot_applications")).toHaveLength(0);
	});

	it("rejects a body that is not JSON instead of accepting it silently", async () => {
		const { handle, writes } = await loadApply();
		const malformed = await handle(applyRequest("{not json"));
		expect(malformed.status).toBe(400);
		expect(await malformed.json()).toEqual({ error: "invalid_json" });

		const empty = await handle(
			new Request(APPLY_URL, {
				method: "POST",
				headers: {
					Authorization: `Bearer ${VALID_TOKEN}`,
					Origin: ORIGIN,
					"X-AIDR-Tenant-ID": TENANT,
				},
			}),
		);
		expect(empty.status).toBe(400);
		expect(await empty.json()).toEqual({ error: "invalid_json" });
		expect(writes).toHaveLength(0);
	});

	it("rejects a request without a session token before any database work", async () => {
		const { handle, db } = await loadApply();
		const response = await handle(applyRequest(INTENT, { Authorization: "" }));

		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "missing_access_token" });
		expect(db.auth.getUser).not.toHaveBeenCalled();
		expect(db.from).not.toHaveBeenCalled();
	});

	it("rejects an invalid session token before any table read", async () => {
		const { handle, db } = await loadApply();
		const response = await handle(applyRequest(INTENT, { Authorization: "Bearer expired-token" }));

		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "invalid_access_token" });
		expect(db.from).not.toHaveBeenCalled();
	});

	it("validates the submitted email without ever looking an account up by it", async () => {
		const { handle, queries, rows } = await loadApply({
			applications: [{ user_id: OTHER_USER, tenant_id: OTHER_USER, status: "approved" }],
		});
		const probe = "someone-else@aidr.example";
		const response = await handle(applyRequest({ ...INTENT, email: probe }));
		const payload = (await response.json()) as Record<string, unknown>;

		expect(response.status).toBe(200);
		// The response describes the caller's own application and nothing else, so
		// it cannot be used to confirm that the probed address is registered.
		expect(Object.keys(payload).sort()).toEqual(["ok", "status"]);
		expect(payload).toEqual({ ok: true, status: "pending" });
		expect(queries.every((query) => !Object.values(query.filter).includes(probe))).toBe(true);
		expect(rows.get(applicationKey(OTHER_USER, OTHER_USER))?.status).toBe("approved");
		expect(rows.get(applicationKey(OTHER_USER, OTHER_USER))?.notes).toBeUndefined();
	});

	it("fails closed when the session-state storage read fails", async () => {
		const { handle, writes } = await loadApply({ identityError: true });
		const response = await handle(applyRequest(INTENT));

		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "identity_state_unavailable" });
		expect(writes.filter((entry) => entry.table === "pilot_applications")).toHaveLength(0);
	});

	it("refuses the intake when the RPC cannot inspect the existing application", async () => {
		const { handle, writes } = await loadApply({ applicationReadError: true });
		const response = await handle(applyRequest(INTENT));

		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "pilot_application_unavailable" });
		expect(writes).toHaveLength(0);
	});

	it("never reports success when the application write fails", async () => {
		const { handle, rows, writes } = await loadApply({ applicationWriteError: true });
		const response = await handle(applyRequest(INTENT));

		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "pilot_application_unavailable" });
		expect(rows.size).toBe(0);
		expect(writes.filter((entry) => entry.table === "admin_audit_logs")).toHaveLength(0);
	});

	it("rolls back the application when its audit trail cannot be recorded", async () => {
		const { handle, rows, writes } = await loadApply({ auditError: true });
		const response = await handle(applyRequest(INTENT));
		const payload = (await response.json()) as Record<string, unknown>;

		expect(response.status).toBe(503);
		expect(payload).toEqual({ error: "pilot_application_unavailable" });
		expect(payload.ok).not.toBe(true);
		expect(rows.size).toBe(0);
		expect(writes).toHaveLength(0);
	});

	it("keeps an existing application unchanged if the audit insert fails", async () => {
		const original = { user_id: USER, tenant_id: TENANT, status: "approved", notes: "original" };
		const { handle, rows, writes } = await loadApply({ applications: [original], auditError: true });
		const response = await handle(applyRequest(INTENT));

		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "pilot_application_unavailable" });
		expect(rows.get(applicationKey(USER, TENANT))).toEqual(original);
		expect(writes).toHaveLength(0);
	});

	it("fails closed for a rejected RPC or an invalid application state", async () => {
		for (const [message, expectedError] of [
			["db_down", "pilot_application_unavailable"],
			["invalid_pilot_application_state", "invalid_pilot_application_state"],
		] as const) {
			const { handle, rows, writes } = await loadApply({ rpcError: message });
			const response = await handle(applyRequest(INTENT));
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: expectedError });
			expect(rows.size).toBe(0);
			expect(writes).toHaveLength(0);
		}
	});

	it("does not modify an application whose stored state the RPC rejects", async () => {
		const original = { user_id: USER, tenant_id: TENANT, status: "archived", notes: "original" };
		const { handle, rows, writes } = await loadApply({ applications: [original] });
		const response = await handle(applyRequest(INTENT));

		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "invalid_pilot_application_state" });
		expect(rows.get(applicationKey(USER, TENANT))).toEqual(original);
		expect(writes).toHaveLength(0);
	});

	it.each([null, {}, { status: "unexpected" }, { status: 1 }])(
		"fails closed for malformed RPC data: %j",
		async (rpcData) => {
			const { handle } = await loadApply({ rpcData });
			const response = await handle(applyRequest(INTENT));
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: "pilot_application_unavailable" });
		},
	);

	it("refuses the privileged write when the tenant requires an assurance the session lacks", async () => {
		const { handle, writes } = await loadApply({
			applications: [{ user_id: USER, tenant_id: TENANT, status: "pending" }],
			requireMfa: true,
			assuranceLevel: "aal1",
		});
		const response = await handle(applyRequest(INTENT));

		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "mfa_required" });
		expect(writes.filter((entry) => entry.table === "pilot_applications")).toHaveLength(0);
	});
});

describe("pilot-status contract", () => {
	it("reports GA admission without consulting or inheriting pilot approval", async () => {
		const { handle, db, queries } = await loadStatus({ applications: [
			{ user_id: OTHER_USER, tenant_id: TENANT, status: "approved", cohort: "old-pilot" },
		], admission: {
			mode: "cloud", status: "none", access_kind: null,
			allowed_agents: 0, expires_at: null, trial_available: true,
		} });
		const response = await handle(statusRequest({ "X-AIDR-Tenant-ID": TENANT }));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			ok: true, status: "none", tenant_id: TENANT,
			admission: { mode: "cloud", status: "none", trial_available: true },
			legal: { configured: true, terms: LEGAL_TERMS, privacy: LEGAL_PRIVACY },
		});
		expect(db.rpc).toHaveBeenCalledWith("get_tenant_admission", { p_tenant_id: TENANT, p_user_id: USER });
		expect(db.rpc).toHaveBeenCalledWith("get_ga_legal_documents");
		expect(queries.filter((query) => query.table === "pilot_applications")).toHaveLength(0);
	});

	it("starts a verified owner's one-seat trial server-side and reads back admission", async () => {
		const { handle, db } = await loadStatus({ admission: {
			mode: "cloud", status: "none", access_kind: null,
			allowed_agents: 0, expires_at: null, trial_available: true,
		} });
		const response = await handle(new Request(STATUS_URL, {
			method: "POST",
			headers: { Authorization: `Bearer ${VALID_TOKEN}`, Origin: ORIGIN, "X-AIDR-Tenant-ID": TENANT, "Content-Type": "application/json" },
			body: JSON.stringify(CONSENT),
		}));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			ok: true,
			admission: { mode: "cloud", status: "active", access_kind: "trial", allowed_agents: 1, trial_available: false },
		});
		expect(db.rpc).toHaveBeenCalledWith("start_verified_trial", { p_tenant_id: TENANT, p_user_id: USER, p_terms: CONSENT.terms, p_privacy: CONSENT.privacy });
	});

	it("keeps a cloud trial unavailable until approved legal documents are configured", async () => {
		const { handle } = await loadStatus({
			admission: { mode: "cloud", status: "none", access_kind: null, allowed_agents: 0, expires_at: null, trial_available: true },
			legal: { configured: false, terms: null, privacy: null },
		});
		const response = await handle(statusRequest({ "X-AIDR-Tenant-ID": TENANT }));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			admission: { mode: "cloud", trial_available: false },
			legal: { configured: false, terms: null, privacy: null },
		});
	});

	it("fails closed when the legal document projection is unavailable", async () => {
		const { handle } = await loadStatus({
			admission: { mode: "cloud", status: "none", access_kind: null, allowed_agents: 0, expires_at: null, trial_available: true },
			legalError: true,
		});
		const response = await handle(statusRequest({ "X-AIDR-Tenant-ID": TENANT }));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "trial_legal_unavailable" });
	});

	it("does not make paid cloud admission depend on trial legal configuration", async () => {
		const { handle, db } = await loadStatus({
			admission: { mode: "cloud", status: "active", access_kind: "licensed", allowed_agents: 20,
				expires_at: "2027-09-23T00:00:00.000Z", trial_available: false },
			legalError: true,
		});
		const response = await handle(statusRequest({ "X-AIDR-Tenant-ID": TENANT }));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ admission: { mode: "cloud", access_kind: "licensed", allowed_agents: 20 } });
		expect(db.rpc).not.toHaveBeenCalledWith("get_ga_legal_documents");
	});

	it("rejects an ineligible trial without exposing a token or active admission", async () => {
		const { handle } = await loadStatus({ trialStartStatus: "ineligible" });
		const response = await handle(new Request(STATUS_URL, {
			method: "POST",
			headers: { Authorization: `Bearer ${VALID_TOKEN}`, Origin: ORIGIN, "X-AIDR-Tenant-ID": TENANT, "Content-Type": "application/json" },
			body: JSON.stringify(CONSENT),
		}));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "trial_not_available" });
	});

	it("rejects trial activation without affirmative exact-document consent before the RPC", async () => {
		const { handle, db } = await loadStatus();
		for (const body of [
			{ action: "start_trial" },
			{ ...CONSENT, accepted: false },
			{ ...CONSENT, terms: { ...CONSENT.terms, sha256: "c".repeat(64) }, extra: true },
		]) {
			const response = await handle(new Request(STATUS_URL, {
				method: "POST",
				headers: { Authorization: `Bearer ${VALID_TOKEN}`, Origin: ORIGIN, "X-AIDR-Tenant-ID": TENANT, "Content-Type": "application/json" },
				body: JSON.stringify(body),
			}));
			expect(response.status).toBe(400);
			expect(await response.json()).toEqual({ error: "legal_consent_required" });
		}
		expect(db.rpc).not.toHaveBeenCalledWith("start_verified_trial", expect.anything());
	});

	it.each([
		["legal_not_configured", 403, "trial_legal_unavailable"],
		["legal_documents_changed", 409, "legal_documents_changed"],
	])("maps %s without claiming activation", async (trialStartStatus, expectedStatus, expectedError) => {
		const { handle } = await loadStatus({ trialStartStatus });
		const response = await handle(new Request(STATUS_URL, {
			method: "POST",
			headers: { Authorization: `Bearer ${VALID_TOKEN}`, Origin: ORIGIN, "X-AIDR-Tenant-ID": TENANT, "Content-Type": "application/json" },
			body: JSON.stringify(CONSENT),
		}));
		expect(response.status).toBe(expectedStatus);
		expect(await response.json()).toEqual({ error: expectedError });
	});

	it("fails closed when GA admission lookup is unavailable", async () => {
		const { handle } = await loadStatus({ admissionError: true });
		const response = await handle(statusRequest({ "X-AIDR-Tenant-ID": TENANT }));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "admission_unavailable" });
	});

	it("rejects an unauthenticated request before any database work", async () => {
		const { handle, db } = await loadStatus();
		const response = await handle(statusRequest({ Authorization: "" }));

		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "missing_access_token" });
		expect(db.auth.getUser).not.toHaveBeenCalled();
		expect(db.from).not.toHaveBeenCalled();
	});

	it("rejects an invalid session token before any table read", async () => {
		const { handle, db } = await loadStatus();
		const response = await handle(statusRequest({ Authorization: "Bearer expired-token" }));

		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "invalid_access_token" });
		expect(db.from).not.toHaveBeenCalled();
	});

	it("reports the caller's own application", async () => {
		const { handle } = await loadStatus({
			applications: [{ user_id: USER, tenant_id: USER, status: "approved", cohort: "cohort-a" }],
			memberships: [{ tenant_id: USER, user_id: USER, role: "owner", expires_at: null }],
		});
		const response = await handle(statusRequest());

		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({
			ok: true,
			user_id: USER,
			tenant_id: USER,
			status: "approved",
			cohort: "cohort-a",
		});
	});

	it("returns an applicant's own pending application only while its tenant membership is active", async () => {
		const { handle } = await loadStatus({
			applications: [{ user_id: USER, tenant_id: TENANT, status: "pending" }],
			memberships: [{ tenant_id: TENANT, user_id: USER, role: "owner", expires_at: null }],
		});
		const response = await handle(statusRequest());

		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ ok: true, status: "pending", tenant_id: TENANT });
	});

	it("withholds an existing application after its tenant membership is revoked", async () => {
		const { handle } = await loadStatus({
			applications: [{ user_id: USER, tenant_id: TENANT, status: "pending" }],
			memberships: [],
		});
		const response = await handle(statusRequest());

		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "tenant_access_denied" });
	});

	it("requires tenant scope if more than one application exists", async () => {
		const { handle } = await loadStatus({ applications: [
			{ user_id: USER, tenant_id: USER, status: "pending" },
			{ user_id: USER, tenant_id: TENANT, status: "approved" },
		] });
		const response = await handle(statusRequest());
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "tenant_required" });
	});

	it("reports no application as the documented empty status", async () => {
		const { handle } = await loadStatus();
		const response = await handle(statusRequest());

		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, status: "none" });
	});

	it("reports not-found rather than leaking another applicant's row", async () => {
		const { handle, queries } = await loadStatus({
			applications: [
				{
					user_id: OTHER_USER,
					tenant_id: OTHER_TENANT,
					status: "approved",
					cohort: "cohort-b",
					notes: "another applicant's notes",
				},
			],
		});
		const response = await handle(statusRequest());
		const payload = (await response.json()) as Record<string, unknown>;

		expect(response.status).toBe(200);
		expect(payload).toEqual({ ok: true, status: "none" });
		expect(JSON.stringify(payload)).not.toContain("cohort-b");
		expect(JSON.stringify(payload)).not.toContain("another applicant's notes");
		// The lookup is keyed on the verified user, never on anything the caller
		// could substitute.
		expect(
			queries
				.filter((query) => query.table === "pilot_applications")
				.every((query) => query.filter.user_id === USER),
		).toBe(true);
	});

	it("never answers 2xx for an application that cannot be read", async () => {
		const { handle } = await loadStatus({ applicationReadError: true });
		const response = await handle(statusRequest());
		const payload = (await response.json()) as Record<string, unknown>;

		// An unavailable status read is an availability failure, not "no
		// application": it must never be reported as an empty success.
		expect(response.status).toBeGreaterThanOrEqual(500);
		expect(response.status).toBeLessThan(600);
		expect(payload).toEqual({ error: "pilot_status_unavailable" });
		expect(payload).not.toMatchObject({ ok: true, status: "none" });
	});

	it("refuses a malformed tenant header", async () => {
		const { handle, queries } = await loadStatus();
		const response = await handle(statusRequest({ "X-AIDR-Tenant-ID": "not-a-tenant" }));

		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "invalid_tenant" });
		expect(queries.filter((query) => query.table === "tenant_members")).toHaveLength(0);
	});

	it("refuses a tenant the caller is not an active member of", async () => {
		const { handle } = await loadStatus({
			memberships: [],
			applications: [{ user_id: OTHER_USER, tenant_id: OTHER_TENANT, status: "approved" }],
		});
		const response = await handle(statusRequest({ "X-AIDR-Tenant-ID": OTHER_TENANT }));

		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "tenant_access_denied" });
	});

	it("fails closed when the membership or tenant read fails", async () => {
		const failingMembership = await loadStatus({ membershipError: true });
		const membershipResponse = await failingMembership.handle(
			statusRequest({ "X-AIDR-Tenant-ID": TENANT }),
		);
		expect(membershipResponse.status).toBe(503);
		expect(await membershipResponse.json()).toEqual({ error: "authorization_unavailable" });

		const suspended = await loadStatus({ tenantStatus: "suspended" });
		const suspendedResponse = await suspended.handle(statusRequest({ "X-AIDR-Tenant-ID": TENANT }));
		expect(suspendedResponse.status).toBe(403);
		expect(await suspendedResponse.json()).toEqual({ error: "tenant_access_denied" });
	});

	it("reports the tenant's approved pilot to a verified active member", async () => {
		const { handle } = await loadStatus({
			applications: [{ user_id: OTHER_USER, tenant_id: TENANT, status: "approved", cohort: "cohort-a" }],
		});
		const response = await handle(statusRequest({ "X-AIDR-Tenant-ID": TENANT }));

		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			ok: true,
			status: "approved",
			tenant_id: TENANT,
			cohort: "cohort-a",
		});
	});

	it.each(["pending", "denied"] as const)(
		"prefers tenant approval over the caller's own %s application",
		async (ownStatus) => {
			const { handle } = await loadStatus({
				applications: [
					{ user_id: USER, tenant_id: TENANT, status: ownStatus },
					{ user_id: OTHER_USER, tenant_id: TENANT, status: "approved", cohort: "cohort-a" },
				],
			});
			for (const request of [
				statusRequest({ "X-AIDR-Tenant-ID": TENANT }),
				statusRequest(),
			]) {
				const response = await handle(request);
				expect(response.status).toBe(200);
				expect(await response.json()).toMatchObject({
					ok: true,
					status: "approved",
					tenant_id: TENANT,
					cohort: "cohort-a",
				});
			}
		},
	);

	it("never answers 2xx for an unreadable tenant approval", async () => {
		const { handle } = await loadStatus({ applicationReadError: true });
		const response = await handle(statusRequest({ "X-AIDR-Tenant-ID": TENANT }));

		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "pilot_status_unavailable" });
	});

	it("fails closed when the revocation barrier is unreadable", async () => {
		const { handle } = await loadStatus({ identityError: true });
		const response = await handle(statusRequest());

		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "identity_state_unavailable" });
	});
});

interface Route {
	name: string;
	url: string;
	method: string;
	load: (options?: DbOptions) => Promise<Harness>;
	request: (headers?: Record<string, string>) => Request;
}

const ROUTES: Route[] = [
	{
		name: "pilot-apply",
		url: APPLY_URL,
		method: "POST",
		load: loadApply,
		request: (headers = {}) => applyRequest(INTENT, headers),
	},
	{
		name: "pilot-status",
		url: STATUS_URL,
		method: "GET",
		load: loadStatus,
		request: (headers = {}) => statusRequest(headers),
	},
];

describe("pilot handler origin, method and configuration contract", () => {
	it.each(ROUTES)("$name rejects an origin outside AIDR_ALLOWED_ORIGINS before any database work", async (route) => {
		const { handle, db } = await route.load();
		const response = await handle(route.request({ Origin: EVIL_ORIGIN }));

		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "origin_not_allowed" });
		// A refused origin is never echoed back.
		expect(response.headers.get("access-control-allow-origin")).toBeNull();
		expect(db.auth.getUser).not.toHaveBeenCalled();
		expect(db.from).not.toHaveBeenCalled();
	});

	it.each(ROUTES)("$name refuses a look-alike origin rather than matching a prefix", async (route) => {
		const { handle } = await route.load();
		const response = await handle(route.request({ Origin: `${ORIGIN}.attacker.example` }));

		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "origin_not_allowed" });
	});

	it.each(ROUTES)("$name echoes only the allowlisted origin", async (route) => {
		const { handle } = await route.load();
		const response = await handle(route.request());

		expect(response.status).toBe(200);
		expect(response.headers.get("access-control-allow-origin")).toBe(ORIGIN);
		expect(response.headers.get("vary")).toContain("Origin");
	});

	it.each(ROUTES)("$name answers an OPTIONS preflight successfully", async (route) => {
		const { handle, db } = await route.load();
		const response = await handle(
			new Request(route.url, { method: "OPTIONS", headers: { Origin: ORIGIN } }),
		);

		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true });
		expect(db.auth.getUser).not.toHaveBeenCalled();
		expect(db.from).not.toHaveBeenCalled();
	});

	it.each(ROUTES)("$name refuses an unsupported method", async (route) => {
		const { handle, db } = await route.load();
		const disallowed = route.method === "POST" ? "GET" : "PATCH";
		const response = await handle(new Request(route.url, { method: disallowed }));

		expect(response.status).toBe(405);
		expect(await response.json()).toEqual({ error: "method_not_allowed" });
		expect(db.auth.getUser).not.toHaveBeenCalled();
		expect(db.from).not.toHaveBeenCalled();
	});

	it.each(ROUTES)(
		"$name fails fast on missing configuration without publishing a value or touching the database",
		async (route) => {
			const { handle, db } = await route.load();
			vi.stubEnv("SUPABASE_URL", "");
			const logged = vi.spyOn(console, "error").mockImplementation(() => undefined);
			try {
				const response = await handle(route.request());
				const payload = (await response.json()) as Record<string, unknown>;

				expect(response.status).toBe(500);
				expect(payload).toEqual({ error: "server_misconfigured", missing: ["SUPABASE_URL"] });
				expect(JSON.stringify(payload)).not.toContain("service-role-key");
				expect(logged).toHaveBeenCalledWith(
					`[${route.name}] configuration error`,
					expect.stringContaining("SUPABASE_URL"),
				);
				expect(JSON.stringify(logged.mock.calls)).not.toContain("service-role-key");
				expect(db.auth.getUser).not.toHaveBeenCalled();
				expect(db.from).not.toHaveBeenCalled();
			} finally {
				logged.mockRestore();
			}
		},
	);
});

describe("pilot handler source contract", () => {
	const sources: Array<[string, string]> = [
		["pilot-apply", applySource],
		["pilot-status", statusSource],
	];

	it.each(sources)("%s validates configuration through the shared helper only", (_name, source) => {
		expect(source).toContain('from "../_shared/config.ts"');
		expect(source).toContain("loadConfig(runtimeEnv,");
		expect(source).toContain("configFailure(");
		expect(source).toContain('"SUPABASE_URL"');
		expect(source).toContain('"SUPABASE_SERVICE_ROLE_KEY"');
		// The platform credentials are never read outside `_shared/config.ts`.
		expect(source).not.toMatch(/Deno\.env\.get\(\s*"SUPABASE_(URL|SERVICE_ROLE_KEY)"\s*\)/);
	});

	it.each(sources)("%s answers through the shared CORS helper only", (_name, source) => {
		expect(source).toContain('from "../_shared/cors.ts"');
		expect(source).toContain("handleCors(req)");
		expect(source).toContain("corsJson(req");
	});

	it.each(sources)("%s exports the handler factory the contract suite drives", (_name, source) => {
		expect(source).toMatch(/export function createPilot(Apply|Status)Handler\(/);
		expect(source).toContain("Deno.serve(createPilot");
	});

	it("keeps the identity barrier on both halves of the gate", () => {
		expect(applySource).toContain("checkIdentityBarrier(");
		expect(statusSource).toContain("checkIdentityBarrier(");
	});

	it("bounds and validates the intake before the atomic RPC", () => {
		expect(applySource).toContain("readBoundedJson(req, MAX_BODY_BYTES)");
		expect(applySource).toContain("parseIntake(parsed.value)");
		expect(applySource).toContain('supabase.rpc("submit_pilot_application"');
		expect(applySource.indexOf('supabase.rpc("submit_pilot_application"')).toBeGreaterThan(
			applySource.indexOf("parseIntake(parsed.value)"),
		);
		expect(applySource).not.toMatch(/\.from\(\s*"(?:pilot_applications|admin_audit_logs)"/);
	});

	it("never queries an applicant by an address supplied in the body", () => {
		expect(applySource).not.toMatch(/\.eq\(\s*"email"/);
		expect(statusSource).not.toMatch(/\.eq\(\s*"email"/);
	});
});

describe("pilot application tenant-scope migration contract", () => {
	it("uses a composite tenant key without moving an existing application", () => {
		expect(scopeMigrationSource).toMatch(/primary key\s*\(user_id,\s*tenant_id\)/i);
		expect(scopeMigrationSource).not.toMatch(/set\s+tenant_id\s*=/i);
		expect(tenancyMigrationSource).toContain("'pilot_applications'");
		expect(tenancyMigrationSource).toContain("if tg_op = 'UPDATE' and new.tenant_id is distinct from old.tenant_id then");
	});

	it("scopes bootstrap approval and grants execution only to the service role", () => {
		expect(scopeMigrationSource).toContain("where l.action = 'customer.bootstrap'");
		expect(scopeMigrationSource).toMatch(/on conflict\s*\(user_id, tenant_id\) do update/i);
		expect(scopeMigrationSource).toContain("to service_role");
		expect(scopeMigrationSource).not.toContain("to authenticated");
	});
});
