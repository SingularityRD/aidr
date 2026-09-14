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
vi.mock("npm:@supabase/supabase-js@2", () => ({
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

const APPLY_URL = "https://project.supabase.co/functions/v1/pilot-apply";
const STATUS_URL = "https://project.supabase.co/functions/v1/pilot-status";

const USER = "11111111-1111-4111-8111-111111111111";
const OTHER_USER = "22222222-2222-4222-8222-222222222222";
const TENANT = "33333333-3333-4333-8333-333333333333";
const OTHER_TENANT = "44444444-4444-4444-8444-444444444444";

const ORIGIN = "https://app.aidr.example";
const EVIL_ORIGIN = "https://app.aidr.example.evil.example";

const VALID_TOKEN = "valid-token";
const OTHER_TOKEN = "other-token";
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
	op: "insert" | "upsert";
	row: Record<string, unknown>;
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
	memberships?: Array<{ tenant_id: string; role: string; expires_at: string | null }>;
	membershipError?: boolean;
	tenantStatus?: string | null;
}

/**
 * Minimal PostgREST-shaped fake: `select().eq().maybeSingle()` chains for reads,
 * awaited `insert()`/`upsert()` for writes. It records every query so a test can
 * assert not just the outcome but *which rows the handler was willing to look
 * at* — that is how the "never reads another applicant's row" property is
 * falsifiable rather than assumed.
 */
function database(options: DbOptions = {}) {
	const rows = new Map<string, ApplicationRow>();
	for (const row of options.applications ?? []) rows.set(row.user_id, { ...row });
	const writes: Write[] = [];
	const queries: Query[] = [];
	let filter: Record<string, unknown> = {};

	const settle = async (table: string): Promise<{ data: unknown; error: unknown }> => {
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
			const found = memberships.find((row) => row.tenant_id === filter.tenant_id);
			return {
				data: found ?? null,
				error: options.membershipError ? { message: "db_down" } : null,
			};
		}
		if (table === "tenants") {
			return { data: { status: options.tenantStatus ?? "active" }, error: null };
		}
		if (table === "pilot_applications") {
			if (options.applicationReadError) return { data: null, error: { message: "db_down" } };
			if (typeof filter.user_id === "string") {
				return { data: rows.get(filter.user_id) ?? null, error: null };
			}
			const match = [...rows.values()].find(
				(row) =>
					row.tenant_id === filter.tenant_id &&
					(filter.status === undefined || row.status === filter.status),
			);
			return { data: match ?? null, error: null };
		}
		return { data: null, error: null };
	};

	const write = (
		table: string,
		op: "insert" | "upsert",
		row: Record<string, unknown>,
		onConflict?: string,
	) => {
		writes.push({ table, op, row, onConflict });
		if (table === "pilot_applications" && options.applicationWriteError) {
			return Promise.resolve({ data: null, error: { message: "db_down" } });
		}
		if (table === "admin_audit_logs" && options.auditError) {
			return Promise.resolve({ data: null, error: { message: "db_down" } });
		}
		if (table === "pilot_applications") {
			const key = String(row.user_id);
			rows.set(key, { ...(rows.get(key) ?? {}), ...row } as ApplicationRow);
		}
		return Promise.resolve({ data: null, error: null });
	};

	const builder = (table: string) => {
		filter = {};
		const query = {
			select: () => query,
			eq: (column: string, value: unknown) => {
				filter[column] = value;
				return query;
			},
			limit: () => query,
			maybeSingle: () => settle(table),
			insert: (row: Record<string, unknown>) => write(table, "insert", row),
			upsert: (row: Record<string, unknown>, opts?: { onConflict?: string }) =>
				write(table, "upsert", row, opts?.onConflict),
			then: (
				onFulfilled: (value: unknown) => unknown,
				onRejected?: (reason: unknown) => unknown,
			) => settle(table).then(onFulfilled, onRejected),
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
		const { handle, rows, writes, queries } = await loadApply();
		const response = await handle(applyRequest(INTENT));

		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, status: "pending" });
		expect(response.headers.get("access-control-allow-origin")).toBe(ORIGIN);

		expect(rows.size).toBe(1);
		expect(rows.get(USER)).toMatchObject({
			user_id: USER,
			tenant_id: USER,
			status: "pending",
			notes: INTENT.useCase,
		});

		const upserts = writes.filter((entry) => entry.table === "pilot_applications");
		expect(upserts).toHaveLength(1);
		expect(upserts[0]?.op).toBe("upsert");
		// The identity key is the verified session, and the row is keyed on it.
		expect(upserts[0]?.onConflict).toBe("user_id");
		expect(upserts[0]?.row).toMatchObject({ user_id: USER, status: "pending" });

		const audits = writes.filter((entry) => entry.table === "admin_audit_logs");
		expect(audits).toHaveLength(1);
		expect(audits[0]?.row).toMatchObject({
			actor_user_id: USER,
			tenant_id: USER,
			action: "pilot.apply",
			target_user_id: USER,
			detail: { has_use_case: true },
		});
		expect(queries.some((query) => query.table === "pilot_applications" && query.filter.user_id === USER)).toBe(
			true,
		);
	});

	it("returns the same application for the same caller and never creates a second record", async () => {
		const { handle, rows, writes } = await loadApply();
		const first = await handle(applyRequest(INTENT));
		const second = await handle(applyRequest(INTENT));

		expect(first.status).toBe(200);
		expect(second.status).toBe(200);
		expect(await second.json()).toEqual(await first.json());
		expect(rows.size).toBe(1);
		expect(rows.get(USER)?.user_id).toBe(USER);
		// Two upsert attempts, both onto the same identity key, still one record.
		expect(writes.filter((entry) => entry.table === "pilot_applications")).toHaveLength(2);
		expect(
			writes
				.filter((entry) => entry.table === "pilot_applications")
				.every((entry) => entry.onConflict === "user_id"),
		).toBe(true);
	});

	it("refuses to let a conflicting re-submission reset an already approved application", async () => {
		const { handle, rows } = await loadApply({
			applications: [{ user_id: USER, tenant_id: TENANT, status: "approved", cohort: "cohort-a" }],
		});
		const response = await handle(applyRequest({ ...INTENT, useCase: "A different story entirely." }));

		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, status: "approved" });
		expect(rows.get(USER)).toMatchObject({
			status: "approved",
			tenant_id: TENANT,
			cohort: "cohort-a",
		});
	});

	it("rejects a body that tries to assert user_id, tenant_id or status", async () => {
		const { handle, writes } = await loadApply();
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
	});

	it("binds each application to its own caller", async () => {
		const { handle, rows } = await loadApply();
		const first = await handle(applyRequest(INTENT));
		const second = await handle(applyRequest(INTENT, { Authorization: `Bearer ${OTHER_TOKEN}` }));

		expect(first.status).toBe(200);
		expect(second.status).toBe(200);
		expect(rows.size).toBe(2);
		expect(rows.get(USER)?.user_id).toBe(USER);
		expect(rows.get(OTHER_USER)?.user_id).toBe(OTHER_USER);
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
				headers: { Authorization: `Bearer ${VALID_TOKEN}`, Origin: ORIGIN },
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
		expect(rows.get(OTHER_USER)?.status).toBe("approved");
		expect(rows.get(OTHER_USER)?.notes).toBeUndefined();
	});

	it("fails closed when the session-state storage read fails", async () => {
		const { handle, writes } = await loadApply({ identityError: true });
		const response = await handle(applyRequest(INTENT));

		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "identity_state_unavailable" });
		expect(writes.filter((entry) => entry.table === "pilot_applications")).toHaveLength(0);
	});

	it("refuses the intake when the existing application cannot be read", async () => {
		const { handle, writes } = await loadApply({ applicationReadError: true });
		const response = await handle(applyRequest(INTENT));

		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "pilot_application_unavailable" });
		expect(writes.filter((entry) => entry.table === "pilot_applications")).toHaveLength(0);
	});

	it("never reports success when the application write fails", async () => {
		const { handle, rows, writes } = await loadApply({ applicationWriteError: true });
		const response = await handle(applyRequest(INTENT));

		expect(response.status).toBe(500);
		expect(await response.json()).toEqual({ error: "pilot_application_unavailable" });
		expect(rows.size).toBe(0);
		expect(writes.filter((entry) => entry.table === "admin_audit_logs")).toHaveLength(0);
	});

	it("never reports success when the audit trail cannot be recorded", async () => {
		const { handle } = await loadApply({ auditError: true });
		const response = await handle(applyRequest(INTENT));
		const payload = (await response.json()) as Record<string, unknown>;

		expect(response.status).toBe(500);
		expect(payload).toEqual({ error: "pilot_audit_unavailable" });
		expect(payload.ok).not.toBe(true);
	});

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

	it.each(ROUTES)("$name refuses every method but $method", async (route) => {
		const { handle, db } = await route.load();
		const disallowed = route.method === "POST" ? "GET" : "POST";
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

	it("bounds the intake body and validates it before any write", () => {
		expect(applySource).toContain("readBoundedJson(req, MAX_BODY_BYTES)");
		expect(applySource).toContain("parseIntake(parsed.value)");
		expect(applySource.indexOf("parseIntake(parsed.value)")).toBeLessThan(
			applySource.indexOf(".upsert("),
		);
	});

	it("never queries an applicant by an address supplied in the body", () => {
		expect(applySource).not.toMatch(/\.eq\(\s*"email"/);
		expect(statusSource).not.toMatch(/\.eq\(\s*"email"/);
	});
});
