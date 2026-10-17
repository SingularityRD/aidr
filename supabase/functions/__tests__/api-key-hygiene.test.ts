// CP-8: API key hygiene. Keys carry the prefix of their type (also after
// rotation), dashboard-issued keys expire by default, an expired key is refused
// by every API-key guard, and labels are bounded in the edge function and the
// database.
import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiKeyExpired, authenticateTenantApiKey } from "../_shared/api-key-auth.ts";
import {
	apiKeyPrefix,
	DEFAULT_KEY_TTL_DAYS,
	defaultKeyTtlDays,
	MAX_KEY_TTL_DAYS,
	parseLabel,
	resolveExpiry,
} from "../api-keys/hygiene.ts";

const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: sdk.createClient }));
vi.mock("../_shared/identity-barrier.ts", () => ({
	checkIdentityBarrier: async () => ({ ok: true }),
}));

const USER_ID = "11111111-1111-4111-8111-111111111111";
const TENANT_ID = "22222222-2222-4222-8222-222222222222";
const KEY_ID = "44444444-4444-4444-8444-444444444444";
const DAY = 86_400_000;

describe("hygiene rules", () => {
	it("maps every key type to its own prefix", () => {
		expect(apiKeyPrefix("tenant")).toBe("aidr_live_");
		expect(apiKeyPrefix("ingest:browser_guard")).toBe("aidr_ingest_");
	});

	it("bounds labels to 1..100 characters without control characters", () => {
		expect(parseLabel(undefined)).toEqual({ ok: true, value: null });
		expect(parseLabel("   ")).toEqual({ ok: true, value: null });
		expect(parseLabel("  build server ")).toEqual({ ok: true, value: "build server" });
		expect(parseLabel("x".repeat(100))).toEqual({ ok: true, value: "x".repeat(100) });
		// Code points, like Postgres char_length.
		expect(parseLabel("é".repeat(100))).toEqual({ ok: true, value: "é".repeat(100) });
		expect(parseLabel("x".repeat(101))).toEqual({ ok: false });
		expect(parseLabel("x".repeat(8192))).toEqual({ ok: false });
		expect(parseLabel("line\nbreak")).toEqual({ ok: false });
		expect(parseLabel("bell\u0007")).toEqual({ ok: false });
		expect(parseLabel("c1\u009b31m")).toEqual({ ok: false });
		expect(parseLabel(42)).toEqual({ ok: false });
	});

	it("validates the default lifetime setting", () => {
		expect(defaultKeyTtlDays(undefined)).toBe(DEFAULT_KEY_TTL_DAYS);
		expect(defaultKeyTtlDays("30")).toBe(30);
		expect(defaultKeyTtlDays(String(MAX_KEY_TTL_DAYS))).toBe(MAX_KEY_TTL_DAYS);
		for (const bad of ["", "0", "-1", "731", "1.5", "never", "1e3"]) expect(defaultKeyTtlDays(bad)).toBeNull();
	});

	it("resolves omitted, explicit and non-expiring lifetimes", () => {
		const now = Date.parse("2026-10-13T00:00:00.000Z");
		expect(resolveExpiry({}, 90, now)).toEqual({ ok: true, expiresAt: new Date(now + 90 * DAY).toISOString() });
		expect(resolveExpiry({ expires_in_days: 7 }, 90, now)).toEqual({ ok: true, expiresAt: new Date(now + 7 * DAY).toISOString() });
		expect(resolveExpiry({ expires_in_days: null }, 90, now)).toEqual({ ok: true, expiresAt: null });
		for (const bad of [0, -1, 731, 1.5, "7", true]) expect(resolveExpiry({ expires_in_days: bad }, 90, now)).toEqual({ ok: false });
	});
});

describe("API-key guard refuses an expired key", () => {
	function database(key: Record<string, unknown>) {
		const rows: Record<string, unknown> = {
			api_keys: key,
			tenant_members: { role: "member", expires_at: null },
			tenants: { status: "active" },
		};
		return {
			rpc: async () => ({ data: 1, error: null }),
			from(table: string) {
				const builder = {
					select: () => builder,
					eq: () => builder,
					maybeSingle: async () => ({ data: table === "api_keys" && key.__miss ? null : rows[table] ?? null, error: null }),
				};
				return builder;
			},
		};
	}
	const base = { user_id: "user-1", tenant_id: "tenant-1", revoked: false, scope: "tenant" };
	const now = Date.parse("2026-10-13T12:00:00.000Z");

	it("accepts a key without expiry or with a future one", async () => {
		await expect(authenticateTenantApiKey(database(base), "k", now)).resolves.toMatchObject({ ok: true });
		await expect(
			authenticateTenantApiKey(database({ ...base, expires_at: new Date(now + DAY).toISOString() }), "k", now),
		).resolves.toMatchObject({ ok: true });
	});

	it("refuses a key whose expiry has passed, and a corrupt expiry", async () => {
		for (const expires_at of [new Date(now - 1).toISOString(), new Date(now).toISOString(), "not-a-date"]) {
			await expect(authenticateTenantApiKey(database({ ...base, expires_at }), "k", now)).resolves.toEqual({
				ok: false,
				status: 401,
				error: "invalid_api_key",
			});
		}
		await expect(authenticateTenantApiKey(database({ ...base, expires_at: 12 }), "k", now)).resolves.toMatchObject({
			ok: false,
			status: 401,
		});
		expect(apiKeyExpired(null, now)).toBe(false);
	});
});

// ── /v1/api-keys handler ───────────────────────────────────────────────────
const state = vi.hoisted(() => ({
	role: "owner",
	key: null as Record<string, unknown> | null,
	rpc: vi.fn(),
}));

async function apiKeysHandler(env: Record<string, string> = {}) {
	let handler: ((request: Request) => Promise<Response>) | undefined;
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role");
	for (const [name, value] of Object.entries(env)) vi.stubEnv(name, value);
	vi.stubGlobal("crypto", webcrypto);
	vi.stubGlobal("Deno", {
		env: { get: (name: string) => process.env[name] },
		serve: (value: typeof handler) => {
			handler = value;
		},
	});
	sdk.createClient.mockReturnValue({
		auth: { getUser: async () => ({ data: { user: { id: USER_ID } }, error: null }) },
		rpc: state.rpc,
		from(table: string) {
			const query = {
				select: () => query,
				eq: () => query,
				maybeSingle: async () => ({
					data:
						table === "tenant_members"
							? { tenant_id: TENANT_ID, role: state.role, expires_at: null }
							: table === "tenants"
								? { status: "active" }
								: table === "rate_limits"
									? { count: 1 }
									: table === "api_keys"
										? state.key
										: null,
					error: null,
				}),
			};
			return query;
		},
	});
	vi.resetModules();
	await import("../api-keys/index.ts");
	if (!handler) throw new Error("api-keys did not register a handler");
	return handler;
}

function post(body: Record<string, unknown>) {
	return new Request("https://project.supabase.co/functions/v1/api-keys", {
		method: "POST",
		headers: {
			Authorization: "Bearer synthetic-access-token",
			"Content-Type": "application/json",
			"X-AIDR-Tenant-ID": TENANT_ID,
		},
		body: JSON.stringify(body),
	});
}

const mutationNames = () => state.rpc.mock.calls.map(([name]) => name).filter((name) => name !== "increment_rate_limit");

describe("/v1/api-keys hygiene", () => {
	beforeEach(() => {
		state.role = "owner";
		state.key = null;
		state.rpc.mockReset();
		state.rpc.mockImplementation(async (name: string, args: Record<string, unknown>) => {
			if (name === "increment_rate_limit") return { data: null, error: null };
			if (name === "renew_api_key_with_audit") {
				return {
					data: { status: "rotated", id: KEY_ID, previous_secret_valid_until: null, expires_at: args.p_expires_at },
					error: null,
				};
			}
			return { data: { status: "issued", id: KEY_ID }, error: null };
		});
	});
	afterEach(() => {
		vi.unstubAllEnvs();
		vi.unstubAllGlobals();
		sdk.createClient.mockReset();
	});

	it("renews a Browser Guard ingest key with the aidr_ingest_ prefix (not aidr_live_)", async () => {
		state.key = { id: KEY_ID, key_hash: "a".repeat(64), revoked: false, scope: "ingest:browser_guard", expires_at: null };
		const handler = await apiKeysHandler();
		const response = await handler(post({ action: "renew", id: KEY_ID }));
		expect(response.status).toBe(200);
		const body = await response.json();
		expect(body.api_key).toMatch(/^aidr_ingest_[A-Za-z0-9_-]{43}$/);
		expect(body.scope).toBe("ingest:browser_guard");
		const renew = state.rpc.mock.calls.find(([name]) => name === "renew_api_key_with_audit");
		expect(renew?.[1]).toMatchObject({
			p_new_hash: createHash("sha256").update(body.api_key).digest("hex"),
			p_set_expiry: true,
		});
	});

	it("renews a tenant key with the aidr_live_ prefix and the requested lifetime", async () => {
		state.key = { id: KEY_ID, key_hash: "a".repeat(64), revoked: false, scope: "tenant", expires_at: null };
		const handler = await apiKeysHandler();
		const response = await handler(post({ action: "renew", id: KEY_ID, expires_in_days: 30 }));
		const body = await response.json();
		expect(body.api_key).toMatch(/^aidr_live_/);
		expect(Math.round((Date.parse(body.expires_at) - Date.now()) / DAY)).toBe(30);
	});

	it("refuses to renew an expired key", async () => {
		state.key = {
			id: KEY_ID,
			key_hash: "a".repeat(64),
			revoked: false,
			scope: "tenant",
			expires_at: new Date(Date.now() - 1000).toISOString(),
		};
		const handler = await apiKeysHandler();
		const response = await handler(post({ action: "renew", id: KEY_ID }));
		expect(response.status).toBe(409);
		expect(await response.json()).toEqual({ error: "key_expired" });
		expect(mutationNames()).toEqual([]);
	});

	it("maps the database's expired answer for a key that expired mid-request", async () => {
		state.key = { id: KEY_ID, key_hash: "a".repeat(64), revoked: false, scope: "tenant", expires_at: null };
		state.rpc.mockImplementation(async (name: string) =>
			name === "increment_rate_limit" ? { data: null, error: null } : { data: { status: "expired" }, error: null },
		);
		const handler = await apiKeysHandler();
		const response = await handler(post({ action: "renew", id: KEY_ID }));
		expect(response.status).toBe(409);
		expect(await response.json()).toEqual({ error: "key_expired" });
	});

	it("issues a tenant key with the default lifetime, a chosen one, or explicitly none", async () => {
		const handler = await apiKeysHandler({ AIDR_APIKEY_DEFAULT_TTL_DAYS: "90" });
		const byDefault = await (await handler(post({ action: "create", label: "laptop" }))).json();
		expect(byDefault.api_key).toMatch(/^aidr_live_/);
		expect(Math.round((Date.parse(byDefault.expires_at) - Date.now()) / DAY)).toBe(90);
		const chosen = await (await handler(post({ action: "create", expires_in_days: 7 }))).json();
		expect(Math.round((Date.parse(chosen.expires_at) - Date.now()) / DAY)).toBe(7);
		const never = await (await handler(post({ action: "create", expires_in_days: null }))).json();
		expect(never.expires_at).toBeNull();
		const issued = state.rpc.mock.calls.filter(([name]) => name === "issue_api_key_with_audit").map(([, args]) => args);
		expect(issued.map((args) => args.p_expires_at)).toEqual([byDefault.expires_at, chosen.expires_at, null]);
		expect(issued[0]?.p_label).toBe("laptop");
	});

	it.each([
		["a 101-character label", { label: "x".repeat(101) }, "invalid_label"],
		["a 4000-character label", { label: "x".repeat(4000) }, "invalid_label"],
		["a label with a forged log line", { label: "evil\r\nINFO forged audit line" }, "invalid_label"],
		["a non-string label", { label: 7 }, "invalid_label"],
		["a zero-day lifetime", { expires_in_days: 0 }, "invalid_expiry"],
		["a lifetime above two years", { expires_in_days: 731 }, "invalid_expiry"],
		["a string lifetime", { expires_in_days: "30" }, "invalid_expiry"],
	])("refuses %s before spending budget or touching the database", async (_name, body, error) => {
		const handler = await apiKeysHandler();
		const response = await handler(post({ action: "create", ...body }));
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error });
		expect(state.rpc).not.toHaveBeenCalled();
	});

	it("fails closed when the default lifetime setting is malformed", async () => {
		const handler = await apiKeysHandler({ AIDR_APIKEY_DEFAULT_TTL_DAYS: "forever" });
		const response = await handler(post({ action: "create" }));
		expect(response.status).toBe(500);
		expect(await response.json()).toEqual({ error: "server_misconfigured", invalid: ["AIDR_APIKEY_DEFAULT_TTL_DAYS"] });
		expect(state.rpc).not.toHaveBeenCalled();
	});

	it("lists expiry, rotation time and tenant ownership so the dashboard can warn", () => {
		const source = readFileSync(new URL("../api-keys/index.ts", import.meta.url), "utf8");
		expect(source).toContain('.select("id,label,revoked,created_at,scope,install_limit,expires_at,rotated_at,fleet_key_id")');
	});
});

describe("API key hygiene migration", () => {
	const migration = readFileSync(
		new URL("../../migrations/20261013000510_api_key_expiry_and_label_bounds.sql", import.meta.url),
		"utf8",
	);

	it("adds an optional expiry and bounds labels in the table", () => {
		expect(migration).toMatch(/alter table public\.api_keys add column if not exists expires_at timestamptz;/);
		expect(migration).toMatch(
			/api_keys_label_check check \(\s*label is null or \(char_length\(label\) between 1 and 100 and label !~ '\[\[:cntrl:\]\]'\)\s*\)/,
		);
		expect(migration).toMatch(/api_keys_expiry_check check \(\s*expires_at is null or expires_at > created_at\s*\)/);
		// Existing labels are normalized before the constraint is validated.
		expect(migration.indexOf("update public.api_keys")).toBeLessThan(migration.indexOf("add constraint api_keys_label_check"));
	});

	it("validates label and expiry in every issuing RPC and refuses to revive an expired key", () => {
		for (const fn of ["issue_api_key_with_audit(", "issue_scoped_api_key_with_audit("]) {
			const body = migration.slice(migration.indexOf(`create or replace function public.${fn}`));
			const head = body.slice(0, body.indexOf("$$;"));
			expect(head).toContain("not app.api_key_label_valid(p_label)");
			expect(head).toContain("p_expires_at <= clock_timestamp()");
			expect(head).toMatch(/p_expires_at timestamptz default null/);
		}
		const renew = migration.slice(migration.indexOf("create or replace function public.renew_api_key_with_audit("));
		expect(renew).toMatch(/p_set_expiry boolean default false/);
		expect(renew).toContain("return jsonb_build_object('status', 'expired');");
		expect(renew.indexOf("'status', 'expired'")).toBeLessThan(renew.indexOf("update public.api_keys set key_hash"));
		expect(renew).toContain("v_expires_at := case when p_set_expiry then p_expires_at else v_key.expires_at end;");
	});

	it("keeps the new signatures service-only", () => {
		for (const signature of [
			"issue_api_key_with_audit(uuid, uuid, text, text, timestamptz)",
			"issue_scoped_api_key_with_audit(uuid, uuid, text, text, text, integer, timestamptz)",
			"renew_api_key_with_audit(uuid, uuid, uuid, text, text, integer, boolean, timestamptz)",
		]) {
			expect(migration).toContain(`revoke all on function public.${signature}\n  from public, anon, authenticated;`);
			expect(migration).toContain(`grant execute on function public.${signature}\n  to service_role;`);
		}
	});
});
