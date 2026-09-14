// Contract suite for the tenant resource controls that close three gaps:
//
//   1. stored bytes for the private `aidr-audit-exports` bucket had no
//      per-tenant cap (the route is the only writer);
//   2. `poll_fleet_response_command ... for update skip locked limit 1` is a
//      delivery lease, not a queue-depth bound;
//   3. `increment_rate_limit` accepted any caller-chosen key.
//
// The route handlers are driven through their exported factories with a fake
// `deps.db`, exactly like `billing-invoice-entitlement.test.ts`.

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The Edge Functions import Supabase through Deno's `npm:` specifier, which a
// Node test runner cannot resolve. The runtime factory only needs to exist and
// must never be reached: every case injects `deps.db`.
vi.mock("npm:@supabase/supabase-js@2", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through the handler deps");
	},
}));

// The Edge runtime provides `Deno.env` and `Deno.serve`; the test process does
// not. The env stub delegates to `process.env` and `serve` is a no-op because
// the suite drives the exported handler factories directly.
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: {
		get: (name: string) => process.env[name],
	},
	serve: () => undefined,
};

const FUNCTIONS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT = resolve(FUNCTIONS_DIR, "..", "..");
// Normalized so the assertions below read the same on a checkout that rewrites
// line endings.
const MIGRATION = readFileSync(
	join(REPO_ROOT, "supabase", "migrations", "20260913000005_tenant_storage_queue_quotas.sql"),
	"utf8",
).replace(/\r\n/g, "\n");

const STORAGE_RPC = MIGRATION.split("create function public.register_audit_export_object(")[1]?.split("\n$$;")[0] ?? "";
const QUEUE_RPC =
	MIGRATION.split("create function public.queue_bounded_fleet_response_command(")[1]?.split("\n$$;")[0] ?? "";
const RATE_LIMIT_RPC =
	MIGRATION.split("create or replace function public.increment_rate_limit(")[1]?.split("\n$$;")[0] ?? "";

const TENANT = "22222222-2222-4222-8222-222222222222";
const OTHER_TENANT = "33333333-3333-4333-8333-333333333333";
const USER = "11111111-1111-4111-8111-111111111111";
const AGENT = "44444444-4444-4444-8444-444444444444";
const COMMAND = "55555555-5555-4555-8555-555555555555";

type QueryResult = { data: unknown; error: unknown };
type RpcCall = { name: string; args: Record<string, unknown> };

/** Minimal PostgREST-shaped builder: chainable, awaitable and `.maybeSingle()`-terminated. */
function tableBuilder(result: () => QueryResult) {
	const builder = {} as Record<string, unknown> & PromiseLike<QueryResult>;
	const chain = () => builder;
	Object.assign(builder, {
		select: chain,
		eq: chain,
		lte: chain,
		or: chain,
		order: chain,
		limit: chain,
		maybeSingle: async () => result(),
		then: (onFulfilled?: (value: QueryResult) => unknown, onRejected?: (reason: unknown) => unknown) =>
			Promise.resolve(result()).then(onFulfilled, onRejected),
	});
	return builder;
}

describe("tenant storage byte quota", () => {
	interface StorageOptions {
		quota?: QueryResult;
		rows?: unknown[];
	}

	function database(options: StorageOptions = {}) {
		const rpcCalls: RpcCall[] = [];
		const upload = vi.fn(async () => ({ error: null }));
		const createSignedUrl = vi.fn(async (path: string) => ({
			data: { signedUrl: `https://project.supabase.co/storage/v1/object/sign/aidr-audit-exports/${path}?token=a` },
			error: null,
		}));
		const table = (name: string) => {
			if (name === "identity_user_session_state") return tableBuilder(() => ({ data: { revoked_before: null }, error: null }));
			if (name === "tenant_identity_policies") return tableBuilder(() => ({ data: { require_mfa: false }, error: null }));
			if (name === "tenant_members") return tableBuilder(() => ({ data: { role: "owner", expires_at: null }, error: null }));
			if (name === "tenants") return tableBuilder(() => ({ data: { status: "active" }, error: null }));
			if (name === "audit_logs") return tableBuilder(() => ({ data: options.rows ?? [], error: null }));
			return tableBuilder(() => ({ data: null, error: null }));
		};
		const db = {
			auth: {
				getUser: vi.fn(async (token: string) =>
					token === "valid-token"
						? { data: { user: { id: USER } }, error: null }
						: { data: { user: null }, error: new Error("invalid") },
				),
			},
			from: vi.fn((name: string) => table(name)),
			storage: { from: vi.fn(() => ({ upload, createSignedUrl })) },
			rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
				rpcCalls.push({ name, args });
				if (name === "register_audit_export_object") {
					return options.quota ?? { data: [{ allowed: true, remaining_bytes: 1024 }], error: null };
				}
				return { data: null, error: null };
			}),
		};
		return { db, rpcCalls, upload };
	}

	beforeEach(() => {
		vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
		vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "service-role-key");
	});
	afterEach(() => {
		vi.unstubAllEnvs();
		vi.resetModules();
	});

	async function handlerWith(options: StorageOptions = {}) {
		const { db, rpcCalls, upload } = database(options);
		const mod = await import("../audit-export/index.ts");
		return { handle: mod.createAuditExportHandler({ db: db as never }), rpcCalls, upload };
	}

	function post(teamId = TENANT): Request {
		return new Request("https://project.supabase.co/functions/v1/audit-export", {
			method: "POST",
			headers: { Authorization: "Bearer valid-token", "Content-Type": "application/json" },
			body: JSON.stringify({ team_id: teamId, format: "json" }),
		});
	}

	it("rejects a storage write that would exceed the tenant byte quota", async () => {
		const refused = await handlerWith({
			quota: { data: [{ allowed: false, remaining_bytes: 0 }], error: null },
			rows: [],
		});
		const response = await refused.handle(post());
		expect(response.status).toBe(429);
		expect(await response.json()).toMatchObject({
			error: "tenant_storage_quota_exceeded",
			tenant_storage_bytes_remaining: 0,
		});
		// The bytes are reserved before the object exists: nothing was uploaded.
		expect(refused.upload).not.toHaveBeenCalled();

		// The reservation is tenant-bound and sized from the serialized page, and
		// it is the only storage RPC the route performs.
		expect(refused.rpcCalls).toHaveLength(1);
		expect(refused.rpcCalls[0]).toEqual({
			name: "register_audit_export_object",
			args: {
				p_tenant_id: TENANT,
				p_actor_user_id: USER,
				p_path: expect.stringMatching(new RegExp(`^${TENANT}/[0-9a-f-]{36}\\.json$`)),
				p_bytes: 2,
				p_limit_bytes: 536870912,
			},
		});
		// The reservation names exactly one tenant: the one the identity barrier
		// and membership check above resolved.
		expect(refused.rpcCalls[0]?.args.p_tenant_id).not.toBe(OTHER_TENANT);
	});

	it("reserves the bytes under the quota and only then uploads", async () => {
		const admitted = await handlerWith({ quota: { data: [{ allowed: true, remaining_bytes: 1024 }], error: null } });
		const response = await admitted.handle(post());
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ ok: true, tenant_storage_bytes_remaining: 1024 });
		expect(admitted.upload).toHaveBeenCalledTimes(1);
		expect(admitted.rpcCalls[0]?.name).toBe("register_audit_export_object");
	});

	it("fails closed when the storage ledger is unavailable or malformed", async () => {
		for (const quota of [
			{ data: null, error: { code: "08006", message: "offline" } },
			{ data: [{ allowed: "yes", remaining_bytes: 1 }], error: null },
			{ data: [], error: null },
			{ data: [{ allowed: true, remaining_bytes: -1 }], error: null },
		]) {
			const broken = await handlerWith({ quota });
			const response = await broken.handle(post());
			expect(response.status).toBe(503);
			expect(await response.json()).toMatchObject({ error: "export_retention_unavailable" });
			expect(broken.upload).not.toHaveBeenCalled();
		}
	});

	it("keeps the byte budget tenant-scoped, bounded and ceiling-checked in SQL", () => {
		expect(MIGRATION).toContain("alter table public.audit_export_objects\n  add column if not exists bytes bigint not null default 0");
		// The usage read and the reservation insert share one tenant advisory lock.
		const lock = STORAGE_RPC.indexOf("pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2615))");
		expect(lock).toBeGreaterThan(-1);
		expect(STORAGE_RPC.indexOf("select coalesce(sum(o.bytes), 0) into v_used")).toBeGreaterThan(lock);
		expect(STORAGE_RPC.indexOf("insert into public.audit_export_objects")).toBeGreaterThan(lock);
		// The ceiling is a plan figure, not a caller-controlled switch.
		expect(STORAGE_RPC).toContain("p_limit_bytes is null or p_limit_bytes < 1 or p_limit_bytes > 1099511627776");
		expect(STORAGE_RPC).toContain("p_bytes is null or p_bytes < 1 or p_bytes > 8388608");
		expect(STORAGE_RPC).toContain("split_part(p_path, '/', 1) <> p_tenant_id::text");
		expect(STORAGE_RPC).toContain("t.status = 'active'");
		expect(MIGRATION).toContain(
			"revoke all on function public.register_audit_export_object(uuid, uuid, text, bigint, bigint)",
		);
		expect(MIGRATION).toContain(
			"grant execute on function public.register_audit_export_object(uuid, uuid, text, bigint, bigint)",
		);
	});

	it("binds storage objects to the tenant folder and denies client writes", () => {
		expect(MIGRATION).toContain("alter table storage.objects enable row level security");
		expect(MIGRATION).toContain("create policy audit_exports_read_own_tenant on storage.objects");
		expect(MIGRATION).toContain("(storage.foldername(name))[1] = app.current_tenant_id()::text");
		expect(MIGRATION).toContain("app.is_tenant_member(app.current_tenant_id())");
		// A client role can never create, replace or delete an export object, even
		// if a later migration adds a permissive policy for this bucket.
		for (const command of ["insert", "update", "delete"]) {
			expect(MIGRATION).toContain(
				`as restrictive for ${command} to anon, authenticated\n  ` +
					`${command === "insert" ? "with check" : "using"} (bucket_id <> 'aidr-audit-exports')`,
			);
		}
	});
});

describe("tenant fleet-response queue depth", () => {
	interface FleetOptions {
		queueError?: { code: string; message: string } | null;
	}

	function database(options: FleetOptions = {}) {
		const rpcCalls: RpcCall[] = [];
		const table = (name: string) => {
			if (name === "identity_user_session_state") return tableBuilder(() => ({ data: { revoked_before: null }, error: null }));
			if (name === "tenant_identity_policies") return tableBuilder(() => ({ data: { require_mfa: false }, error: null }));
			if (name === "tenant_members") return tableBuilder(() => ({ data: { role: "owner", expires_at: null }, error: null }));
			if (name === "tenants") return tableBuilder(() => ({ data: { status: "active" }, error: null }));
			return tableBuilder(() => ({ data: null, error: null }));
		};
		const db = {
			auth: {
				getUser: vi.fn(async (token: string) =>
					token === "valid-token"
						? { data: { user: { id: USER } }, error: null }
						: { data: { user: null }, error: new Error("invalid") },
				),
				mfa: { getAuthenticatorAssuranceLevel: vi.fn(async () => ({ data: { currentLevel: "aal2" }, error: null })) },
			},
			from: vi.fn((name: string) => table(name)),
			rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
				rpcCalls.push({ name, args });
				if (name === "consume_tenant_rate_limit") return { data: [{ allowed: true, remaining: 59 }], error: null };
				if (name === "queue_bounded_fleet_response_command") {
					return options.queueError
						? { data: null, error: options.queueError }
						: {
								data: {
									id: COMMAND,
									agent_id: AGENT,
									command_type: "agent_pause",
									state: "pending",
									expires_at: "2026-09-13T00:05:00.000Z",
									rollback_of: null,
								},
								error: null,
							};
				}
				return { data: null, error: null };
			}),
		};
		return { db, rpcCalls };
	}

	beforeEach(() => {
		vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
		vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "service-role-key");
	});
	afterEach(() => {
		vi.unstubAllEnvs();
		vi.resetModules();
	});

	async function handlerWith(options: FleetOptions = {}) {
		const { db, rpcCalls } = database(options);
		const mod = await import("../revocations/index.ts");
		return { handle: mod.createFleetCommandHandler({ db: db as never }), rpcCalls };
	}

	const QUEUE = {
		action: "queue",
		tenant_id: TENANT,
		agent_id: AGENT,
		command_type: "agent_pause",
		reason: "contains a suspicious background process",
		idempotency_key: "queue-0001-abcd",
		ttl_seconds: 300,
	};

	function post(body: unknown = QUEUE): Request {
		return new Request("https://project.supabase.co/functions/v1/revocations", {
			method: "POST",
			headers: { Authorization: "Bearer valid-token", "Content-Type": "application/json" },
			body: JSON.stringify(body),
		});
	}

	it("bounds concurrent fleet response commands per tenant", async () => {
		const refused = await handlerWith({ queueError: { code: "54000", message: "tenant_queue_limit_reached" } });
		const response = await refused.handle(post());
		expect(response.status).toBe(429);
		expect(await response.json()).toEqual({ error: "tenant_queue_limit_reached" });

		// The depth-bounded entry point is the only command-queue RPC the route
		// uses, and the tenant/actor are server facts, never body fields.
		const queued = refused.rpcCalls.find((call) => call.name.includes("fleet_response_command"));
		expect(queued?.name).toBe("queue_bounded_fleet_response_command");
		expect(queued?.args).toEqual({
			p_tenant_id: TENANT,
			p_actor_user_id: USER,
			p_agent_id: AGENT,
			p_command_type: "agent_pause",
			p_reason: QUEUE.reason,
			p_idempotency_key: QUEUE.idempotency_key,
			p_ttl_seconds: 300,
			p_rollback_of: null,
		});
		// The rejection is a quota answer, not a retryable transport failure.
		expect(queued?.args.p_tenant_id).not.toBe(OTHER_TENANT);

		// A client-supplied tenant is still only a *request*: the guard rejects it
		// before any queue RPC is attempted.
		const mismatch = await handlerWith({ queueError: { code: "54000", message: "tenant_queue_limit_reached" } });
		const forged = await mismatch.handle(post({ ...QUEUE, tenant_id: "not-a-uuid" }));
		expect(forged.status).toBe(400);
		expect(mismatch.rpcCalls).toEqual([]);
	});

	it("answers a bounded-queue failure as the declared status and never retries another limiter", async () => {
		const admitted = await handlerWith();
		const ok = await admitted.handle(post());
		expect(ok.status).toBe(200);
		expect(await ok.json()).toMatchObject({ ok: true, command: { id: COMMAND, state: "pending" } });
		// Exactly one queue RPC: no fallback to a caller-key limiter exists.
		expect(admitted.rpcCalls.filter((call) => call.name.includes("rate_limit"))).toHaveLength(1);

		const conflict = await handlerWith({ queueError: { code: "PT409", message: "fleet_idempotency_conflict" } });
		expect(await (await conflict.handle(post())).json()).toEqual({ error: "fleet_command_conflict" });

		const forbidden = await handlerWith({ queueError: { code: "42501", message: "fleet_operator_forbidden" } });
		expect((await forbidden.handle(post())).status).toBe(403);

		const unavailable = await handlerWith({ queueError: { code: "08006", message: "connection failure" } });
		const response = await unavailable.handle(post());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "fleet_queue_unavailable" });
	});

	it("serializes the depth check with the insert and removes the unbounded entry point", () => {
		expect(MIGRATION).toContain("create function public.queue_bounded_fleet_response_command(");
		// The ceiling is a reviewed constant, not a caller argument.
		expect(QUEUE_RPC).toContain("c_max_outstanding constant integer := 200");
		expect(QUEUE_RPC).toContain("raise exception 'tenant_queue_limit_reached' using errcode='54000'");
		// Depth is counted and inserted under one tenant lock, so parallel queue
		// attempts cannot both observe the pre-limit count.
		const lock = QUEUE_RPC.indexOf("pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2616))");
		expect(lock).toBeGreaterThan(-1);
		expect(QUEUE_RPC.indexOf("select count(*) into v_outstanding")).toBeGreaterThan(lock);
		expect(QUEUE_RPC.indexOf("select * into v_command from public.queue_fleet_response_command(")).toBeGreaterThan(lock);
		// Only live, unexpired commands consume depth, an idempotent retry is not
		// new depth, and a rollback (recovery) is always admitted.
		expect(QUEUE_RPC).toContain("c.state in ('pending', 'delivered', 'acknowledged')");
		expect(QUEUE_RPC).toContain("c.expires_at > now()");
		expect(QUEUE_RPC).toContain("if p_rollback_of is null and not exists (");
		// The unbounded function is no longer callable by any API role.
		expect(MIGRATION).toContain(
			"revoke all on function public.queue_fleet_response_command(uuid, uuid, uuid, text, text, text, integer, uuid)\n  from public, anon, authenticated, service_role;",
		);
		expect(MIGRATION).toContain(
			"grant execute on function public.queue_bounded_fleet_response_command(uuid, uuid, uuid, text, text, text, integer, uuid)\n  to service_role;",
		);
	});
});

describe("legacy caller-key rate limiter", () => {
	// Derived from the code: the only remaining callers of
	// `increment_rate_limit` and the scope each one addresses. A new caller (or a
	// new scope) fails this suite until the database allowlist is reviewed.
	const LEGACY_CALLERS = new Map<string, string[]>([
		["api-keys", ["apikey_create"]],
		["device-start", ["device_start"]],
		["enroll", ["enroll"]],
		["enrollment-tokens", ["enrolltoken_create"]],
		["identity-security", ["identity-reset", "identity-break-glass"]],
		["team-invite", ["team-invite"]],
		["waitlist-signup", ["waitlist"]],
	]);

	it("refuses the legacy caller-key rate limiter", () => {
		const discovered = readdirSync(FUNCTIONS_DIR, { withFileTypes: true })
			.filter((entry) => entry.isDirectory() && !entry.name.startsWith("_") && entry.name !== "__tests__")
			.map((entry) => entry.name)
			.filter((name) => readFileSync(join(FUNCTIONS_DIR, name, "index.ts"), "utf8").includes("increment_rate_limit"))
			.sort();
		expect(discovered).toEqual([...LEGACY_CALLERS.keys()].sort());

		// The replacement refuses a key that is not shaped like a reviewed scope,
		// and refuses deltas that could decrement a counter instead of consuming it.
		expect(RATE_LIMIT_RPC).toContain("raise exception using errcode = '22023', message = 'invalid_rate_limit_contract'");
		expect(RATE_LIMIT_RPC).toContain("v_scope := split_part(p_key, ':', 1)");
		expect(RATE_LIMIT_RPC).toContain("raise exception using errcode = '22023', message = 'invalid_rate_limit_scope'");
		expect(RATE_LIMIT_RPC).toContain("or p_delta is null or p_delta < 1 or p_delta > 1000");
		expect(RATE_LIMIT_RPC).toContain("octet_length(p_key) > 160");

		// Every scope a route uses is allowlisted, and the allowlist carries no
		// scope that no route uses.
		const allowlist = (RATE_LIMIT_RPC.split("v_scope not in (")[1] ?? "").split(") then")[0] ?? "";
		const allowlisted = [...allowlist.matchAll(/'([a-z][a-z0-9_-]*)'/g)].map((match) => match[1]).sort();
		const used = [...new Set([...LEGACY_CALLERS.values()].flat())].sort();
		expect(allowlisted).toEqual(used);
		for (const [name, scopes] of LEGACY_CALLERS) {
			const source = readFileSync(join(FUNCTIONS_DIR, name, "index.ts"), "utf8");
			for (const scope of scopes) expect(source, `${name} must address ${scope}`).toContain(`${scope}:`);
		}

		// The restricted-grant guarantee the README requires after every schema
		// change is re-asserted for the legacy signature.
		expect(MIGRATION).toContain(
			"revoke all on function public.increment_rate_limit(text, bigint, integer) from public, anon, authenticated;",
		);
		expect(MIGRATION).toContain(
			"grant execute on function public.increment_rate_limit(text, bigint, integer) to service_role;",
		);
		expect(MIGRATION).not.toMatch(/grant execute on function public\.increment_rate_limit[^;]*\bto\s+(?:public|anon|authenticated)\b/);
	});
});
