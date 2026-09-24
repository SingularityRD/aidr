import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import ts from "typescript";
import { authenticateTenantApiKey } from "../_shared/api-key-auth.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
import {
	boundedOverlapHours,
	retiredSecretActive,
	rotationPlan,
} from "../_shared/key-rotation.ts";

const FUNCTIONS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MIGRATIONS_DIR = resolve(FUNCTIONS_DIR, "..", "migrations");
const ROTATION_MIGRATION = (() => {
	const name = readdirSync(MIGRATIONS_DIR).find((entry) => entry.endsWith("_key_rotation_overlap.sql"));
	if (!name) throw new Error("the key rotation overlap migration is missing");
	return readFileSync(join(MIGRATIONS_DIR, name), "utf8").replace(/\r\n/g, "\n");
})();
const ATOMIC_CREDENTIAL_MIGRATION = (() => {
	const name = readdirSync(MIGRATIONS_DIR).find((entry) => entry.endsWith("_atomic_credential_lifecycle.sql"));
	if (!name) throw new Error("the atomic credential lifecycle migration is missing");
	return readFileSync(join(MIGRATIONS_DIR, name), "utf8").replace(/\r\n/g, "\n");
})();
const EXCHANGE_RPC =
	ROTATION_MIGRATION.split("create or replace function public.exchange_enrollment_token(")[1]?.split(
		"\nend;\n$$;",
	)[0] ?? "";

const apiKeysSource = readFileSync(join(FUNCTIONS_DIR, "api-keys", "index.ts"), "utf8");
const enrollmentTokensSource = readFileSync(
	join(FUNCTIONS_DIR, "enrollment-tokens", "index.ts"),
	"utf8",
);
const verifySource = readFileSync(join(FUNCTIONS_DIR, "device-verify", "index.ts"), "utf8");

/** Renewal branch only, so revoke/delete scoping cannot satisfy the assertions. */
function renewalBranch(source: string): string {
	return source.split('if (action === "renew")')[1]?.split("// create")[0] ?? "";
}

function atomicFunction(name: string): string {
	return ATOMIC_CREDENTIAL_MIGRATION.split(`function public.${name}(`)[1]?.split("\n$$;")[0] ?? "";
}

type Query = { table: string; filters: Record<string, unknown> };

/**
 * PostgREST-shaped client for `authenticateTenantApiKey`. The active hash never
 * matches (as after a rotation); the retired-hash lookup answers with `row`.
 */
function keyDatabase(row: Record<string, unknown> | null) {
	const queries: Query[] = [];
	const client = {
		rpc: () => Promise.resolve({ data: 1, error: null }),
		from(table: string) {
			const filters: Record<string, unknown> = {};
			const builder = {
				select: () => builder,
				eq(column: string, value: unknown) {
					filters[column] = value;
					return builder;
				},
				maybeSingle: () => {
					queries.push({ table, filters: { ...filters } });
					if (table === "api_keys") {
						return Promise.resolve({ data: "key_hash" in filters ? null : row, error: null });
					}
					if (table === "tenant_members") {
						return Promise.resolve({ data: { role: "member", expires_at: null }, error: null });
					}
					if (table === "tenants") {
						return Promise.resolve({ data: { status: "active" }, error: null });
					}
					return Promise.resolve({ data: null, error: null });
				},
			};
			return builder;
		},
	};
	return { client, queries };
}

const TEST_USER_ID = "22222222-2222-4222-8222-222222222222";
const TEST_TENANT_ID = "11111111-1111-4111-8111-111111111111";
const CREDENTIAL_CASES = [
	{ kind: "api", action: "create", source: apiKeysSource, rpc: "issue_api_key_with_audit", secret: "api_key" },
	{ kind: "api", action: "renew", source: apiKeysSource, rpc: "renew_api_key_with_audit", secret: "api_key" },
	{ kind: "api", action: "revoke", source: apiKeysSource, rpc: "revoke_api_key_with_audit", secret: "api_key" },
	{ kind: "token", action: "create", source: enrollmentTokensSource, rpc: "issue_enrollment_token_with_audit", secret: "enrollment_token" },
	{ kind: "token", action: "renew", source: enrollmentTokensSource, rpc: "renew_enrollment_token_with_audit", secret: "enrollment_token" },
	{ kind: "token", action: "delete", source: enrollmentTokensSource, rpc: "delete_enrollment_token_with_audit", secret: "enrollment_token" },
] as const;

function credentialMutationHarness(
	credential: (typeof CREDENTIAL_CASES)[number],
	responses: Array<{ data: unknown; error: unknown | null }>,
) {
	const compiled = ts.transpileModule(credential.source.replace(/^import .*;\r?\n/gm, ""), {
		compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
	}).outputText;
	let handler: ((request: Request) => Promise<Response>) | undefined;
	let mutationIndex = 0;
	let directCredentialWrites = 0;
	const calls: Array<{ name: string; args: Record<string, unknown> }> = [];
	const currentCredential = credential.kind === "api"
		? { id: "credential-1", user_id: TEST_USER_ID, key_hash: "a".repeat(64), revoked: false }
		: {
			id: "credential-1",
			user_id: TEST_USER_ID,
			token_hash: "a".repeat(64),
			expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
			consumed_at: null,
		};
	const client = {
		auth: { getUser: async () => ({ data: { user: { id: TEST_USER_ID } }, error: null }) },
		from(table: string) {
			const query = {
				select(_columns: string) { return query; },
				eq(_column: string, _value: unknown) { return query; },
				order(_column: string, _options: unknown) { return query; },
				limit(_count: number) { return query; },
				insert(_values: unknown) { directCredentialWrites++; return query; },
				update(_values: unknown) { directCredentialWrites++; return query; },
				delete() { directCredentialWrites++; return query; },
				async maybeSingle() {
					if (table === "tenant_members") {
						return { data: { tenant_id: TEST_TENANT_ID, role: "owner", expires_at: null }, error: null };
					}
					if (table === "tenants") return { data: { status: "active" }, error: null };
					if (table === "rate_limits") return { data: { count: 1 }, error: null };
					if (table === "api_keys" || table === "enrollment_tokens") {
						return { data: currentCredential, error: null };
					}
					throw new Error(`unexpected table ${table}`);
				},
			};
			return query;
		},
		async rpc(name: string, args: Record<string, unknown>) {
			if (name === "increment_rate_limit") return { data: null, error: null };
			calls.push({ name, args });
			const response = responses[Math.min(mutationIndex, responses.length - 1)];
			mutationIndex++;
			return response ?? { data: null, error: new Error("missing injected response") };
		},
	};
	const deno = { env: { get: () => undefined }, serve: (fn: typeof handler) => { handler = fn; } };
	const common = [
		deno,
		() => client,
		async () => ({ ok: true }),
		() => { throw new Error("unexpected config failure"); },
		() => ({ ok: true, values: { SUPABASE_URL: "https://test.invalid", SUPABASE_SERVICE_ROLE_KEY: "test" } }),
		{},
		(_request: Request, status: number, body: unknown) => Response.json(body, { status }),
		() => null,
		() => 24,
		() => true,
		readBoundedJson,
	];
	if (credential.kind === "api") {
		new Function(
			"Deno", "createClient", "getBearerToken", "checkIdentityBarrier", "configFailure", "loadConfig",
			"runtimeEnv", "corsJson", "handleCors", "boundedOverlapHours", "membershipActive", "readBoundedJson", compiled,
		)(
			...common.slice(0, 2),
			(header: string | null) => header?.match(/^Bearer\s+(.+)$/i)?.[1] ?? null,
			...common.slice(2),
		);
	} else {
		new Function(
			"Deno", "createClient", "checkIdentityBarrier", "configFailure", "loadConfig", "runtimeEnv",
			"corsJson", "handleCors", "boundedOverlapHours", "membershipActive", "readBoundedJson", compiled,
		)(...common);
	}
	if (!handler) throw new Error("credential handler was not registered");
	const body = credential.action === "create"
		? { action: credential.action, label: "failure-test" }
		: { action: credential.action, id: "credential-1" };
	return {
		calls,
		get directCredentialWrites() { return directCredentialWrites; },
		async request() {
			const response = await handler!(new Request("https://test.invalid/credentials", {
				method: "POST",
				headers: {
					Authorization: "Bearer test-session",
					"X-AIDR-Tenant-ID": TEST_TENANT_ID,
				},
				body: JSON.stringify(body),
			}));
			return { status: response.status, body: await response.json() as Record<string, unknown> };
		},
	};
}

describe("atomic credential audit failure injection", () => {
	it.each(CREDENTIAL_CASES)("fails closed on persistent audit failure for $kind $action", async (credential) => {
		const auditFailure = { data: null, error: { message: "injected audit insert failure" } };
		const app = credentialMutationHarness(credential, [auditFailure, auditFailure]);
		const response = await app.request();

		expect(response.status).toBe(503);
		expect(response.body.error).toBe("audit_unavailable");
		expect(response.body[credential.secret]).toBeUndefined();
		expect(app.calls).toHaveLength(2);
		expect(app.calls.every((call) => call.name === credential.rpc)).toBe(true);
		if (credential.action === "create" || credential.action === "renew") {
			const secretHash = app.calls[0]!.args.p_key_hash ?? app.calls[0]!.args.p_token_hash ?? app.calls[0]!.args.p_new_hash;
			expect(secretHash).toMatch(/^[a-f0-9]{64}$/);
			expect(app.calls[1]!.args.p_key_hash ?? app.calls[1]!.args.p_token_hash ?? app.calls[1]!.args.p_new_hash)
				.toBe(secretHash);
		} else {
			expect(app.calls[1]!.args).toEqual(app.calls[0]!.args);
			expect(app.calls[0]!.args.p_id).toBe("credential-1");
		}
		expect(app.directCredentialWrites).toBe(0);
	});

	it.each(CREDENTIAL_CASES)("recovers a committed $kind $action mutation after a lost response", async (credential) => {
		const success = credential.action === "create"
			? { status: "issued", expires_at: new Date(Date.now() + 60_000).toISOString() }
			: credential.action === "renew"
				? { status: "rotated", expires_at: new Date(Date.now() + 60_000).toISOString(), previous_secret_valid_until: null }
				: credential.action === "revoke" ? { status: "revoked" } : { status: "deleted" };
		const app = credentialMutationHarness(credential, [
			{ data: null, error: { message: "injected lost response after commit" } },
			{ data: success, error: null },
		]);
		const response = await app.request();

		expect(response.status).toBe(200);
		if (credential.action === "create" || credential.action === "renew") {
			const secret = response.body[credential.secret];
			expect(secret).toEqual(expect.any(String));
			const sentHash = app.calls[0]!.args.p_key_hash ?? app.calls[0]!.args.p_token_hash ?? app.calls[0]!.args.p_new_hash;
			expect(createHash("sha256").update(secret as string).digest("hex")).toBe(sentHash);
			expect(app.calls[1]!.args.p_key_hash ?? app.calls[1]!.args.p_token_hash ?? app.calls[1]!.args.p_new_hash)
				.toBe(sentHash);
		} else {
			expect(response.body[credential.secret]).toBeUndefined();
			expect(app.calls[1]!.args).toEqual(app.calls[0]!.args);
		}
		expect(app.directCredentialWrites).toBe(0);
	});
});

describe("bounded rotation window", () => {
	const now = Date.parse("2026-09-15T00:00:00.000Z");
	const presentedKey = "aidr_live_retired_secret";
	const retiredHash = createHash("sha256").update(presentedKey).digest("hex");
	const retiredExpiry = new Date(now + 60_000).toISOString();
	const rotatedRow = {
		user_id: "user-1",
		tenant_id: "tenant-1",
		agent_id: "agent-1",
		revoked: false,
		scope: "tenant",
		previous_hash: retiredHash,
		previous_hash_expires_at: retiredExpiry,
	};

	it("keeps the previous secret usable only inside the overlap window", async () => {
		const { client, queries } = keyDatabase(rotatedRow);

		await expect(authenticateTenantApiKey(client, presentedKey, now)).resolves.toEqual({
			ok: true,
			userId: "user-1",
			tenantId: "tenant-1",
			agentId: "agent-1",
			scope: "tenant",
			installLimit: null,
		});
		// The window closes exactly at its recorded deadline.
		await expect(
			authenticateTenantApiKey(client, presentedKey, Date.parse(retiredExpiry)),
		).resolves.toEqual({ ok: false, status: 401, error: "invalid_api_key" });
		await expect(
			authenticateTenantApiKey(client, presentedKey, Date.parse(retiredExpiry) + 1),
		).resolves.toEqual({ ok: false, status: 401, error: "invalid_api_key" });

		expect(queries.some((query) => query.table === "api_keys" && query.filters.previous_hash === retiredHash)).toBe(true);
	});

	it("refuses an unknown token instead of falling back to a retired hash", async () => {
		const { client, queries } = keyDatabase(rotatedRow);
		await expect(authenticateTenantApiKey(client, "aidr_live_never_issued", now)).resolves.toEqual({
			ok: false,
			status: 401,
			error: "invalid_api_key",
		});
		expect(
			queries.some(
				(query) =>
					query.table === "api_keys" &&
					query.filters.previous_hash ===
						createHash("sha256").update("aidr_live_never_issued").digest("hex"),
			),
		).toBe(true);
	});

	it("never rotates to a window longer than the retired secret's own validity", () => {
		expect(rotationPlan(now, 24, null)).toEqual({
			rotatedAt: new Date(now).toISOString(),
			previousHashExpiresAt: new Date(now + 24 * 60 * 60 * 1000).toISOString(),
		});
		expect(boundedOverlapHours("0")).toBe(1);
		expect(boundedOverlapHours("9999")).toBe(168);
		expect(boundedOverlapHours("not-a-number")).toBe(24);

		const ownExpiry = new Date(now + 300_000).toISOString();
		expect(rotationPlan(now, 168, ownExpiry).previousHashExpiresAt).toBe(ownExpiry);
		// A secret that is already dead has nothing to overlap.
		expect(rotationPlan(now, 24, new Date(now - 1).toISOString()).previousHashExpiresAt).toBeNull();
		expect(rotationPlan(now, 24, "not-a-timestamp").previousHashExpiresAt).toBeNull();
	});

	it("matches a retired hash only when it is the recorded predecessor", () => {
		const expiresAt = new Date(2_000_000).toISOString();
		const recorded = { previous_hash: "b".repeat(64), previous_hash_expires_at: expiresAt };
		expect(retiredSecretActive(recorded, "b".repeat(64), 1_000)).toBe(true);
		expect(retiredSecretActive(recorded, "b".repeat(64), 2_000_000)).toBe(false);
		expect(retiredSecretActive(recorded, "b".repeat(64), 2_000_001)).toBe(false);
		expect(retiredSecretActive(recorded, "c".repeat(64), 1_000)).toBe(false);
		expect(retiredSecretActive(null, "b".repeat(64), 1_000)).toBe(false);
		expect(retiredSecretActive({ previous_hash: "b".repeat(64) }, "b".repeat(64), 1_000)).toBe(false);
	});
});

describe("renewal action contract", () => {
	it("records the retired hash with a bounded, database-enforced window", () => {
		for (const table of ["api_keys", "enrollment_tokens"]) {
			expect(ROTATION_MIGRATION).toContain("add column if not exists previous_hash text");
			expect(ROTATION_MIGRATION).toContain("add column if not exists previous_hash_expires_at timestamptz");
			expect(ROTATION_MIGRATION).toContain("add column if not exists rotated_at timestamptz");
			expect(ROTATION_MIGRATION).toContain(`${table}_rotation_window_check`);
		}
		expect(ROTATION_MIGRATION).toContain("previous_hash ~ '^[a-f0-9]{64}$'");
		expect(ROTATION_MIGRATION).toContain("previous_hash_expires_at > rotated_at");
		expect(ROTATION_MIGRATION).toContain("previous_hash_expires_at <= rotated_at + interval '7 days'");

		// The exchange accepts the retired hash only inside its window and never
		// lets it shadow the active hash.
		expect(EXCHANGE_RPC).toContain("t.previous_hash = p_token_hash");
		expect(EXCHANGE_RPC).toContain("t.previous_hash_expires_at > now()");
		expect(EXCHANGE_RPC).toContain("order by (t.token_hash = p_token_hash) desc");
		expect(EXCHANGE_RPC.indexOf("t.token_hash = p_token_hash")).toBeLessThan(
			EXCHANGE_RPC.indexOf("t.previous_hash = p_token_hash"),
		);
		expect(EXCHANGE_RPC).toContain("for update;");
		expect(EXCHANGE_RPC).toContain("v_token.consumed_at is not null or v_token.expires_at <= now()");
		expect(EXCHANGE_RPC).toContain("public.register_agent_for_ingest(");
		expect(EXCHANGE_RPC).toContain("if v_agent.seat_exceeded then");
		expect(EXCHANGE_RPC.indexOf("insert into public.api_keys")).toBeGreaterThan(0);
		expect(EXCHANGE_RPC.indexOf("update public.enrollment_tokens set consumed_at")).toBeGreaterThan(
			EXCHANGE_RPC.indexOf("insert into public.api_keys"),
		);
		expect(ROTATION_MIGRATION).toContain(
			"grant execute on function public.exchange_enrollment_token(text, text, text, text, text) to service_role",
		);
	});

	it("scopes a renewal to the tenant and refuses an unknown or spent credential", () => {
		const apiKeyRenewal = renewalBranch(apiKeysSource);
		const tokenRenewal = renewalBranch(enrollmentTokensSource);

		expect(apiKeysSource).toContain('["create", "revoke", "renew"]');
		expect(enrollmentTokensSource).toContain('["create", "delete", "renew"]');

		expect(apiKeyRenewal).toContain('.eq("tenant_id", tenant.id)');
		expect(apiKeyRenewal).toContain('{ error: "key_not_found_or_not_owned" }');
		expect(apiKeyRenewal).toContain('{ error: "key_revoked" }');
		expect(apiKeyRenewal).toContain('rpc("renew_api_key_with_audit"');
		expect(apiKeyRenewal).toContain("p_expected_hash: currentHash");
		expect(apiKeyRenewal).toContain("p_overlap_hours: overlapHours");
		expect(apiKeyRenewal).toContain("rateLimitCreate(");
		expect(apiKeyRenewal).not.toContain("revoked: false");

		expect(tokenRenewal).toContain('.eq("tenant_id", tenantId)');
		expect(tokenRenewal).toContain('{ error: "token_not_found_or_not_owned" }');
		expect(tokenRenewal).toContain('{ error: "token_already_consumed" }');
		expect(tokenRenewal).toContain('rpc("renew_enrollment_token_with_audit"');
		expect(tokenRenewal).toContain("p_expected_hash: currentHash");
		expect(tokenRenewal).toContain("p_ttl_hours: ttlHours");
		expect(tokenRenewal).toContain("rateLimitCreate(");
		expect(tokenRenewal).not.toContain("consumed_at: null");

		// The identity barrier still precedes the new action, and the renewal is
		// audited like every other credential lifecycle change.
		expect(apiKeysSource.indexOf("checkIdentityBarrier(")).toBeLessThan(apiKeysSource.indexOf('"renew"'));
		expect(enrollmentTokensSource.indexOf("checkIdentityBarrier(")).toBeLessThan(
			enrollmentTokensSource.indexOf('"renew"'),
		);
		expect(ATOMIC_CREDENTIAL_MIGRATION).toContain("'api_key.renew'");
		expect(ATOMIC_CREDENTIAL_MIGRATION).toContain("'enrollment_token.renew'");
	});

	it("surfaces the authorization window without adding an auto-approval or bypass", () => {
		expect(verifySource).toContain("expires_at: session.expires_at");
		for (const source of [apiKeysSource, enrollmentTokensSource, ROTATION_MIGRATION]) {
			expect(source).not.toMatch(/auto.?approv|bypass/i);
		}
	});
});

describe("credential list and audit ownership contract", () => {
	it("limits non-admin credential lists to rows they own", () => {
		for (const source of [apiKeysSource, enrollmentTokensSource]) {
			const listBranch = source.split('if (req.method === "GET")')[1]?.split('if (req.method === "POST")')[0] ?? "";
			expect(listBranch).toContain('if (!["owner", "admin"].includes(tenant.role)) query = query.eq("user_id", userId)');
		}
	});

	it("keeps every credential mutation behind its atomic audit RPC", () => {
		const keyCreate = apiKeysSource.split("// create")[1] ?? "";
		const tokenCreate = enrollmentTokensSource.split("// create")[1] ?? "";
		const keyRevoke = apiKeysSource.split('if (action === "revoke")')[1]?.split("// renew")[0] ?? "";
		const tokenDelete = enrollmentTokensSource.split('if (action === "delete")')[1]?.split("// renew")[0] ?? "";
		for (const [source, fn, branch] of [
			[apiKeysSource, "issue_api_key_with_audit", keyCreate],
			[apiKeysSource, "renew_api_key_with_audit", renewalBranch(apiKeysSource)],
			[apiKeysSource, "revoke_api_key_with_audit", keyRevoke],
			[enrollmentTokensSource, "issue_enrollment_token_with_audit", tokenCreate],
			[enrollmentTokensSource, "renew_enrollment_token_with_audit", renewalBranch(enrollmentTokensSource)],
			[enrollmentTokensSource, "delete_enrollment_token_with_audit", tokenDelete],
		] as const) {
			expect(source).toContain(`rpc("${fn}"`);
			expect(branch).toContain('if (!mutation || mutation.error) return corsJson(req, 503, { error: "audit_unavailable" });');
		}
		expect(keyCreate).not.toContain(".insert(");
		expect(keyRevoke).not.toContain(".update(");
		expect(renewalBranch(apiKeysSource)).not.toContain(".update(");
		expect(tokenCreate).not.toContain(".insert(");
		expect(tokenDelete).not.toContain(".delete(");
		expect(renewalBranch(enrollmentTokensSource)).not.toContain(".update(");
	});

	it("commits each credential mutation and audit row in the same restricted RPC", () => {
		for (const [name, mutation] of [
			["issue_api_key_with_audit", "insert into public.api_keys"],
			["renew_api_key_with_audit", "update public.api_keys set"],
			["revoke_api_key_with_audit", "update public.api_keys set revoked = true"],
			["issue_enrollment_token_with_audit", "insert into public.enrollment_tokens"],
			["renew_enrollment_token_with_audit", "update public.enrollment_tokens set"],
			["delete_enrollment_token_with_audit", "delete from public.enrollment_tokens"],
		] as const) {
			const fn = atomicFunction(name);
			const mutationAt = fn.indexOf(mutation);
			const auditAt = fn.indexOf("insert into public.admin_audit_logs");
			expect(mutationAt).toBeGreaterThanOrEqual(0);
			expect(auditAt).toBeGreaterThan(mutationAt);
			expect(fn).not.toContain("when others");
			expect(fn.slice(auditAt)).not.toMatch(/\bexception\b/);
			expect(ATOMIC_CREDENTIAL_MIGRATION).toContain(`grant execute on function public.${name}`);
		}
		expect(ATOMIC_CREDENTIAL_MIGRATION).toContain("'api_key.renew', v_key.user_id");
		expect(ATOMIC_CREDENTIAL_MIGRATION).toContain("'enrollment_token.renew', v_token.user_id");
		expect(ATOMIC_CREDENTIAL_MIGRATION).toContain("p_key_hash text");
		expect(ATOMIC_CREDENTIAL_MIGRATION).toContain("p_token_hash text");
		expect(atomicFunction("issue_api_key_with_audit")).toContain("where key_hash = p_key_hash");
		expect(atomicFunction("issue_enrollment_token_with_audit")).toContain("where token_hash = p_token_hash");
		expect(atomicFunction("renew_api_key_with_audit")).toContain("v_key.key_hash = p_new_hash");
		expect(atomicFunction("renew_enrollment_token_with_audit")).toContain("v_token.token_hash = p_new_hash");
		expect(atomicFunction("revoke_api_key_with_audit")).toContain("'api_key.revoke', v_key.user_id");
		expect(atomicFunction("delete_enrollment_token_with_audit")).toContain("'enrollment_token.delete', v_token.user_id");
		expect(atomicFunction("revoke_api_key_with_audit")).toContain("for update;");
		expect(atomicFunction("delete_enrollment_token_with_audit")).toContain("for update;");
		expect(atomicFunction("revoke_api_key_with_audit")).toContain("v_role <> 'member' or k.user_id = p_actor_user_id");
		expect(atomicFunction("delete_enrollment_token_with_audit")).toContain("v_role <> 'member' or e.user_id = p_actor_user_id");
		expect(ATOMIC_CREDENTIAL_MIGRATION).not.toContain("p_secret text");
	});

	it("records the credential owner, not the acting admin, as the audit target", () => {
		const keyRevoke = apiKeysSource.split('if (action === "revoke")')[1]?.split("// renew")[0] ?? "";
		const keyRenew = renewalBranch(apiKeysSource);
		const tokenDelete = enrollmentTokensSource.split('if (action === "delete")')[1]?.split("// renew")[0] ?? "";
		const tokenRenew = renewalBranch(enrollmentTokensSource);
		expect(keyRevoke).toContain('rpc("revoke_api_key_with_audit"');
		expect(tokenDelete).toContain('rpc("delete_enrollment_token_with_audit"');
		expect(ATOMIC_CREDENTIAL_MIGRATION).toContain("'api_key.renew', v_key.user_id");
		expect(ATOMIC_CREDENTIAL_MIGRATION).toContain("'enrollment_token.renew', v_token.user_id");
	});
});
