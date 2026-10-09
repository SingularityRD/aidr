import { createHash, generateKeyPairSync, verify } from "node:crypto";
import { canonicalJson } from "../../_shared/policy-signature.ts";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => { throw new Error("test must inject its database"); },
}));

const tenantId = "11111111-1111-4111-8111-111111111111";
const userId = "22222222-2222-4222-8222-222222222222";
const agentId = "33333333-3333-4333-8333-333333333333";
const commandId = "44444444-4444-4444-8444-444444444444";
const bearer = "enrolled-agent-key";
const keyHash = createHash("sha256").update(bearer).digest("hex");
const signer = generateKeyPairSync("ed25519");
const signingEnv = {
	AIDR_REVOCATION_SIGNING_KEY_ID: "fleet-test-key",
	AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64: signer.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
};
const deviceAttestation = {
	schema_version: 1,
	installation_id: "installation-001",
	key_hash: keyHash,
};

function database(options: { revoked?: boolean; accessTokenValid?: boolean; previousHashExpiresAt?: string; admission?: number; snapshot?: Record<string, unknown> | null; scope?: string; unresolvedCount?: number; budgetUnavailable?: boolean } = {}) {
	const calls: Array<{ name: string; args: Record<string, unknown> }> = [];
	const tableReads: string[] = [];
	const accessTokenChecks: string[] = [];
	const db = {
		auth: {
			getUser: async (token: string) => {
				accessTokenChecks.push(token);
				return options.accessTokenValid === true
					? { data: { user: { id: userId } }, error: null }
					: { data: { user: null }, error: { message: "invalid access token" } };
			},
			mfa: { getAuthenticatorAssuranceLevel: async () => ({ data: null, error: null }) },
		},
		from(table: string) {
			tableReads.push(table);
			const row = table === "rate_limits"
				? { count: options.unresolvedCount ?? 0 }
				: table === "api_keys"
				? { tenant_id: tenantId, user_id: userId, agent_id: agentId, revoked: options.revoked === true,
					id: "key-1",
					scope: options.scope ?? "tenant",
					install_limit: (options.scope ?? "tenant") === "tenant" ? null : 5,
					previous_hash: keyHash, previous_hash_expires_at: options.previousHashExpiresAt }
				: table === "tenant_members"
					? { role: "owner", expires_at: null }
					: table === "tenants"
						? { status: "active" }
						: { id: agentId, tenant_id: tenantId, iid: "installation-001" };
			let lookupColumn = "";
			const query = {
				eq: (column: string) => { lookupColumn = column; return query; },
				maybeSingle: async () => ({
					data: table === "api_keys" && options.previousHashExpiresAt && lookupColumn === "key_hash" ? null : row,
					error: table === "rate_limits" && options.budgetUnavailable ? { message: "budget storage unavailable" } : null,
				}),
			};
			return { select: () => query };
		},
		async rpc(name: string, args: Record<string, unknown>) {
			calls.push({ name, args });
			if (name === "increment_rate_limit") return { data: 1, error: null };
			if (name === "tenant_admission_capacity") return { data: options.admission ?? 1, error: null };
			if (name === "consume_tenant_rate_limit") {
				return { data: { allowed: true, remaining: 10 }, error: null };
			}
			if (name === "poll_bound_fleet_response_command") {
				return { data: options.snapshot === undefined ? {
					tenant_id: tenantId, agent_id: agentId, installation_id: "installation-001", key_hash: keyHash,
					command: {
					id: commandId, command_type: "agent_pause", attempts: 1,
					tenant_id: tenantId, agent_id: agentId,
					created_at: new Date().toISOString(),
					expires_at: new Date(Date.now() + 300_000).toISOString(), rollback_of: null,
					reason: "Confidential incident details", actor_user_id: userId, token: bearer,
					},
				} : options.snapshot, error: null };
			}
			return { data: {
				id: commandId,
				state: args.p_stage === "ack" ? "acknowledged" : args.p_outcome,
			}, error: null };
		},
	};
	return { db, calls, tableReads, accessTokenChecks };
}

function post(body: Record<string, unknown>, authorization: string | null = `Bearer ${bearer}`) {
	return new Request("https://project.supabase.co/functions/v1/revocations", {
		method: "POST",
		headers: {
			...(authorization ? { Authorization: authorization } : {}),
			"Content-Type": "application/json",
		},
		body: JSON.stringify(body),
	});
}

describe("fleet response device handler", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.resetModules();
	});

	it("polls, acknowledges, and reports only the enrolled agent's command", async () => {
		vi.stubGlobal("Deno", {
			env: { get: (name: string) => ({
				...signingEnv,
				SUPABASE_URL: "https://project.supabase.co",
				SUPABASE_SERVICE_ROLE_KEY: "test-service-role",
			} as Record<string, string>)[name] },
			serve: () => undefined,
		});
		const { createFleetCommandHandler } = await import("../index.ts");
		const { db, calls } = database();
		const handle = createFleetCommandHandler({ db: db as never });
		const common = { tenant_id: tenantId, device_attestation: deviceAttestation };
		const poll = await handle(post({ ...common, action: "poll" }));
		expect(poll.status).toBe(200);
		const delivery = await poll.json();
		expect(delivery).toMatchObject({
			ok: true, command_signed: { alg: "ed25519", key_id: "fleet-test-key", payload: {
				id: commandId, command_type: "agent_pause", tenant_id: tenantId, agent_id: agentId,
				installation_id: "installation-001", key_hash: keyHash, payload: {},
			} },
		});
		expect(delivery).not.toHaveProperty("command");
		expect(verify(null, Buffer.from(canonicalJson(delivery.command_signed.payload)), signer.publicKey,
			Buffer.from(delivery.command_signed.sig_b64, "base64"))).toBe(true);
		expect(JSON.stringify(delivery)).not.toContain(bearer);
		expect(JSON.stringify(delivery)).not.toContain("Confidential incident");
		expect(JSON.stringify(delivery)).not.toContain(signingEnv.AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64);
		for (const patch of [
			{ tenant_id: userId }, { agent_id: userId }, { installation_id: "other-installation" },
			{ key_hash: "a".repeat(64) }, { command_type: "network_isolate" }, { payload: { shell: "execute" } },
			{ expires_at: new Date(Date.now() + 3_600_000).toISOString() },
			{ rollback_of: userId }, { attempt: 2 }, { purpose: "aidr.runtime-policy" },
		]) {
			expect(verify(null, Buffer.from(canonicalJson({ ...delivery.command_signed.payload, ...patch })), signer.publicKey,
				Buffer.from(delivery.command_signed.sig_b64, "base64"))).toBe(false);
		}
		const ack = await handle(post({ ...common, action: "ack", command_id: commandId, outcome: "accepted" }));
		expect(await ack.json()).toEqual({ ok: true, command_id: commandId, state: "acknowledged" });
		const result = await handle(post({ ...common, action: "result", command_id: commandId, outcome: "succeeded" }));
		expect(await result.json()).toEqual({ ok: true, command_id: commandId, state: "succeeded" });
		expect(calls.filter((call) => call.name === "record_fleet_response_command")).toMatchObject([
			{ args: { p_tenant_id: tenantId, p_agent_id: agentId, p_key_hash: keyHash, p_stage: "ack" } },
			{ args: { p_tenant_id: tenantId, p_agent_id: agentId, p_key_hash: keyHash, p_stage: "result" } },
		]);
		const mismatched = await handle(post({ ...common, action: "poll", tenant_id: userId }));
		expect(mismatched.status).toBe(403);
		expect(calls.filter((call) => call.name === "poll_bound_fleet_response_command")).toHaveLength(1);
		expect(calls.some((call) => call.name === "increment_rate_limit")).toBe(false);
	});

	it.each([
		{ unresolvedCount: 6000, status: 429, error: "rate_limited" },
		{ budgetUnavailable: true, status: 503, error: "rate_limit_unavailable" },
	])("refuses device requests before credential lookup when the unresolved budget returns $error", async (options) => {
		vi.stubGlobal("Deno", {
			env: { get: (name: string) => ({ ...signingEnv,
				AIDR_UNRESOLVED_API_KEY_RL_PER_MIN: "6000",
				SUPABASE_URL: "https://project.supabase.co", SUPABASE_SERVICE_ROLE_KEY: "test-service-role",
			} as Record<string, string>)[name] }, serve: () => undefined,
		});
		const { createFleetCommandHandler } = await import("../index.ts");
		const { db, calls, tableReads } = database(options);
		const handle = createFleetCommandHandler({ db: db as never });
		for (const action of ["poll", "ack", "result"]) {
			const response = await handle(post({ action, device_attestation: deviceAttestation,
				command_id: commandId, outcome: action === "ack" ? "accepted" : "succeeded" }));
			expect(response.status).toBe(options.status);
			expect(await response.json()).toEqual({ error: options.error });
		}
		expect(tableReads).toEqual(["rate_limits", "rate_limits", "rate_limits"]);
		expect(calls).toEqual([]);
	});

	it.each(["missing", "half", "invalid"])("fails %s signing setup before leasing a command", async (mode) => {
		const env: Record<string, string> = {
			SUPABASE_URL: "https://project.supabase.co", SUPABASE_SERVICE_ROLE_KEY: "test-service-role",
			...(mode === "missing" ? {} : { AIDR_REVOCATION_SIGNING_KEY_ID: "fleet-test-key" }),
			...(mode === "invalid" ? { AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64: "invalid-key" } : {}),
		};
		vi.stubGlobal("Deno", { env: { get: (name: string) => env[name] }, serve: () => undefined });
		const { createFleetCommandHandler } = await import("../index.ts");
		const { db, calls } = database();
		const handle = createFleetCommandHandler({ db: db as never });
		const response = await handle(post({ action: "poll", device_attestation: deviceAttestation }));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "fleet_command_signing_unavailable" });
		expect(calls.some(call => call.name === "poll_bound_fleet_response_command")).toBe(false);
	});

	it("refuses malformed or mismatched locked snapshots and signs no sensitive row fields", async () => {
		vi.stubGlobal("Deno", { env: { get: (name: string) => ({ ...signingEnv,
			SUPABASE_URL: "https://project.supabase.co", SUPABASE_SERVICE_ROLE_KEY: "test-service-role",
		} as Record<string, string>)[name] }, serve: () => undefined });
		const { createFleetCommandHandler } = await import("../index.ts");
		const row = { id: commandId, tenant_id: tenantId, agent_id: agentId, command_type: "agent_pause",
			attempts: 1, rollback_of: null, created_at: new Date().toISOString(),
			expires_at: new Date(Date.now() + 300_000).toISOString() };
		const snapshot = { tenant_id: tenantId, agent_id: agentId, installation_id: "installation-001", key_hash: keyHash, command: row };
		for (const invalid of [
			null, { ...snapshot, key_hash: "a".repeat(64) }, { ...snapshot, installation_id: "other-device" },
			{ ...snapshot, command: { ...row, tenant_id: userId } },
			{ ...snapshot, command: { ...row, agent_id: userId } },
			{ ...snapshot, command: { ...row, command_type: "shell_exec" } },
			{ ...snapshot, command: { ...row, attempts: 0 } },
			{ ...snapshot, command: { ...row, attempts: 6 } },
			{ ...snapshot, command: { ...row, rollback_of: userId } },
			{ ...snapshot, command: { ...row, command_type: "agent_resume" } },
			{ ...snapshot, command: { ...row, created_at: new Date(Date.now() + 120_000).toISOString() } },
			{ ...snapshot, command: { ...row, expires_at: new Date(Date.now() + 3_601_000).toISOString() } },
			{ ...snapshot, command: { ...row, expires_at: "2000-01-01" } },
		]) {
			const { db } = database({ snapshot: invalid });
			const response = await createFleetCommandHandler({ db: db as never })(post({ action: "poll", device_attestation: deviceAttestation }));
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: "fleet_command_binding_unavailable" });
		}
		const { db } = database({ snapshot: { ...snapshot, command: null } });
		const idle = await createFleetCommandHandler({ db: db as never })(post({ action: "poll", device_attestation: deviceAttestation }));
		expect(await idle.json()).toEqual({ ok: true, command_signed: null });
	});

	it("rejects a revoked device credential before poll or result state can change", async () => {
		vi.stubGlobal("Deno", {
			env: { get: (name: string) => ({
				...signingEnv,
				SUPABASE_URL: "https://project.supabase.co",
				SUPABASE_SERVICE_ROLE_KEY: "test-service-role",
			} as Record<string, string>)[name] },
			serve: () => undefined,
		});
		const { createFleetCommandHandler } = await import("../index.ts");
		const { db, calls } = database({ revoked: true });
		const handle = createFleetCommandHandler({ db: db as never });
		const common = { tenant_id: tenantId, device_attestation: deviceAttestation };

		for (const body of [
			{ ...common, action: "poll" },
			{ ...common, action: "result", command_id: commandId, outcome: "succeeded" },
		]) {
			const response = await handle(post(body));
			expect(response.status).toBe(401);
			expect(await response.json()).toEqual({ error: "invalid_api_key" });
		}
		expect(calls).toEqual(Array.from({ length: 2 }, () => ({
			name: "increment_rate_limit",
			args: { p_key: "api-key:v1:unresolved:fleet-response", p_window_start: expect.any(Number), p_delta: 1 },
		})));
	});

	it("preserves the presented retired hash for attestation and atomic RPC expiry rechecks", async () => {
		vi.stubGlobal("Deno", {
			env: { get: (name: string) => ({ ...signingEnv, SUPABASE_URL: "https://project.supabase.co", SUPABASE_SERVICE_ROLE_KEY: "test-service-role" } as Record<string, string>)[name] },
			serve: () => undefined,
		});
		const { createFleetCommandHandler } = await import("../index.ts");
		const { db, calls } = database({ previousHashExpiresAt: new Date(Date.now() + 60_000).toISOString() });
		const handle = createFleetCommandHandler({ db: db as never });
		const response = await handle(post({ action: "poll", device_attestation: deviceAttestation }));
		expect(response.status).toBe(200);
		expect(calls.find((call) => call.name === "poll_bound_fleet_response_command")?.args)
			.toEqual({ p_key_hash: keyHash, p_tenant_id: tenantId, p_agent_id: agentId, p_installation_id: "installation-001" });
		for (const options of [
			{ previousHashExpiresAt: "2000-01-01T00:00:00.000Z" },
			{ previousHashExpiresAt: new Date(Date.now() + 60_000).toISOString(), revoked: true },
			{ admission: 0 },
		]) {
			const refused = database(options);
			const refusedHandler = createFleetCommandHandler({ db: refused.db as never });
			const denied = await refusedHandler(post({ action: "poll", device_attestation: deviceAttestation }));
			expect(denied.status).toBe(options.admission === 0 ? 403 : 401);
			expect(refused.calls.some((call) => call.name === "poll_bound_fleet_response_command")).toBe(false);
		}
	});

	it("refuses an ingest-only Browser Guard key before poll or result state can change", async () => {
		vi.stubGlobal("Deno", {
			env: { get: (name: string) => ({
				SUPABASE_URL: "https://project.supabase.co",
				SUPABASE_SERVICE_ROLE_KEY: "test-service-role",
			} as Record<string, string>)[name] },
			serve: () => undefined,
		});
		const { createFleetCommandHandler } = await import("../index.ts");
		const { db, calls } = database({ scope: "ingest:browser_guard" });
		const handle = createFleetCommandHandler({ db: db as never });
		const common = { tenant_id: tenantId, device_attestation: deviceAttestation };

		for (const body of [
			{ ...common, action: "poll" },
			{ ...common, action: "result", command_id: commandId, outcome: "succeeded" },
		]) {
			const response = await handle(post(body));
			expect(response.status).toBe(403);
			expect(await response.json()).toEqual({ error: "api_key_scope_denied" });
		}
		expect(calls).toEqual([]);
	});

	it.each([
		["missing", null, "missing_access_token", 0],
		["invalid", "Bearer expired-human-session", "invalid_access_token", 1],
	] as const)("rejects %s human credentials before operator reads or mutations", async (_kind, authorization, error, expectedAuthChecks) => {
		vi.stubGlobal("Deno", {
			env: { get: (name: string) => ({
				...signingEnv,
				SUPABASE_URL: "https://project.supabase.co",
				SUPABASE_SERVICE_ROLE_KEY: "test-service-role",
			} as Record<string, string>)[name] },
			serve: () => undefined,
		});
		const { createFleetCommandHandler } = await import("../index.ts");
		const { db, calls, tableReads, accessTokenChecks } = database();
		const handle = createFleetCommandHandler({ db: db as never });
		const response = await handle(post({ action: "queue", tenant_id: tenantId }, authorization));

		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error });
		expect(accessTokenChecks).toHaveLength(expectedAuthChecks);
		expect(tableReads).toEqual([]);
		expect(calls).toEqual([]);
	});
});
