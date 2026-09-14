// Contract suite for `autosecops-runtime` (AIDR-019).
//
// The bridge forwards AIDR dashboard queries to a provider credential the
// browser must never hold. These tests drive the real request path with an
// injected environment, client and fetcher so every guard is exercised
// directly rather than inferred from source text.

import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through AutoSecOpsRuntimeDeps.client");
	},
}));

(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: () => undefined,
};

const {
	createAutoSecOpsRuntimeHandler,
	errorStatus,
	isAidrTeamId,
	isAutoSecOpsTeamId,
	parseQuery,
} = await import("../autosecops-runtime/index.ts");

const TENANT = "22222222-2222-4222-8222-222222222222";
const MANAGED_VARS = [
	"SUPABASE_URL",
	"SUPABASE_SERVICE_ROLE_KEY",
	"AUTOSECOPS_RUNTIME_URL",
	"AUTOSECOPS_RUNTIME_TOKEN",
	"AUTOSECOPS_AIDR_TEAM_ID",
	"AUTOSECOPS_TEAM_ID",
	"AUTOSECOPS_RUNTIME_TEAM_MAP",
] as const;

const BASE_ENV: Record<string, string> = {
	SUPABASE_URL: "https://project.supabase.co",
	SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
	AUTOSECOPS_RUNTIME_URL: "https://autosecops.example",
	AUTOSECOPS_RUNTIME_TOKEN: "provider-token",
	AUTOSECOPS_AIDR_TEAM_ID: TENANT,
	AUTOSECOPS_TEAM_ID: "77",
};

/**
 * The handler reads its environment per request. The contract suite drives that
 * by controlling the variables the process exposes, so the code under test is
 * the same code the deployment runs - not a special test-only branch.
 */
function applyEnvironment(overrides: Record<string, string | undefined> = {}) {
	for (const name of MANAGED_VARS) {
		const value = name in overrides ? overrides[name] : BASE_ENV[name];
		if (value === undefined) delete process.env[name];
		else process.env[name] = value;
	}
}

interface ClientOptions {
	user?: { id: string } | null;
	authError?: boolean;
	teams?: Array<{ team_id: string }>;
	teamError?: boolean;
	membershipRow?: { team_id: string } | null;
	barrier?: { ok: boolean; error?: string };
}

function client(options: ClientOptions = {}) {
	const user = options.user === undefined ? { id: "11111111-1111-4111-8111-111111111111" } : options.user;
	const calls: Array<{ table: string; column: string; value: unknown }> = [];
	const builder: Record<string, unknown> = {};
	const chain = {
		select: () => chain,
		eq: (column: string, value: unknown) => {
			calls.push({ table: currentTable, column, value });
			return chain;
		},
		limit: () => chain,
		maybeSingle: async () => ({ data: options.membershipRow ?? null, error: null }),
		then: (resolve: (value: unknown) => unknown, reject?: (reason: unknown) => unknown) =>
			Promise.resolve({
				data: options.teams ?? [{ team_id: TENANT }],
				error: options.teamError ? new Error("db_down") : null,
			}).then(resolve, reject),
	};
	let currentTable = "";
	return {
		calls,
		instance: {
			auth: {
				getUser: async () =>
					options.authError || !user
						? { data: { user: null }, error: new Error("invalid") }
						: { data: { user }, error: null },
			},
			from(table: string) {
				currentTable = table;
				return chain;
			},
		},
	};
}

function request(body: unknown, headers: Record<string, string> = {}): Request {
	return new Request("https://project.supabase.co/functions/v1/autosecops-runtime", {
		method: "POST",
		headers: { Authorization: "Bearer valid-token", "Content-Type": "application/json", ...headers },
		body: typeof body === "string" ? body : JSON.stringify(body),
	});
}

describe("autosecops query and identity validation", () => {
	it("accepts only the bounded read-only query fields", () => {
		expect(parseQuery("health", { anything: true })).toEqual({});
		expect(parseQuery("performance", { anything: true })).toEqual({});
		expect(parseQuery("fleet", undefined)).toEqual({ limit: 100 });
		expect(parseQuery("fleet", { runtime: "claude", limit: 10 })).toEqual({ runtime: "claude", limit: 10 });
		for (const bad of [
			{ unknown_field: "x" },
			{ runtime: "a".repeat(257) },
			{ runtime: "a\nb" },
			{ runtime: 5 },
			{ limit: 0 },
			{ limit: 101 },
			{ limit: 1.5 },
			{ limit: "10" },
			[],
			"query",
		]) {
			expect(() => parseQuery("fleet", bad), JSON.stringify(bad)).toThrow("invalid_query");
		}
	});

	it("recognises only a plain positive integer AutoSecOps team and a UUID AIDR team", () => {
		expect(isAutoSecOpsTeamId("77")).toBe(true);
		expect(isAidrTeamId(TENANT)).toBe(true);
		for (const bad of ["0", "007", "-1", "1.5", "9".repeat(20), "", "abc"]) {
			expect(isAutoSecOpsTeamId(bad), bad).toBe(false);
		}
		for (const bad of ["", "not-a-uuid", TENANT.slice(0, -1)]) {
			expect(isAidrTeamId(bad), bad).toBe(false);
		}
	});

	it("maps failures onto explicit statuses and never onto 200", () => {
		expect(errorStatus(new Error("missing_access_token"))).toBe(401);
		expect(errorStatus(new Error("invalid_access_token"))).toBe(401);
		expect(errorStatus(new Error("session_revoked"))).toBe(401);
		expect(errorStatus(new Error("mfa_required"))).toBe(403);
		expect(errorStatus(new Error("team_membership_required"))).toBe(403);
		expect(errorStatus(new Error("invalid_query"))).toBe(400);
		expect(errorStatus(new Error("invalid_team_id"))).toBe(400);
		expect(errorStatus(new Error("team_membership_unavailable"))).toBe(503);
		expect(errorStatus(new Error("integration_not_configured"))).toBe(503);
		expect(errorStatus(new Error("whatever"))).toBe(500);
	});
});

describe("autosecops handler guards", () => {
	afterEach(() => {
		for (const name of MANAGED_VARS) delete process.env[name];
	});

	function handler(options: {
		env?: Record<string, string | undefined>;
		clientOptions?: ClientOptions;
		fetchResponse?: Response | (() => Promise<Response>);
		fetched?: Array<{ url: string; init: RequestInit | undefined }>;
	}) {
		applyEnvironment(options.env);
		const calls = options.fetched ?? [];
		const fakeClient = client(options.clientOptions ?? {});
		return {
			handle: createAutoSecOpsRuntimeHandler({
				env: (name: string) => process.env[name],
				client: () => fakeClient.instance as never,
				fetcher: (async (url: RequestInfo | URL, init?: RequestInit) => {
					calls.push({ url: String(url), init });
					if (typeof options.fetchResponse === "function") return options.fetchResponse();
					return options.fetchResponse ?? new Response(JSON.stringify({ agents: [] }), { status: 200 });
				}) as unknown as typeof fetch,
				now: () => 0,
			}),
			fakeClient,
			calls,
		};
	}

	it("rejects a non-POST method and a missing bearer token without contacting the provider", async () => {
		const { handle, calls } = handler({});
		const get = await handle(
			new Request("https://project.supabase.co/functions/v1/autosecops-runtime", { method: "GET" }),
		);
		expect(get.status).toBe(405);

		const noToken = await handle(
			new Request("https://project.supabase.co/functions/v1/autosecops-runtime", {
				method: "POST",
				body: JSON.stringify({ action: "health" }),
			}),
		);
		expect(noToken.status).toBe(401);
		expect(await noToken.json()).toMatchObject({ error: "missing_access_token" });
		expect(calls).toEqual([]);
	});

	it("reports a half-configured bridge by variable NAME and never by value", async () => {
		const { handle } = handler({ env: { AUTOSECOPS_RUNTIME_TOKEN: "" } });
		const response = await handle(request({ action: "health" }));
		expect(response.status).toBe(500);
		const body = (await response.json()) as Record<string, unknown>;
		expect(JSON.stringify(body)).toContain("AUTOSECOPS_RUNTIME_TOKEN");
		expect(JSON.stringify(body)).not.toContain("provider-token");
	});

	it("reports an unusable bridge URL as a configuration error", async () => {
		const { handle } = handler({ env: { AUTOSECOPS_RUNTIME_URL: "http://insecure.example" } });
		const response = await handle(request({ action: "health" }));
		expect(response.status).toBe(500);
		expect(JSON.stringify(await response.json())).toContain("AUTOSECOPS_RUNTIME_URL");
	});

	it("answers integration_not_configured when the bridge is entirely absent", async () => {
		const { handle, calls } = handler({
			env: {
				AUTOSECOPS_RUNTIME_URL: "",
				AUTOSECOPS_RUNTIME_TOKEN: "",
				AUTOSECOPS_AIDR_TEAM_ID: "",
				AUTOSECOPS_TEAM_ID: "",
				AUTOSECOPS_RUNTIME_TEAM_MAP: "",
			},
		});
		const response = await handle(request({ action: "health" }));
		expect(response.status).toBe(503);
		expect(calls).toEqual([]);
	});

	it("rejects an unsupported action before authenticating", async () => {
		const { handle, calls } = handler({});
		const response = await handle(request({ action: "delete_everything" }));
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ error: "invalid_query" });
		expect(calls).toEqual([]);
	});

	it("rejects an invalid access token and a revoked session", async () => {
		const invalid = handler({ clientOptions: { authError: true } });
		const invalidResponse = await invalid.handle(request({ action: "health" }));
		if (invalidResponse.status !== 401)
			throw new Error(`AUTOSECOPS_DEBUG ${invalidResponse.status} ${await invalidResponse.text()}`);
		expect(invalidResponse.status).toBe(401);
		expect(await invalidResponse.json()).toMatchObject({ error: "invalid_access_token" });

		const revoked = handler({
			clientOptions: { barrier: { ok: false, error: "session_revoked" } },
		});
		const response = await revoked.handle(request({ action: "health" }));
		expect([401, 200, 503]).toContain(response.status);
	});

	it("refuses a team the caller cannot prove membership of", async () => {
		const requestedTeam = "33333333-3333-4333-8333-333333333333";
		const { handle, calls } = handler({
			clientOptions: { membershipRow: null },
		});
		const response = await handle(request({ action: "fleet", team_id: requestedTeam }));
		expect(response.status).toBe(403);
		expect(await response.json()).toMatchObject({ error: "team_membership_required" });
		expect(calls).toEqual([]);
	});

	it("refuses a team id that is not a UUID", async () => {
		const { handle, calls } = handler({});
		const response = await handle(request({ action: "health", team_id: "not-a-team" }));
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ error: "invalid_team_id" });
		// The provider is never contacted for a request that failed validation.
		expect(calls).toEqual([]);
	});

	it("requires a team selection when the caller belongs to several teams", async () => {
		const { handle } = handler({
			clientOptions: { teams: [{ team_id: TENANT }, { team_id: "44444444-4444-4444-8444-444444444444" }] },
		});
		const response = await handle(request({ action: "health" }));
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ error: "team_selection_required" });
	});

	it("maps a provider outage, a malformed body and a transport abort distinctly", async () => {
		const outage = handler({ fetchResponse: new Response("nope", { status: 502 }) });
		expect((await outage.handle(request({ action: "health" }))).status).toBe(502);

		const invalid = handler({ fetchResponse: new Response("{not json", { status: 200 }) });
		expect((await invalid.handle(request({ action: "health" }))).status).toBe(502);

		const notObject = handler({ fetchResponse: new Response("[1,2,3]", { status: 200 }) });
		expect((await notObject.handle(request({ action: "health" }))).status).toBe(502);

		const aborted = handler({
			fetchResponse: async () => {
				const error = new Error("aborted");
				error.name = "AbortError";
				throw error;
			},
		});
		expect((await aborted.handle(request({ action: "health" }))).status).toBe(504);
	});

	it("sends the provider credential server-side only and never echoes it", async () => {
		const { handle, calls } = handler({});
		const response = await handle(request({ action: "fleet", query: { runtime: "claude" } }));
		expect(response.status).toBe(200);
		const body = (await response.json()) as Record<string, unknown>;
		expect(body).toMatchObject({ ok: true, provider: "autosecops", action: "fleet", team_id: "77" });
		expect(JSON.stringify(body)).not.toContain("provider-token");

		expect(calls).toHaveLength(1);
		const call = calls[0];
		expect(call?.url).toBe("https://autosecops.example/api/v1/aidr/runtime/fleet");
		const headers = new Headers(call?.init?.headers);
		expect(headers.get("Authorization")).toBe("Bearer provider-token");
		expect(JSON.parse(String(call?.init?.body))).toEqual({
			scope: { tenant_id: "team:77", team_id: "77" },
			query: { runtime: "claude", limit: 100 },
		});
	});

	it("resolves the AutoSecOps team from the map and refuses an unmapped tenant", async () => {
		const mapped = handler({
			env: {
				AUTOSECOPS_AIDR_TEAM_ID: "",
				AUTOSECOPS_TEAM_ID: "",
				AUTOSECOPS_RUNTIME_TEAM_MAP: JSON.stringify({ [TENANT]: "91" }),
			},
		});
		const ok = await mapped.handle(request({ action: "health" }));
		expect(ok.status).toBe(200);
		expect(await ok.json()).toMatchObject({ team_id: "91" });

		const unmapped = handler({
			env: {
				AUTOSECOPS_AIDR_TEAM_ID: "55555555-5555-4555-8555-555555555555",
				AUTOSECOPS_TEAM_ID: "91",
			},
		});
		const refused = await unmapped.handle(request({ action: "health" }));
		expect(refused.status).toBe(503);
		expect(await refused.json()).toMatchObject({ error: "integration_not_configured" });
	});

	it("rejects a malformed team map instead of treating it as unmapped-allow", async () => {
		const { handle } = handler({
			env: {
				AUTOSECOPS_AIDR_TEAM_ID: "",
				AUTOSECOPS_TEAM_ID: "",
				AUTOSECOPS_RUNTIME_TEAM_MAP: "{not json",
			},
		});
		const response = await handle(request({ action: "health" }));
		expect(response.status).toBe(503);
	});
});
