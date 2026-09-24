import { afterEach, describe, expect, it, vi } from "vitest";

const runtime = vi.hoisted(() => ({
	db: null as unknown,
	handler: null as unknown,
}));

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: () => runtime.db }));

const TENANT = "11111111-1111-4111-8111-111111111111";
const env: Record<string, string> = {
	SUPABASE_URL: "https://project.supabase.co",
	SUPABASE_SERVICE_ROLE_KEY: "synthetic-service-role",
	AIDR_DELEGATION_ISSUER: "https://control.example.test",
	AIDR_DELEGATION_SIGNING_KEY_ID: "test-key",
	AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64: "unused-private-key",
	AIDR_DELEGATION_SIGNING_PUBLIC_KEY_SPKI_B64: "unused-public-key",
};

function database() {
	const calls: string[] = [];
	return {
		calls,
		db: {
			auth: {
				getUser: async () => {
					calls.push("auth.getUser");
					return { data: { user: null }, error: { message: "invalid access token" } };
				},
			},
			from: (table: string) => {
				calls.push(`from:${table}`);
				throw new Error("unauthorized route must not read service-role tables");
			},
			rpc: (name: string) => {
				calls.push(`rpc:${name}`);
				throw new Error("unauthorized route must not call service-role RPCs");
			},
		},
	};
}

async function handler(db: unknown) {
	runtime.db = db;
	runtime.handler = null;
	vi.stubGlobal("Deno", {
		env: { get: (name: string) => env[name] },
		serve: (route: unknown) => { runtime.handler = route; },
	});
	vi.resetModules();
	await import("../index.ts");
	return runtime.handler as (request: Request) => Promise<Response>;
}

function post(action: string, authorization?: string) {
	return new Request("https://project.supabase.co/functions/v1/delegated-credentials", {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			...(authorization ? { Authorization: authorization } : {}),
		},
		body: JSON.stringify({
			action,
			tenant_id: TENANT,
			scopes: ["contents:read"],
			context: {},
		}),
	});
}

describe("delegated credential handler authentication boundaries", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.resetModules();
	});

	it.each([
		["missing", undefined, "missing_access_token", 0],
		["invalid", "Bearer expired-human-session", "invalid_access_token", 1],
	] as const)("rejects %s human credentials before privileged reads or RPCs", async (_kind, authorization, error, expectedAuthChecks) => {
		const { db, calls } = database();
		const handle = await handler(db);
		const response = await handle(post("grant", authorization));

		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error });
		expect(calls.filter((call) => call.startsWith("auth."))).toHaveLength(expectedAuthChecks);
		expect(calls.filter((call) => !call.startsWith("auth."))).toEqual([]);
	});

	it.each(["introspect", "redelegate"])("rejects missing delegated credentials for %s before broker access", async (action) => {
		const { db, calls } = database();
		const handle = await handler(db);
		const response = await handle(post(action));

		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "missing_delegated_credential" });
		expect(calls).toEqual([]);
	});

	it.each(["introspect", "redelegate"])("rejects invalid delegated credentials for %s before broker access", async (action) => {
		const { db, calls } = database();
		const handle = await handler(db);
		const response = await handle(post(action, "Bearer not-a-delegated-token-with-no-signature"));

		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "invalid_token" });
		expect(calls).toEqual([]);
	});
});
