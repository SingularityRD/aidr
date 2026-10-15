import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const USER = "11111111-1111-4111-8111-111111111111";
const client = vi.hoisted(() => ({ current: null as unknown }));

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => client.current,
}));
vi.mock("../_shared/identity-barrier.ts", () => ({
	checkIdentityBarrier: async () => ({ ok: true }),
}));

const served: Array<(req: Request) => Promise<Response>> = [];
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: (handler: (req: Request) => Promise<Response>) => { served.push(handler); },
};

const teamInvite = await import("../team-invite/index.ts");
const oauthCallback = await import("../oauth-callback/index.ts");
const auditExport = await import("../audit-export/index.ts");
await import("../device-verify/index.ts");
const pilotAdmin = await import("../pilot-admin/index.ts");
const operatorAdmin = await import("../operator-admin/index.ts");

const TOKEN = `header.${btoa(JSON.stringify({ iat: Math.floor(Date.now() / 1000) }))}.signature`;
const routes = [
	["team-invite", teamInvite.createTeamInviteHandler()],
	["oauth-callback", oauthCallback.createOAuthCallbackHandler()],
	["audit-export", auditExport.createAuditExportHandler()],
	["device-verify", served[3]],
	["pilot-admin", pilotAdmin.createPilotAdminHandler()],
	["operator-admin", operatorAdmin.createOperatorAdminHandler()],
] as const;

function database() {
	const mutations: string[] = [];
	const db = {
		auth: {
			getUser: async () => ({ data: { user: { id: USER } }, error: null }),
			mfa: { getAuthenticatorAssuranceLevel: async () => ({ data: { currentLevel: "aal2" }, error: null }) },
		},
		from: (table: string) => {
			const query = {
				select: () => query,
				eq: () => query,
				maybeSingle: async () => ({
					data: table === "pilot_admins"
						? { user_id: USER }
						: table === "platform_operators"
							? { user_id: USER, expires_at: "2999-01-01T00:00:00.000Z", revoked_at: null }
							: table === "rate_limits" ? { count: 1 } : null,
					error: null,
				}),
				insert: () => { mutations.push(`${table}.insert`); return query; },
				update: () => { mutations.push(`${table}.update`); return query; },
			};
			return query;
		},
		rpc: async (name: string) => { mutations.push(`rpc:${name}`); return { data: null, error: null }; },
	};
	return { db, mutations };
}

function expectNoBusinessMutation(route: string, mutations: string[]) {
	// device-verify deliberately consumes its per-user quota before reading the
	// user code, including malformed requests; this is the anti-guessing boundary.
	expect(mutations).toEqual(route === "device-verify" ? ["rpc:increment_rate_limit"] : []);
}

function post(route: string, body: BodyInit, headers: Record<string, string> = {}): Request {
	return new Request(`https://project.supabase.co/functions/v1/${route}`, {
		method: "POST",
		headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json", ...headers },
		body,
		...(body instanceof ReadableStream ? { duplex: "half" } : {}),
	} as RequestInit);
}

describe("JSON mutation body limits", () => {
	beforeEach(() => {
		vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
		vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key");
		vi.stubEnv("AIDR_DASHBOARD_URL", "https://app.aidr.example");
	});
	afterEach(() => vi.unstubAllEnvs());

	it.each(routes)("rejects malformed %s JSON before any business mutation", async (route, handler) => {
		const fake = database();
		client.current = fake.db;
		const response = await handler(post(route, "{"));
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "invalid_json" });
		expectNoBusinessMutation(route, fake.mutations);
	});

	// operator-admin accepts a signed license file (64 KiB) in its body.
	const oversized = (route: string) => (route === "operator-admin" ? 128_000 : 20_000);

	it.each(routes)("rejects declared-oversized %s JSON before any business mutation", async (route, handler) => {
		const fake = database();
		client.current = fake.db;
		const response = await handler(post(route, "{}", { "Content-Length": String(oversized(route)) }));
		expect(response.status).toBe(413);
		expect(await response.json()).toEqual({ error: "request_too_large" });
		expectNoBusinessMutation(route, fake.mutations);
	});

	it.each(routes)("rejects streamed-oversized %s JSON before any business mutation", async (route, handler) => {
		const fake = database();
		client.current = fake.db;
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new TextEncoder().encode(JSON.stringify({ payload: "x".repeat(oversized(route)) })));
				controller.close();
			},
		});
		const response = await handler(post(route, body));
		expect(response.status).toBe(413);
		expect(await response.json()).toEqual({ error: "request_too_large" });
		expectNoBusinessMutation(route, fake.mutations);
	});
});
