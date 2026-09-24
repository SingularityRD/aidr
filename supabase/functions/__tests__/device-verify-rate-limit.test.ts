import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import ts from "typescript";

const source = readFileSync(
	join(dirname(fileURLToPath(import.meta.url)), "..", "device-verify", "index.ts"),
	"utf8",
);
const compiled = ts.transpileModule(source.replace(/^import .*;\r?\n/gm, ""), {
	compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;

type Handler = (request: Request) => Promise<Response>;

function harness(options: { rateLimitError?: boolean; malformedCount?: boolean } = {}) {
	let handler: Handler | undefined;
	let count = 0;
	let sessionReads = 0;
	let authorizationCalls = 0;
	const userId = "11111111-1111-4111-8111-111111111111";
	const tenantId = "22222222-2222-4222-8222-222222222222";
	const db = {
		auth: { getUser: async () => ({ data: { user: { id: userId } }, error: null }) },
		async rpc(name: string) {
			if (name === "increment_rate_limit") {
				if (options.rateLimitError) return { data: null, error: { message: "counter unavailable" } };
				count++;
				return { data: null, error: null };
			}
			if (name === "tenant_admission_capacity") return { data: 1, error: null };
			if (name === "authorize_device_session") {
				authorizationCalls++;
				return { data: [{ id: "device-1" }], error: null };
			}
			throw new Error(`unexpected RPC ${name}`);
		},
		from(table: string) {
			let key = "";
			let windowStart = 0;
			const query = {
				select: (_columns: string) => query,
				eq: (column: string, value: string | number) => {
					if (column === "key") key = String(value);
					if (column === "window_start") windowStart = Number(value);
					return query;
				},
				async maybeSingle() {
					if (table === "rate_limits") {
						return { data: options.malformedCount ? { count: "invalid" } : { count }, error: null };
					}
					if (table === "device_sessions") {
						sessionReads++;
						return { data: {
							id: "device-1", authorized_at: null,
							expires_at: new Date(Date.now() + 60_000).toISOString(),
							user_id: null, tenant_id: tenantId,
						}, error: null };
					}
					if (table === "tenant_members") return { data: { role: "owner", expires_at: null }, error: null };
					if (table === "tenants") return { data: { status: "active" }, error: null };
					throw new Error(`unexpected table ${table}; ${key}:${windowStart}`);
				},
			};
			return query;
		},
	};
	new Function(
		"Deno", "createClient", "checkIdentityBarrier", "getBearerToken", "configFailure",
		"loadConfig", "runtimeEnv", "corsJson", "handleCors", "evaluateDeviceVerifyState",
		"readBoundedJson", "jwtIssuedAtMs", compiled,
	)(
		{ env: { get: () => undefined }, serve: (fn: Handler) => { handler = fn; } },
		() => db,
		async () => ({ ok: true }),
		(header: string | null) => header?.replace(/^Bearer\s+/i, "") ?? null,
		() => { throw new Error("unexpected config failure"); },
		() => ({ ok: true, values: { SUPABASE_URL: "https://test.invalid", SUPABASE_SERVICE_ROLE_KEY: "test" } }),
		{},
		(_request: Request, status: number, body: unknown, headers: Record<string, string> = {}) =>
			Response.json(body, { status, headers }),
		() => null,
		(input: { nowMs: number; expiresAtIso: string; authorizedAt: string | null; pilotApproved: boolean }) =>
			input.expiresAtIso > new Date(input.nowMs).toISOString()
				? { status: "ok", httpStatus: 200 }
				: { status: "expired", httpStatus: 410, error: "device_code_expired" },
		async (request: Request) => ({ ok: true as const, value: await request.json(), bytes: 0 }),
		() => Date.now(),
	);
	if (!handler) throw new Error("device-verify did not register a handler");
	const run = async () => {
		const response = await handler!(new Request("https://test.invalid/device-verify", {
			method: "POST",
			headers: { Authorization: "Bearer verified-session" },
			body: JSON.stringify({ user_code: "ABCDEFGH" }),
		}));
		return { status: response.status, body: await response.json() as Record<string, unknown> };
	};
	return { run, get count() { return count; }, get sessionReads() { return sessionReads; }, get authorizationCalls() { return authorizationCalls; } };
}

describe("device verification rate limit", () => {
	it("caps code lookups per authenticated user in a minute", async () => {
		const app = harness();
		for (let attempt = 0; attempt < 30; attempt++) {
			expect(await app.run()).toMatchObject({ status: 200, body: { ok: true } });
		}
		expect(await app.run()).toMatchObject({ status: 429, body: { error: "rate_limited" } });
		expect(app.count).toBe(31);
		expect(app.sessionReads).toBe(30);
		expect(app.authorizationCalls).toBe(30);
	});

	it.each([
		{ rateLimitError: true },
		{ malformedCount: true },
	])("fails closed without looking up a device code when quota state is unavailable", async (options) => {
		const app = harness(options);
		expect(await app.run()).toMatchObject({ status: 503, body: { error: "rate_limit_unavailable" } });
		expect(app.sessionReads).toBe(0);
		expect(app.authorizationCalls).toBe(0);
	});
});
