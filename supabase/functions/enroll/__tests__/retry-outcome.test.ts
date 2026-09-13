import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { entitlementWindow, validateEnrollmentBody } from "../contract.ts";

const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "index.ts"), "utf8")
	.replace(/^import .*;\r?\n/gm, "");
const compiled = ts.transpileModule(source, {
	compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;

function enrollmentHandler(exchangeResult: { data: unknown; error: unknown }) {
	let handler: ((request: Request) => Promise<Response>) | undefined;
	const client = {
		rpc: async (name: string) => name === "increment_rate_limit"
			? { data: null, error: null } : exchangeResult,
		from: (table: string) => {
			if (table !== "rate_limits") throw new Error(`unexpected table: ${table}`);
			const query = {
				select: () => query,
				eq: () => query,
				single: async () => ({ data: { count: 1 }, error: null }),
			};
			return query;
		},
	};
	new Function("Deno", "createClient", "configFailure", "loadConfig", "partialGroupError",
		"runtimeEnv", "readBoundedJson", "entitlementWindow", "validateEnrollmentBody", compiled)(
		{ env: { get: () => undefined }, serve: (fn: typeof handler) => { handler = fn; } },
		() => client,
		() => { throw new Error("unexpected configuration failure"); },
		() => ({ ok: true, values: { SUPABASE_URL: "https://test.invalid", SUPABASE_SERVICE_ROLE_KEY: "test" } }),
		() => null,
		{},
		async (request: Request) => ({ ok: true, value: await request.json() }),
		entitlementWindow,
		validateEnrollmentBody,
	);
	if (!handler) throw new Error("enroll handler was not registered");
	return handler;
}

describe("enrollment retry outcome", () => {
	it("does not present a consumed-token retry as a confirmed rollback", async () => {
		const handler = enrollmentHandler({ data: { status: "invalid_token" }, error: null });
		const response = await handler(new Request("https://test.invalid/enroll", {
			method: "POST",
			headers: { Authorization: "Bearer aidr_enroll_test-token" },
			body: JSON.stringify({ iid: "iid-1" }),
		}));
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({
			error: "invalid_or_expired_enrollment_token",
			enrollment_outcome: "unknown",
		});
	});

	it("keeps a lost RPC response explicitly uncertain", async () => {
		const handler = enrollmentHandler({ data: null, error: { message: "response lost" } });
		const response = await handler(new Request("https://test.invalid/enroll", {
			method: "POST",
			headers: { Authorization: "Bearer aidr_enroll_test-token" },
			body: JSON.stringify({ iid: "iid-1" }),
		}));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({
			error: "enrollment_exchange_failed",
			enrollment_outcome: "unknown",
		});
	});
});
