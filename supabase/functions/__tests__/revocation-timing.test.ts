// CP-7: the signed revocation feed's TTL and epoch settings are bounded and a
// bad value refuses to sign (500 server_misconfigured naming the variable)
// instead of minting an already-expired, years-long or rolled-back list.

import { afterEach, describe, expect, it, vi } from "vitest";
import {
	MAX_REVOCATION_EPOCH,
	MAX_REVOCATION_TTL_HOURS,
	REVOCATION_EPOCH_ENV,
	REVOCATION_TTL_ENV,
	revocationTiming,
} from "../revocations/timing.ts";

const createClient = vi.hoisted(() => vi.fn());
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient }));

type Handler = (request: Request) => Promise<Response>;

function envOf(values: Record<string, string | undefined>) {
	return (name: string) => values[name];
}

describe("revocationTiming", () => {
	it("defaults to a 24 h TTL and epoch 1 when unset", () => {
		expect(revocationTiming(envOf({}))).toEqual({ ok: true, ttlHours: 24, epoch: 1 });
	});

	it("accepts in-range integers", () => {
		expect(revocationTiming(envOf({ [REVOCATION_TTL_ENV]: "1", [REVOCATION_EPOCH_ENV]: "42" }))).toEqual({
			ok: true,
			ttlHours: 1,
			epoch: 42,
		});
		expect(
			revocationTiming(envOf({ [REVOCATION_TTL_ENV]: String(MAX_REVOCATION_TTL_HOURS), [REVOCATION_EPOCH_ENV]: String(MAX_REVOCATION_EPOCH) })),
		).toEqual({ ok: true, ttlHours: MAX_REVOCATION_TTL_HOURS, epoch: MAX_REVOCATION_EPOCH });
	});

	it.each([
		["NaN TTL (used to expire on arrival)", { [REVOCATION_TTL_ENV]: "24h" }, [REVOCATION_TTL_ENV]],
		["zero TTL", { [REVOCATION_TTL_ENV]: "0" }, [REVOCATION_TTL_ENV]],
		["negative TTL", { [REVOCATION_TTL_ENV]: "-5" }, [REVOCATION_TTL_ENV]],
		["years-long TTL", { [REVOCATION_TTL_ENV]: "87600" }, [REVOCATION_TTL_ENV]],
		["fractional TTL", { [REVOCATION_TTL_ENV]: "1.5" }, [REVOCATION_TTL_ENV]],
		["empty TTL", { [REVOCATION_TTL_ENV]: "" }, [REVOCATION_TTL_ENV]],
		["malformed epoch (used to roll back to 1)", { [REVOCATION_EPOCH_ENV]: "v7" }, [REVOCATION_EPOCH_ENV]],
		["zero epoch", { [REVOCATION_EPOCH_ENV]: "0" }, [REVOCATION_EPOCH_ENV]],
		["epoch above int4", { [REVOCATION_EPOCH_ENV]: "2147483648" }, [REVOCATION_EPOCH_ENV]],
		["both bad", { [REVOCATION_TTL_ENV]: "x", [REVOCATION_EPOCH_ENV]: "y" }, [REVOCATION_TTL_ENV, REVOCATION_EPOCH_ENV]],
	])("rejects %s", (_label, values, invalid) => {
		const result = revocationTiming(envOf(values));
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.toResponseBody()).toEqual({ error: "server_misconfigured", invalid });
	});
});

describe("GET /v1/revocations with a bad timing setting", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.resetModules();
		createClient.mockReset();
	});

	async function serveWith(env: Record<string, string>): Promise<Handler> {
		let handler: Handler | undefined;
		vi.stubGlobal("Deno", {
			env: { get: (name: string) => env[name] },
			serve: (h: Handler) => {
				handler = h;
			},
		});
		const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
		await import("../revocations/index.ts");
		errors.mockRestore();
		if (!handler) throw new Error("revocations did not register a handler");
		return handler;
	}

	it("fails closed with 500 naming the variable before any auth or database work", async () => {
		const handle = await serveWith({
			SUPABASE_URL: "https://project.supabase.co",
			SUPABASE_SERVICE_ROLE_KEY: "service-role",
			[REVOCATION_TTL_ENV]: "twenty-four",
		});
		const response = await handle(
			new Request("https://project.supabase.co/functions/v1/revocations", {
				method: "GET",
				headers: { Authorization: "Bearer some-api-key" },
			}),
		);
		expect(response.status).toBe(500);
		expect(await response.json()).toEqual({ error: "server_misconfigured", invalid: [REVOCATION_TTL_ENV] });
		expect(createClient).not.toHaveBeenCalled();
	});
});
