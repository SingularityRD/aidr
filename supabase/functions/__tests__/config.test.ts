// Behaviour of the shared Edge Function configuration guard (AIDR-011).
//
// The guard is what turns `Deno.env.get("SUPABASE_URL") ?? ""` into an explicit
// fail-closed 500 that names the missing variable. It is pure and Deno-free on
// purpose, so the exact module the Edge Functions import is the module under
// test here.
//
// COVERAGE BOUNDARY: nothing in this suite executes the deployed Deno runtime
// or talks to Supabase. `__tests__/config-contract.test.ts` covers the wiring
// inside each function file, which cannot be imported into vitest because those
// files call `Deno.serve` and import `npm:@supabase/supabase-js@2.116.0`.

import { afterEach, describe, expect, it, vi } from "vitest";
import {
	CONFIGURATION_ERROR_CODE,
	CONFIGURATION_ERROR_STATUS,
	ConfigurationError,
	configFailure,
	isConfigurationError,
	isConfiguredValue,
	loadConfig,
	logConfigFailure,
	partialGroupError,
	readConfigValue,
	runtimeEnv,
} from "../_shared/config.ts";

/** Distinctive, obviously-not-real secret material for leak assertions. */
const SECRET_URL = "https://project-ref.supabase.co";
const SECRET_KEY = "sbp_service_role_do_not_leak_9f3c1a2b4d";

const CONFIGURED: Record<string, string> = {
	SUPABASE_URL: SECRET_URL,
	SUPABASE_SERVICE_ROLE_KEY: SECRET_KEY,
};

function envFrom(values: Record<string, string | undefined>) {
	return (name: string): string | undefined => values[name];
}

function jsonResponder(status: number, body: Record<string, unknown>): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function captureConsoleError(): string[] {
	const lines: string[] = [];
	vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
		lines.push(args.map((arg) => String(arg)).join(" "));
	});
	return lines;
}

afterEach(() => {
	vi.restoreAllMocks();
});

describe("loadConfig - missing required configuration", () => {
	it("names the missing variable and reports a 500-class configuration error", () => {
		const result = loadConfig(envFrom({ SUPABASE_SERVICE_ROLE_KEY: SECRET_KEY }), [
			"SUPABASE_URL",
			"SUPABASE_SERVICE_ROLE_KEY",
		]);

		expect(result.ok).toBe(false);
		if (result.ok) throw new Error("unreachable");
		expect(result.error).toBeInstanceOf(ConfigurationError);
		expect(result.error.status).toBe(CONFIGURATION_ERROR_STATUS);
		expect(result.error.status).toBe(500);
		expect(result.error.code).toBe(CONFIGURATION_ERROR_CODE);
		expect(result.error.missing).toEqual(["SUPABASE_URL"]);
		expect(result.error.message).toContain("SUPABASE_URL");
	});

	it("reports every missing variable in one pass", () => {
		const result = loadConfig(envFrom({}), ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"]);
		if (result.ok) throw new Error("unreachable");
		expect(result.error.missing).toEqual(["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"]);
	});

	it("treats a whitespace-only value as unset", () => {
		const result = loadConfig(envFrom({ SUPABASE_URL: "   \n\t" }), ["SUPABASE_URL"]);
		expect(result.ok).toBe(false);
		if (result.ok) throw new Error("unreachable");
		expect(result.error.missing).toEqual(["SUPABASE_URL"]);
	});

	it("treats an unreadable variable as unset (fails closed)", () => {
		const result = loadConfig(
			() => {
				throw new Error("env read denied");
			},
			["SUPABASE_URL"],
		);
		expect(result.ok).toBe(false);
	});
});

describe("loadConfig - configured environment (no regression)", () => {
	it("returns the same values the old `Deno.env.get(x) ?? \"\"` read would return", () => {
		const result = loadConfig(envFrom(CONFIGURED), [
			"SUPABASE_URL",
			"SUPABASE_SERVICE_ROLE_KEY",
		]);

		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error("unreachable");
		// Values are returned verbatim: a deployment that worked before still works.
		expect(result.values.SUPABASE_URL).toBe(SECRET_URL);
		expect(result.values.SUPABASE_SERVICE_ROLE_KEY).toBe(SECRET_KEY);
	});

	it("does not trim, so a value is never silently rewritten", () => {
		const result = loadConfig(envFrom({ SUPABASE_URL: " https://example.test " }), [
			"SUPABASE_URL",
		]);
		if (!result.ok) throw new Error("unreachable");
		expect(result.values.SUPABASE_URL).toBe(" https://example.test ");
	});

	it("only reads the variables it was asked for", () => {
		const seen: string[] = [];
		loadConfig(
			(name) => {
				seen.push(name);
				return CONFIGURED[name];
			},
			["SUPABASE_URL"],
		);
		expect(seen).toEqual(["SUPABASE_URL"]);
	});
});

describe("loadConfig - programming errors", () => {
	it("rejects a name that is not an environment-variable name without echoing it", () => {
		expect(() => loadConfig(envFrom({}), ["not a variable name"])).toThrow(TypeError);
		expect(() => loadConfig(envFrom({}), [SECRET_KEY])).toThrow(TypeError);

		try {
			loadConfig(envFrom({}), [SECRET_KEY]);
			throw new Error("unreachable");
		} catch (error) {
			// The offending string could have been a value: it must not be echoed.
			expect(String((error as Error).message)).not.toContain(SECRET_KEY);
		}
	});
});

describe("ConfigurationError - no secret value can be published", () => {
	it("keeps values out of the response body, the log detail and the message", () => {
		const result = loadConfig(envFrom({ SUPABASE_URL: SECRET_URL }), [
			"SUPABASE_URL",
			"SUPABASE_SERVICE_ROLE_KEY",
		]);
		if (result.ok) throw new Error("unreachable");

		const serialized = JSON.stringify({
			body: result.error.toResponseBody(),
			log: result.error.toLogDetail(),
			message: result.error.message,
			stack: result.error.stack ?? "",
		});

		expect(serialized).not.toContain(SECRET_URL);
		expect(serialized).not.toContain(SECRET_KEY);
		expect(serialized).not.toContain("sbp_service_role");
		expect(serialized).toContain("SUPABASE_SERVICE_ROLE_KEY");
	});

	it("drops anything that is not an environment-variable name", () => {
		// Defence in depth: even a caller that passes a value where a name
		// belongs cannot get it into a caller-visible projection.
		const error = new ConfigurationError({
			missing: ["SUPABASE_URL", SECRET_KEY, "sbp_lower_case_value"],
			invalid: ["AUTOSECOPS_RUNTIME_URL", "https://leak.example"],
		});

		const serialized = JSON.stringify({
			body: error.toResponseBody(),
			log: error.toLogDetail(),
			message: error.message,
		});

		expect(error.missing).toEqual(["SUPABASE_URL"]);
		expect(error.invalid).toEqual(["AUTOSECOPS_RUNTIME_URL"]);
		expect(serialized).not.toContain(SECRET_KEY);
		expect(serialized).not.toContain("sbp_lower_case_value");
		expect(serialized).not.toContain("leak.example");
	});

	it("omits empty lists from the caller-visible body", () => {
		expect(new ConfigurationError({ missing: ["SUPABASE_URL"] }).toResponseBody()).toEqual({
			error: "server_misconfigured",
			missing: ["SUPABASE_URL"],
		});
		expect(
			new ConfigurationError({ invalid: ["AUTOSECOPS_RUNTIME_URL"] }).toResponseBody(),
		).toEqual({
			error: "server_misconfigured",
			invalid: ["AUTOSECOPS_RUNTIME_URL"],
		});
	});

	it("still produces a code and a status when it is given nothing to name", () => {
		const error = new ConfigurationError({});
		expect(error.toResponseBody()).toEqual({ error: "server_misconfigured" });
		expect(error.variables).toEqual([]);
	});

	it("is recognisable at a catch boundary", () => {
		expect(isConfigurationError(new ConfigurationError({ missing: ["X"] }))).toBe(true);
		expect(isConfigurationError(new Error("nope"))).toBe(false);
		expect(isConfigurationError(null)).toBe(false);
	});
});

describe("configFailure - the response an operator actually sees", () => {
	it("returns the structured error with variable names and logs nothing else", async () => {
		const logged = captureConsoleError();

		const result = loadConfig(envFrom({ SUPABASE_URL: SECRET_URL }), [
			"SUPABASE_URL",
			"SUPABASE_SERVICE_ROLE_KEY",
		]);
		if (result.ok) throw new Error("unreachable");

		const response = configFailure("url-check", result.error, jsonResponder);

		expect(response.status).toBe(500);
		const body = await response.json();
		expect(body).toEqual({
			error: "server_misconfigured",
			missing: ["SUPABASE_SERVICE_ROLE_KEY"],
		});

		// The log names the variable and carries no value.
		expect(logged).toHaveLength(1);
		expect(logged[0]).toContain("[url-check]");
		expect(logged[0]).toContain("SUPABASE_SERVICE_ROLE_KEY");
		expect(logged[0]).not.toContain(SECRET_URL);
		expect(logged[0]).not.toContain(SECRET_KEY);
	});

	it("demonstrates the exact missing-variable response (status + body)", async () => {
		// Mirrors the real call site: a handler with no SUPABASE_URL configured.
		const logged = captureConsoleError();
		const handler = (env: Record<string, string | undefined>) => {
			const config = loadConfig(envFrom(env), [
				"SUPABASE_URL",
				"SUPABASE_SERVICE_ROLE_KEY",
			] as const);
			if (!config.ok) return configFailure("device-start", config.error, jsonResponder);
			return jsonResponder(200, { ok: true });
		};

		const missing = handler({});
		const bodyText = await missing.text();
		console.log(`[demo] missing-var response -> status=${missing.status} body=${bodyText}`);
		logged.length = 0;

		expect(missing.status).toBe(500);
		expect(JSON.parse(bodyText)).toEqual({
			error: "server_misconfigured",
			missing: ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"],
		});

		// Configured environment: unchanged success path.
		const ok = handler(CONFIGURED);
		expect(ok.status).toBe(200);
		expect(await ok.json()).toEqual({ ok: true });
		expect(logged).toHaveLength(0);
	});
});

describe("partialGroupError - half-configured secrets", () => {
	it("reports the absent half of a key pair", () => {
		const problem = partialGroupError({
			AIDR_ENTITLEMENT_SIGNING_KEY_ID: "aidr-k1",
			AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64: "",
		});
		expect(problem).not.toBeNull();
		expect(problem?.missing).toEqual(["AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64"]);
		expect(JSON.stringify(problem?.toResponseBody())).not.toContain("aidr-k1");
	});

	it("stays quiet when the group is fully configured", () => {
		expect(
			partialGroupError({
				AIDR_REVOCATION_SIGNING_KEY_ID: "k1",
				AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64: "cHJpdmF0ZQ==",
			}),
		).toBeNull();
	});

	it("stays quiet when the group is entirely unprovisioned", () => {
		expect(
			partialGroupError({
				AIDR_REVOCATION_SIGNING_KEY_ID: "",
				AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64: "   ",
			}),
		).toBeNull();
	});

	it("never names a value-shaped key", () => {
		const problem = partialGroupError({
			SUPABASE_URL: SECRET_URL,
			SUPABASE_SERVICE_ROLE_KEY: "",
		});
		expect(problem?.missing).toEqual(["SUPABASE_SERVICE_ROLE_KEY"]);
	});
});

describe("small helpers", () => {
	it("readConfigValue returns an empty string for an unset or invalid name", () => {
		expect(readConfigValue(envFrom({ A: "1" }), "MISSING")).toBe("");
		expect(readConfigValue(envFrom({ A: "1" }), "lower_case")).toBe("");
		expect(readConfigValue(envFrom({ A: "1" }), "A")).toBe("1");
	});

	it("isConfiguredValue rejects blank values", () => {
		expect(isConfiguredValue("x")).toBe(true);
		expect(isConfiguredValue("")).toBe(false);
		expect(isConfiguredValue("  ")).toBe(false);
		expect(isConfiguredValue(undefined)).toBe(false);
		expect(isConfiguredValue(null)).toBe(false);
	});

	it("logConfigFailure writes one line naming variables only", () => {
		const logged = captureConsoleError();
		logConfigFailure("scope", new ConfigurationError({ missing: ["SUPABASE_URL"] }));
		expect(logged).toHaveLength(1);
		expect(logged[0]).toContain('"missing":["SUPABASE_URL"]');
	});
});

describe("runtimeEnv", () => {
	it("is defined without touching Deno at import time", () => {
		// The module is imported at the top of this file under Node, which is the
		// proof: nothing Deno-specific runs until the reader is called.
		expect(typeof runtimeEnv).toBe("function");
	});
});
