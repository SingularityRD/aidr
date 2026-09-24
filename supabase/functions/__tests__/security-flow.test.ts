import { afterEach, describe, expect, it, vi } from "vitest";
import { getBearerToken } from "../_shared/auth.ts";
import { evaluateDevicePollState, evaluateDeviceVerifyState } from "../_shared/device-auth.ts";
import { parseAllowedOrigins, resolveAllowedOrigin } from "../_shared/origin.ts";

const waitlistMocks = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: waitlistMocks.createClient }));

(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: () => undefined,
};

async function waitlistHandler(rateLimit = "10") {
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "service-role-secret");
	vi.stubEnv("AIDR_ALLOWED_ORIGINS", "https://app.aidr.example");
	vi.stubEnv("AIDR_WAITLIST_RL_PER_MIN", rateLimit);
	vi.resetModules();
	waitlistMocks.createClient.mockReset();
	const mod = await import("../waitlist-signup/index.ts");
	return mod.handleWaitlistSignup;
}

function waitlistRequest(body: string): Request {
	return new Request("https://project.supabase.co/functions/v1/waitlist-signup", {
		method: "POST",
		headers: { Origin: "https://app.aidr.example", "Content-Type": "application/json" },
		body,
	});
}

afterEach(() => {
	vi.unstubAllEnvs();
	vi.restoreAllMocks();
	vi.resetModules();
});

describe("waitlist origin policy", () => {
	it("allows configured origin", () => {
		const allowed = parseAllowedOrigins("https://app.singularityrd.com,https://aidr.dev");
		expect(resolveAllowedOrigin("https://aidr.dev", allowed)).toBe("https://aidr.dev");
	});

	it("normalizes exact HTTPS origins and rejects wildcard, malformed, and insecure entries", () => {
		const allowed = parseAllowedOrigins(
			"*, https://APP.singularityrd.com:443/, http://aidr.dev, https://aidr.dev/path, not-a-url",
		);
		expect([...allowed]).toEqual(["https://app.singularityrd.com"]);
		expect(resolveAllowedOrigin("https://APP.singularityrd.com:443", allowed))
			.toBe("https://app.singularityrd.com");
		expect(resolveAllowedOrigin("https://app.singularityrd.com/path", allowed)).toBeNull();
	});

	it("allows loopback HTTP only in explicit local development mode", () => {
		const production = parseAllowedOrigins("http://localhost:5173,http://127.0.0.1:8080");
		expect(production.size).toBe(0);

		const local = parseAllowedOrigins(
			"http://localhost:5173,http://127.0.0.1:8080,http://example.com",
			true,
		);
		expect([...local]).toEqual(["http://localhost:5173", "http://127.0.0.1:8080"]);
	});

	it("blocks disallowed origin", () => {
		const allowed = parseAllowedOrigins("https://app.singularityrd.com");
		expect(resolveAllowedOrigin("https://evil.example", allowed)).toBeNull();
	});
});

describe("waitlist request boundary", () => {
	it.each(["0", "-1", "not-a-number", "1.5", "100001"])(
		"fails closed before database work for invalid rate limit %s",
		async (rateLimit) => {
			vi.spyOn(console, "error").mockImplementation(() => undefined);
			const handle = await waitlistHandler(rateLimit);
			const response = await handle(waitlistRequest(JSON.stringify({ email: "test@aidr.example" })));
			expect(response.status).toBe(500);
			expect(await response.json()).toEqual({
				error: "server_misconfigured",
				invalid: ["AIDR_WAITLIST_RL_PER_MIN"],
			});
			expect(waitlistMocks.createClient).not.toHaveBeenCalled();
		},
	);

	it.each([
		["malformed", "{", 400, "invalid_json"],
		["null", "null", 400, "invalid_json"],
		["array", "[]", 400, "invalid_json"],
		["oversize", JSON.stringify({ value: "x".repeat(8 * 1024) }), 413, "request_too_large"],
	])("rejects %s bodies before database work", async (_label, body, status, error) => {
		const handle = await waitlistHandler();
		const response = await handle(waitlistRequest(body as string));
		expect(response.status).toBe(status);
		expect(await response.json()).toEqual({ error });
		expect(waitlistMocks.createClient).not.toHaveBeenCalled();
	});
});

describe("device poll states", () => {
	const nowMs = Date.parse("2026-03-28T10:00:00.000Z");

	it("returns pending before verification", () => {
		const state = evaluateDevicePollState({
			nowMs,
			expiresAtIso: "2026-03-28T11:00:00.000Z",
			authorizedAt: null,
			userId: null,
			pilotApproved: true,
			exchangedAt: null,
		});
		expect(state.status).toBe("pending");
	});

	it("returns pilot_not_approved after verify if user not approved", () => {
		const state = evaluateDevicePollState({
			nowMs,
			expiresAtIso: "2026-03-28T11:00:00.000Z",
			authorizedAt: "2026-03-28T09:59:59.000Z",
			userId: "u1",
			pilotApproved: false,
			exchangedAt: null,
		});
		expect(state.status).toBe("forbidden");
	});

	it("returns expired for stale code", () => {
		const state = evaluateDevicePollState({
			nowMs,
			expiresAtIso: "2026-03-28T09:00:00.000Z",
			authorizedAt: null,
			userId: null,
			pilotApproved: true,
			exchangedAt: null,
		});
		expect(state.status).toBe("expired");
	});
});

describe("device verify states", () => {
	const nowMs = Date.parse("2026-03-28T10:00:00.000Z");

	it("returns pilot_not_approved when pending user verifies", () => {
		const state = evaluateDeviceVerifyState({
			nowMs,
			expiresAtIso: "2026-03-28T11:00:00.000Z",
			authorizedAt: null,
			pilotApproved: false,
		});
		expect(state.status).toBe("forbidden");
	});

	it("returns device_code_expired on expired code", () => {
		const state = evaluateDeviceVerifyState({
			nowMs,
			expiresAtIso: "2026-03-28T09:59:59.000Z",
			authorizedAt: null,
			pilotApproved: true,
		});
		expect(state.status).toBe("expired");
	});
});

describe("auth helpers", () => {
	it("extracts bearer token", () => {
		expect(getBearerToken("Bearer aidr_live_test")).toBe("aidr_live_test");
	});

	it("rejects malformed auth header", () => {
		expect(getBearerToken("Basic abc")).toBeNull();
	});
});
