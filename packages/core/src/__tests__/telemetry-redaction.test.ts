import { describe, expect, it } from "vitest";
import { redactRemoteEvent } from "../managed.js";
import {
	redactTelemetryAttributes,
	redactTelemetryData,
	redactTelemetryString,
	sanitizeTelemetryEndpoint,
} from "../telemetry-redaction.js";

describe("telemetry redaction boundary", () => {
	it("removes bearer, key/value, JWT and URL credential material", () => {
		const raw =
			"Authorization: Bearer live-secret auth_token=auth-secret x-api-key=header-secret token=abc123 sk_live_1234567890abcdef https://user:pass@example.test/a?access_token=xyz eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature";
		const safe = redactTelemetryString(raw);

		expect(safe).not.toContain("live-secret");
		expect(safe).not.toContain("abc123");
		expect(safe).not.toContain("auth-secret");
		expect(safe).not.toContain("header-secret");
		expect(safe).not.toContain("sk_live_1234567890abcdef");
		expect(safe).not.toContain("user:pass");
		expect(safe).not.toContain("access_token=xyz");
		expect(safe).not.toContain("eyJhbGciOiJIUzI1NiJ9");
		expect(safe).toContain("https://user:[Redacted]@example.test/a");
	});

	it("redacts sensitive object keys and nested values without mutating input", () => {
		const input = {
			apiKey: "live-api-key",
			request: { url: "https://example.test/hook?token=secret", safe: "kept" },
			items: [{ Authorization: "Bearer abc", value: "ok" }],
		};
		const safe = redactTelemetryData(input);

		expect(input.apiKey).toBe("live-api-key");
		expect(safe).toMatchObject({
			apiKey: "[Redacted]",
			request: { url: "https://example.test/hook?token=[Redacted]", safe: "kept" },
			items: [{ Authorization: "[Redacted]", value: "ok" }],
		});
	});

	it("breaks cyclic diagnostic objects instead of serializing a cycle", () => {
		const input: { name: string; self?: unknown } = { name: "safe" };
		input.self = input;
		const safe = redactTelemetryData(input) as { name: string; self?: unknown };
		expect(safe.name).toBe("safe");
		expect(safe.self).toBe("[Redacted]");
	});

	it("redacts string attributes while retaining numeric metrics", () => {
		expect(
			redactTelemetryAttributes({
				"http.url": "https://example.test/?api_key=secret",
				api_key: "live",
				count: 3,
			}),
		).toEqual({
			"http.url": "https://example.test/?api_key=[Redacted]",
			api_key: "[Redacted]",
			count: 3,
		});
	});

	it("normalizes OTLP endpoints and strips credentials/query fragments", () => {
		expect(
			sanitizeTelemetryEndpoint("https://collector:userpass@example.test/v1/traces?token=secret#x"),
		).toBe("https://example.test/v1/traces");
		expect(sanitizeTelemetryEndpoint("file:///tmp/traces")).toBeUndefined();
		expect(sanitizeTelemetryEndpoint("not-a-url")).toBeUndefined();
	});

	it("applies a mandatory credential scrub at the control-plane boundary", () => {
		const safe = redactRemoteEvent(
			{
				type: "runtime_verdict",
				tool_input_summary: "curl https://example.test/?token=secret",
				artifacts: ["Authorization: Bearer live-token"],
				reasons: ["prompt token=secret"],
			},
			"none",
		);

		expect(JSON.stringify(safe)).not.toContain("live-token");
		expect(JSON.stringify(safe)).not.toContain("token=secret");

		const defaultSafe = redactRemoteEvent(
			{ tool_input_summary: "ordinary command", artifacts: ["ordinary command"] },
			undefined,
		);
		expect(defaultSafe.tool_input_summary).toMatch(/^sha256:[0-9a-f]{64}$/);
	});
});
