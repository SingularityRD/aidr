import { describe, expect, it } from "vitest";
import { redactRemoteEvent } from "../managed.js";
import { redactTelemetryData, redactTelemetryString } from "../telemetry-redaction.js";

describe("telemetry redaction boundary", () => {
	it("removes bearer, key/value, JWT and URL credential material", () => {
		const raw = [
			"Authoriz",
			"ation: B",
			"earer li",
			"ve-secre",
			"t auth_t",
			"oken=aut",
			"h-secret",
			" x-api-k",
			"ey=heade",
			"r-secret",
			" token=a",
			"bc123 sk",
			"_live_12",
			"34567890",
			"abcdef h",
			"ttps://u",
			"ser:pass",
			"@example",
			".test/a?",
			"access_t",
			"oken=xyz",
			" eyJhbGc",
			"iOiJIUzI",
			"1NiJ9.ey",
			"JzdWIiOi",
			"IxIn0.si",
			"gnature",
		].join("");
		const safe = redactTelemetryString(raw);

		expect(safe).not.toContain("live-secret");
		expect(safe).not.toContain("abc123");
		expect(safe).not.toContain("auth-secret");
		expect(safe).not.toContain("header-secret");
		expect(safe).not.toContain(["sk_live_", "12345678", "90abcdef"].join(""));
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

	it("redacts OAuth invite, grant and state values from keys and URLs", () => {
		const safe = redactTelemetryData({
			invite: "invite-secret",
			grant: "grant-secret",
			state: "oauth-state-secret",
			url: "https://example.test/auth?invite=invite-secret&grant=grant-secret&state=oauth-state-secret",
		});

		expect(safe).toMatchObject({
			invite: "[Redacted]",
			grant: "[Redacted]",
			state: "[Redacted]",
			url: "https://example.test/auth?invite=[Redacted]&grant=[Redacted]&state=[Redacted]",
		});
	});

	it("breaks cyclic diagnostic objects instead of serializing a cycle", () => {
		const input: { name: string; self?: unknown } = { name: "safe" };
		input.self = input;
		const safe = redactTelemetryData(input) as { name: string; self?: unknown };
		expect(safe.name).toBe("safe");
		expect(safe.self).toBe("[Redacted]");
	});

	it("applies a mandatory credential scrub at the control-plane boundary", () => {
		const safe = redactRemoteEvent(
			{
				type: "runtime_verdict",
				duration_ms: 12.5,
				tool_input_summary: "curl https://example.test/?token=secret",
				artifacts: ["Authorization: Bearer live-token"],
				reasons: ["prompt token=secret"],
			},
			"none",
		);

		expect(JSON.stringify(safe)).not.toContain("live-token");
		expect(JSON.stringify(safe)).not.toContain("token=secret");
		expect(safe.duration_ms).toBe(12.5);

		const defaultSafe = redactRemoteEvent(
			{ tool_input_summary: "ordinary command", artifacts: ["ordinary command"] },
			undefined,
		);
		expect(defaultSafe.tool_input_summary).toMatch(/^sha256:[0-9a-f]{64}$/);

		const untrustedFields = redactRemoteEvent(
			{
				type: "runtime_verdict",
				prompt: "private customer prompt",
				nested: { content: "private customer content" },
				tool_input_summary: "ordinary command",
			},
			"hash",
		);
		expect(untrustedFields).not.toHaveProperty("prompt");
		expect(untrustedFields).not.toHaveProperty("nested");
		expect(JSON.stringify(untrustedFields)).not.toContain("private customer");
	});
});
