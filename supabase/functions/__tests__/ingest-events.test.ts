import { describe, expect, it } from "vitest";
import {
	MAX_INGEST_EVENTS,
	normalizeIngestEvents,
} from "../ingest/events.ts";

describe("ingest event delivery contract", () => {
	it("requires stable event identity and accepts a bounded valid batch", () => {
		expect(normalizeIngestEvents(undefined)).toEqual({ ok: true, events: [] });
		expect(
			normalizeIngestEvents([{ event_id: "evt:01-test", type: "runtime_verdict" }]),
		).toEqual({
			ok: true,
			events: [{ event_id: "evt:01-test", type: "runtime_verdict" }],
		});
		expect(normalizeIngestEvents([{ type: "runtime_verdict" }])).toMatchObject({
			ok: false,
			status: 400,
			error: "missing_event_id",
		});
	});

	it("rejects duplicate identities inside one request", () => {
		const result = normalizeIngestEvents([
			{ event_id: "evt-1", type: "runtime_verdict" },
			{ event_id: "evt-1", type: "incident" },
		]);
		expect(result).toMatchObject({ ok: false, status: 400, error: "invalid_event" });
	});

	it("rejects batches beyond the contract instead of silently slicing them", () => {
		const events = Array.from({ length: MAX_INGEST_EVENTS + 1 }, (_, index) => ({
			event_id: `evt-${index}`,
			type: "runtime_verdict",
		}));
		expect(normalizeIngestEvents(events)).toEqual({
			ok: false,
			status: 413,
			error: "events_limit_exceeded",
		});
	});

	it("rejects an event that exceeds its storage budget", () => {
		const result = normalizeIngestEvents([
			{ event_id: "evt-large", type: "runtime_verdict", payload: "x".repeat(300_000) },
		]);
		expect(result).toMatchObject({
			ok: false,
			status: 413,
			error: "events_batch_too_large",
		});
	});

	it("keeps the verdict and incident fields needed by dashboard triage", () => {
		const result = normalizeIngestEvents([
			{
				event_id: "evt-verdict-1",
				type: "runtime_verdict",
				timestamp: "2026-09-13T10:00:00Z",
				session_id: "session-123",
				tool_name: "Bash",
				verdict: "deny",
				severity: "critical",
				matched_threat_id: "AIDR-001",
				user_override: false,
				tool_input_summary: `sha256:${"a".repeat(64)}`,
			},
			{
				event_id: "evt-incident-1",
				type: "incident",
				incident_id: "inc_session-123_42",
				status: "open",
				decision: "deny",
				severity: "high",
				recommended_actions: ["review", "investigate"],
			},
		]);
		expect(result).toEqual({
			ok: true,
			events: [
				{
					event_id: "evt-verdict-1", type: "runtime_verdict",
					timestamp: "2026-09-13T10:00:00.000Z", session_id: "session-123",
					tool_name: "Bash", verdict: "deny", severity: "critical",
					matched_threat_id: "AIDR-001", user_override: false,
					tool_input_summary: `sha256:${"a".repeat(64)}`,
				},
				{
					event_id: "evt-incident-1", type: "incident",
					incident_id: "inc_session-123_42", status: "open",
					decision: "deny", severity: "high",
					recommended_actions: ["review", "investigate"],
				},
			],
		});
	});

	it("minimizes nested raw content from a client that bypasses local scrubbing", () => {
		const secret = ["sk_live_", "abcdefgh", "ijklmnop"].join("");
		const email = "person@example.test";
		const result = normalizeIngestEvents([{
			event_id: "evt-private-1", type: "runtime_verdict", verdict: "deny", severity: "high",
			tool_name: "Bash", session_id: email, source: secret,
			tool_input_summary: `curl -H 'Authorization: Bearer ${secret}' https://example.test/${email}`,
			artifacts: [`https://example.test/?token=${secret}`, { prompt: email }],
			reasons: [`The prompt included ${email} and ${secret}`],
			tenant_id: "forged-other-tenant",
			user_id: "forged-other-user",
			prompt: email,
			content: { token: secret, personal_data: [{ address: email }] },
			nested: { child: { deep: { secret, email } } },
		}]);
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		const stored = result.events[0];
		expect(stored).toMatchObject({
			event_id: "evt-private-1", type: "runtime_verdict", verdict: "deny", severity: "high",
			tool_name: "Bash", tool_input_summary: "[Redacted]", artifacts: ["[Redacted]", "[Redacted]"], reasons: [],
		});
		expect(JSON.stringify(stored)).not.toContain(secret);
		expect(JSON.stringify(stored)).not.toContain(email);
		expect(stored).not.toHaveProperty("content");
		expect(stored).not.toHaveProperty("nested");
		expect(stored).not.toHaveProperty("tenant_id");
		expect(stored).not.toHaveProperty("user_id");
	});

	it("omits JWT-shaped values from every projected identifier and rejects them as event IDs", () => {
		// Joined at runtime so repository secret scanners do not flag the fixture.
		const jwt = ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJ1c2VyLTEyMyJ9", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEF"].join(".");
		const result = normalizeIngestEvents([{
			event_id: "evt-safe-1", type: "runtime_verdict",
			session_id: jwt,
			incident_id: jwt,
			tool_name: jwt,
			source: jwt,
			matched_threat_id: jwt,
			plugin_key: jwt,
			runtime_policy_cache: { source: jwt, policy_version: jwt, usable: true },
		}]);
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		const stored = result.events[0];
		for (const key of ["session_id", "incident_id", "tool_name", "source", "matched_threat_id", "plugin_key"]) {
			expect(stored).not.toHaveProperty(key);
		}
		expect(stored.runtime_policy_cache).toEqual({ usable: true });
		expect(JSON.stringify(stored)).not.toContain(jwt);

		const rejected = normalizeIngestEvents([{ event_id: jwt, type: "runtime_verdict" }]);
		expect(rejected).toMatchObject({ ok: false, status: 400, error: "invalid_event" });
		expect(JSON.stringify(rejected)).not.toContain(jwt);
	});

	it("omits obvious bearer and provider-key identifier formats but preserves benign dotted IDs", () => {
		const values = {
			event_id: "evt-safe-credentials",
			type: "runtime_verdict",
			session_id: "Bearer:opaque-secret-123456",
			incident_id: `sk_live_${"AbCdEfGhIjKlMnOpQr"}`,
			tool_name: "Bash.v2",
			source: "server.policy.v2",
			matched_threat_id: "AIDR-001",
			plugin_key: "github_pat_0123456789abcdefgh",
		};
		const result = normalizeIngestEvents([values]);
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		const stored = result.events[0];
		expect(stored).not.toHaveProperty("session_id");
		expect(stored).not.toHaveProperty("incident_id");
		expect(stored).not.toHaveProperty("plugin_key");
		expect(stored).toMatchObject({
			tool_name: "Bash.v2",
			source: "server.policy.v2",
			matched_threat_id: "AIDR-001",
		});
		const serialized = JSON.stringify(stored);
		for (const secret of [values.session_id, values.incident_id, values.plugin_key]) {
			expect(serialized).not.toContain(secret);
		}
	});

	it("bounds the nested cache projection and rejects a credential-shaped event identity", () => {
		const result = normalizeIngestEvents([{
			event_id: "evt-cache-1", type: "runtime_policy_cache",
			runtime_policy_cache: {
				source: "server", usable: true, policy_version: "v12",
				credentials: { private_key: "very-private" },
			},
		}]);
		expect(result).toEqual({
			ok: true,
			events: [{ event_id: "evt-cache-1", type: "runtime_policy_cache", runtime_policy_cache: { source: "server", policy_version: "v12", usable: true } }],
		});
		expect(normalizeIngestEvents([{ event_id: ["sk_live_", "abcdefgh", "ijklmnop"].join(""), type: "runtime_verdict" }]))
			.toMatchObject({ ok: false, status: 400, error: "invalid_event" });
		expect(normalizeIngestEvents([{ event_id: "5551234567", type: "runtime_verdict" }]))
			.toMatchObject({ ok: false, status: 400, error: "invalid_event" });
		expect(normalizeIngestEvents([{ event_id: "evt-unknown", type: "unknown_private_event", content: "secret" }]))
			.toMatchObject({ ok: false, status: 400, error: "invalid_event" });
	});

	it("rejects deeply nested JSON without crashing or acknowledging it", () => {
		let deep: unknown = "private";
		for (let i = 0; i < 12_000; i += 1) deep = { next: deep };
		const result = normalizeIngestEvents([{ event_id: "evt-deep", type: "runtime_verdict", content: deep }]);
		expect(result).toMatchObject({ ok: false, status: 400, error: "invalid_event" });
	});
});
