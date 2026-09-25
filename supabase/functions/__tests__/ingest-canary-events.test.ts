import { describe, expect, it } from "vitest";
import { normalizeIngestEvents } from "../ingest/events.ts";

/**
 * Canary credential triggers reach the control plane through the existing
 * runtime_verdict / incident events. The dashboard labels them from `source`
 * and `matched_threat_id`, so both must survive the storage projection, while
 * reasons and artifacts (canary ids) stay redacted like any other event.
 */
describe("canary trigger events", () => {
	it("keep the fields the incident view labels them by", () => {
		const result = normalizeIngestEvents([
			{
				event_id: "evt-canary-1",
				type: "incident",
				incident_id: "inc_session_1",
				tool_name: "Read",
				decision: "deny",
				severity: "critical",
				status: "open",
				source: "canary",
				matched_threat_id: "AIDR-CANARY-002",
				category: "canary_triggered",
				artifacts: ["canary:cny_0123456789abcdef"],
				reasons: ["canary_triggered: This tool call accesses a canary credential file (aws)"],
				recommended_actions: ["review", "block"],
			},
		]);
		expect(result).toMatchObject({ ok: true });
		if (!result.ok) return;
		const [event] = result.events;
		expect(event).toMatchObject({
			type: "incident",
			source: "canary",
			matched_threat_id: "AIDR-CANARY-002",
			decision: "deny",
			severity: "critical",
			artifacts: ["[Redacted]"],
			reasons: [],
		});
	});
});
