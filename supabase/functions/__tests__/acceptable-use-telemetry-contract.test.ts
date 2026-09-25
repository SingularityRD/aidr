// Contract suite for Browser Guard acceptable-use acknowledgements
// (docs/contracts/privacy-telemetry.md, "aup_acknowledgement"): the ingest
// projection keeps the site enum, the notice identifier and the version only.
import { describe, expect, it } from "vitest";
import { AUP_ACK_EVENT_KEYS, buildAupAckEvent, sanitizeAupAckEvent } from "../../../packages/browser-guard/src/background/telemetry.ts";
import { AUP_NOTICE_ID_PATTERN, MAX_AUP_NOTICE_VERSION, normalizeIngestEvents } from "../ingest/events.ts";

function ack(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		event_id: "bg:6f2c1d9a-3b4e-4c5d-8e7f-0a1b2c3d4e5f",
		event_type: "aup_acknowledgement",
		timestamp: "2026-09-24T10:16:00Z",
		site: "chatgpt",
		notice_id: "acme-aup",
		notice_version: 3,
		...overrides,
	};
}

function project(event: Record<string, unknown>) {
	const result = normalizeIngestEvents([event]);
	if (!result.ok) return { rejected: result.detail };
	return result.events[0];
}

describe("aup_acknowledgement ingest projection", () => {
	it("stores the contract example as site, notice id and version only", () => {
		expect(project(ack({ notice_text: "Never paste customer records", url: "https://chat.example/c/1", user: "alice" })))
			.toEqual({
				event_id: "bg:6f2c1d9a-3b4e-4c5d-8e7f-0a1b2c3d4e5f",
				type: "aup_acknowledgement",
				timestamp: "2026-09-24T10:16:00.000Z",
				site: "chatgpt",
				notice_id: "acme-aup",
				notice_version: 3,
			});
	});

	it("files an unknown site under other and refuses malformed notice fields", () => {
		expect(project(ack({ site: "https://chat.example" }))).toMatchObject({ site: "other" });
		for (const [overrides, field] of [
			[{ notice_id: undefined }, "notice_id"],
			[{ notice_id: "has space" }, "notice_id"],
			[{ notice_id: "x".repeat(65) }, "notice_id"],
			[{ notice_id: "sk-proj-secret" }, "notice_id"],
			[{ notice_version: 0 }, "notice_version"],
			[{ notice_version: 1.5 }, "notice_version"],
			[{ notice_version: "3" }, "notice_version"],
			[{ notice_version: MAX_AUP_NOTICE_VERSION + 1 }, "notice_version"],
		] as const) {
			expect(project(ack(overrides as Record<string, unknown>))).toEqual({ rejected: `events[0].${field}` });
		}
	});

	it("agrees with the Browser Guard client on the event shape", () => {
		const built = buildAupAckEvent({ site: "gemini", noticeId: "acme-aup", noticeVersion: 7 }, Date.parse("2026-09-24T10:00:00Z"));
		expect(built).not.toBeNull();
		expect(Object.keys(built ?? {}).sort()).toEqual([...AUP_ACK_EVENT_KEYS].sort());
		expect(project(built as unknown as Record<string, unknown>)).toEqual({
			event_id: built?.event_id,
			type: "aup_acknowledgement",
			timestamp: "2026-09-24T10:00:00.000Z",
			site: "gemini",
			notice_id: "acme-aup",
			notice_version: 7,
		});
		expect(AUP_NOTICE_ID_PATTERN.test("acme-aup")).toBe(true);
		expect(sanitizeAupAckEvent({ ...built, notice_text: "x" })).toBeNull();
	});
});
