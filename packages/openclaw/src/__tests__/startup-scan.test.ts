import { describe, expect, it } from "vitest";
import {
	createBeforePromptBuildHandler,
	hookSessionKey,
	MAX_PENDING_FINDINGS_SESSIONS,
	PENDING_FINDINGS_TTL_MS,
	PendingScanFindings,
} from "../startup-scan.js";

describe("OpenClaw prompt-build security findings", () => {
	it("prepends pending scan findings once through the supported hook contract", () => {
		let findings: string | null = "Detected a risky installed plugin.";
		const messages: string[] = [];
		const handler = createBeforePromptBuildHandler(
			() => findings,
			() => {
				findings = null;
			},
			{
				debug() {},
				info(message) {
					messages.push(message);
				},
				warn() {},
				error() {},
			},
		);

		expect(handler()).toEqual({
			prependContext: [
				'<security-alert source="aidr-plugin-scan">',
				"Detected a risky installed plugin.",
				"",
				"Inform the user about these security findings.",
				"</security-alert>",
			].join("\n"),
		});
		expect(handler()).toBeUndefined();
		expect(messages).toContain("AIDR: surfacing plugin scan findings via before_prompt_build");
	});
});

describe("OpenClaw pending scan findings are keyed by session", () => {
	it("delivers a session's findings only to that session, once", () => {
		const pending = new PendingScanFindings();
		pending.set("agent:main:a", "finding for a");
		expect(pending.take("agent:main:b")).toBeNull();
		expect(pending.take("agent:main:a")).toBe("finding for a");
		expect(pending.take("agent:main:a")).toBeNull();
	});

	it("delivers startup findings to the next prompt of any session", () => {
		const pending = new PendingScanFindings();
		pending.setGlobal("startup finding");
		pending.set(undefined, "no-session finding");
		pending.set("s1", "session finding");
		expect(pending.take("s2")).toBe("no-session finding");
		expect(pending.take("s1")).toBe("session finding");
	});

	it("expires and bounds findings of sessions that never prompt", () => {
		let now = 0;
		const pending = new PendingScanFindings(() => now);
		for (let index = 0; index <= MAX_PENDING_FINDINGS_SESSIONS; index++) {
			pending.set(`s${index}`, "finding");
		}
		expect(pending.sessionCount).toBe(MAX_PENDING_FINDINGS_SESSIONS);
		expect(pending.take("s0")).toBeNull();
		now += PENDING_FINDINGS_TTL_MS + 1;
		expect(pending.sessionCount).toBe(0);
	});

	it("reads the session from the hook context, then the event", () => {
		expect(hookSessionKey({ sessionKey: "k" }, { sessionId: "e" })).toBe("k");
		expect(hookSessionKey(undefined, { sessionId: "e" })).toBe("e");
		expect(hookSessionKey({}, {})).toBeUndefined();
	});
});
