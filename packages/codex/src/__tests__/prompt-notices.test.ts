/**
 * Codex has no session-start hook, so the first prompt carries the first-run
 * privacy notice (D4) and dashboard decision notices (D8), for the user only.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { codexPromptNotices, withUserNotice } from "../prompt-protection.js";

describe("withUserNotice", () => {
	it("adds the notice to an allow and to a warning, never to the model context", () => {
		expect(withUserNotice(null, "NOTICE")).toEqual({ systemMessage: "NOTICE" });
		const warned = withUserNotice(
			{
				systemMessage: "personal data found",
				hookSpecificOutput: { hookEventName: "UserPromptSubmit", additionalContext: "ctx" },
			},
			"NOTICE",
		);
		expect(warned?.systemMessage).toBe("personal data found\nNOTICE");
		expect(warned?.hookSpecificOutput?.additionalContext).toBe("ctx");
	});

	it("leaves a block and an empty notice alone", () => {
		const block = { decision: "block" as const, reason: "secret" };
		expect(withUserNotice(block, "NOTICE")).toBe(block);
		expect(withUserNotice(null, null)).toBeNull();
	});
});

describe("codexPromptNotices", () => {
	it("shows the privacy notice on the first prompt only", async () => {
		const aidrDir = mkdtempSync(join(tmpdir(), "aidr-codex-notice-"));
		try {
			const first = await codexPromptNotices({ aidrDir, unprotectedTools: [] });
			expect(first).toContain("What it does not guard");
			expect(await codexPromptNotices({ aidrDir, unprotectedTools: [] })).toBeNull();
		} finally {
			rmSync(aidrDir, { recursive: true, force: true });
		}
	});
});
