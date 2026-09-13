/**
 * The user-visible block message must report what the runtime DID.
 *
 * A response action that only appears in a log is effectively invisible: the
 * person whose file was copied needs to be told, at the moment they are blocked,
 * that a copy exists and where it is.
 */

import { describe, expect, it } from "vitest";
import { formatAskMessage, formatDenyMessage } from "../guard.js";
import type { ResponseActionRecord } from "../response-actions.js";
import type { Verdict } from "../types.js";

const verdict: Verdict = {
	decision: "deny",
	category: "secrets",
	confidence: 0.95,
	severity: "warning",
	source: "heuristic",
	artifacts: [],
	matchedThreatId: "CLT-FILE-002",
	reasons: ["Access SSH key or config file"],
};

const success: ResponseActionRecord = {
	action: "snapshot",
	outcome: "success",
	target: "/home/u/.ssh/authorized_keys",
	vaultPath: "/home/u/.aidr/response-vault/2026_x_authorized_keys",
	bytes: 42,
};

const failure: ResponseActionRecord = {
	action: "snapshot",
	outcome: "failure",
	target: "/home/u/.ssh/authorized_keys",
	reason: "snapshot_failed",
	detail: "EACCES",
};

describe("formatDenyMessage", () => {
	it("is unchanged when no response action ran", () => {
		const message = formatDenyMessage(verdict);
		expect(message).toContain("Singularity AIDR blocked this action.");
		expect(message).not.toContain("Response:");
	});

	it("tells the user what was preserved and where", () => {
		const message = formatDenyMessage(verdict, [success]);
		expect(message).toContain("Response:");
		expect(message).toContain("preserved a copy of");
		expect(message).toContain("/home/u/.ssh/authorized_keys");
		expect(message).toContain(success.vaultPath as string);
	});

	it("says plainly when a response action FAILED, so the user does not assume it worked", () => {
		const message = formatDenyMessage(verdict, [failure]);
		expect(message).toContain("failed");
		expect(message).toContain("nothing was preserved");
	});

	it("still blocks and reports for a skipped action", () => {
		const skipped: ResponseActionRecord = {
			action: "snapshot",
			outcome: "skipped",
			target: "/home/u/.ssh/authorized_keys",
			reason: "target_absent",
		};
		const message = formatDenyMessage(verdict, [skipped]);
		expect(message).toContain("blocked this action");
		// A skip is not a failure; it should not claim something went wrong.
		expect(message).not.toContain("nothing was preserved");
	});
});

describe("formatAskMessage", () => {
	it("keeps the approval contract and adds the response line", () => {
		const message = formatAskMessage("a".repeat(64), verdict, [], [success]);
		expect(message).toContain("pending explicit user approval");
		expect(message).toContain("You cannot approve this action yourself");
		expect(message).toContain("Response:");
		expect(message).toContain("preserved a copy of");
	});

	it("omits the response line when nothing ran", () => {
		const message = formatAskMessage("a".repeat(64), verdict, []);
		expect(message).not.toContain("Response:");
	});
});
