import { describe, expect, it } from "vitest";
import { readErrorMessage } from "../lib/errors";

describe("public dashboard errors", () => {
	it("keeps stable public error codes", () => {
		expect(readErrorMessage(new Error("policy_document_save_failed"), "Save failed")).toBe(
			"policy_document_save_failed",
		);
	});

	it("does not expose backend or credential details", () => {
		expect(
			readErrorMessage(
				{ message: "permission denied for table team_policies" },
				"Failed to load policy",
			),
		).toBe("Failed to load policy");
		expect(
			readErrorMessage(new Error("request https://api.test?token=secret failed"), "Request failed"),
		).toBe("Request failed");
		expect(
			readErrorMessage(
				Object.assign(new Error("upstream included a private tenant"), { status: 503 }),
				"Request failed",
			),
		).toBe("Request failed");
	});

	it("keeps locally-authored failure descriptions", () => {
		expect(readErrorMessage(new Error("Dashboard query timed out."), "Request failed")).toBe(
			"Dashboard query timed out.",
		);
	});
});
