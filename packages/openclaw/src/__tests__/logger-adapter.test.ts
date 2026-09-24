import { describe, expect, it } from "vitest";
import { createLogger } from "../logger-adapter.js";

describe("OpenClaw logger adapter", () => {
	it("redacts credentials and raw prompt content before forwarding to the host", () => {
		const output: string[] = [];
		const logger = createLogger({
			info: (message) => output.push(message),
			warn: (message) => output.push(message),
			error: (message) => output.push(message),
		});

		logger.warn("request failed: Authorization: Bearer raw-secret", {
			prompt: "private prompt text",
			url: "https://example.test/?token=raw-secret",
			status: "failed",
		});

		expect(output).toHaveLength(1);
		expect(output[0]).toContain("[Redacted]");
		expect(output[0]).toContain("failed");
		expect(output[0]).not.toContain("raw-secret");
		expect(output[0]).not.toContain("private prompt text");
	});
});
