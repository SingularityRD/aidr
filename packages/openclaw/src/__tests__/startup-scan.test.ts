import { describe, expect, it } from "vitest";
import { createBeforePromptBuildHandler } from "../startup-scan.js";

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
		expect(messages).toContain(
			"AIDR: surfacing plugin scan findings via before_prompt_build",
		);
	});
});
