import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "../policy.js";
import { ConfigSchema } from "../types.js";

describe("runtime default policy enforcement", () => {
	it("asks for benign commands when command default requires approval", async () => {
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				runtime_defaults: {
					command_action: "require_approval",
				},
			},
		});

		const verdict = await evaluatePolicy("Bash", [{ type: "command", value: "npm test" }], config, {
			command: "npm test",
		});

		expect(verdict?.decision).toBe("ask");
		expect(verdict?.category).toBe("command_execution");
		expect(verdict?.matchedThreatId).toBe("POL-DEFAULT-CMD-001");
	});

	it("applies package defaults before command defaults for package-manager commands", async () => {
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				runtime_defaults: {
					command_action: "require_approval",
					package_action: "block",
				},
			},
		});

		const verdict = await evaluatePolicy(
			"Bash",
			[{ type: "command", value: "npm install left-pad" }],
			config,
			{ command: "npm install left-pad" },
		);

		expect(verdict?.decision).toBe("deny");
		expect(verdict?.category).toBe("supply_chain");
		expect(verdict?.matchedThreatId).toBe("POL-DEFAULT-PKG-001");
		expect(verdict?.artifacts.join(" ")).toContain("left-pad");
	});

	it("uses file, url, and output defaults for matching artifacts", async () => {
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				runtime_defaults: {
					file_action: "require_approval",
					url_action: "block",
					output_action: "require_approval",
				},
			},
		});

		const fileVerdict = await evaluatePolicy(
			"Write",
			[{ type: "file_path", value: ".env" }],
			config,
			{
				file_path: ".env",
			},
		);
		const urlVerdict = await evaluatePolicy(
			"WebFetch",
			[{ type: "url", value: "https://example.test" }],
			config,
			{},
		);
		const outputVerdict = await evaluatePolicy(
			"PostToolUse",
			[{ type: "content", value: "token=abc", context: "agent_output" }],
			config,
			{},
		);

		expect(fileVerdict?.matchedThreatId).toBe("POL-DEFAULT-FILE-001");
		expect(fileVerdict?.decision).toBe("ask");
		expect(urlVerdict?.matchedThreatId).toBe("POL-DEFAULT-URL-001");
		expect(urlVerdict?.decision).toBe("deny");
		expect(outputVerdict?.matchedThreatId).toBe("POL-DEFAULT-OUT-001");
		expect(outputVerdict?.decision).toBe("ask");
	});
});
