import { describe, expect, it } from "vitest";
import { isInvalidConfig, loadConfig } from "../config.js";
import { PolicyDocumentSchema } from "../policy-document.js";
import { ConfigSchema } from "../types.js";

/**
 * Pins the exact runtime defaults ConfigSchema produces. The snapshot was
 * recorded on zod 3 before the zod 4 migration; zod 4 changed how `.default()`
 * interacts with nested objects (a default value is no longer re-parsed) and
 * with `.optional()` (inner defaults now fire inside an optional field), so any
 * drift in a security default shows up here as a snapshot diff.
 */
describe("ConfigSchema runtime defaults (zod migration parity)", () => {
	it("parses an empty config to the recorded defaults", () => {
		expect(ConfigSchema.parse({})).toMatchSnapshot();
	});

	const partials: Record<string, unknown> = {
		"empty nested blocks": {
			policy: {},
			response: {},
			cache: {},
			prompt_protection: {},
			agent_safety: {},
		},
		"nested object with one sibling set": {
			response: { actions: { snapshot_on_deny: true } },
			policy: { filesystem: { enabled: true } },
		},
		"explicit optional blocks": { cache: { encryption: {} }, privacy: {} },
		"transformed fields": {
			url_check: { timeout_seconds: 999 },
			file_check: { timeout_seconds: -1 },
			prompt_protection: { content_safety: { sexual_minors: "off" } },
		},
	};

	for (const [name, input] of Object.entries(partials)) {
		it(`parses ${name} to the recorded result`, () => {
			expect(ConfigSchema.parse(input)).toMatchSnapshot();
		});
	}

	it("parses a minimal policy document to the recorded defaults", () => {
		expect(
			PolicyDocumentSchema.parse({ version: 1, default_action: "ask", rules: [] }),
		).toMatchSnapshot();
	});

	it.each([
		["wrong scalar type", { heuristics_enabled: "yes" }],
		["unknown enum value", { sensitivity: "lenient" }],
		["out-of-range number", { agent_safety: { runaway: { window_seconds: 1 } } }],
		["unknown key in a strict block", { privacy: { required: true, extra: 1 } }],
		["non-object nested block", { policy: [] }],
	])("rejects invalid config (%s)", (_name, input) => {
		expect(ConfigSchema.safeParse(input).success).toBe(false);
	});

	it("fails closed when a present config file is invalid", async () => {
		const config = await loadConfig("unused.json", undefined, undefined, {
			raw: JSON.stringify({ sensitivity: "lenient" }),
		});
		expect(isInvalidConfig(config)).toBe(true);
		expect(config.control_plane.remote_policy_required).toBe(true);
	});
});
