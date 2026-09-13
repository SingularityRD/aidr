import { describe, expect, it } from "vitest";
import { configPathParts, displayConfigValue, parseConfigValue } from "../utils/config-values.js";

describe("CLI configuration safety", () => {
	it.each(["__proto__.polluted", "constructor.prototype.polluted", "auth..api_key"])("rejects %s", (key) => {
		expect(() => configPathParts(key)).toThrow();
		expect(({} as Record<string, unknown>).polluted).toBeUndefined();
	});
	it.each(["apiKey", "auth.api_key", "auth.enrollment_token", "licensing.private_key"])("redacts %s", (key) => expect(displayConfigValue(key, "sensitive")).toBe("[redacted]"));
	it("preserves boolean and numeric types", () => {
		expect(parseConfigValue("false")).toBe(false);
		expect(parseConfigValue("5")).toBe(5);
		expect(parseConfigValue("managed")).toBe("managed");
	});
});
