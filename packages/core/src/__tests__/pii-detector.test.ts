import { describe, expect, it } from "vitest";
import { detectPII, maskPII, redactPII, validateNoPII } from "../pii-detector.js";

describe("PII Detection", () => {
	it("should detect email addresses", () => {
		const result = detectPII("Contact me at user@example.com");
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].type).toBe("email");
		expect(result.findings[0].value).toBe("user@example.com");
		expect(result.findings[0].severity).toBe("high");
	});

	it("should detect phone numbers", () => {
		const result = detectPII("Call 555-123-4567");
		expect(result.findings.some((f) => f.type === "phone")).toBe(true);
	});

	it("should detect SSNs", () => {
		const result = detectPII("SSN: 123-45-6789");
		expect(result.hasCritical).toBe(true);
		expect(result.findings.some((f) => f.type === "ssn")).toBe(true);
	});

	it("should detect credit card numbers", () => {
		const result = detectPII("Card: 4532-1234-5678-9012");
		expect(result.hasCritical).toBe(true);
	});

	it("should detect API keys", () => {
		const result = detectPII(["api_key:", " sk_live", "_1234567", "890abcde", "f"].join(""));
		expect(result.hasCritical).toBe(true);
	});

	it("should detect AWS access keys", () => {
		const result = detectPII("AKIAIOSFODNN7EXAMPLE");
		expect(result.findings.some((f) => f.type === "aws_access_key")).toBe(true);
	});

	it("should detect private keys", () => {
		const result = detectPII("-----BEGIN RSA PRIVATE KEY-----\nMII...");
		expect(result.hasCritical).toBe(true);
	});

	it("should redact all PII", () => {
		const text = "Email: user@example.com, Phone: 555-123-4567";
		const result = detectPII(text);
		expect(result.redacted).not.toContain("user@example.com");
		expect(result.redacted).not.toContain("555-123-4567");
		expect(result.redacted).toContain("[REDACTED_EMAIL]");
		expect(result.redacted).toContain("[REDACTED_PHONE]");
	});

	it("masks PII with a fixed placeholder that reveals no characters", () => {
		expect(maskPII("secretpassword123", "password")).toBe("[MASKED_PASSWORD]");
		expect(maskPII("x", "password")).toBe("[MASKED_PASSWORD]");
	});

	it("redacts overlapping findings as one merged span", () => {
		const text = "pay 4111-1111-1111-1111 now";
		const findings = [
			{
				type: "credit_card",
				value: "4111-1111-1111-1111",
				index: 4,
				severity: "critical" as const,
			},
			{ type: "phone", value: "1111-1111", index: 9, severity: "high" as const },
			{ type: "ssn", value: "111-1111-1111", index: 10, severity: "critical" as const },
		];
		expect(redactPII(text, findings)).toBe("pay [REDACTED_CREDIT_CARD] now");
		// Order of the input list must not matter.
		expect(redactPII(text, [...findings].reverse())).toBe("pay [REDACTED_CREDIT_CARD] now");
	});

	it("covers the union of partially overlapping findings", () => {
		const text = "abcdefghij";
		const redacted = redactPII(text, [
			{ type: "phone", value: "cdef", index: 2, severity: "high" },
			{ type: "api_key", value: "efgh", index: 4, severity: "critical" },
		]);
		expect(redacted).toBe("ab[REDACTED_API_KEY]ij");
	});

	it("redacts every finding detectPII reports without leaving fragments", () => {
		const text = "Card 4532 1234 5678 9012 and SSN 123-45-6789";
		const { redacted } = detectPII(text);
		expect(redacted).not.toMatch(/\d{3}/);
	});

	it("should throw on critical PII validation", () => {
		expect(() => validateNoPII("SSN: 123-45-6789", "log message")).toThrow();
	});

	it("should not throw on safe content", () => {
		expect(() => validateNoPII("Hello world", "log message")).not.toThrow();
	});

	it("should handle multiple PII types", () => {
		const text = [
			"\n      U",
			"ser: joh",
			"n@exampl",
			"e.com\n  ",
			"    Phon",
			"e: (555)",
			" 123-456",
			"7\n      ",
			"SSN: 123",
			"-45-6789",
			"\n      A",
			"PI Key: ",
			"sk_live_",
			"abc123de",
			"f456\n   ",
			" ",
		].join("");
		const result = detectPII(text);
		expect(result.findings.length).toBeGreaterThanOrEqual(4);
		expect(result.hasCritical).toBe(true);
		expect(result.hasHigh).toBe(true);
	});
});
