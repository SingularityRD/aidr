import { describe, expect, it } from "vitest";
import { detectPII, maskPII, validateNoPII } from "../pii-detector.js";

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
		const result = detectPII("Card: 4111-1111-1111-1111");
		expect(result.hasCritical).toBe(true);
	});

	it("reports only Luhn-valid digit runs as card numbers", () => {
		// 4111 1111 1111 1111 is the public Visa test number (Luhn-valid).
		expect(
			detectPII("Card: 4111 1111 1111 1111").findings.some((f) => f.type === "credit_card"),
		).toBe(true);
		// A UUID whose digit run once made the MCP gateway block its own request id.
		const uuid = detectPII("aidr-list-80603057-4456-4755-8776-0272150cd499");
		expect(uuid.findings.some((f) => f.type === "credit_card")).toBe(false);
		expect(detectPII("order 1234567890123").findings.some((f) => f.type === "credit_card")).toBe(
			false,
		);
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

	it("should mask PII partially", () => {
		expect(maskPII("secretpassword123", "password")).toBe("se*************23");
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
