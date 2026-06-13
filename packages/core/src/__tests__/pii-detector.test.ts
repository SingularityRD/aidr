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
		const result = detectPII("Card: 4532-1234-5678-9012");
		expect(result.hasCritical).toBe(true);
	});

	it("should detect API keys", () => {
		const result = detectPII("api_key: sk_live_1234567890abcdef");
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
		const text = `
      User: john@example.com
      Phone: (555) 123-4567
      SSN: 123-45-6789
      API Key: sk_live_abc123def456
    `;
		const result = detectPII(text);
		expect(result.findings.length).toBeGreaterThanOrEqual(4);
		expect(result.hasCritical).toBe(true);
		expect(result.hasHigh).toBe(true);
	});
});
