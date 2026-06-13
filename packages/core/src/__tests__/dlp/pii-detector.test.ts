import { describe, expect, it } from "vitest";
import type { PiiMatch } from "../../dlp/pii-detector.js";
import {
	calculateConfidence,
	luhnCheck,
	PiiDetectorConfigSchema,
	PiiDetectorImpl,
	PiiMatchSchema,
	PiiTypeSchema,
	shannonEntropy,
} from "../../dlp/pii-detector.js";

// ── Schema Validation ───────────────────────────────────────────────────

describe("PiiTypeSchema", () => {
	it("accepts valid PII types", () => {
		expect(PiiTypeSchema.parse("ssn")).toBe("ssn");
		expect(PiiTypeSchema.parse("credit_card")).toBe("credit_card");
		expect(PiiTypeSchema.parse("email")).toBe("email");
		expect(PiiTypeSchema.parse("phone")).toBe("phone");
		expect(PiiTypeSchema.parse("ip_address")).toBe("ip_address");
		expect(PiiTypeSchema.parse("aws_key")).toBe("aws_key");
		expect(PiiTypeSchema.parse("api_key")).toBe("api_key");
	});

	it("rejects invalid PII types", () => {
		expect(() => PiiTypeSchema.parse("password")).toThrow();
		expect(() => PiiTypeSchema.parse("")).toThrow();
	});
});

describe("PiiMatchSchema", () => {
	it("accepts a valid match object", () => {
		const match: PiiMatch = {
			type: "email",
			value: "a@b.com",
			start: 0,
			end: 7,
			confidence: 0.9,
			severity: "high",
		};
		expect(() => PiiMatchSchema.parse(match)).not.toThrow();
	});

	it("rejects a match with negative start", () => {
		expect(() =>
			PiiMatchSchema.parse({
				type: "email",
				value: "a@b.com",
				start: -1,
				end: 7,
				confidence: 0.9,
				severity: "high",
			}),
		).toThrow();
	});

	it("rejects confidence out of range", () => {
		expect(() =>
			PiiMatchSchema.parse({
				type: "email",
				value: "a@b.com",
				start: 0,
				end: 7,
				confidence: 1.5,
				severity: "high",
			}),
		).toThrow();
	});
});

describe("PiiDetectorConfigSchema", () => {
	it("applies defaults for empty input", () => {
		const config = PiiDetectorConfigSchema.parse({});
		expect(config.enableSsn).toBe(true);
		expect(config.enableCreditCard).toBe(true);
		expect(config.enableEmail).toBe(true);
		expect(config.enablePhone).toBe(true);
		expect(config.enableIpAddress).toBe(true);
		expect(config.enableAwsKey).toBe(true);
		expect(config.enableApiKey).toBe(true);
		expect(config.minConfidence).toBe(0.5);
		expect(config.entropyThreshold).toBe(4.5);
	});

	it("accepts partial overrides", () => {
		const config = PiiDetectorConfigSchema.parse({ enableSsn: false, minConfidence: 0.8 });
		expect(config.enableSsn).toBe(false);
		expect(config.enableEmail).toBe(true); // default
		expect(config.minConfidence).toBe(0.8);
	});

	it("rejects out-of-range minConfidence", () => {
		expect(() => PiiDetectorConfigSchema.parse({ minConfidence: 1.5 })).toThrow();
		expect(() => PiiDetectorConfigSchema.parse({ minConfidence: -0.1 })).toThrow();
	});
});

// ── Luhn Check ──────────────────────────────────────────────────────────

describe("luhnCheck", () => {
	it("validates a correct Visa number", () => {
		expect(luhnCheck("4111111111111111")).toBe(true);
	});

	it("validates a correct Mastercard number", () => {
		expect(luhnCheck("5500000000000004")).toBe(true);
	});

	it("validates a correct Amex number", () => {
		expect(luhnCheck("340000000000009")).toBe(true);
	});

	it("validates a correct Discover number", () => {
		expect(luhnCheck("6011111111111117")).toBe(true);
	});

	it("rejects an invalid number", () => {
		expect(luhnCheck("1234567890123456")).toBe(false);
	});

	it("rejects strings with fewer than 13 digits", () => {
		expect(luhnCheck("123")).toBe(false);
	});

	it("rejects empty string", () => {
		expect(luhnCheck("")).toBe(false);
	});

	it("strips non-digit characters before check", () => {
		expect(luhnCheck("4111-1111-1111-1111")).toBe(true);
	});
});

// ── Shannon Entropy ─────────────────────────────────────────────────────

describe("shannonEntropy", () => {
	it("returns 0 for empty string", () => {
		expect(shannonEntropy("")).toBe(0);
	});

	it("returns 0 for single repeated character", () => {
		expect(shannonEntropy("aaa")).toBe(0);
	});

	it("returns higher entropy for varied strings", () => {
		const low = shannonEntropy("aaaaaaaabbbb");
		const high = shannonEntropy("aB3!xY9$zW1+qR8");
		expect(high).toBeGreaterThan(low);
	});

	it("returns log2 of unique chars for uniform distribution", () => {
		const entropy = shannonEntropy("abcd");
		// Each of 4 unique chars appears once → p=0.25 → entropy = 4 * -(0.25*log2(0.25)) = 2
		expect(entropy).toBeCloseTo(2, 5);
	});
});

// ── Confidence Calculation ──────────────────────────────────────────────

describe("calculateConfidence", () => {
	it("returns base confidence for low-entropy value", () => {
		// Use a simple pattern def for testing
		const def = {
			type: "email" as const,
			regex: /foo/g,
			severity: "high" as const,
			confidenceBase: 0.9,
		};
		const confidence = calculateConfidence("aaaaaa", def, 4.5);
		expect(confidence).toBe(0.9);
	});

	it("adds entropy bonus for high-entropy value", () => {
		const def = {
			type: "aws_key" as const,
			regex: /foo/g,
			severity: "critical" as const,
			confidenceBase: 0.8,
		};
		// High-entropy mixed-case alphanumeric string
		const confidence = calculateConfidence("AKIAaB3xY9zW1qR8mK2p", def, 3.5);
		expect(confidence).toBeGreaterThan(0.8);
	});
});

// ── PiiDetectorImpl — Core Detection ─────────────────────────────────────────

describe("PiiDetectorImpl", () => {
	describe("constructor", () => {
		it("applies default config when no argument given", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("test@example.com");
			expect(results.length).toBeGreaterThan(0);
		});

		it("accepts a partial config object", () => {
			const detector = new PiiDetectorImpl({ enableEmail: false });
			const results = detector.detect("test@example.com");
			expect(results).toHaveLength(0);
		});
	});

	describe("SSN detection", () => {
		it("detects standard SSN format", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("My SSN is 123-45-6789");
			expect(results.some((m) => m.type === "ssn")).toBe(true);
			expect(results.some((m) => m.value === "123-45-6789")).toBe(true);
		});

		it("detects SSN without dashes", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("SSN: 123456789");
			expect(results.some((m) => m.type === "ssn")).toBe(true);
		});

		it("does not flag invalid SSN prefixes (000, 666, 9xx)", () => {
			const detector = new PiiDetectorImpl({ enablePhone: false });
			expect(detector.detect("000-12-3456")).toHaveLength(0);
			expect(detector.detect("666-12-3456")).toHaveLength(0);
			expect(detector.detect("987-12-3456")).toHaveLength(0);
		});

		it("can be disabled via config", () => {
			const detector = new PiiDetectorImpl({ enableSsn: false, enablePhone: false });
			expect(detector.detect("123-45-6789")).toHaveLength(0);
		});
	});

	describe("credit card detection", () => {
		it("detects Visa card numbers", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("Card: 4111 1111 1111 1111");
			expect(results.some((m) => m.type === "credit_card")).toBe(true);
		});

		it("detects Mastercard numbers", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("MC: 5500 0000 0000 0004");
			expect(results.some((m) => m.type === "credit_card")).toBe(true);
		});

		it("detects Amex numbers", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("Amex: 3400 0000 0000 009");
			expect(results.some((m) => m.type === "credit_card")).toBe(true);
		});

		it("can be disabled via config", () => {
			const detector = new PiiDetectorImpl({ enableCreditCard: false });
			expect(detector.detect("4111111111111111")).toHaveLength(0);
		});
	});

	describe("email detection", () => {
		it("detects standard email addresses", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("Contact: user@example.com");
			expect(results.some((m) => m.type === "email")).toBe(true);
			expect(results.some((m) => m.value === "user@example.com")).toBe(true);
		});

		it("detects email with subdomain", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("user@sub.example.co.uk");
			expect(results.some((m) => m.type === "email")).toBe(true);
		});

		it("detects email with plus addressing", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("user+tag@example.com");
			expect(results.some((m) => m.type === "email")).toBe(true);
		});

		it("can be disabled via config", () => {
			const detector = new PiiDetectorImpl({ enableEmail: false });
			expect(detector.detect("user@example.com")).toHaveLength(0);
		});
	});

	describe("phone number detection", () => {
		it("detects US format (555-123-4567)", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("Call 555-123-4567");
			expect(results.some((m) => m.type === "phone")).toBe(true);
		});

		it("detects US format with parentheses", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("Call (555) 123-4567");
			expect(results.some((m) => m.type === "phone")).toBe(true);
		});

		it("detects international format", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("Call +44 20 7946 0958");
			expect(results.some((m) => m.type === "phone")).toBe(true);
		});

		it("can be disabled via config", () => {
			const detector = new PiiDetectorImpl({ enablePhone: false });
			expect(detector.detect("555-123-4567")).toHaveLength(0);
		});
	});

	describe("IP address detection", () => {
		it("detects IPv4 addresses", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("Server: 192.168.1.1");
			expect(results.some((m) => m.type === "ip_address")).toBe(true);
		});

		it("detects IPv6 loopback", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("IPv6: ::1");
			expect(results.some((m) => m.type === "ip_address")).toBe(true);
		});

		it("detects full IPv6 address", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("addr: 2001:0db8:85a3:0000:0000:8a2e:0370:7334");
			expect(results.some((m) => m.type === "ip_address")).toBe(true);
		});

		it("can be disabled via config", () => {
			const detector = new PiiDetectorImpl({ enableIpAddress: false });
			expect(detector.detect("192.168.1.1")).toHaveLength(0);
		});
	});

	describe("AWS key detection", () => {
		it("detects AKIA-format keys", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("Key: AKIAIOSFODNN7EXAMPLE");
			expect(results.some((m) => m.type === "aws_key")).toBe(true);
		});

		it("can be disabled via config", () => {
			const detector = new PiiDetectorImpl({ enableAwsKey: false });
			expect(detector.detect("AKIAIOSFODNN7EXAMPLE")).toHaveLength(0);
		});
	});

	describe("API key detection", () => {
		it("detects sk- prefixed keys", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("sk-abc123def456ghi789jkl012");
			expect(results.some((m) => m.type === "api_key")).toBe(true);
		});

		it("detects pk- prefixed keys", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("pk_live_abcdefghijklmnopqrstuv");
			expect(results.some((m) => m.type === "api_key")).toBe(true);
		});

		it("can be disabled via config", () => {
			const detector = new PiiDetectorImpl({ enableApiKey: false });
			expect(detector.detect("sk-abcdefghijklmnopqrstuvwxyz")).toHaveLength(0);
		});
	});

	describe("multi-type detection", () => {
		it("detects multiple PII types in one input", () => {
			const detector = new PiiDetectorImpl();
			const text = `
        Email: john@example.com
        Phone: (555) 123-4567
        SSN: 123-45-6789
        IP: 10.0.0.1
      `;
			const results = detector.detect(text);
			const types = new Set(results.map((m) => m.type));
			expect(types.has("email")).toBe(true);
			expect(types.has("phone")).toBe(true);
			expect(types.has("ssn")).toBe(true);
			expect(types.has("ip_address")).toBe(true);
		});

		it("sorts results by start position", () => {
			const detector = new PiiDetectorImpl();
			const text = "SSN: 123-45-6789, Email: user@example.com";
			const results = detector.detect(text);
			for (let i = 1; i < results.length; i++) {
				expect(results[i].start).toBeGreaterThanOrEqual(results[i - 1].start);
			}
		});
	});

	describe("containsPii", () => {
		it("returns true for text containing PII", () => {
			const detector = new PiiDetectorImpl();
			expect(detector.containsPii("email: test@example.com")).toBe(true);
		});

		it("returns false for clean text", () => {
			const detector = new PiiDetectorImpl();
			expect(detector.containsPii("Hello world, this is a safe message.")).toBe(false);
		});

		it("respects disabled patterns", () => {
			const detector = new PiiDetectorImpl({ enableEmail: false, enableSsn: false });
			expect(detector.containsPii("test@example.com")).toBe(false);
		});
	});

	describe("edge cases", () => {
		it("handles empty string", () => {
			const detector = new PiiDetectorImpl();
			expect(detector.detect("")).toHaveLength(0);
		});

		it("handles non-string input gracefully", () => {
			const detector = new PiiDetectorImpl();
			// @ts-expect-error — testing runtime resilience
			expect(detector.detect(null)).toHaveLength(0);
			// @ts-expect-error — testing runtime resilience
			expect(detector.detect(undefined)).toHaveLength(0);
		});

		it("does not flag very short api key patterns", () => {
			const detector = new PiiDetectorImpl({ minConfidence: 0.5 });
			// "sk-abc" is too short (only 6 chars after prefix) — won't match
			expect(detector.detect("sk-abc")).toHaveLength(0);
		});

		it("respects minConfidence threshold", () => {
			const detector = new PiiDetectorImpl({ minConfidence: 0.99 });
			// Most matches have confidence lower than 0.99
			expect(detector.detect("555-123-4567")).toHaveLength(0);
		});

		it("deduplicates overlapping matches at same position", () => {
			const detector = new PiiDetectorImpl();
			const results = detector.detect("test@example.com");
			// Should not have duplicate email entries for the same span
			const emailResults = results.filter((m) => m.type === "email");
			expect(emailResults).toHaveLength(1);
		});
	});
});
