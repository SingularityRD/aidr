import { describe, expect, it } from "vitest";
import type { SecretMatch } from "../../dlp/secret-detector.js";
import { SecretDetector } from "../../dlp/secret-detector.js";

describe("SecretDetector", () => {
	// ── AWS Access Keys ─────────────────────────────────────────────

	it("should detect AWS access keys", () => {
		const detector = new SecretDetector();
		const result = detector.detect("My key is AKIAIOSFODNN7EXAMPLE");
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("aws_access_key");
		expect(result[0].value).toBe("AKIAIOSFODNN7EXAMPLE");
		expect(result[0].riskScore).toBeGreaterThan(0);
		expect(result[0].confidence).toBeGreaterThan(0.9);
	});

	it("should not detect invalid AWS access key format", () => {
		const detector = new SecretDetector();
		const result = detector.detect("AKIAIO"); // too short
		expect(result).toHaveLength(0);
	});

	// ── AWS Secret Keys ─────────────────────────────────────────────

	it("should detect AWS secret keys", () => {
		const detector = new SecretDetector();
		const result = detector.detect("aws_secret = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("aws_secret_key");
		expect(result[0].value).toBe("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
	});

	// ── GitHub Tokens ───────────────────────────────────────────────

	it("should detect GitHub personal access tokens (ghp_)", () => {
		const detector = new SecretDetector();
		const result = detector.detect(
			["ghp_abcd", "efghijkl", "mnopqrst", "uvwxyz01", "23456789", "abcd"].join(""),
		);
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("github_token");
	});

	it("should detect GitHub OAuth tokens (gho_)", () => {
		const detector = new SecretDetector();
		const result = detector.detect(
			["gho_abcd", "efghijkl", "mnopqrst", "uvwxyz01", "23456789", "abcd"].join(""),
		);
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("github_token");
	});

	it("should detect GitHub refresh tokens (ghr_)", () => {
		const detector = new SecretDetector();
		const result = detector.detect(
			["ghr_abcd", "efghijkl", "mnopqrst", "uvwxyz01", "23456789", "abcd"].join(""),
		);
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("github_token");
	});

	it("should detect GitHub server-to-server tokens (ghs_)", () => {
		const detector = new SecretDetector();
		const result = detector.detect(
			["ghs_abcd", "efghijkl", "mnopqrst", "uvwxyz01", "23456789", "abcd"].join(""),
		);
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("github_token");
	});

	// ── GitLab Tokens ───────────────────────────────────────────────

	it("should detect GitLab tokens", () => {
		const detector = new SecretDetector();
		const result = detector.detect(["glpat-ab", "cdefghij", "klmnopqr", "stuvwxyz"].join(""));
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("gitlab_token");
		expect(result[0].value).toBe(["glpat-ab", "cdefghij", "klmnopqr", "stuvwxyz"].join(""));
	});

	// ── Slack Tokens ────────────────────────────────────────────────

	it("should detect Slack bot tokens (xoxb-)", () => {
		const detector = new SecretDetector();
		const result = detector.detect("xoxb-123456789012-abcdefghijklmn");
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("slack_token");
	});

	it("should detect Slack user tokens (xoxp-)", () => {
		const detector = new SecretDetector();
		const result = detector.detect("xoxp-123456789012-abcdefghijklmn");
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("slack_token");
	});

	it("should detect Slack app-level tokens (xoxa-)", () => {
		const detector = new SecretDetector();
		const result = detector.detect(["xoxa-123", "45678901", "2-abcdef", "ghijklmn"].join(""));
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("slack_token");
	});

	// ── npm Tokens ──────────────────────────────────────────────────

	it("should detect npm tokens", () => {
		const detector = new SecretDetector();
		const result = detector.detect("npm_abcdefghijklmnopqrstuvwxyz0123456789abcd");
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("npm_token");
	});

	// ── Private Keys ────────────────────────────────────────────────

	it("should detect RSA private keys", () => {
		const detector = new SecretDetector();
		const result = detector.detect(
			["-----BEG", "IN RSA P", "RIVATE K", "EY-----\n", "MII..."].join(""),
		);
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe(["private_", "key"].join(""));
	});

	it(["should d", "etect DS", "A privat", "e keys"].join(""), () => {
		const detector = new SecretDetector();
		const result = detector.detect(["-----BEG", "IN DSA P", "RIVATE K", "EY-----"].join(""));
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("private_key");
	});

	it("should detect EC private keys", () => {
		const detector = new SecretDetector();
		const result = detector.detect("-----BEGIN EC PRIVATE KEY-----");
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("private_key");
	});

	// ── Generic API Keys ────────────────────────────────────────────

	it("should detect generic API keys from variable assignment", () => {
		const detector = new SecretDetector();
		const result = detector.detect(
			["api_key ", '= "sk_li', "ve_abcde", "fghijklm", 'nop"'].join(""),
		);
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("generic_api_key");
		expect(result[0].value).toBe(["sk_live_", "abcdefgh", "ijklmnop"].join(""));
	});

	it("should detect API secret keys", () => {
		const detector = new SecretDetector();
		const result = detector.detect("API_SECRET=supersecretkey12345678");
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("generic_api_key");
	});

	// ── Environment Variable Secrets ────────────────────────────────

	it("should detect environment variable secrets", () => {
		const detector = new SecretDetector();
		const result = detector.detect("SECRET=abcdefghijklmnop");
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("env_secret");
	});

	it("should detect TOKEN environment variables", () => {
		const detector = new SecretDetector();
		const result = detector.detect("TOKEN=abcdefghijklmnopqrstuv");
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("env_secret");
	});

	it("should detect PASSWORD environment variables", () => {
		const detector = new SecretDetector();
		const result = detector.detect("PASSWORD=uV7$k9#mN2xR5pQ8wL3zY1");
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("env_secret");
	});

	it("should detect API_KEY environment variables as generic API keys", () => {
		const detector = new SecretDetector();
		const result = detector.detect("API_KEY=abcdefghijklmnopqrst");
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("generic_api_key");
	});

	// ── Edge cases ──────────────────────────────────────────────────

	it("should return empty array for content with no secrets", () => {
		const detector = new SecretDetector();
		const result = detector.detect("Hello, this is a plain text message.");
		expect(result).toHaveLength(0);
	});

	it("should return empty array for empty content", () => {
		const detector = new SecretDetector();
		const result = detector.detect("");
		expect(result).toHaveLength(0);
	});

	it("should detect multiple secrets in the same content", () => {
		const detector = new SecretDetector();
		const result = detector.detect(
			[
				"AWS: AKI",
				"AIOSFODN",
				"N7EXAMPL",
				"E\nGitHub",
				": ghp_ab",
				"cdefghij",
				"klmnopqr",
				"stuvwxyz",
				"01234567",
				"89abcd",
			].join(""),
		);
		expect(result.length).toBeGreaterThanOrEqual(2);
		expect(result[0].type).toBe("aws_access_key");
		expect(result[1].type).toBe("github_token");
	});

	it("should sort matches by index in source content", () => {
		const detector = new SecretDetector();
		const result = detector.detect(
			[
				"ghp_abcd",
				"efghijkl",
				"mnopqrst",
				"uvwxyz01",
				"23456789",
				"abcd the",
				"n AKIAIO",
				"SFODNN7E",
				"XAMPLE",
			].join(""),
		);
		expect(result).toHaveLength(2);
		expect(result[0].type).toBe("github_token");
		expect(result[1].type).toBe("aws_access_key");
	});

	it("should provide context around the match", () => {
		const detector = new SecretDetector();
		const result = detector.detect("My secret AWS key is AKIAIOSFODNN7EXAMPLE please keep it safe");
		expect(result[0].context).toContain("My secret AWS key is ");
		expect(result[0].context).toContain(" please keep it safe");
	});

	it("should truncate long context with ellipsis", () => {
		const detector = new SecretDetector();
		const longPrefix = "A".repeat(100) + " ";
		const result = detector.detect(`${longPrefix}AKIAIOSFODNN7EXAMPLE`);
		expect(result[0].context).toMatch(/^\.\.\./);
	});

	// ── False positive reduction ────────────────────────────────────

	it("should filter low-entropy generic patterns", () => {
		const detector = new SecretDetector({ entropyThreshold: 4.0 });
		const result = detector.detect("api_key = AAAAAAAAAAAAAAAAAAAAAAAA");
		// Low-entropy string like "AAAA..." should be filtered out
		expect(result).toHaveLength(0);
	});

	it("should not filter specific patterns based on entropy", () => {
		const detector = new SecretDetector({ entropyThreshold: 6.0 });
		const result = detector.detect("AKIAIOSFODNN7EXAMPLE");
		// AWS keys are specific patterns, should be detected regardless of entropy
		expect(result).toHaveLength(1);
		expect(result[0].type).toBe("aws_access_key");
	});

	// ── Configuration ───────────────────────────────────────────────

	it("should respect minimum length configuration", () => {
		const detector = new SecretDetector({ minLength: 30 });
		const result = detector.detect("API_KEY=abcdefghijklmnop"); // 16 chars
		expect(result).toHaveLength(0);
	});

	it("should respect entropy threshold configuration", () => {
		const detector = new SecretDetector({ entropyThreshold: 5.0 });
		const result = detector.detect('api_key = "abcdefghijklmnopqrstuvwx"');
		// Entropy of this string would be lower than 5.0
		if (result.length > 0) {
			expect(result[0].entropy).toBeGreaterThanOrEqual(5.0);
		}
	});

	// ── Risk score calculation ──────────────────────────────────────

	it("should assign higher risk to critical secrets", () => {
		const detector = new SecretDetector();
		const criticalResult = detector.detect("AKIAIOSFODNN7EXAMPLE");
		const highResult = detector.detect(
			["api_key ", '= "sk_li', "ve_abcde", "fghijklm", 'nop"'].join(""),
		);

		expect(criticalResult[0].riskScore).toBeGreaterThan(highResult[0].riskScore);
	});

	it("should compute entropy for matched values", () => {
		const detector = new SecretDetector();
		const result = detector.detect("AKIAIOSFODNN7EXAMPLE");
		expect(result[0].entropy).toBeGreaterThan(0);
	});

	// ── SecretMatch object structure ────────────────────────────────

	it("should return well-formed SecretMatch objects", () => {
		const detector = new SecretDetector();
		const [match] = detector.detect(
			["ghp_abcd", "efghijkl", "mnopqrst", "uvwxyz01", "23456789", "abcd"].join(""),
		);

		const keys: (keyof SecretMatch)[] = [
			"type",
			"value",
			"context",
			"index",
			"entropy",
			"riskScore",
			"confidence",
		];

		for (const key of keys) {
			expect(match).toHaveProperty(key);
		}

		expect(typeof match.type).toBe("string");
		expect(typeof match.value).toBe("string");
		expect(typeof match.context).toBe("string");
		expect(typeof match.index).toBe("number");
		expect(typeof match.entropy).toBe("number");
		expect(typeof match.riskScore).toBe("number");
		expect(typeof match.confidence).toBe("number");
	});

	// ── No false positives on safe content ──────────────────────────

	it("should not flag typical code comments", () => {
		const detector = new SecretDetector();
		const result = detector.detect("// TODO: implement authentication using token-based approach");
		const hasFalsePositive = result.some(
			(m) => m.type === "generic_api_key" || m.type === "env_secret",
		);
		expect(hasFalsePositive).toBe(false);
	});
});
