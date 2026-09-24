import { describe, expect, it } from "vitest";
import { detectPII, maskPII, validateNoPII } from "../pii-detector.js";

describe("pii-detector enhancements", () => {
	describe("JWT token detection", () => {
		it("detects a valid JWT token", () => {
			const jwt = [
				"Bearer e",
				"yJhbGciO",
				"iJIUzI1N",
				"iIsInR5c",
				"CI6IkpXV",
				"CJ9.eyJz",
				"dWIiOiIx",
				"MjM0NTY3",
				"ODkwIiwi",
				"bmFtZSI6",
				"IkpvaG4g",
				"RG9lIiwi",
				"aWF0Ijox",
				"NTE2MjM5",
				"MDIyfQ.S",
				"flKxwRJS",
				"MeKKF2QT",
				"4fwpMeJf",
				"36POk6yJ",
				"V_adQssw",
				"5c",
			].join("");
			const report = detectPII(jwt);
			expect(report.findings.some((f) => f.type === "jwt_token")).toBe(true);
		});

		it("does not flag non-JWT base64 strings", () => {
			const nonJwt = "just_some_base64_encoded_string_that_is_not_a_jwt";
			const report = detectPII(nonJwt);
			expect(report.findings.some((f) => f.type === "jwt_token")).toBe(false);
		});
	});

	describe("GitHub token detection", () => {
		it("detects GitHub personal access token (fine-grained)", () => {
			const token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
			const report = detectPII(token);
			expect(report.findings.some((f) => f.type === "github_token")).toBe(true);
		});

		it("detects GitHub OAuth token", () => {
			const token = "gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
			const report = detectPII(token);
			expect(report.findings.some((f) => f.type === "github_token")).toBe(true);
		});

		it("detects github_pat token", () => {
			const token = "github_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
			const report = detectPII(token);
			expect(report.findings.some((f) => f.type === "github_token")).toBe(true);
		});
	});

	describe("Slack webhook detection", () => {
		it("detects Slack incoming webhook URL", () => {
			const url = [
				"https://",
				"hooks.sl",
				"ack.com/",
				"services",
				"/T000000",
				"00/B0000",
				"0000/XXX",
				"XXXXXXXX",
				"XXXXXXXX",
				"XXXXX",
			].join("");
			const report = detectPII(url);
			expect(report.findings.some((f) => f.type === "slack_webhook")).toBe(true);
		});
	});

	describe("Google API key detection", () => {
		it("detects Google API key", () => {
			const key = ["AIzaSyDd", "I0hCZtE6", "vySjMm-W", "EfRq3CPz", "qKqqsHI"].join("");
			const report = detectPII(key);
			expect(report.findings.some((f) => f.type === "google_api_key")).toBe(true);
		});
	});

	describe("Anthropic API key detection", () => {
		it("detects Anthropic API key", () => {
			const key =
				"sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
			const report = detectPII(key);
			expect(report.findings.some((f) => f.type === "api_key")).toBe(true);
		});
	});

	describe("HuggingFace token detection", () => {
		it("detects HuggingFace access token", () => {
			const token = "hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
			const report = detectPII(token);
			expect(report.findings.some((f) => f.type === "huggingface_token")).toBe(true);
		});
	});

	describe("Bearer token detection", () => {
		it("detects Bearer authorization header", () => {
			const header = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
			const report = detectPII(header);
			expect(report.findings.some((f) => f.type === "bearer_token")).toBe(true);
		});
	});

	describe("Generic secret assignment detection", () => {
		it("detects SECRET= assignment", () => {
			const line = 'SECRET="my_super_secret_value_12345678"';
			const report = detectPII(line);
			expect(report.findings.some((f) => f.type === "secret_assignment")).toBe(true);
		});

		it("detects PASSWORD= assignment", () => {
			const line = "PASSWORD='hunter2_is_strong'";
			const report = detectPII(line);
			expect(report.findings.some((f) => f.type === "secret_assignment")).toBe(true);
		});

		it("detects unquoted API_KEY assignment", () => {
			const line = ["API_KEY=", "abcdefgh", "ijklmnop", "qrstuvwx", "yz123456"].join("");
			const report = detectPII(line);
			expect(report.findings.some((f) => f.type === "secret_assignment")).toBe(true);
		});
	});

	describe("Redaction correctness", () => {
		it("redacts all detected secrets without leaking them", () => {
			const jwt = [
				"eyJhbGci",
				"OiJIUzI1",
				"NiIsInR5",
				"cCI6IkpX",
				"VCJ9.eyJ",
				"zdWIiOiI",
				"xMjM0NTY",
				"3ODkwIiw",
				"ibmFtZSI",
				"6IkpvaG4",
				"gRG9lIiw",
				"iaWF0Ijo",
				"xNTE2MjM",
				"5MDIyfQ.",
				"SflKxwRJ",
				"SMeKKF2Q",
				"T4fwpMeJ",
				"f36POk6y",
				"JV_adQss",
				"w5c",
			].join("");
			const input = `API_KEY=sk-ant-api03-xxxxxxxxxxxxxxxxxxxx and jwt=${jwt} token`;
			const report = detectPII(input);
			expect(report.redacted.includes("sk-ant-api03")).toBe(false);
			expect(report.redacted.includes("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")).toBe(false);
		});
	});

	describe("validateNoPII throws on critical findings", () => {
		it("throws when critical secret is present", () => {
			expect(() => validateNoPII("AWS AKIAIOSFODNN7EXAMPLE", "test context")).toThrow();
		});

		it("does not throw when no critical secrets present", () => {
			expect(() => validateNoPII("hello world this is safe text", "test context")).not.toThrow();
		});
	});

	describe("maskPII correctness", () => {
		it("masks short values completely", () => {
			expect(maskPII("short", "password")).toBe("*****");
		});

		it("masks long values with visible prefix and suffix", () => {
			const masked = maskPII("verylongsecretvalue", "secret");
			expect(masked).toBe("ve***************ue");
		});
	});

	describe("negative detection cases", () => {
		it("does not treat short TOKEN=test as critical secret", () => {
			const report = detectPII("TOKEN=test");
			expect(report.findings.some((f) => f.type === "secret_assignment")).toBe(false);
			expect(report.hasCritical).toBe(false);
		});

		it("does not treat uppercase words as secrets", () => {
			const report = detectPII("THIS IS JUST NORMAL UPPERCASE TEXT");
			expect(report.findings.length).toBe(0);
		});
	});
});
