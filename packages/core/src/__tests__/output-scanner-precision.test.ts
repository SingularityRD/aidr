import { describe, expect, it } from "vitest";
import { scanModelOutput } from "../output-scanner.js";
import { detectOutputSensitiveData } from "../output-sensitive-data.js";

// Credential fixtures are assembled at runtime so secret scanners do not flag
// this file; none of them is a live credential.
const AWS_KEY = ["AKIA", "Q3EGRTZ7", "WMXN4K2P"].join("");
const GITHUB_TOKEN = ["ghp_", "a1B2c3D4e5F6g7H8i9J0", "k1L2m3N4o5P6q7R8"].join("");
const OPENAI_KEY = ["sk-proj-", "T3BlbkFJx8Qm2Zr7Kp4Wn", "9Vd6Hs1Lc5Yg0Ub3"].join("");
const ANTHROPIC_KEY = ["sk-ant-", "api03-", "Zq8Xw7Vu6Ts5Rq4Po3Nm2Lk1Ji0Hg"].join("");
const JWT = [
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
	"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
].join(".");
const PEM = [
	["-----BEGIN", "RSA PRIVATE KEY-----"].join(" "),
	"MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun",
	"VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK",
	["-----END", "RSA PRIVATE KEY-----"].join(" "),
].join("\n");

function ruleIds(output: string): string[] {
	return scanModelOutput(output).map((finding) => finding.ruleId);
}

describe("output scanner precision: ordinary developer output stays clean", () => {
	it.each([
		[
			"epoch seconds and milliseconds",
			"created_at=1727190000 updated_at=1727190000123 took 1695.3ms",
		],
		[
			"git log author and committer emails",
			[
				"commit 9fceb02d0ae598e95dc970b74767f19372d61af8",
				"Author: Jane Doe <jane.doe@example.com>",
				"Date:   Tue Sep 24 10:11:12 2026 +0000",
				"",
				"    fix(core): tighten output scanning (Co-Authored-By: Bot <bot@users.noreply.github.com>)",
			].join("\n"),
		],
		["nine-digit ids", "order 123456789 shipped; ticket #987654321; account 555012345"],
		["ten-digit ids", "invoice 4155552671 and trace 9876543210"],
		[
			"sha-256 digests",
			"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  dist/index.js",
		],
		["uuids", "request 550e8400-e29b-41d4-a716-446655440000 finished"],
		["semver strings", "upgraded typescript 5.4.2 -> 5.6.3, next@14.2.15, 2.10.0-beta.1"],
		["prices", "Total: $1,234.56 (USD 4999.00, EUR 12.99)"],
		["ip addresses", "listening on 10.0.0.12:8080 and 192.168.1.254"],
		["non-Luhn 16-digit number", "reference 1234 5678 9012 3456"],
		["unlabelled SSN-shaped value", "part number 123-45-6789 is back in stock"],
		[
			"masked or placeholder credentials",
			'password: "********" api_key=<your-api-key> token: ${TOKEN}',
		],
		[
			"secret-named keys assigned to variables or environment references",
			[
				"const apiKey = process.env.OPENAI_API_KEY;",
				"password = hashedPasswordValue",
				"API_KEY=$OPENAI_API_KEY_VALUE",
				"TOKEN=${GITHUB_TOKEN_FROM_CI}",
			].join("\n"),
		],
		["pagination tokens", "next_page_token=CiAKGjBpNDd2Nmp2Zml2cXRtcGRqcWhkaXhkbmlmdGUSBQiA"],
		[
			"a PEM header without key material",
			'if (line.startsWith("-----BEGIN RSA PRIVATE KEY-----")) {',
		],
	])("does not flag %s", (_label, output) => {
		expect(scanModelOutput(output)).toEqual([]);
	});

	it("reports no findings for a long realistic git log", () => {
		const entry = (index: number) =>
			[
				`commit ${index.toString(16).padStart(40, "a")}`,
				`Author: Dev ${index} <dev${index}@company.example>`,
				`Date:   ${1_727_190_000 + index}`,
				"",
				`    chore: bump deps to 1.${index}.0 (#${100_000_000 + index})`,
			].join("\n");
		const log = Array.from({ length: 200 }, (_value, index) => entry(index)).join("\n\n");
		expect(scanModelOutput(log)).toEqual([]);
	});
});

describe("output scanner precision: real secrets are still quarantined", () => {
	it.each([
		["AWS access key", `aws_access_key_id = ${AWS_KEY}`, "OUT-PII-AWS_ACCESS_KEY"],
		["PEM private key", PEM, "OUT-PII-PRIVATE_KEY"],
		["GitHub token", `token: ${GITHUB_TOKEN}`, "OUT-PII-GITHUB_TOKEN"],
		["OpenAI key", `OPENAI_API_KEY=${OPENAI_KEY}`, "OUT-PII-API_KEY"],
		["Anthropic key", `key ${ANTHROPIC_KEY}`, "OUT-PII-API_KEY"],
		["JWT", `session=${JWT}`, "OUT-PII-JWT_TOKEN"],
		["dotenv secret literal", "API_KEY=qwertyuiopasdfghjkl", "OUT-PII-SECRET_ASSIGNMENT"],
		["Luhn-valid Visa card", "card 4111 1111 1111 1111 exp 12/29", "OUT-PII-CREDIT_CARD"],
		["labelled SSN", "Employee SSN: 123-45-6789", "OUT-PII-SSN"],
		[
			"bearer token",
			"Authorization: bearer 9f8e7d6c5b4a39281706f5e4d3c2b1a0Zz",
			"OUT-PII-BEARER_TOKEN",
		],
	])("flags a %s", (_label, output, ruleId) => {
		const findings = scanModelOutput(output);
		expect(findings.map((finding) => finding.ruleId)).toContain(ruleId);
		expect(findings.every((finding) => finding.type === "secret_leak")).toBe(true);
	});

	it("never places the raw secret in a finding", () => {
		const output = [AWS_KEY, GITHUB_TOKEN, OPENAI_KEY, ANTHROPIC_KEY, JWT].join("\n");
		const serialized = JSON.stringify(scanModelOutput(output));
		for (const secret of [AWS_KEY, GITHUB_TOKEN, OPENAI_KEY, ANTHROPIC_KEY, JWT]) {
			expect(serialized).not.toContain(secret);
		}
	});

	it("reports a JWT once even though it also looks like a bearer credential", () => {
		const matches = detectOutputSensitiveData(`Authorization: Bearer ${JWT}`);
		expect(matches.map((match) => match.type)).toEqual(["jwt_token"]);
	});

	it("rejects a Luhn-valid number that belongs to no card network", () => {
		// 16 digits, Luhn-valid, but the 9 prefix is not an issued card range.
		expect(ruleIds("id 9000 0000 0000 0008")).toEqual([]);
	});

	it("rejects a JWT-shaped string whose header is not a JWT header", () => {
		const fake = [
			"eyJub3QiOiJhIGp3dCJ9",
			"eyJzdWIiOiIxMjM0NTY3ODkwIn0",
			"c2lnbmF0dXJlLXNlZ21lbnQ",
		].join(".");
		expect(ruleIds(fake)).toEqual([]);
	});
});
