/**
 * Built-in common-PII masking under a `redact` policy (catalog item 27).
 *
 * All values below are synthetic test data: checksum-valid fixtures (Visa test
 * card, documented example IBAN, TCKN built for its checksum), example.com
 * addresses and reserved 555 phone numbers.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { shellLiteralSpans } from "../dlp/pii-masking.js";
import { type DlpPolicy, DlpPolicySchema } from "../dlp/policy.js";
import { evaluateToolCall, type ToolEvaluationContext } from "../evaluator.js";
import { COMMON_PII_TYPES, type CommonPiiType, maskCommonPiiInToolInput } from "../pii-baseline.js";
import { makeTmpDir } from "./test-utils.js";

const TENANT = "tenant-a";

const SAMPLES: Record<CommonPiiType, { value: string; placeholder: string }> = {
	email: { value: "jane.doe@example.com", placeholder: "[EMAIL_1]" },
	phone: { value: "555-123-4567", placeholder: "[PHONE_1]" },
	tc_kimlik: { value: "10000000146", placeholder: "[TCKN_1]" },
	iban: { value: "DE89370400440532013000", placeholder: "[IBAN_1]" },
	credit_card: { value: "4111 1111 1111 1111", placeholder: "[CARD_1]" },
	ssn: { value: "219-09-9999", placeholder: "[SSN_1]" },
};
const ALL_VALUES = Object.values(SAMPLES).map((sample) => sample.value);

let configPath: string;
let homeDir: string;

function policy(
	actions: Partial<Record<CommonPiiType, "block" | "ask" | "redact">> = Object.fromEntries(
		COMMON_PII_TYPES.map((type) => [type, "redact"]),
	),
	extraRules: Array<Record<string, unknown>> = [],
): DlpPolicy {
	return DlpPolicySchema.parse({
		version: 1,
		tenantId: TENANT,
		supportedFormats: ["application/json"],
		labels: [{ id: "pii", tenantId: TENANT, name: "PII", sensitivity: "restricted" }],
		rules: [
			...Object.entries(actions).map(([type, action]) => ({
				id: `pii-${type}`,
				tenantId: TENANT,
				labelId: "pii",
				name: `Common PII ${type}`,
				action,
				directions: ["input"],
				matchers: [{ type: "keyword", values: ["NEVER-PRESENT-MARKER"] }],
			})),
			...extraRules,
		],
		exceptions: [],
	});
}

function context(dlpPolicy: DlpPolicy = policy(), rewrite = true): ToolEvaluationContext {
	return {
		threatsDir: join(homeDir, "empty-threats"),
		allowlistsDir: join(homeDir, "empty-allowlists"),
		configPath,
		runtimeDetectors: { tenantId: TENANT, dlp: { enabled: true, policy: dlpPolicy } },
		...(rewrite ? { supportsInputRewrite: true } : {}),
	};
}

function call(toolName: string, toolInput: Record<string, unknown>) {
	return { sessionId: "session-a", toolName, toolInput, artifacts: [] };
}

beforeEach(async () => {
	homeDir = await makeTmpDir();
	vi.stubEnv("HOME", homeDir);
	vi.stubEnv("USERPROFILE", homeDir);
	await mkdir(join(homeDir, ".singularity-aidr"), { recursive: true });
	configPath = join(homeDir, "config.json");
	await writeFile(
		configPath,
		JSON.stringify({
			mode: "local",
			control_plane: { enabled: false },
			licensing: { require_signed_entitlements: false },
			heuristics_enabled: false,
			url_check: { enabled: false },
			package_check: { enabled: false },
			cache: { enabled: false },
			logging: { enabled: true, path: "~/.singularity-aidr/audit.jsonl" },
			allowlist: { path: "~/.singularity-aidr/allowlist.json" },
		}),
	);
});

afterEach(() => vi.unstubAllEnvs());

describe("common-PII masking with a redact policy", () => {
	for (const type of COMMON_PII_TYPES) {
		const { value, placeholder } = SAMPLES[type];

		it(`masks ${type} in Write content and keeps the tool runnable`, async () => {
			const verdict = await evaluateToolCall(
				call("Write", {
					file_path: "/tmp/notes.txt",
					content: `Customer record: ${value} (verified)`,
				}),
				context(),
			);
			expect(verdict).toMatchObject({
				decision: "allow",
				category: "dlp_redacted",
				source: "dlp",
				matchedThreatId: `pii-${type}`,
				transformedInput: {
					file_path: "/tmp/notes.txt",
					content: `Customer record: ${placeholder} (verified)`,
				},
			});
			expect(JSON.stringify(verdict)).not.toContain(value);
		});

		it(`masks ${type} in a WebFetch prompt`, async () => {
			const verdict = await evaluateToolCall(
				call("WebFetch", {
					url: "https://docs.example.com/page",
					prompt: `Summarize the account of ${value} please`,
				}),
				context(),
			);
			expect(verdict.decision).toBe("allow");
			expect(verdict.transformedInput).toEqual({
				url: "https://docs.example.com/page",
				prompt: `Summarize the account of ${placeholder} please`,
			});
		});

		it(`masks ${type} in nested MCP arguments`, async () => {
			const verdict = await evaluateToolCall(
				call("mcp__crm__create_note", {
					customer: { notes: [`Caller gave ${value} on the phone`] },
					priority: 2,
				}),
				context(),
			);
			expect(verdict.decision).toBe("allow");
			expect(verdict.transformedInput).toEqual({
				customer: { notes: [`Caller gave ${placeholder} on the phone`] },
				priority: 2,
			});
		});

		it(`masks ${type} inside a quoted Bash argument`, async () => {
			const verdict = await evaluateToolCall(
				call("Bash", { command: `printf '%s\\n' 'Customer ${value}' >> notes.txt` }),
				context(),
			);
			expect(verdict.decision).toBe("allow");
			expect(verdict.transformedInput).toEqual({
				command: `printf '%s\\n' 'Customer ${placeholder}' >> notes.txt`,
			});
		});
	}

	it("gives a repeated value the same placeholder and a new value the next one", async () => {
		const verdict = await evaluateToolCall(
			call("Write", {
				file_path: "/tmp/a.txt",
				content: "jane.doe@example.com, JANE.DOE@example.com and john.roe@example.com",
			}),
			context(),
		);
		expect(verdict.transformedInput).toEqual({
			file_path: "/tmp/a.txt",
			content: "[EMAIL_1], [EMAIL_1] and [EMAIL_2]",
		});
		expect(verdict.reasons.join(" ")).toContain("EMAIL x3");
	});

	it("masks every type in one call and records type/count only in the audit log", async () => {
		const content = ALL_VALUES.map((value, index) => `field${index}: ${value}`).join("\n");
		const verdict = await evaluateToolCall(
			call("Write", { file_path: "/tmp/all.txt", content }),
			context(),
		);
		expect(verdict.decision).toBe("allow");
		const masked = String(verdict.transformedInput?.content);
		for (const value of ALL_VALUES) expect(masked).not.toContain(value);
		for (const { placeholder } of Object.values(SAMPLES)) expect(masked).toContain(placeholder);

		const audit = await readFile(join(homeDir, ".singularity-aidr", "audit.jsonl"), "utf8");
		for (const value of ALL_VALUES) expect(audit).not.toContain(value);
		expect(audit).not.toContain("[EMAIL_1]");
		expect(audit).toContain("Common PII masked before the tool ran");
		expect(audit).toContain("TCKN x1");
	});

	it("does not reuse a placeholder that already appears in the input", async () => {
		const verdict = await evaluateToolCall(
			call("Write", {
				file_path: "/tmp/a.txt",
				content: "[EMAIL_1] is a template; real: jane.doe@example.com",
			}),
			context(),
		);
		expect(verdict.transformedInput?.content).toBe("[EMAIL_1] is a template; real: [EMAIL_2]");
	});

	it("masks double-quoted Bash literals without expansions", async () => {
		const verdict = await evaluateToolCall(
			call("Bash", { command: 'git commit -m "Fix record for jane.doe@example.com"' }),
			context(),
		);
		expect(verdict.transformedInput).toEqual({
			command: 'git commit -m "Fix record for [EMAIL_1]"',
		});
	});
});

describe("common-PII masking fails closed", () => {
	async function expectDenied(toolName: string, toolInput: Record<string, unknown>) {
		const verdict = await evaluateToolCall(call(toolName, toolInput), context());
		expect(verdict).toMatchObject({ decision: "deny", source: "dlp", category: "dlp" });
		expect(verdict.transformedInput).toBeUndefined();
		expect(verdict.reasons.join(" ")).toContain("could not be masked safely");
		for (const value of ALL_VALUES) expect(JSON.stringify(verdict)).not.toContain(value);
		return verdict;
	}

	it("denies an unquoted Bash argument", async () => {
		await expectDenied("Bash", { command: "echo jane.doe@example.com >> notes.txt" });
	});

	it("denies a double-quoted Bash string with an expansion", async () => {
		await expectDenied("Bash", { command: 'echo "$PREFIX jane.doe@example.com"' });
	});

	it("denies ANSI-C quoting and unterminated quotes", async () => {
		await expectDenied("Bash", { command: "echo $'jane.doe@example.com'" });
		await expectDenied("Bash", { command: "echo 'jane.doe@example.com" });
	});

	it("denies an unquoted heredoc body", async () => {
		await expectDenied("Bash", { command: "cat <<EOF > a.txt\njane.doe@example.com\nEOF" });
	});

	it("denies PII in a locator field", async () => {
		await expectDenied("Write", { file_path: "/tmp/jane.doe@example.com.txt", content: "x" });
		await expectDenied("WebFetch", {
			url: "https://example.com/?email=jane.doe@example.com",
			prompt: "summarize",
		});
		await expectDenied("Edit", {
			file_path: "/tmp/a.txt",
			old_string: "jane.doe@example.com",
			new_string: "x",
		});
	});

	it("denies a field whose entire value is the PII operand", async () => {
		await expectDenied("mcp__mail__send", { to: "jane.doe@example.com", body: "hello" });
	});

	it("denies residual PII it cannot rewrite (JSON number, object key)", async () => {
		await expectDenied("mcp__crm__lookup", { note: "lookup", tckn: 10000000146 });
		await expectDenied("mcp__crm__lookup", { note: "x", map: { "jane.doe@example.com": "y" } });
	});

	it("denies when another PII type in the call is governed by block", async () => {
		const verdict = await evaluateToolCall(
			call("Write", {
				file_path: "/tmp/a.txt",
				content: "jane.doe@example.com and 10000000146",
			}),
			context(policy({ email: "redact" })),
		);
		expect(verdict).toMatchObject({ decision: "deny", matchedThreatId: "pii-tc_kimlik" });
		expect(verdict.transformedInput).toBeUndefined();
	});

	it("denies when a tenant rule in the same call asks for approval", async () => {
		const askRule = {
			id: "tenant-ask",
			tenantId: TENANT,
			labelId: "pii",
			name: "Ask rule",
			action: "ask",
			directions: ["input"],
			matchers: [{ type: "keyword", values: ["REVIEW-ME"], wholeWord: false }],
		};
		const verdict = await evaluateToolCall(
			call("Write", { file_path: "/tmp/a.txt", content: "REVIEW-ME jane.doe@example.com" }),
			context(policy(undefined, [askRule])),
		);
		expect(verdict).toMatchObject({ decision: "deny", matchedThreatId: "pii-email" });
		expect(verdict.reasons.join(" ")).toContain("requires approval");
	});

	it("combines tenant redaction with PII masking", async () => {
		const redactRule = {
			id: "tenant-redact",
			tenantId: TENANT,
			labelId: "pii",
			name: "Redact rule",
			action: "redact",
			directions: ["input"],
			matchers: [{ type: "keyword", values: ["PROJECT-ORION"], wholeWord: false }],
		};
		const verdict = await evaluateToolCall(
			call("Write", {
				file_path: "/tmp/a.txt",
				content: "PROJECT-ORION owner jane.doe@example.com",
			}),
			context(policy(undefined, [redactRule])),
		);
		expect(verdict.decision).toBe("allow");
		const content = String(verdict.transformedInput?.content);
		expect(content).not.toContain("PROJECT-ORION");
		expect(content).toContain("[EMAIL_1]");
	});

	it("denies when the connector cannot rewrite tool input", async () => {
		const verdict = await evaluateToolCall(
			call("Write", { file_path: "/tmp/a.txt", content: "Customer jane.doe@example.com" }),
			context(policy(), false),
		);
		expect(verdict).toMatchObject({ decision: "deny", matchedThreatId: "pii-email" });
		expect(verdict.reasons.join(" ")).toContain("this connector cannot rewrite tool input");
		expect(verdict.transformedInput).toBeUndefined();
	});

	it("keeps the default (no reserved rule) as a deny even on a rewriting connector", async () => {
		const verdict = await evaluateToolCall(
			call("Write", { file_path: "/tmp/a.txt", content: "Customer jane.doe@example.com" }),
			context(policy({})),
		);
		expect(verdict).toMatchObject({ decision: "deny", matchedThreatId: "pii-email" });
		expect(verdict.transformedInput).toBeUndefined();
	});
});

describe("masking helpers", () => {
	it("reports only plain quoted literal spans", () => {
		const command = `a 'one' "two" "t$hree" $'four' b\\'c`;
		const spans = shellLiteralSpans(command)?.map(([start, end]) => command.slice(start, end));
		expect(spans).toEqual(["one", "two"]);
		expect(shellLiteralSpans("echo 'open")).toBeNull();
	});

	it("leaves values of disabled types untouched", () => {
		const disabled = DlpPolicySchema.parse({
			...policy({ email: "redact" }),
			rules: [
				...policy({ email: "redact" }).rules,
				{ ...policy({ phone: "block" }).rules[0], enabled: false },
			],
		});
		const result = maskCommonPiiInToolInput(disabled, {
			body: "jane.doe@example.com or 555-123-4567",
		});
		expect(result?.input).toEqual({ body: "[EMAIL_1] or 555-123-4567" });
		expect(result?.counts).toEqual({ EMAIL: 1 });
	});
});
