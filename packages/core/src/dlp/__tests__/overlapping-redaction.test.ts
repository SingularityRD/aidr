import { describe, expect, it } from "vitest";
import { DlpPolicySchema } from "../policy.js";
import { scanDlpOutput } from "../scanner.js";

function policyFor(patterns: Array<{ id: string; value: string; priority: number }>) {
	return DlpPolicySchema.parse({
		version: 1,
		tenantId: "tenant-a",
		labels: [
			{
				id: "sensitive",
				tenantId: "tenant-a",
				name: "Sensitive value",
				sensitivity: "restricted",
			},
		],
		rules: patterns.map(({ id, value, priority }) => ({
			id,
			tenantId: "tenant-a",
			labelId: "sensitive",
			name: id,
			action: "redact",
			priority,
			matchers: [{ type: "keyword", values: [value], wholeWord: false }],
		})),
	});
}

describe("overlapping tenant DLP redaction", () => {
	it("covers the full sensitive span when a higher-priority label matches only its prefix", () => {
		const policy = policyFor([
			{ id: "prefix", value: "api-key", priority: 200 },
			{ id: "full-value", value: "api-key-123", priority: 100 },
		]);
		const result = scanDlpOutput(policy, {
			tenantId: "tenant-a",
			contentType: "text/plain",
			content: "Send api-key-123 to support",
		});

		expect(result).toMatchObject({
			status: "inspected",
			action: "redact",
			transformedContent: "Send [REDACTED] to support",
		});
		expect(result.findings).toHaveLength(2);
	});

	it("merges transitive overlaps while preserving separate redactions", () => {
		const policy = policyFor([
			{ id: "first", value: "abc", priority: 300 },
			{ id: "middle", value: "cde", priority: 200 },
			{ id: "last", value: "efg", priority: 100 },
		]);
		const result = scanDlpOutput(policy, {
			tenantId: "tenant-a",
			contentType: "text/plain",
			content: "abcdefg and abc",
		});

		expect(result).toMatchObject({
			status: "inspected",
			action: "redact",
			transformedContent: "[REDACTED] and [REDACTED]",
		});
	});
});
