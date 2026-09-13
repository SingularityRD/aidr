import { describe, expect, it } from "vitest";
import { DlpPolicySchema } from "../policy.js";
import { scanDlpOutput } from "../scanner.js";

function policy(overrides: { maxContentBytes?: number; replacement?: string } = {}) {
	return DlpPolicySchema.parse({
		version: 1,
		tenantId: "tenant-a",
		maxContentBytes: overrides.maxContentBytes ?? 1024,
		supportedFormats: ["application/json", "application/vnd.example+json"],
		labels: [
			{
				id: "customer-secret",
				tenantId: "tenant-a",
				name: "Customer secret",
				sensitivity: "restricted",
			},
		],
		rules: [
			{
				id: "secret-key",
				tenantId: "tenant-a",
				labelId: "customer-secret",
				name: "Secret key",
				action: "redact",
				matchers: [{ type: "keyword", values: ["api-key-123"] }],
				...(overrides.replacement === undefined ? {} : { replacement: overrides.replacement }),
			},
		],
	});
}

describe("JSON tenant DLP inspection", () => {
	it("detects Unicode-escaped secrets and redacts the exact raw JSON span", () => {
		const content = '{"token":"api\\u002dkey-123","safe":"team\\u002dnotes"}';
		const result = scanDlpOutput(policy(), {
			tenantId: "tenant-a",
			contentType: "application/vnd.example+json; charset=utf-8",
			content,
		});

		expect(result).toMatchObject({ status: "inspected", action: "redact" });
		if (result.status !== "inspected") throw new Error("expected inspected result");
		expect(result.findings).toHaveLength(1);
		expect(content.slice(result.findings[0].start, result.findings[0].end)).toBe(
			"api\\u002dkey-123",
		);
		expect(JSON.parse(result.transformedContent ?? "")).toEqual({
			token: "[REDACTED]",
			safe: "team-notes",
		});
		expect(JSON.stringify(result)).not.toContain("api-key-123");
	});

	it("allows benign escaped JSON without creating a finding", () => {
		const result = scanDlpOutput(policy(), {
			tenantId: "tenant-a",
			contentType: "application/json",
			content: '{"safe":"team\\u002dnotes"}',
		});

		expect(result).toMatchObject({ status: "inspected", action: "allow", findings: [] });
	});

	it("fails closed for malformed JSON and checks the byte limit before parsing", () => {
		const malformed = '{"token":"api\\u002dkey-123",';
		const invalid = scanDlpOutput(policy(), {
			tenantId: "tenant-a",
			contentType: "application/json",
			content: malformed,
		});
		const oversized = scanDlpOutput(policy({ maxContentBytes: 12 }), {
			tenantId: "tenant-a",
			contentType: "application/json",
			content: malformed,
		});

		expect(invalid).toMatchObject({
			status: "unavailable",
			action: "block",
			unavailable: { reason: "malformed_format" },
		});
		expect(oversized).toMatchObject({
			status: "unavailable",
			action: "block",
			unavailable: { reason: "oversize" },
		});
	});

	it("fails closed when a configured replacement would make JSON invalid", () => {
		const result = scanDlpOutput(policy({ replacement: '"' }), {
			tenantId: "tenant-a",
			contentType: "application/json",
			content: '{"token":"api\\u002dkey-123"}',
		});

		expect(result).toMatchObject({
			status: "unavailable",
			action: "block",
			unavailable: { reason: "transformation_failed" },
		});
		expect(result).not.toHaveProperty("transformedContent");
	});
});
