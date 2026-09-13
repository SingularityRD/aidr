import { describe, expect, it } from "vitest";
import { serializeAuditExport } from "../_shared/audit-export.ts";

describe("audit export", () => {
	it("prevents spreadsheet formula execution and quotes CSV cells", () => {
		const content = serializeAuditExport([{ id: "a", action: '=HYPERLINK("https://evil.test")', verdict: { decision: "deny" } }], "csv");
		expect(content).toContain("'=HYPERLINK");
		expect(content).toContain('""decision"":""deny""');
	});
	it("preserves structured JSON evidence", () => {
		const rows = [{ id: "one", verdict: { decision: "deny" } }];
		expect(JSON.parse(serializeAuditExport(rows, "json"))).toEqual(rows);
	});
});
