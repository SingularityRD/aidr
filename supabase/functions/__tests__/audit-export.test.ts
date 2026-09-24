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
	it("keeps membership audit receipts visible in both export formats", () => {
		const row = {
			id: "receipt", created_at: "2026-09-23T00:00:00Z", user_id: "actor",
			action: "team.member.role_changed",
			verdict: { event_id: "event", target_user_id: "target", old_role: "member", new_role: "viewer" },
		};
		expect(JSON.parse(serializeAuditExport([row], "json"))).toEqual([row]);
		const csv = serializeAuditExport([row], "csv");
		expect(csv).toContain("team.member.role_changed");
		expect(csv).toContain("event_id");
		expect(csv).toContain("target_user_id");
	});
});
