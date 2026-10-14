// Control-plane side of the developer loop:
//   - `false-positive-reports` (D9): strict body schema, API key required;
//   - approval requests name the dashboard page (D8), never a token;
//   - approval notifications link the approvals page (D8);
//   - new channels select approval notifications by default (D8, migration);
//   - unprotected AI tool hosts are accepted by the posture ingest (D6).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("no database in this suite");
	},
}));

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const read = (...parts: string[]) => readFileSync(join(ROOT, ...parts), "utf8");
const NOW = Date.parse("2026-10-14T10:00:00.000Z");

type FpModule = typeof import("../false-positive-reports/index.ts");
type ApprovalModule = typeof import("../approval-requests/index.ts");
let fp: FpModule;
let approvals: ApprovalModule;

beforeAll(async () => {
	vi.stubGlobal("Deno", { env: { get: () => undefined }, serve: () => undefined });
	fp = await import("../false-positive-reports/index.ts");
	approvals = await import("../approval-requests/index.ts");
});

function validBody(extra: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		feedback_id: `fpfb_${"a".repeat(64)}`,
		record_hash: "b".repeat(64),
		iid: "host-a",
		agent_runtime: "cli",
		action_id: "c".repeat(64),
		rule_id: "CLT-CMD-006",
		decision: "deny",
		severity: "critical",
		tool: "Bash",
		reason_code: "developer_test",
		rationale: "a test fixture",
		occurred_at: new Date(NOW - 60_000).toISOString(),
		...extra,
	};
}

describe("false-positive-reports body", () => {
	it("accepts a bounded report", () => {
		const parsed = fp.parseReportBody(validBody(), NOW);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) expect(parsed.value).toMatchObject({ decision: "deny", ruleId: "CLT-CMD-006" });
	});

	it("refuses unknown keys, so a command or file content cannot ride along", () => {
		expect(fp.parseReportBody(validBody({ command: "rm -rf /" }), NOW)).toEqual({
			ok: false,
			error: "invalid_request",
		});
	});

	it("refuses malformed ids, decisions, reasons and invisible characters", () => {
		for (const bad of [
			{ feedback_id: "fpfb_xyz" },
			{ action_id: "../../etc" },
			{ decision: "allow" },
			{ reason_code: "because" },
			{ rationale: "ok‮txt" },
			{ rationale: "x".repeat(fp.RATIONALE_MAX + 1) },
			{ tool: "a\u0000b" },
		]) {
			expect(fp.parseReportBody(validBody(bad), NOW).ok).toBe(false);
		}
		expect(fp.parseReportBody(validBody({ occurred_at: new Date(NOW + 3_600_000).toISOString() }), NOW)).toEqual({
			ok: false,
			error: "invalid_occurred_at",
		});
	});

	it("requires a tenant API key and POST", async () => {
		const handle = fp.createFalsePositiveReportsHandler({
			env: (name) =>
				({ SUPABASE_URL: "https://project.supabase.co", SUPABASE_SERVICE_ROLE_KEY: "service" })[name],
		});
		const url = "https://project.supabase.co/functions/v1/false-positive-reports";
		expect((await handle(new Request(url, { method: "GET" }))).status).toBe(405);
		const noKey = await handle(
			new Request(url, { method: "POST", body: JSON.stringify(validBody()) }),
		);
		expect(noKey.status).toBe(401);
		expect(await noKey.json()).toEqual({ error: "missing_api_key" });
	});

	it("is deployed with gateway JWT verification off and a client-read-only table", () => {
		expect(read("supabase", "config.toml")).toMatch(
			/\[functions\.false-positive-reports\][^[]*verify_jwt = false/,
		);
		const migration = read(
			"supabase",
			"migrations",
			"20261014003300_approval_notify_unprotected_hosts_fp_reports.sql",
		);
		expect(migration).toContain("enable row level security");
		expect(migration).toMatch(/grant select on public\.false_positive_reports to authenticated/);
		expect(migration).not.toMatch(/grant [^;]*insert[^;]*to authenticated/);
		expect(migration).toContain("unique (tenant_id, feedback_id)");
	});
});

describe("approval requests: dashboard deep link", () => {
	const id = "0f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f";

	it("links the approvals page from the configured dashboard origin only", () => {
		expect(approvals.approvalConsoleUrl("https://console.example.test/some/path?x=1", id)).toBe(
			`https://console.example.test/approvals?request=${id}`,
		);
		expect(approvals.approvalConsoleUrl(undefined, id)).toBeNull();
		expect(approvals.approvalConsoleUrl("http://console.example.test", id)).toBeNull();
		expect(approvals.approvalConsoleUrl("https://u:p@console.example.test", id)).toBeNull();
		expect(approvals.approvalConsoleUrl("https://console.example.test", "not-a-uuid")).toBeNull();
	});
});

describe("approval notifications and posture hosts", () => {
	it("an approval notification links the approvals page", () => {
		expect(read("supabase", "functions", "_shared", "notification-delivery.ts")).toContain(
			'"approval.requested": "/approvals"',
		);
	});

	it("new channels select approval notifications; existing rows are untouched", () => {
		const migration = read(
			"supabase",
			"migrations",
			"20261014003300_approval_notify_unprotected_hosts_fp_reports.sql",
		);
		expect(migration).toContain("alter column on_approval_requested set default true");
		expect(migration).not.toMatch(/update public\.notification_channels/);
		const dashboardDefaults = read("packages", "dashboard", "src", "lib", "notification-channels.ts");
		expect(dashboardDefaults).toMatch(/approvalRequested: true/);
	});

	it("the posture ingest, the table constraint and the core host list agree", () => {
		const ingest = read("supabase", "functions", "ingest", "posture.ts");
		const migration = read(
			"supabase",
			"migrations",
			"20261014003300_approval_notify_unprotected_hosts_fp_reports.sql",
		);
		for (const host of ["windsurf", "jetbrains-ai", "cline", "roo-code", "copilot-cli", "amazon-q", "kiro", "zed"]) {
			expect(ingest).toContain(`"${host}"`);
			expect(migration.split(`'${host}'`).length - 1).toBeGreaterThanOrEqual(2);
		}
	});
});
