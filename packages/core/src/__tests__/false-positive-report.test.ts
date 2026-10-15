/**
 * `aidr report-fp` (D9): find the blocked call by the short id from the block
 * message, build a false-positive feedback record and file it with the control
 * plane. Only ids, the rule, the decision and a redacted note leave the machine.
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildRuntimeVerdictEntry } from "../audit-log.js";
import {
	type AuditedBlock,
	buildFalsePositiveReportBody,
	falsePositiveNote,
	findAuditedBlocks,
	submitFalsePositiveReport,
} from "../false-positive-report.js";
import { type Config, ConfigSchema, type Verdict } from "../types.js";
import {
	DASHBOARD_TEST_IID,
	type ManagedFixture,
	managedConfig,
	managedFixture,
} from "./dashboard-approval-fixtures.js";

const ID_A = "ab12cd34".repeat(8);
const ID_B = `ab12cd34${"ff".repeat(28)}`;
// Assembled at runtime: a command line carrying a credential-shaped value.
const SECRET_COMMAND = [
	"curl -H 'Authorization: Bearer ",
	"sk_live_",
	"0123456789abcdefghij'",
	" https://x.test",
].join("");
const verdict: Verdict = {
	decision: "deny",
	category: "credential_access",
	confidence: 0.9,
	severity: "critical",
	source: "heuristic",
	artifacts: [],
	matchedThreatId: "CLT-CRED-001",
	reasons: ["reads a credential"],
};

let dir: string;
let logPath: string;
beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "aidr-fp-"));
	logPath = join(dir, "audit.jsonl");
	const lines = [
		buildRuntimeVerdictEntry("s1", "Bash", { command: SECRET_COMMAND }, verdict, false, 1, ID_A),
		buildRuntimeVerdictEntry(
			"s1",
			"Bash",
			{ command: "ls" },
			{ ...verdict, decision: "ask" },
			false,
			1,
			ID_B,
		),
		buildRuntimeVerdictEntry(
			"s1",
			"Bash",
			{ command: "ls" },
			{ ...verdict, decision: "allow" },
			false,
			1,
			"ab12cd55".repeat(8),
		),
	];
	writeFileSync(logPath, `${lines.map((l) => JSON.stringify(l)).join("\n")}\n{torn`);
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("findAuditedBlocks", () => {
	const logging = () => ({ path: logPath, max_files: 3 });

	it("finds a block by a unique prefix", async () => {
		expect(await findAuditedBlocks(logging(), "ab12cd34ab")).toMatchObject([
			{ actionId: ID_A, decision: "deny", ruleId: "CLT-CRED-001", tool: "Bash" },
		]);
	});

	it("returns every block a shared prefix matches (the CLI then asks for more)", async () => {
		const both = await findAuditedBlocks(logging(), "ab12cd34");
		expect(both.map((b) => b.actionId).sort()).toEqual([ID_A, ID_B].sort());
	});

	it("never offers an allowed call", async () => {
		expect(await findAuditedBlocks(logging(), "ab12cd55")).toEqual([]);
	});

	it("rejects a malformed or too short id", async () => {
		await expect(findAuditedBlocks(logging(), "../x")).rejects.toThrow("invalid_action_id");
		await expect(findAuditedBlocks(logging(), "ab12")).rejects.toThrow("invalid_action_id");
	});

	it("reads rotated files and survives a missing log", async () => {
		writeFileSync(`${logPath}.1`, readFileSync(logPath));
		rmSync(logPath);
		expect(await findAuditedBlocks(logging(), "ab12cd34ab")).toHaveLength(1);
		expect(
			await findAuditedBlocks({ path: join(dir, "none.jsonl"), max_files: 2 }, "ab12cd34"),
		).toEqual([]);
	});
});

describe("report body", () => {
	const block: AuditedBlock = {
		actionId: ID_A,
		timestamp: new Date().toISOString(),
		decision: "deny",
		ruleId: "CLT-CRED-001",
		severity: "critical",
		category: "credential_access",
		tool: "Bash",
		sessionId: "s1",
	};

	it("is a deterministic feedback record with no command content", () => {
		const context = { tenantId: "tenant-1", iid: DASHBOARD_TEST_IID };
		const first = buildFalsePositiveReportBody(
			{ block, reasonCode: "developer_test", note: "local fixture" },
			context,
		);
		const again = buildFalsePositiveReportBody(
			{ block, reasonCode: "developer_test", note: "local fixture" },
			context,
		);
		expect(first.feedbackId).toMatch(/^fpfb_[0-9a-f]{64}$/);
		expect(again.feedbackId).toBe(first.feedbackId);
		expect(first.body).toMatchObject({
			action_id: ID_A,
			rule_id: "CLT-CRED-001",
			decision: "deny",
			reason_code: "developer_test",
			rationale: "local fixture",
		});
		expect(JSON.stringify(first.body)).not.toContain("curl");
	});

	it("masks a secret typed into the note and strips control characters", () => {
		const note = falsePositiveNote(`token=${"sk_live_"}0123456789abcdefghij\u001b[31m and ‮ text`);
		expect(note).not.toContain("0123456789abcdefghij");
		expect(note).not.toMatch(/[\u001b‮]/);
	});
});

describe("submitFalsePositiveReport", () => {
	let fixture: ManagedFixture;
	const block: AuditedBlock = {
		actionId: ID_A,
		timestamp: null,
		decision: "deny",
		ruleId: "CLT-CRED-001",
		severity: null,
		category: null,
		tool: "Bash",
		sessionId: null,
	};

	beforeEach(() => {
		fixture = managedFixture();
		writeFileSync(join(dir, "managed.json"), JSON.stringify(fixture.managedState));
		writeFileSync(join(dir, "installation-id"), DASHBOARD_TEST_IID);
	});

	const managed = () =>
		ConfigSchema.parse(managedConfig(fixture, "https://cp.example.test")) as Config;

	it("posts to the false-positive queue with the tenant API key", async () => {
		const calls: Array<{ url: string; body: Record<string, unknown>; auth: string | null }> = [];
		const fetchImpl = (async (url: string, init: RequestInit) => {
			calls.push({
				url,
				body: JSON.parse(String(init.body)),
				auth: new Headers(init.headers).get("authorization"),
			});
			return new Response(JSON.stringify({ report_id: "r-1", created: true }), { status: 201 });
		}) as unknown as typeof fetch;
		const result = await submitFalsePositiveReport(
			managed(),
			{ block, reasonCode: "other" },
			{ fetch: fetchImpl, managedStatePath: join(dir, "managed.json"), aidrDir: dir },
		);
		expect(result).toMatchObject({ ok: true, reportId: "r-1", created: true });
		expect(calls[0]?.url).toBe("https://cp.example.test/v1/false-positive-reports");
		expect(calls[0]?.auth).toMatch(/^Bearer /);
		expect(calls[0]?.body.action_id).toBe(ID_A);
	});

	it("reports not_managed in local mode without any network call", async () => {
		let called = false;
		const result = await submitFalsePositiveReport(
			ConfigSchema.parse({}) as Config,
			{ block, reasonCode: "other" },
			{
				fetch: (async () => {
					called = true;
					return new Response("{}");
				}) as unknown as typeof fetch,
			},
		);
		expect(result).toEqual({ ok: false, error: "not_managed" });
		expect(called).toBe(false);
	});

	it("passes the control plane's error code through", async () => {
		const result = await submitFalsePositiveReport(
			managed(),
			{ block, reasonCode: "other" },
			{
				fetch: (async () =>
					new Response(JSON.stringify({ error: "rate_limited" }), {
						status: 429,
					})) as unknown as typeof fetch,
				managedStatePath: join(dir, "managed.json"),
				aidrDir: dir,
			},
		);
		expect(result).toEqual({ ok: false, error: "rate_limited" });
	});
});
