/**
 * `aidr pending`, `aidr approve`, `aidr allowlist`, `aidr audit` and `aidr doctor`.
 *
 * The approval commands are the out-of-band, human-only channel for `ask`
 * verdicts, so the tests pin that they refuse to act without a human
 * confirmation and that they only ever approve what the operator was shown.
 */

import { createHash, randomBytes } from "node:crypto";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import {
	clearOperatorApprovalKeyCache,
	consumeOperatorApproval,
	hashCommand,
	listOperatorApprovals,
	type OperatorApprovalStoreOptions,
	recordPendingAsk,
} from "@singularityrd/aidr-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	allowlistAddCommand,
	allowlistListCommand,
	allowlistRemoveCommand,
} from "../commands/allowlist.js";
import { approveCommand, pendingCommand } from "../commands/approvals.js";
import { auditExportCommand, auditTailCommand, parseSince, toCsv } from "../commands/audit.js";
import { runDoctor } from "../commands/doctor.js";
import type { ConnectorStatus } from "../utils/connector-status.js";
import { OPERATOR_NONINTERACTIVE_ENV } from "../utils/operator-confirm.js";

const COMMAND = "chmod 777 ./deploy.sh";

let home: string;
let originalHome: string | undefined;
let store: OperatorApprovalStoreOptions;
let out: string[];
let err: string[];

function actionId(seed: string): string {
	return createHash("sha256").update(seed).digest("hex");
}

function ttyStreams(answer: string) {
	const input = Object.assign(new PassThrough(), { isTTY: true });
	const output = Object.assign(new PassThrough(), { isTTY: true });
	output.resume();
	setTimeout(() => input.write(`${answer}\n`), 10);
	return { input, output };
}

function nonTtyStreams() {
	const output = new PassThrough();
	output.resume();
	return { input: new PassThrough(), output };
}

async function pendingAsk(id: string) {
	await recordPendingAsk(
		{
			actionId: id,
			toolName: "bash",
			toolInput: { command: COMMAND },
			artifacts: [{ type: "command", value: COMMAND }],
			sessionId: "session-1",
			verdict: {
				severity: "warning",
				category: "permissions",
				reasons: ["World-writable permissions"],
				matchedThreatId: "CLT-TEST-001",
			},
			connector: "opencode",
		},
		store,
	);
}

beforeEach(() => {
	originalHome = process.env.HOME;
	home = mkdtempSync(join(tmpdir(), "aidr-operator-cli-"));
	mkdirSync(join(home, ".singularity-aidr"), { recursive: true, mode: 0o700 });
	process.env.HOME = home;
	clearOperatorApprovalKeyCache();
	const key = randomBytes(32);
	store = {
		path: join(home, ".singularity-aidr", "approvals.json"),
		keyProvider: { load: () => ({ key, location: "file", store: "file" }) },
	};
	out = [];
	err = [];
	vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
		out.push(args.map(String).join(" "));
	});
	vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
		err.push(args.map(String).join(" "));
	});
	process.exitCode = undefined;
});

afterEach(() => {
	vi.restoreAllMocks();
	process.exitCode = undefined;
	clearOperatorApprovalKeyCache();
	if (originalHome === undefined) delete process.env.HOME;
	else process.env.HOME = originalHome;
	rmSync(home, { recursive: true, force: true });
});

describe("aidr pending", () => {
	it("lists open asks without raw session ids", async () => {
		const id = actionId("pending");
		await pendingAsk(id);
		await pendingCommand({ json: true }, { store });
		const report = JSON.parse(out.join("\n")) as { pending: Array<Record<string, unknown>> };
		expect(report.pending).toHaveLength(1);
		expect(report.pending[0]?.actionId).toBe(id);
		expect(report.pending[0]?.verified).toBe(true);
		expect(out.join("\n")).not.toContain("session-1");
	});

	it("says so when nothing is waiting", async () => {
		await pendingCommand({}, { store });
		expect(out.join("\n")).toContain("No Singularity AIDR asks");
		expect(process.exitCode).toBeUndefined();
	});
});

describe("aidr approve", () => {
	it("refuses without an interactive terminal and records nothing", async () => {
		const id = actionId("no-tty");
		await pendingAsk(id);
		await approveCommand(id, {}, { store, env: {}, streams: nonTtyStreams() });
		expect(process.exitCode).toBe(1);
		expect(err.join("\n")).toContain("interactive terminal");
		expect(await listOperatorApprovals(store)).toHaveLength(0);
	});

	it("ignores --yes unless the operator also set AIDR_OPERATOR_NONINTERACTIVE=1", async () => {
		const id = actionId("yes-only");
		await pendingAsk(id);
		await approveCommand(id, { yes: true }, { store, env: {}, streams: nonTtyStreams() });
		expect(process.exitCode).toBe(1);
		expect(await listOperatorApprovals(store)).toHaveLength(0);
	});

	it("approves non-interactively with --yes and the operator variable", async () => {
		const id = actionId("automation");
		await pendingAsk(id);
		await approveCommand(
			id,
			{ yes: true, json: true },
			{ store, env: { [OPERATOR_NONINTERACTIVE_ENV]: "1" }, streams: nonTtyStreams() },
		);
		expect(process.exitCode).toBeUndefined();
		const receipt = JSON.parse(out.join("\n")) as { approval: Record<string, unknown> };
		expect(receipt.approval.approver).toMatch(/\(non-interactive\)$/);
		expect(receipt.approval.singleUse).toBe(true);

		const consumed = await consumeOperatorApproval(
			{ actionId: id, tool: "bash", artifacts: [{ type: "command", value: COMMAND }] },
			store,
		);
		expect(consumed.approved).toBe(true);
	});

	it("approves when the operator types the confirmation word", async () => {
		const id = actionId("interactive");
		await pendingAsk(id);
		await approveCommand(id, { ttl: "5" }, { store, env: {}, streams: ttyStreams("approve") });
		expect(process.exitCode).toBeUndefined();
		const [approval] = await listOperatorApprovals(store);
		expect(approval?.approver).toMatch(/\(interactive\)$/);
		expect(Date.parse(approval?.expiresAt ?? "") - Date.parse(approval?.approvedAt ?? "")).toBe(
			5 * 60 * 1000,
		);
	});

	it("does nothing when the operator declines", async () => {
		const id = actionId("declined");
		await pendingAsk(id);
		await approveCommand(id, {}, { store, env: {}, streams: ttyStreams("no") });
		expect(process.exitCode).toBe(1);
		expect(await listOperatorApprovals(store)).toHaveLength(0);
	});

	it("rejects unknown, malformed and tampered references", async () => {
		const env = { [OPERATOR_NONINTERACTIVE_ENV]: "1" };
		await approveCommand(
			actionId("unknown"),
			{ yes: true },
			{ store, env, streams: nonTtyStreams() },
		);
		expect(err.join("\n")).toContain("No pending Singularity AIDR ask");

		await approveCommand("zzz", { yes: true }, { store, env, streams: nonTtyStreams() });
		expect(err.join("\n")).toContain("64-character");

		const id = actionId("tampered");
		await pendingAsk(id);
		const doc = JSON.parse(readFileSync(store.path as string, "utf8"));
		doc.pending[0].tool = "write";
		writeFileSync(store.path as string, JSON.stringify(doc));
		await approveCommand(id, { yes: true }, { store, env, streams: nonTtyStreams() });
		expect(err.join("\n")).toContain("integrity verification");
		expect(await listOperatorApprovals(store)).toHaveLength(0);
		expect(process.exitCode).toBe(1);
	});

	it("rejects an out-of-range TTL", async () => {
		const id = actionId("ttl");
		await pendingAsk(id);
		const env = { [OPERATOR_NONINTERACTIVE_ENV]: "1" };
		await approveCommand(id, { yes: true, ttl: "5000" }, { store, env, streams: nonTtyStreams() });
		expect(err.join("\n")).toContain("invalid_ttl");
		await approveCommand(id, { yes: true, ttl: "-1" }, { store, env, streams: nonTtyStreams() });
		expect(err.join("\n")).toContain("whole number of minutes");
	});
});

describe("aidr allowlist", () => {
	const env = { [OPERATOR_NONINTERACTIVE_ENV]: "1" };

	it("requires confirmation to add, then lists and removes entries", async () => {
		await allowlistAddCommand(
			"url",
			"https://example.com/a",
			{},
			{ env: {}, streams: nonTtyStreams() },
		);
		expect(process.exitCode).toBe(1);
		expect(existsSync(join(home, ".singularity-aidr", "allowlist.json"))).toBe(false);
		process.exitCode = undefined;
		err = [];

		const yes = { yes: true };
		await allowlistAddCommand("url", "https://example.com/a", yes, {
			env,
			streams: nonTtyStreams(),
		});
		await allowlistAddCommand(
			"command",
			"make deploy",
			{ ...yes, reason: "release" },
			{ env, streams: nonTtyStreams() },
		);
		await allowlistAddCommand("file", "/tmp/aidr-test/x", yes, { env, streams: nonTtyStreams() });
		expect(err).toEqual([]);
		expect(process.exitCode).toBeUndefined();
		const saved = join(home, ".singularity-aidr", "allowlist.json");
		expect(JSON.parse(readFileSync(saved, "utf8")).commands).toHaveProperty(
			hashCommand("make deploy"),
		);

		out = [];
		await allowlistListCommand({ json: true });
		const listed = JSON.parse(out.join("\n")) as {
			entries: Array<{ type: string; value: string; reason: string }>;
		};
		expect(listed.entries.map((e) => e.type).sort()).toEqual(["command", "file_path", "url"]);
		expect(listed.entries.find((e) => e.type === "command")?.reason).toBe("release");
		expect(out.join("\n")).not.toContain("make deploy");

		await allowlistRemoveCommand("command", hashCommand("make deploy").slice(0, 16));
		await allowlistRemoveCommand("url", "https://example.com/a");
		await allowlistRemoveCommand("file_path", "/tmp/aidr-test/x");
		expect(process.exitCode).toBeUndefined();
		out = [];
		await allowlistListCommand({ json: true });
		expect((JSON.parse(out.join("\n")) as { entries: unknown[] }).entries).toEqual([]);
	});

	it("reports a missing entry and an unknown type", async () => {
		await allowlistRemoveCommand("url", "https://never-added.test");
		expect(process.exitCode).toBe(1);
		process.exitCode = undefined;
		await allowlistAddCommand("registry", "x", { yes: true }, { env, streams: nonTtyStreams() });
		expect(err.join("\n")).toContain("Unknown allowlist type");
	});
});

describe("aidr audit", () => {
	const secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

	function writeAudit(): void {
		const dir = join(home, ".singularity-aidr");
		const entry = (timestamp: string, verdict: string, summary: string) =>
			JSON.stringify({
				type: "runtime_verdict",
				timestamp,
				session_id: "raw-session-id",
				tool_name: "bash",
				tool_input_summary: summary,
				verdict,
				severity: "warning",
				reasons: [`token=${secret}`],
				source: "heuristic",
				matched_threat_id: "CLT-TEST-001",
				user_override: false,
			});
		writeFileSync(
			join(dir, "audit.jsonl.1"),
			`${entry("2026-09-20T10:00:00.000Z", "deny", "=cmd|' /C calc'!A0")}\n`,
		);
		writeFileSync(
			join(dir, "audit.jsonl"),
			[
				entry("2026-09-24T09:00:00.000Z", "ask", `curl -H "Authorization: Bearer ${secret}" x`),
				"not json",
				entry("2026-09-24T09:30:00.000Z", "deny", "rm -rf /"),
			].join("\n"),
		);
	}

	it("tails the newest entries, redacted", async () => {
		writeAudit();
		await auditTailCommand({ lines: "2", json: true });
		const entries = out.map((line) => JSON.parse(line) as Record<string, unknown>);
		expect(entries.map((e) => e.verdict)).toEqual(["ask", "deny"]);
		expect(out.join("\n")).not.toContain(secret);
		expect(out.join("\n")).not.toContain("raw-session-id");
		expect(entries[0]?.session_digest).toMatch(/^[a-f0-9]{16}$/);
	});

	it("exports across rotated files as JSONL or CSV, filtered by --since", async () => {
		writeAudit();
		const now = () => Date.parse("2026-09-24T10:00:00.000Z");
		const writes: string[] = [];
		vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
			writes.push(String(chunk));
			return true;
		});

		await auditExportCommand({ format: "jsonl" }, { now });
		const all = writes.join("").trim().split("\n");
		expect(all).toHaveLength(3);
		expect(err.join("\n")).toContain("1 unreadable audit line");

		writes.length = 0;
		await auditExportCommand({ format: "jsonl", since: "2h" }, { now });
		expect(writes.join("").trim().split("\n")).toHaveLength(2);

		writes.length = 0;
		await auditExportCommand({ format: "csv", since: "2026-09-01" }, { now });
		const csv = writes.join("");
		expect(csv.split("\n")[0]).toContain("timestamp,type,decision");
		expect(csv).not.toContain(secret);
		expect(csv).not.toContain("raw-session-id");
		// A spreadsheet must not evaluate a logged command as a formula.
		expect(csv).toContain("'=cmd");
	});

	it("writes an owner-only export file and never overwrites one", async () => {
		writeAudit();
		const target = join(home, "export.jsonl");
		await auditExportCommand({ output: target });
		if (process.platform !== "win32") expect(statSync(target).mode & 0o777).toBe(0o600);
		await auditExportCommand({ output: target });
		expect(process.exitCode).toBe(1);
		expect(err.join("\n")).toContain("already exists");
	});

	it("validates its arguments", async () => {
		await auditExportCommand({ format: "xml" });
		expect(process.exitCode).toBe(1);
		expect(parseSince("7d", 10 * 86_400_000)).toBe(3 * 86_400_000);
		expect(parseSince("yesterday-ish", 0)).toBeNull();
		expect(toCsv([])).toBe(
			"timestamp,type,decision,severity,category,tool_name,matched_threat_id,source,user_override,session_digest,tool_input_summary,reasons\n",
		);
	});
});

describe("aidr doctor", () => {
	function connector(state: ConnectorStatus["state"]): ConnectorStatus {
		return { id: "opencode", label: "OpenCode", state, detail: "test", evidence: [] };
	}

	it("fails when no hook is registered", async () => {
		const report = await runDoctor({
			connectors: () => [connector("runtime_present_not_installed")],
			operatorApprovals: store,
		});
		expect(report.ok).toBe(false);
		expect(report.checks.find((c) => c.id === "connectors")?.status).toBe("fail");
		expect(report.checks.find((c) => c.id === "connectors")?.summary).toContain("aidr setup");
	});

	it("passes with a registered hook and reports mode, rules, DLP, approvals and last verdict", async () => {
		writeFileSync(
			join(home, ".singularity-aidr", "audit.jsonl"),
			`${JSON.stringify({ type: "runtime_verdict", timestamp: "2026-09-24T09:00:00.000Z", verdict: "deny", tool_name: "bash", session_id: "s" })}\n`,
		);
		await pendingAsk(actionId("doctor"));
		const report = await runDoctor({
			connectors: () => [connector("installed")],
			operatorApprovals: store,
			loadDetectors: async () => ({}),
		});
		const byId = Object.fromEntries(report.checks.map((c) => [c.id, c]));
		expect(report.ok).toBe(true);
		expect(byId.core_version?.summary).toMatch(/core \d+\.\d+\.\d+/);
		expect(byId.configuration?.summary).toContain("Mode: local");
		expect(byId.detection?.status).toBe("ok");
		expect(byId.dlp?.status).toBe("warn");
		expect(byId.dlp?.summary).toContain("local mode has no DLP");
		expect(byId.operator_approvals?.summary).toContain("1 ask(s) pending");
		expect(byId.last_verdict?.summary).toContain("deny for bash");
	});

	it("fails on an invalid configuration or an invalid detector policy", async () => {
		writeFileSync(join(home, ".singularity-aidr", "config.json"), "{ not json");
		const report = await runDoctor({
			connectors: () => [connector("installed")],
			operatorApprovals: store,
			loadDetectors: async () => {
				throw new Error("signature mismatch");
			},
		});
		const byId = Object.fromEntries(report.checks.map((c) => [c.id, c]));
		expect(report.ok).toBe(false);
		expect(byId.configuration?.status).toBe("fail");
		expect(byId.dlp?.status).toBe("fail");
		expect(byId.dlp?.summary).toContain("opencode");
	});
});
