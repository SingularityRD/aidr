/**
 * The developer-facing commands: `aidr report-fp` (D9), `aidr privacy notice`
 * (D4/D14), and AI tools without AIDR protection in `aidr status` and
 * `aidr coverage` (D6).
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
	buildRuntimeVerdictEntry,
	type Config,
	ConfigSchema,
	type UnprotectedAiTool,
	type Verdict,
} from "@singularityrd/aidr-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runCoverage } from "../commands/coverage.js";
import { privacyNoticeCommand } from "../commands/privacy-notice.js";
import { reportFpCommand } from "../commands/report-fp.js";

const ACTION_ID = "0f1e2d3c".repeat(8);
const deny: Verdict = {
	decision: "deny",
	category: "tool",
	confidence: 0.95,
	severity: "critical",
	source: "heuristic",
	artifacts: [],
	matchedThreatId: "CLT-CMD-006",
	reasons: ["Recursive forced deletion"],
};
const TOOLS: UnprotectedAiTool[] = [
	{ id: "windsurf", label: "Windsurf", evidence: ["/x"] },
	{ id: "gemini-cli", label: "Gemini CLI", evidence: ["PATH:gemini"] },
];

let dir: string;
let out: string[];
let err: string[];
const io = () => ({ out: (t: string) => out.push(t), err: (t: string) => err.push(t) });

function configWithLog(extra: Record<string, unknown> = {}): Config {
	const path = join(dir, "audit.jsonl");
	writeFileSync(
		path,
		`${JSON.stringify(buildRuntimeVerdictEntry("s", "Bash", { command: "rm -rf build" }, deny, false, 1, ACTION_ID))}\n`,
	);
	return ConfigSchema.parse({ logging: { path }, ...extra }) as Config;
}

beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "aidr-devloop-"));
	out = [];
	err = [];
	process.exitCode = undefined;
});
afterEach(() => {
	process.exitCode = undefined;
	rmSync(dir, { recursive: true, force: true });
	vi.restoreAllMocks();
});

describe("aidr report-fp", () => {
	it("files the report found by the short id from the block message", async () => {
		const submit = vi.fn(async () => ({
			ok: true as const,
			reportId: "rep-1",
			created: true,
			feedbackId: `fpfb_${"0".repeat(64)}`,
		}));
		await reportFpCommand(
			"0F1E2D3C",
			{ reason: "developer_test", note: "fixture" },
			{
				config: configWithLog({
					organization: { support_contact_url: "https://help.example/aidr" },
				}),
				submit,
				...io(),
			},
		);
		expect(process.exitCode).toBeUndefined();
		expect(submit).toHaveBeenCalledWith(
			expect.anything(),
			expect.objectContaining({
				reasonCode: "developer_test",
				note: "fixture",
				block: expect.objectContaining({ actionId: ACTION_ID, ruleId: "CLT-CMD-006" }),
			}),
		);
		const text = out.join("\n");
		expect(text).toContain("rule CLT-CMD-006");
		expect(text).toContain("Reported as a false positive (report rep-1)");
		expect(text).toContain("https://help.example/aidr");
		expect(text).not.toContain("rm -rf build");
	});

	it("local mode: nothing to send, so it says whom to tell and exits 0", async () => {
		await reportFpCommand(
			"0f1e2d3c",
			{},
			{
				config: configWithLog(),
				submit: async () => ({ ok: false, error: "not_managed" }),
				...io(),
			},
		);
		expect(process.exitCode).toBeUndefined();
		expect(out.join("\n")).toContain("not connected to a Singularity AIDR console");
	});

	it("a failed submission exits 1", async () => {
		await reportFpCommand(
			"0f1e2d3c",
			{},
			{
				config: configWithLog(),
				submit: async () => ({ ok: false, error: "timeout" }),
				...io(),
			},
		);
		expect(process.exitCode).toBe(1);
		expect(err.join("\n")).toContain("could not be sent (timeout)");
	});

	it("refuses a bad id, an unknown reason and an id with no audit record", async () => {
		const config = configWithLog();
		await reportFpCommand("xyz", {}, { config, ...io() });
		expect(err.pop()).toContain("8 to 64 hexadecimal");
		await reportFpCommand("0f1e2d3c", { reason: "because" }, { config, ...io() });
		expect(err.pop()).toContain('Unknown reason "because"');
		await reportFpCommand("deadbeef", {}, { config, ...io() });
		expect(err.pop()).toContain("No blocked or held action with id deadbeef");
		expect(process.exitCode).toBe(1);
	});

	it("--dry-run --json sends nothing", async () => {
		const submit = vi.fn();
		await reportFpCommand(
			"0f1e2d3c",
			{ dryRun: true, json: true },
			{
				config: configWithLog(),
				submit,
				...io(),
			},
		);
		expect(submit).not.toHaveBeenCalled();
		expect(JSON.parse(out.join(""))).toMatchObject({ action_id: ACTION_ID, submitted: false });
	});
});

describe("aidr privacy notice", () => {
	it("prints the notice with the unprotected tools", async () => {
		await privacyNoticeCommand(
			{},
			{ config: ConfigSchema.parse({}) as Config, unprotectedTools: TOOLS, ...io() },
		);
		const text = out.join("\n");
		expect(text).toContain("What it does not guard");
		expect(text).toContain("Windsurf, Gemini CLI");
	});

	it("--json prints the facts it is built from", async () => {
		await privacyNoticeCommand(
			{ json: true },
			{
				config: ConfigSchema.parse({
					organization: { privacy_notice_url: "https://intranet.example/kvkk" },
				}) as Config,
				unprotectedTools: TOOLS,
				...io(),
			},
		);
		expect(JSON.parse(out.join(""))).toMatchObject({
			mode: "local",
			privacy_notice_url: "https://intranet.example/kvkk",
			unprotected_ai_tools: ["windsurf", "gemini-cli"],
		});
	});
});

describe("unprotected AI tools in status and coverage", () => {
	const repoThreats = fileURLToPath(new URL("../../../../threats", import.meta.url));

	it("aidr coverage names them under the matrix and in JSON", async () => {
		await runCoverage({}, { threatsDir: repoThreats, unprotectedTools: TOOLS, ...io() });
		expect(out.join("")).toContain("does not protect: Windsurf, Gemini CLI");
		out = [];
		await runCoverage(
			{ format: "json" },
			{ threatsDir: repoThreats, unprotectedTools: [], ...io() },
		);
		expect(JSON.parse(out.join("")).unprotected_ai_tools).toEqual([]);
	});

	it("aidr status --json lists them", async () => {
		const home = mkdtempSync(join(tmpdir(), "aidr-status-unprot-"));
		mkdirSync(join(home, ".singularity-aidr"), { recursive: true });
		vi.stubEnv("HOME", home);
		const lines: string[] = [];
		vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
			lines.push(args.map(String).join(" "));
		});
		try {
			const statusCommand = (await import("../commands/status.js")).default;
			await statusCommand({ json: true }, { unprotectedTools: TOOLS });
			expect(JSON.parse(lines.join("\n")).unprotected_ai_tools).toEqual([
				{ id: "windsurf", label: "Windsurf" },
				{ id: "gemini-cli", label: "Gemini CLI" },
			]);
		} finally {
			vi.unstubAllEnvs();
			rmSync(home, { recursive: true, force: true });
		}
	});
});
