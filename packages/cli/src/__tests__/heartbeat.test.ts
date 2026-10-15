/**
 * C10: the per-connector heartbeat and the Codex trust check behind
 * `aidr doctor`. Every case runs against a temporary HOME; machine policy is
 * injected, never read from the real /etc.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runDoctor } from "../commands/doctor.js";
import heartbeatCommand from "../commands/heartbeat.js";
import { inspectCodexHookTrust, parseCodexHookStates } from "../utils/codex-trust.js";
import { buildHeartbeat } from "../utils/heartbeat.js";
import type { MachineHookState } from "../utils/machine-hooks.js";

const roots: string[] = [];
afterEach(() => {
	for (const root of roots) rmSync(root, { recursive: true, force: true });
	roots.length = 0;
	process.exitCode = undefined;
});

function home(): string {
	const root = mkdtempSync(join(tmpdir(), "aidr-heartbeat-"));
	roots.push(root);
	return root;
}

function write(path: string, content: string): void {
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, content);
}

const HASH = `sha256:${"a".repeat(64)}`;
const NO_MACHINE: MachineHookState[] = [
	{
		host: "claude-code",
		path: "/etc/claude-code/managed-settings.d/50-singularity-aidr.json",
		registered: false,
		otherHooksLocked: false,
		tamperResistant: null,
		problems: [],
	},
	{
		host: "codex",
		path: "/etc/codex/hooks.json",
		registered: false,
		otherHooksLocked: false,
		tamperResistant: null,
		problems: [],
	},
];
const CODEX_MACHINE: MachineHookState[] = [
	NO_MACHINE[0] as MachineHookState,
	{ ...(NO_MACHINE[1] as MachineHookState), registered: true },
];

function codexHooks(dir: string): void {
	write(
		join(dir, ".codex", "hooks.json"),
		JSON.stringify({
			hooks: {
				PreToolUse: [
					{ matcher: "Bash", hooks: [{ type: "command", command: "/usr/bin/other" }] },
					{
						matcher: "^(Bash|apply_patch|mcp__.+)$",
						hooks: [{ type: "command", command: "aidr-codex-hook", timeout: 10 }],
					},
				],
				UserPromptSubmit: [
					{ hooks: [{ type: "command", command: "aidr-codex-hook", timeout: 10 }] },
				],
			},
		}),
	);
}

describe("Codex hook trust", () => {
	it("parses both forms of hooks.state", () => {
		const states = parseCodexHookStates(
			[
				'[hooks.state."/h/.codex/hooks.json:pre_tool_use:1:0"]',
				`trusted_hash = "${HASH}"`,
				"",
				"[hooks.state]",
				`"/h/.codex/hooks.json:user_prompt_submit:0:0" = { trusted_hash = "${HASH}", enabled = false }`,
				"[model_providers.x]",
				'trusted_hash = "ignored"',
			].join("\n"),
		);
		expect(states.get("/h/.codex/hooks.json:pre_tool_use:1:0")).toEqual({
			trusted: true,
			enabled: null,
		});
		expect(states.get("/h/.codex/hooks.json:user_prompt_submit:0:0")).toEqual({
			trusted: true,
			enabled: false,
		});
		expect(states.size).toBe(2);
	});

	it("keys each AIDR handler the way Codex does and finds the untrusted one", () => {
		const dir = home();
		codexHooks(dir);
		const hooksPath = join(dir, ".codex", "hooks.json");
		write(
			join(dir, ".codex", "config.toml"),
			`[hooks.state."${hooksPath}:pre_tool_use:1:0"]\ntrusted_hash = "${HASH}"\n`,
		);
		const report = inspectCodexHookTrust(dir, {});
		expect(report.handlers).toEqual([
			{ key: `${hooksPath}:pre_tool_use:1:0`, event: "PreToolUse", trust: "trust_recorded" },
			{ key: `${hooksPath}:user_prompt_submit:0:0`, event: "UserPromptSubmit", trust: "untrusted" },
		]);
	});

	it("reads TOML-registered handlers from config.toml with Codex's group and handler indices", () => {
		const dir = home();
		const configPath = join(dir, ".codex", "config.toml");
		write(
			configPath,
			[
				"[[hooks.PreToolUse]]",
				'matcher = "^(Bash|apply_patch|mcp__.+)$"',
				"[[hooks.PreToolUse.hooks]]",
				'type = "command"',
				'command = "aidr-codex-hook"',
				`[hooks.state."${configPath}:pre_tool_use:0:0"]`,
				"enabled = false",
			].join("\n"),
		);
		expect(inspectCodexHookTrust(dir, {}).handlers).toEqual([
			{ key: `${configPath}:pre_tool_use:0:0`, event: "PreToolUse", trust: "disabled" },
		]);
	});
});

describe("aidr doctor flags untrusted Codex hooks", () => {
	const codexInstalled = () => [
		{
			id: "codex" as const,
			label: "Codex",
			state: "installed" as const,
			detail: "registered",
			evidence: [],
		},
	];

	it("fails with the fix when an AIDR handler is untrusted", async () => {
		const dir = home();
		codexHooks(dir);
		const report = await runDoctor({
			home: dir,
			connectors: codexInstalled,
			machine: () => NO_MACHINE,
		});
		const check = report.checks.find((c) => c.id === "codex_hook_trust");
		expect(check?.status).toBe("fail");
		expect(check?.summary).toContain("UserPromptSubmit");
		expect(check?.notes?.[0]).toContain("/hooks");
		expect(report.ok).toBe(false);
	});

	it("is satisfied by a machine-policy registration, which Codex trusts without review", async () => {
		const dir = home();
		codexHooks(dir);
		const report = await runDoctor({
			home: dir,
			connectors: codexInstalled,
			machine: () => CODEX_MACHINE,
		});
		expect(report.checks.find((c) => c.id === "codex_hook_trust")).toMatchObject({
			status: "ok",
			detail: { trust: "managed" },
		});
	});

	it("is absent when Codex is not present", async () => {
		const report = await runDoctor({
			home: home(),
			connectors: () => [],
			machine: () => NO_MACHINE,
		});
		expect(report.checks.some((c) => c.id === "codex_hook_trust")).toBe(false);
	});
});

describe("buildHeartbeat", () => {
	const status = (
		id: "claude-code" | "cursor" | "vscode" | "codex",
		state:
			| "installed"
			| "runtime_present_not_installed"
			| "not_detected"
			| "installed_but_degraded",
	) => ({
		id,
		label: id,
		state,
		detail: "",
		evidence: [],
	});

	it("maps measured host state to enums only, skipping hosts that are not there", () => {
		const dir = home();
		codexHooks(dir);
		write(join(dir, ".claude", "settings.json"), JSON.stringify({ disableAllHooks: true }));
		write(
			join(dir, ".cursor", "hooks.json"),
			'{"hooks":{"beforeShellExecution":[{"command":"x --managed-by aidr-cursor"}]}}',
		);
		const reports = buildHeartbeat({
			home: dir,
			env: {},
			machine: NO_MACHINE,
			connectors: [
				status("claude-code", "runtime_present_not_installed"),
				status("cursor", "installed"),
				status("vscode", "installed"),
				status("codex", "installed"),
			],
			lock: { locked: true, source: "linux_policy_file" },
			events: {
				vscode: {
					disable_attempts: 0,
					hooks_restored: 0,
					disabled_by_user: 2,
					last_event_at: null,
				},
				cursor: {
					disable_attempts: 3,
					hooks_restored: 1,
					disabled_by_user: 0,
					last_event_at: null,
				},
			},
		});
		expect(reports).toEqual([
			{
				connector: "claude-code",
				state: "hook_disabled",
				enforcement: "none",
				protection_locked: false,
				disable_attempts: 0,
			},
			{
				connector: "cursor",
				state: "protected",
				enforcement: "user_config",
				protection_locked: true,
				disable_attempts: 3,
			},
			{
				connector: "vscode",
				state: "hook_disabled",
				enforcement: "none",
				protection_locked: true,
				disable_attempts: 0,
			},
			{
				connector: "codex",
				state: "hook_untrusted",
				enforcement: "none",
				protection_locked: false,
				disable_attempts: 0,
			},
		]);
		for (const report of reports) expect(JSON.stringify(report)).not.toContain(dir);
	});

	it("reports a machine-policy registration as protected, whatever the user's files say", () => {
		const dir = home();
		codexHooks(dir);
		const [codex] = buildHeartbeat({
			home: dir,
			env: {},
			machine: CODEX_MACHINE,
			connectors: [status("codex", "installed")],
			lock: { locked: false, source: "none" },
			events: {},
		});
		expect(codex).toEqual({
			connector: "codex",
			state: "protected",
			enforcement: "machine_policy",
			protection_locked: false,
			disable_attempts: 0,
		});
	});
});

describe("aidr heartbeat", () => {
	it("sends the report in managed mode and fails non-zero when the control plane refuses it", async () => {
		const dir = home();
		write(
			join(dir, ".singularity-aidr", "config.json"),
			JSON.stringify({
				mode: "managed",
				control_plane: { enabled: true, endpoint: "https://cp.example.com" },
			}),
		);
		vi.stubEnv("HOME", dir);
		vi.stubEnv("USERPROFILE", dir);
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
		const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
		try {
			const sent: unknown[] = [];
			const deps = {
				home: dir,
				env: {},
				machine: CODEX_MACHINE,
				connectors: [
					{
						id: "codex" as const,
						label: "Codex",
						state: "installed" as const,
						detail: "",
						evidence: [],
					},
				],
				lock: { locked: false, source: "none" as const },
				events: {},
				iid: async () => "iid-device-1",
			};
			await heartbeatCommand(
				{ quiet: true },
				{
					...deps,
					send: async (payload) => {
						sent.push(payload);
						return { ok: true };
					},
				},
			);
			expect(sent).toEqual([
				{
					iid: "iid-device-1",
					connectors: [
						{
							connector: "codex",
							state: "protected",
							enforcement: "machine_policy",
							protection_locked: false,
							disable_attempts: 0,
						},
					],
				},
			]);
			expect(process.exitCode).toBeUndefined();

			await heartbeatCommand(
				{ quiet: true },
				{ ...deps, send: async () => ({ ok: false, error: "invalid_api_key" }) },
			);
			expect(process.exitCode).toBe(1);
			expect(error.mock.calls.flat().join(" ")).toContain("invalid_api_key");
		} finally {
			log.mockRestore();
			error.mockRestore();
			vi.unstubAllEnvs();
		}
	});
});
