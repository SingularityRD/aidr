import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { escapeTerminalText, resolvePath } from "@singularityrd/aidr-core";
import { ct } from "../i18n/index.js";
import { type ConnectorStatus, detectConnectorStatuses } from "../utils/connector-status.js";
import { canaryCommand, type HookProbe, runHookCommand } from "../utils/standalone.js";

/**
 * `aidr verify`: pass a harmless canary through the real hook entry point of
 * every registered connector and report PASS / FAIL / SKIP per host.
 *
 * The canary (`curl ... | bash` against the reserved `.invalid` domain) is only
 * ever written to the hook's stdin as the tool call the host would ask about;
 * nothing runs it. Only hook commands AIDR registered are executed (the same
 * commands the host runs on every tool call), with the user's HOME. In-process
 * plugins (OpenCode, OpenClaw) and plugin-registered Claude Code hooks have no
 * entry point outside their host and are reported as SKIP, never as PASS.
 */

type VerifyOutcome = "pass" | "fail" | "skip" | "not_registered";

export interface HostVerification {
	host: ConnectorStatus["id"];
	label: string;
	outcome: VerifyOutcome;
	detail: string;
	/** Hook commands exercised, verbatim. */
	commands: string[];
}

export interface VerifyDeps {
	home?: string;
	env?: NodeJS.ProcessEnv;
	/** Hook runner (tests). */
	run?: typeof runHookCommand;
}

type HookEntries = Array<{ hooks?: Array<{ command?: unknown }>; command?: unknown }>;

function readObject(path: string): Record<string, unknown> | null {
	try {
		const parsed = JSON.parse(readFileSync(path, "utf8"));
		return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
	} catch {
		return null;
	}
}

/** `command` strings of `hooks.<event>` entries (nested Claude/Codex form and flat Cursor form). */
function hookCommands(file: string, event: string): string[] {
	const hooks = readObject(file)?.hooks as Record<string, HookEntries> | undefined;
	const entries = hooks?.[event];
	if (!Array.isArray(entries)) return [];
	const commands: string[] = [];
	for (const entry of entries) {
		if (typeof entry?.command === "string") commands.push(entry.command);
		for (const hook of Array.isArray(entry?.hooks) ? entry.hooks : []) {
			if (typeof hook?.command === "string") commands.push(hook.command);
		}
	}
	return commands;
}

interface Plan {
	file: string;
	commands: string[];
	/** Tool call payload for a shell command, in the host's hook format. */
	payload: (command: string) => Record<string, unknown>;
}

/** Benign twin: an ordinary command the same hook must not deny. */
const BENIGN_COMMAND = "ls";

function planFor(status: ConnectorStatus, home: string, cwd: string): Plan | string {
	const claudePayload = (command: string) => ({
		hook_event_name: "PreToolUse",
		session_id: "aidr-verify",
		tool_use_id: "aidr-verify-call",
		cwd,
		tool_name: "Bash",
		tool_input: { command },
	});
	switch (status.id) {
		case "claude-code": {
			const file = join(home, ".claude", "settings.json");
			const commands = hookCommands(file, "PreToolUse").filter(
				(command) => /aidr|singularity/i.test(command) && !command.includes("--managed-by aidr-"),
			);
			return commands.length > 0
				? { file, commands, payload: claudePayload }
				: ct("verify.pluginOnly");
		}
		case "vscode": {
			const file = join(home, ".claude", "settings.json");
			const commands = hookCommands(file, "PreToolUse").filter((command) =>
				command.includes("--managed-by aidr-vscode"),
			);
			return commands.length > 0
				? { file, commands, payload: claudePayload }
				: ct("verify.noEntry", { file });
		}
		case "cursor": {
			const file = join(home, ".cursor", "hooks.json");
			const commands = hookCommands(file, "beforeShellExecution").filter((command) =>
				command.includes("--managed-by aidr-cursor"),
			);
			return commands.length > 0
				? {
						file,
						commands,
						payload: (command: string) => ({
							hook_event_name: "beforeShellExecution",
							command,
							cwd,
						}),
					}
				: ct("verify.noEntry", { file });
		}
		case "codex": {
			const file = join(home, ".codex", "hooks.json");
			const commands = hookCommands(file, "PreToolUse").filter((command) =>
				/\baidr-codex-hook\b/u.test(command),
			);
			return commands.length > 0
				? { file, commands, payload: claudePayload }
				: ct("verify.noEntry", { file: `${file} / ${join(home, ".codex", "config.toml")}` });
		}
		default:
			return ct("verify.inProcess");
	}
}

export function verifyHosts(deps: VerifyDeps = {}): HostVerification[] {
	const home = deps.home ?? resolvePath("~");
	const env = deps.env ?? process.env;
	const run = deps.run ?? runHookCommand;
	// A neutral working directory: no repository-scoped profile changes the verdict.
	const cwd = mkdtempSync(join(tmpdir(), "aidr-verify-"));
	try {
		return detectConnectorStatuses(home, env).map((status): HostVerification => {
			const base = { host: status.id, label: status.label, commands: [] as string[] };
			if (status.state !== "installed") {
				return { ...base, outcome: "not_registered", detail: ct("verify.notRegistered") };
			}
			const plan = planFor(status, home, cwd);
			if (typeof plan === "string") return { ...base, outcome: "skip", detail: plan };
			const failures: string[] = [];
			for (const command of plan.commands) {
				const probe: HookProbe = run(command, plan.payload(canaryCommand()), { home, cwd, env });
				if (probe.decision !== "deny") {
					failures.push(`canary ${probe.decision}: ${probe.detail}`);
					continue;
				}
				// A hook that denies everything (for example after an internal error)
				// would also deny the canary; the benign twin tells the two apart.
				const benign: HookProbe = run(command, plan.payload(BENIGN_COMMAND), { home, cwd, env });
				if (benign.decision === "deny" || benign.decision === "unknown") {
					failures.push(`'${BENIGN_COMMAND}' ${benign.decision}: ${benign.detail}`);
				}
			}
			return {
				...base,
				commands: plan.commands,
				outcome: failures.length === 0 ? "pass" : "fail",
				detail:
					failures.length === 0
						? `${plan.commands.length} hook(s) in ${plan.file} denied the canary and allowed '${BENIGN_COMMAND}'`
						: failures.join("; "),
			};
		});
	} finally {
		rmSync(cwd, { recursive: true, force: true });
	}
}

const LABEL: Record<VerifyOutcome, () => string> = {
	pass: () => ct("verify.pass"),
	fail: () => ct("verify.fail"),
	skip: () => ct("verify.skip"),
	not_registered: () => "-",
};

export default async function verifyCommand(
	options: { json?: boolean } = {},
	deps: VerifyDeps = {},
): Promise<void> {
	const results = verifyHosts(deps);
	const passed = results.filter((entry) => entry.outcome === "pass").length;
	const failed = results.filter((entry) => entry.outcome === "fail").length;
	if (options.json) {
		console.log(
			JSON.stringify({ schema_version: 1, canary: "data-only", hosts: results }, null, 2),
		);
	} else {
		console.log(ct("verify.title"));
		for (const entry of results) {
			console.log(
				`  ${entry.label.padEnd(12)} ${LABEL[entry.outcome]().padEnd(9)} ${escapeTerminalText(entry.detail)}`,
			);
		}
		console.log(
			failed > 0
				? ct("verify.summaryFail", { count: failed })
				: passed > 0
					? ct("verify.summaryPass", { count: passed })
					: ct("verify.summaryNone"),
		);
	}
	if (failed > 0 || passed === 0) process.exitCode = 1;
}
