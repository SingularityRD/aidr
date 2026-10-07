import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { resolvePath } from "@singularityrd/aidr-core";
import type { Environment } from "./config-manager.js";
import { updateConfig } from "./config-manager.js";

const AIDR_DIR = resolvePath("~/.singularity-aidr");

export interface HookInstallResult {
	/** Single line describing precisely what was and was not done. */
	summary: string;
	/** Extra lines shown to the user after setup (documented next steps). */
	followUp: string[];
}

/**
 * Records the local setup state and tells the user truthfully what still has to
 * happen for the agent to be protected.
 *
 * A previous version of this module wrote `claude-hooks.json`, `aidr.enabled` /
 * `aidr.hooksPath` editor settings and an OpenClaw `plugins` array, then reported
 * success. None of those files or keys are read by any shipped connector, so the
 * agent was never actually protected while the CLI claimed it was.
 *
 * Correct behaviour is to point at the documented, real installation path for
 * the detected runtime and never imply that protection is active when it is not.
 */
export async function installHooks(env: Environment): Promise<HookInstallResult> {
	if (!existsSync(AIDR_DIR)) {
		mkdirSync(AIDR_DIR, { recursive: true, mode: 0o700 });
	}

	// Record the detected runtime so `aidr status` can report it. This is state
	// only - it does not install anything.
	recordHooksInstalled(false);

	const followUp = ["Protection is NOT yet active for your agent. Install the connector:"];

	switch (env.agent) {
		case "claude":
			followUp.push(
				"  Claude Code:  verify the publisher-signed release bundle and extract aidr-claude-plugin-<version>.tar.gz.",
				"                Provision the release Ed25519 public key in ~/.singularity-aidr/config.json",
				"                (commercial builds fail closed without it), then from the Claude Code prompt run",
				"                /plugin marketplace add /absolute/path/to/extracted/aidr-claude-plugin",
				"                /plugin install aidr@aidr",
				"                Restart Claude Code and confirm the plugin is active (see docs/getting-started.md).",
			);
			break;
		case "cursor":
			followUp.push(
				"  Cursor:       install the approved aidr-cursor.vsix from the verified release bundle, then run",
				"                cursor --install-extension ./aidr-cursor.vsix",
				"                'Singularity AIDR: Enable protection' from the command palette.",
			);
			break;
		case "vscode":
			followUp.push(
				"  VS Code:      install the approved aidr-vscode.vsix from the verified release bundle, then run",
				"                code --install-extension ./aidr-vscode.vsix and enable protection",
				"                from the command palette.",
			);
			break;
		case "openclaw":
			followUp.push(
				"  OpenClaw:     install the approved package version with",
				"                openclaw plugins install npm:@singularityrd/aidr-openclaw@VERSION",
				"                (replace VERSION with the exact version in the approved release record).",
			);
			break;
		case "opencode":
			followUp.push(
				"  OpenCode:     install the approved version from private GitHub Packages.",
				'                ~/.config/opencode/package.json: {"dependencies":{"@singularityrd/aidr-opencode":"VERSION"}}',
				'                ~/.config/opencode/opencode.json: {"plugin":["@singularityrd/aidr-opencode"]}',
				"                Replace VERSION with the exact approved release version; run a host-side deny canary.",
			);
			break;
		case "codex":
			followUp.push(
				"  Codex:        install @singularityrd/aidr-codex@VERSION from private GitHub Packages.",
				"                Add to ~/.codex/config.toml:",
				"                [[hooks.PreToolUse]]",
				'                matcher = "^(Bash|apply_patch)$"',
				"                [[hooks.PreToolUse.hooks]]",
				'                type = "command"',
				'                command = "aidr-codex-hook"',
				"                timeout = 10",
				"                Replace VERSION with the exact approved release version, trust the hook,",
				"                then run a host-side deny canary.",
			);
			break;
		default:
			followUp.push(
				"  See docs/getting-started.md for the supported runtimes",
				"  (Claude Code, Cursor, VS Code, OpenClaw, OpenCode, Codex).",
			);
			break;
	}

	followUp.push("  Docs: https://aidr.singularityrd.com");

	return {
		summary:
			env.agent === "unknown"
				? "No supported agent detected - nothing installed"
				: `${env.agent} detected - connector install required`,
		followUp,
	};
}

/**
 * Writes a generic hook entry point for runtimes without a dedicated connector.
 * The script is self-contained: it invokes the packaged AIDR hook bundle rather
 * than a CLI subcommand that does not exist.
 */
export function writeGenericHookTemplate(hookBundlePath: string): string {
	const target = join(AIDR_DIR, "hooks", "generic-hook.cjs");
	mkdirSync(join(AIDR_DIR, "hooks"), { recursive: true, mode: 0o700 });

	const template = `#!/usr/bin/env node
// Singularity AIDR generic hook.
// Wire this into your agent's hook system: it reads a tool-call JSON payload on
// stdin and writes the AIDR verdict JSON to stdout.
const { spawnSync } = require("node:child_process");

const HOOK_BUNDLE = ${JSON.stringify(hookBundlePath)};

const chunks = [];
process.stdin.on("data", (c) => chunks.push(c));
process.stdin.on("end", () => {
	const input = Buffer.concat(chunks);
	const result = spawnSync(process.execPath, [HOOK_BUNDLE, "cursor"], { input });
	if (result.stdout) process.stdout.write(result.stdout);
	process.exit(0);
});
`;

	writeFileSync(target, template, { mode: 0o700 });
	return target;
}

/**
 * Records the measured hook state in the local config.
 *
 * Kept in this module so the installer and the uninstaller agree on the single
 * place that writes `hooksInstalled`, rather than each inventing its own state
 * file or leaving the recorded flag stale.
 */
export function recordHooksInstalled(hooksInstalled: boolean): void {
	updateConfig({ hooksInstalled });
}

/**
 * The `statusMessage` the real connector installer writes on every hook it
 * registers (`scripts/endpoint-install.mjs`, and the fleet installers that call
 * it). It is the only signal this tooling treats as proof that a hook belongs to
 * AIDR, so a customer hook — which never carries it — is never removed.
 */
export const MANAGED_HOOK_MARKER = "Singularity AIDR managed installation";

/** One hook registration that was removed, reported verbatim to the user. */
export interface ManagedHookRecord {
	event: string;
	/** The registered command, or null when the hook carried no command string. */
	command: string | null;
	statusMessage: string;
}

export interface ManagedHookRemoval {
	/**
	 * The settings object with every AIDR-managed hook removed. It equals the
	 * input when nothing matched, and callers must not write it unless
	 * `changed` is true.
	 */
	settings: Record<string, unknown>;
	/** Exactly the registrations that were removed — never an inference. */
	removed: ManagedHookRecord[];
	/** Non-AIDR hook objects that were left untouched. */
	preservedHooks: number;
	/** Hook entries (including containers we never inspected) left in place. */
	preservedEntries: number;
	/** Events whose entry list became empty and were therefore deleted. */
	emptiedEvents: string[];
	/** True when the whole `hooks` object became empty and was deleted. */
	removedHooksObject: boolean;
	/** True only when at least one managed hook was removed. */
	changed: boolean;
}

/** Thrown when the caller's settings cannot be edited safely (fail closed). */
export class ManagedHookError extends Error {}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Removes ONLY the hook registrations AIDR installed, preserving every other
 * hook, entry and top-level key byte-for-byte.
 *
 * The filter is deliberately identical to the fleet remover
 * (`deploy/fleet/unix/remove-managed-hooks.mjs`, and `Uninstall-Aidr.ps1` on
 * Windows): a hook is AIDR's only when its `statusMessage` is exactly
 * {@link MANAGED_HOOK_MARKER}. An entry that keeps at least one hook survives
 * with its own fields intact; an entry that loses every hook is dropped, and an
 * event whose entries are all gone is deleted. A settings shape we cannot
 * understand throws instead of being rewritten — a security tool must not
 * "repair" a file it cannot parse.
 */
export function removeManagedHooks(settings: unknown): ManagedHookRemoval {
	if (!isPlainObject(settings)) {
		throw new ManagedHookError("Agent hook settings are not a JSON object.");
	}

	const next: Record<string, unknown> = { ...settings };
	const removed: ManagedHookRecord[] = [];
	const emptiedEvents: string[] = [];
	let preservedHooks = 0;
	let preservedEntries = 0;
	let removedHooksObject = false;

	if (next.hooks === undefined) {
		return {
			settings: next,
			removed,
			preservedHooks,
			preservedEntries,
			emptiedEvents,
			removedHooksObject,
			changed: false,
		};
	}
	if (!isPlainObject(next.hooks)) {
		throw new ManagedHookError("Agent hook settings 'hooks' is not an object.");
	}

	const hooks: Record<string, unknown> = { ...next.hooks };
	for (const [event, value] of Object.entries(hooks)) {
		if (!Array.isArray(value)) {
			throw new ManagedHookError(`Agent hook settings event '${event}' is not an array.`);
		}
		const keptEntries: unknown[] = [];
		for (const entry of value) {
			// An entry without its own `hooks` array is not ours to interpret.
			if (!isPlainObject(entry) || !Array.isArray(entry.hooks)) {
				keptEntries.push(entry);
				preservedEntries += 1;
				continue;
			}
			const keptHooks: unknown[] = [];
			for (const hook of entry.hooks) {
				const statusMessage = isPlainObject(hook) ? hook.statusMessage : undefined;
				if (statusMessage === MANAGED_HOOK_MARKER) {
					removed.push({
						event,
						command: isPlainObject(hook) && typeof hook.command === "string" ? hook.command : null,
						statusMessage: MANAGED_HOOK_MARKER,
					});
					continue;
				}
				preservedHooks += 1;
				keptHooks.push(hook);
			}
			if (keptHooks.length === entry.hooks.length) {
				// Nothing in this entry was ours: keep the original object.
				keptEntries.push(entry);
				preservedEntries += 1;
				continue;
			}
			if (keptHooks.length > 0) {
				keptEntries.push({ ...entry, hooks: keptHooks });
				preservedEntries += 1;
			}
		}
		if (keptEntries.length > 0) hooks[event] = keptEntries;
		else {
			delete hooks[event];
			// Only an event that HAD entries and lost all of them was emptied by
			// this removal; an already-empty list is not a change we made.
			if (value.length > 0) emptiedEvents.push(event);
		}
	}

	const changed = removed.length > 0;
	if (changed) {
		if (Object.keys(hooks).length === 0) {
			delete next.hooks;
			removedHooksObject = true;
		} else {
			next.hooks = hooks;
		}
	}
	return {
		settings: changed ? next : settings,
		removed,
		preservedHooks,
		preservedEntries,
		emptiedEvents,
		removedHooksObject,
		changed,
	};
}
