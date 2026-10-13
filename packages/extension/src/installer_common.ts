import { access } from "node:fs/promises";
import path from "node:path";

import * as vscode from "vscode";

import { LAUNCHER_FILE_NAME } from "./hook-launcher.js";
import type { ExtensionHookHost } from "./hook-responses.js";
import {
	buildShimCommand,
	inspectManagedCommands,
	installHookRuntime,
	resolvedRunnerFor,
	writeHookShims,
} from "./hook-runtime.js";
import type { ManagedHookHealth } from "./managedHooks.js";

/** The bundled runner of the running extension, or the `aidr.hookRunnerPath` override. */
async function resolveRunnerPath(context: vscode.ExtensionContext): Promise<string> {
	const configured =
		vscode.workspace.getConfiguration().get<string>("aidr.hookRunnerPath")?.trim() ?? "";
	if (configured) {
		await access(configured);
		return configured;
	}

	const candidates = [
		context.asAbsolutePath(path.join("dist", "aidr-hook.cjs")),
		context.asAbsolutePath(path.join("resources", "aidr-hook.cjs")),
	];

	for (const candidate of candidates) {
		try {
			await access(candidate);
			return candidate;
		} catch {
			// Try next candidate.
		}
	}

	throw new Error(
		"Unable to locate aidr-hook runner. Build packages/extension or set aidr.hookRunnerPath.",
	);
}

function resolveNodeRuntimePath(): string {
	return process.env.VSCODE_NODE_EXEC_PATH?.trim() || process.execPath;
}

/**
 * Install the stable launcher, point it at this extension's runner, and write
 * the shim next to `configPath`. The returned command never names the
 * versioned extension directory, so it survives updates unchanged.
 */
export async function prepareManagedHookCommand(
	context: vscode.ExtensionContext,
	host: ExtensionHookHost,
	configPath: string,
	marker: string,
): Promise<{ command: string; runnerPath: string }> {
	const runnerPath = await resolveRunnerPath(context);
	const { extension, extensionPath } = context as Partial<vscode.ExtensionContext>;
	const launcherPath = await installHookRuntime({
		host,
		runnerPath,
		launcherSourcePath: context.asAbsolutePath(path.join("dist", LAUNCHER_FILE_NAME)),
		extensionsDir: extensionPath ? path.dirname(extensionPath) : undefined,
		extensionId: extension?.id,
		version: (extension?.packageJSON as { version?: string } | undefined)?.version,
		configPath,
	});
	const shimPath = await writeHookShims(
		host,
		path.join(path.dirname(configPath), "hooks"),
		resolveNodeRuntimePath(),
		launcherPath,
	);
	return { command: buildShimCommand(shimPath, host, marker), runnerPath };
}

/** Health of the managed entries found in a hook file; broken shims make it unhealthy. */
export async function describeManagedHooks(
	host: ExtensionHookHost,
	configPath: string,
	installedEvents: string[],
	managedCommands: string[],
): Promise<ManagedHookHealth> {
	const problems = await inspectManagedCommands(managedCommands);
	return {
		configPath,
		runnerPath: managedCommands.length > 0 ? resolvedRunnerFor(host) : undefined,
		installedEvents,
		managedCommands,
		problems,
		healthy: installedEvents.length > 0 && problems.length === 0,
	};
}
